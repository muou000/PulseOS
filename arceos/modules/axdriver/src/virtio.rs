use alloc::sync::{Arc, Weak};
use core::{
    marker::PhantomData,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use axalloc::global_allocator;
use axdriver_base::{BaseDriverOps, DevError, DevResult, DeviceType};
use axdriver_virtio::{BufferDirection, PhysAddr, VirtIoHal};
use axhal::mem::{phys_to_virt, virt_to_phys};
use axpoll::PollSet;
use cfg_if::cfg_if;
use kspin::SpinNoIrq;

use crate::{AxDeviceEnum, drivers::DriverProbe};

cfg_if! {
    if #[cfg(bus = "pci")] {
        use axdriver_pci::{PciRoot, DeviceFunction, DeviceFunctionInfo, BarInfo};
        type VirtIoTransport = axdriver_virtio::PciTransport;
    } else if #[cfg(bus =  "mmio")] {
        type VirtIoTransport = axdriver_virtio::MmioTransport;
    }
}

/// A trait for VirtIO device meta information.
pub trait VirtIoDevMeta {
    const DEVICE_TYPE: DeviceType;

    type Device: BaseDriverOps;
    type Driver = VirtIoDriver<Self>;

    fn try_new(transport: VirtIoTransport, irq: usize) -> DevResult<AxDeviceEnum>;
}

trait VirtioInterruptHandler: Send + Sync {
    fn handle(&self);
}

struct WeakVirtioInterruptHandler<T> {
    device: Weak<T>,
    handler: fn(&T),
}

impl<T: Send + Sync + 'static> VirtioInterruptHandler for WeakVirtioInterruptHandler<T> {
    fn handle(&self) {
        if let Some(device) = self.device.upgrade() {
            (self.handler)(&device);
        }
    }
}

#[derive(Clone)]
struct VirtioInterruptInfo {
    id: usize,
    handler: Arc<dyn VirtioInterruptHandler>,
}

struct VirtioIrqRegistration {
    irq: usize,
    id: usize,
}

impl Drop for VirtioIrqRegistration {
    fn drop(&mut self) {
        let remove_irq = {
            let mut guard = VIRTIO_INTERRUPTS.lock();
            let Some(infos) = guard.get_mut(&self.irq) else {
                return;
            };
            infos.retain(|info| info.id != self.id);
            if infos.is_empty() {
                guard.remove(&self.irq);
                true
            } else {
                false
            }
        };

        if remove_irq {
            axhal::irq::set_enable(self.irq, false);
            let _ = axhal::irq::unregister(self.irq);
        }
    }
}

static VIRTIO_INTERRUPTS: SpinNoIrq<
    alloc::collections::BTreeMap<usize, alloc::vec::Vec<VirtioInterruptInfo>>,
> = SpinNoIrq::new(alloc::collections::BTreeMap::new());
static NEXT_VIRTIO_INTERRUPT_ID: AtomicUsize = AtomicUsize::new(1);

fn register_virtio_interrupt<T: Send + Sync + 'static>(
    irq: usize,
    device: &Arc<T>,
    handler: fn(&T),
) -> DevResult<VirtioIrqRegistration> {
    if irq == 0 {
        return Err(DevError::BadState);
    }

    let id = NEXT_VIRTIO_INTERRUPT_ID.fetch_add(1, Ordering::Relaxed);
    let mut guard = VIRTIO_INTERRUPTS.lock();
    if !guard.contains_key(&irq) && !axhal::irq::register(irq, common_virtio_irq_handler) {
        return Err(DevError::BadState);
    }
    guard.entry(irq).or_default().push(VirtioInterruptInfo {
        id,
        handler: Arc::new(WeakVirtioInterruptHandler {
            device: Arc::downgrade(device),
            handler,
        }),
    });
    drop(guard);
    axhal::irq::set_enable(irq, true);

    Ok(VirtioIrqRegistration { irq, id })
}

fn common_virtio_irq_handler(irq: usize) {
    axlog::debug!("common_virtio_irq_handler: irq={}", irq);
    let infos = VIRTIO_INTERRUPTS.lock().get(&irq).cloned();
    if let Some(infos) = infos {
        axlog::debug!(
            "common_virtio_irq_handler: found {} handlers for irq={}",
            infos.len(),
            irq
        );
        for info in infos {
            info.handler.handle();
        }
    } else {
        axlog::debug!(
            "common_virtio_irq_handler: no handlers found for irq={}",
            irq
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopInterruptHandler;

    impl VirtioInterruptHandler for NoopInterruptHandler {
        fn handle(&self) {}
    }

    fn noop_device_handler(_: &()) {}

    #[test]
    fn zero_irq_is_rejected() {
        let device = Arc::new(());
        assert!(matches!(
            register_virtio_interrupt(0, &device, noop_device_handler),
            Err(DevError::BadState)
        ));
    }

    #[test]
    fn registration_lives_until_last_shared_owner() {
        let id = NEXT_VIRTIO_INTERRUPT_ID.fetch_add(2, Ordering::Relaxed);
        let sentinel_id = id + 1;
        let irq = usize::MAX - id;
        let handler: Arc<dyn VirtioInterruptHandler> = Arc::new(NoopInterruptHandler);

        VIRTIO_INTERRUPTS.lock().insert(
            irq,
            alloc::vec![
                VirtioInterruptInfo {
                    id,
                    handler: handler.clone(),
                },
                // Keep the shared IRQ populated so this unit test never calls
                // into a real platform IRQ controller.
                VirtioInterruptInfo {
                    id: sentinel_id,
                    handler,
                },
            ],
        );

        let registration = Arc::new(VirtioIrqRegistration { irq, id });
        let cloned_registration = registration.clone();
        drop(registration);
        assert!(
            VIRTIO_INTERRUPTS
                .lock()
                .get(&irq)
                .is_some_and(|infos| infos.iter().any(|info| info.id == id))
        );

        drop(cloned_registration);
        let mut interrupts = VIRTIO_INTERRUPTS.lock();
        assert!(
            interrupts
                .get(&irq)
                .is_some_and(|infos| infos.iter().all(|info| info.id != id))
        );
        interrupts.remove(&irq);
    }

    #[cfg(block_dev = "virtio-blk")]
    #[test]
    fn virtio_block_errors_keep_their_driver_semantics() {
        use virtio_drivers::Error;

        assert!(matches!(
            virtio_err_to_dev(Error::NotReady),
            DevError::Again
        ));
        assert!(matches!(
            virtio_err_to_dev(Error::WrongToken),
            DevError::BadState
        ));
        assert!(matches!(
            virtio_err_to_dev(Error::DmaError),
            DevError::NoMemory
        ));
        assert!(matches!(
            virtio_err_to_dev(Error::Unsupported),
            DevError::Unsupported
        ));
    }

    #[cfg(block_dev = "virtio-blk")]
    #[test]
    fn duplicate_completion_wakers_are_coalesced() {
        let mut wakers: [Option<core::task::Waker>; 2] = core::array::from_fn(|_| None);
        let mut count = 0;
        let waker = core::task::Waker::noop().clone();

        assert!(push_unique_completion_waker(
            &mut wakers,
            &mut count,
            waker.clone()
        ));
        assert!(!push_unique_completion_waker(
            &mut wakers,
            &mut count,
            waker
        ));
        assert_eq!(count, 1);
    }
}

cfg_if! {
    if #[cfg(net_dev = "virtio-net")] {
        pub struct VirtIoNet;

        pub struct VirtIoNetDevInner<H: VirtIoHal, T: virtio_drivers::transport::Transport, const QS: usize> {
            inner: SpinNoIrq<axdriver_virtio::VirtIoNetDev<H, T, QS>>,
            poll_set: Arc<PollSet>,
        }

        pub struct VirtIoNetDevWrapper<H: VirtIoHal, T: virtio_drivers::transport::Transport, const QS: usize> {
            _irq_registration: VirtioIrqRegistration,
            inner: Arc<VirtIoNetDevInner<H, T, QS>>,
        }

        unsafe impl<H: VirtIoHal, T: virtio_drivers::transport::Transport, const QS: usize> Send for VirtIoNetDevWrapper<H, T, QS> {}
        unsafe impl<H: VirtIoHal, T: virtio_drivers::transport::Transport, const QS: usize> Sync for VirtIoNetDevWrapper<H, T, QS> {}

        impl<H: VirtIoHal + Send + Sync + 'static,
             T: virtio_drivers::transport::Transport + Send + Sync + 'static,
             const QS: usize> VirtIoNetDevWrapper<H, T, QS> {
            pub fn try_new(transport: T, irq: usize) -> DevResult<Self> {
                let mut dev = axdriver_virtio::VirtIoNetDev::try_new(transport)?;
                dev.enable_interrupts();
                let poll_set = Arc::new(PollSet::new());
                let inner = Arc::new(VirtIoNetDevInner {
                    inner: SpinNoIrq::new(dev),
                    poll_set,
                });
                fn handler<H: VirtIoHal, T: virtio_drivers::transport::Transport, const QS: usize>(
                    w: &VirtIoNetDevInner<H, T, QS>,
                ) {
                    let mut inner_dev = w.inner.lock();
                    if inner_dev.ack_interrupt() {
                        w.poll_set.wake();
                    }
                }
                let irq_registration =
                    register_virtio_interrupt(irq, &inner, handler::<H, T, QS>)?;
                Ok(Self {
                    _irq_registration: irq_registration,
                    inner,
                })
            }
        }

        impl<H: VirtIoHal, T: virtio_drivers::transport::Transport, const QS: usize> BaseDriverOps for VirtIoNetDevWrapper<H, T, QS> {
            fn device_name(&self) -> &str {
                "virtio-net"
            }
            fn device_type(&self) -> DeviceType {
                DeviceType::Net
            }
        }

        impl<H: VirtIoHal, T: virtio_drivers::transport::Transport, const QS: usize> axdriver_net::NetDriverOps for VirtIoNetDevWrapper<H, T, QS> {
            fn mac_address(&self) -> axdriver_net::EthernetAddress {
                self.inner.inner.lock().mac_address()
            }
            fn can_transmit(&self) -> bool {
                self.inner.inner.lock().can_transmit()
            }
            fn can_receive(&self) -> bool {
                self.inner.inner.lock().can_receive()
            }
            fn rx_queue_size(&self) -> usize {
                self.inner.inner.lock().rx_queue_size()
            }
            fn tx_queue_size(&self) -> usize {
                self.inner.inner.lock().tx_queue_size()
            }
            fn recycle_rx_buffer(&mut self, rx_buf: axdriver_net::NetBufPtr) -> DevResult {
                self.inner.inner.lock().recycle_rx_buffer(rx_buf)
            }
            fn recycle_tx_buffers(&mut self) -> DevResult {
                self.inner.inner.lock().recycle_tx_buffers()
            }
            fn transmit(&mut self, tx_buf: axdriver_net::NetBufPtr) -> DevResult {
                self.inner.inner.lock().transmit(tx_buf)
            }
            fn receive(&mut self) -> DevResult<axdriver_net::NetBufPtr> {
                self.inner.inner.lock().receive()
            }
            fn alloc_tx_buffer(&mut self, size: usize) -> DevResult<axdriver_net::NetBufPtr> {
                self.inner.inner.lock().alloc_tx_buffer(size)
            }
            fn poll_set(&self) -> Option<&axpoll::PollSet> {
                Some(&self.inner.poll_set)
            }
        }

        impl VirtIoDevMeta for VirtIoNet {
            const DEVICE_TYPE: DeviceType = DeviceType::Net;
            type Device = VirtIoNetDevWrapper<VirtIoHalImpl, VirtIoTransport, 64>;

            fn try_new(transport: VirtIoTransport, irq: usize) -> DevResult<AxDeviceEnum> {
                Ok(AxDeviceEnum::from_net(Self::Device::try_new(transport, irq)?))
            }
        }
    }
}

cfg_if! {
    if #[cfg(block_dev = "virtio-blk")] {
        pub struct VirtIoBlk;

        use alloc::{boxed::Box, vec::Vec};
        use core::{
            future::Future,
            pin::Pin,
            task::{Context, Poll, Waker},
        };
        use virtio_drivers::{
            device::blk::{BlkReq, BlkResp, VIRTIO_BLK_QUEUE_SIZE},
            Dma,
        };

        // axfs fills up to 16 page-cache pages (64 KiB) per sequential read.
        // Keep those fallback bounce buffers reusable while direct reads use
        // their registered final page-cache buffer for the data descriptor.
        const DMA_POOL_MAX_DATA_LEN: usize = 64 * 1024;
        const DMA_POOL_MAX_REQUEST_PAGES: usize = (core::mem::size_of::<BlkReq>()
            + DMA_POOL_MAX_DATA_LEN
            + core::mem::size_of::<BlkResp>()
            + virtio_drivers::PAGE_SIZE
            - 1)
            / virtio_drivers::PAGE_SIZE;
        const DMA_POOL_MAX_PAGES: usize =
            VIRTIO_BLK_QUEUE_SIZE * DMA_POOL_MAX_REQUEST_PAGES;
        const COMPLETION_RECHECK_INTERVAL_NS: u64 = 1_000_000;
        fn push_unique_completion_waker<const N: usize>(
            wakers: &mut [Option<Waker>; N],
            count: &mut usize,
            waker: Waker,
        ) -> bool {
            debug_assert!(*count <= N);
            if wakers[..*count]
                .iter()
                .flatten()
                .any(|registered| registered.will_wake(&waker))
            {
                return false;
            }
            assert!(*count < N, "virtio-blk completion wake batch overflow");
            wakers[*count] = Some(waker);
            *count += 1;
            true
        }

        /// Converts a `virtio_drivers::Error` into a `DevError`.
        /// Extracted to avoid repeating this conversion in read/write paths.
        fn virtio_err_to_dev(e: virtio_drivers::Error) -> axdriver_base::DevError {
            use virtio_drivers::Error::*;
            match e {
                QueueFull => DevError::BadState,
                NotReady => DevError::Again,
                WrongToken => DevError::BadState,
                AlreadyUsed => DevError::AlreadyExists,
                InvalidParam => DevError::InvalidParam,
                DmaError => DevError::NoMemory,
                IoError => DevError::Io,
                Unsupported => DevError::Unsupported,
                ConfigSpaceTooSmall | ConfigSpaceMissing | SocketDeviceError(_) => DevError::BadState,
            }
        }

        struct VirtIoBlkState<H: VirtIoHal, T: virtio_drivers::transport::Transport> {
            device: axdriver_virtio::VirtIoBlkDev<H, T>,
            pending: [Option<(u64, PendingBlockRequest<H>)>; VIRTIO_BLK_QUEUE_SIZE],
            pending_direct_reads:
                [Option<axdriver_block::OwnedReadBufferLease>; VIRTIO_BLK_QUEUE_SIZE],
            completed: Vec<(u64, PendingBlockRequest<H>)>,
            dma_pool: Vec<DmaBlockRequest<H>>,
            dma_pool_pages: usize,
            next_request_id: u64,
            submit_wakers: Vec<Waker>,
        }

        pub struct VirtIoBlkDevInner<H: VirtIoHal, T: virtio_drivers::transport::Transport> {
            inner: SpinNoIrq<VirtIoBlkState<H, T>>,
            completion_irq_count: AtomicUsize,
            completion_recheck_armed: AtomicBool,
        }

        pub struct VirtIoBlkDevWrapper<H: VirtIoHal, T: virtio_drivers::transport::Transport> {
            _irq_registration: Arc<VirtioIrqRegistration>,
            inner: Arc<VirtIoBlkDevInner<H, T>>,
        }

        impl<H: VirtIoHal, T: virtio_drivers::transport::Transport> Clone
            for VirtIoBlkDevWrapper<H, T>
        {
            fn clone(&self) -> Self {
                Self {
                    _irq_registration: self._irq_registration.clone(),
                    inner: self.inner.clone(),
                }
            }
        }

        unsafe impl<H: VirtIoHal, T: virtio_drivers::transport::Transport> Send for VirtIoBlkDevWrapper<H, T> {}
        unsafe impl<H: VirtIoHal, T: virtio_drivers::transport::Transport> Sync for VirtIoBlkDevWrapper<H, T> {}

        impl<H: VirtIoHal + Send + Sync + 'static,
             T: virtio_drivers::transport::Transport + Send + Sync + 'static>
            VirtIoBlkDevWrapper<H, T> {
            pub fn try_new(transport: T, irq: usize) -> DevResult<Self> {
                let mut dev = axdriver_virtio::VirtIoBlkDev::try_new(transport)?;
                dev.enable_interrupts();
                let inner = Arc::new(VirtIoBlkDevInner {
                    inner: SpinNoIrq::new(VirtIoBlkState {
                        device: dev,
                        pending: core::array::from_fn(|_| None),
                        pending_direct_reads: core::array::from_fn(|_| None),
                        completed: Vec::with_capacity(VIRTIO_BLK_QUEUE_SIZE),
                        dma_pool: Vec::with_capacity(VIRTIO_BLK_QUEUE_SIZE),
                        dma_pool_pages: 0,
                        next_request_id: 0,
                        submit_wakers: Vec::with_capacity(VIRTIO_BLK_QUEUE_SIZE),
                    }),
                    completion_irq_count: AtomicUsize::new(0),
                    completion_recheck_armed: AtomicBool::new(false),
                });
                fn handler<H: VirtIoHal, T: virtio_drivers::transport::Transport>(
                    w: &VirtIoBlkDevInner<H, T>,
                ) {
                    axlog::debug!("virtio-blk interrupt handler: checking interrupt");
                    let acked = w.inner.lock().device.ack_interrupt();
                    w.completion_irq_count.fetch_add(1, Ordering::Relaxed);
                    axlog::debug!("virtio-blk interrupt handler: acked={}", acked);
                    // Notify unconditionally: for MSI-X mode, the device fires
                    // the interrupt only when I/O completes; `acked` reflects
                    // whether the legacy ISR STATUS bit was set, which is NOT
                    // reliable under MSI-X (QEMU may return false even on completion).
                    // The block wait loops guard correctness via `peek_used()` checks.
                    //
                    // If acked=true (legacy/MMIO mode) or acked=false (MSI-X mode),
                    // both should wake waiters. Wrong wakeups are harmless because
                    // peek_used() will simply return None and the loop will re-sleep.
                    let _ = w.drain_completions(None);
                }
                let irq_registration = Arc::new(register_virtio_interrupt(
                    irq,
                    &inner,
                    handler::<H, T>,
                )?);
                Ok(Self {
                    _irq_registration: irq_registration,
                    inner,
                })
            }
        }

        const DMA_REQUEST_OFFSET: usize = 0;
        const DMA_DATA_OFFSET: usize = core::mem::size_of::<BlkReq>();

        struct DmaBlockRequest<H: VirtIoHal> {
            dma: Dma<H>,
            data_capacity: usize,
            data_len: usize,
        }

        impl<H: VirtIoHal> DmaBlockRequest<H> {
            fn new(data_len: usize) -> virtio_drivers::Result<Self> {
                let bytes = DMA_DATA_OFFSET
                    .checked_add(data_len)
                    .and_then(|value| value.checked_add(core::mem::size_of::<BlkResp>()))
                    .ok_or(virtio_drivers::Error::InvalidParam)?;
                let pages = bytes.div_ceil(virtio_drivers::PAGE_SIZE);
                let dma = Dma::new(pages, BufferDirection::Both)?;
                let data_capacity = pages * virtio_drivers::PAGE_SIZE
                    - DMA_DATA_OFFSET
                    - core::mem::size_of::<BlkResp>();
                Ok(Self {
                    dma,
                    data_capacity,
                    data_len: 0,
                })
            }

            fn pages(&self) -> usize {
                (DMA_DATA_OFFSET + self.data_capacity + core::mem::size_of::<BlkResp>())
                    / virtio_drivers::PAGE_SIZE
            }

            fn can_hold(&self, data_len: usize) -> bool {
                data_len <= self.data_capacity
            }

            fn prepare(&mut self, data_len: usize) {
                assert!(self.can_hold(data_len));
                self.data_len = data_len;
                let request = self.dma.vaddr(DMA_REQUEST_OFFSET).as_ptr().cast::<BlkReq>();
                let response = self
                    .dma
                    .vaddr(DMA_DATA_OFFSET + data_len)
                    .as_ptr()
                    .cast::<BlkResp>();
                // SAFETY: The DMA allocation is exclusively owned by this
                // request while it is prepared for its next submission.
                unsafe {
                    request.write(BlkReq::default());
                    response.write(BlkResp::default());
                }
            }

            fn data(&self) -> &[u8] {
                // SAFETY: The data range lies between the request and response
                // objects and remains valid for the lifetime of `self`.
                unsafe {
                    core::slice::from_raw_parts(
                        self.dma.vaddr(DMA_DATA_OFFSET).as_ptr(),
                        self.data_len,
                    )
                }
            }

            fn data_mut(&mut self) -> &mut [u8] {
                // SAFETY: `&mut self` provides exclusive access to the data
                // range, which is disjoint from the request and response.
                unsafe {
                    core::slice::from_raw_parts_mut(
                        self.dma.vaddr(DMA_DATA_OFFSET).as_ptr(),
                        self.data_len,
                    )
                }
            }

            fn parts_mut(&mut self) -> (&mut BlkReq, &mut [u8], &mut BlkResp) {
                let request = self.dma.vaddr(DMA_REQUEST_OFFSET).as_ptr().cast::<BlkReq>();
                let data = self.dma.vaddr(DMA_DATA_OFFSET).as_ptr();
                let response = self
                    .dma
                    .vaddr(DMA_DATA_OFFSET + self.data_len)
                    .as_ptr()
                    .cast::<BlkResp>();
                // SAFETY: These three ranges were laid out disjointly in
                // `new`, remain allocated, and `&mut self` excludes aliases.
                unsafe {
                    (
                        &mut *request,
                        core::slice::from_raw_parts_mut(data, self.data_len),
                        &mut *response,
                    )
                }
            }
        }

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum BlockRequestOp {
            Read,
            Write,
            Flush,
        }

        enum SubmitOutcome {
            Queued(u16),
            Complete,
        }

        struct PendingBlockRequest<H: VirtIoHal> {
            op: BlockRequestOp,
            dma: DmaBlockRequest<H>,
            result: Option<DevResult>,
            waker: Option<Waker>,
            detached: bool,
        }

        impl<H: VirtIoHal> PendingBlockRequest<H> {
            fn new(
                op: BlockRequestOp,
                data_len: usize,
                direct_read: bool,
                mut dma: DmaBlockRequest<H>,
            ) -> Self {
                debug_assert!(!direct_read || op == BlockRequestOp::Read);
                dma.prepare(if direct_read { 0 } else { data_len });
                Self {
                    op,
                    dma,
                    result: None,
                    waker: None,
                    detached: false,
                }
            }

            fn into_dma(self) -> DmaBlockRequest<H> {
                self.dma
            }

            fn uses_direct_read(&self) -> bool {
                self.op == BlockRequestOp::Read && self.dma.data_len == 0
            }

            fn parts_mut<'a>(
                &'a mut self,
                direct_read: Option<&'a mut axdriver_block::OwnedReadBufferLease>,
            ) -> (&'a mut BlkReq, &'a mut [u8], &'a mut BlkResp) {
                debug_assert_eq!(self.uses_direct_read(), direct_read.is_some());
                let dma = &mut self.dma;
                let (request, bounce_data, response) = dma.parts_mut();
                let data = if let Some(direct_read) = direct_read {
                    // SAFETY: The registration contract reserves the range for
                    // device writes, and this pending request holds its owner
                    // until the descriptor chain is reclaimed.
                    unsafe { direct_read.as_mut_slice() }
                } else {
                    bounce_data
                };
                (request, data, response)
            }

            fn submit<T: virtio_drivers::transport::Transport>(
                &mut self,
                device: &mut axdriver_virtio::VirtIoBlkDev<H, T>,
                block_id: u64,
                direct_read: Option<&mut axdriver_block::OwnedReadBufferLease>,
            ) -> virtio_drivers::Result<SubmitOutcome> {
                let block_id = usize::try_from(block_id)
                    .map_err(|_| virtio_drivers::Error::InvalidParam)?;
                let op = self.op;
                let (request, data, response) = self.parts_mut(direct_read);
                // SAFETY: Request/response storage is owned by `self.dma` and
                // data is either in the same allocation or covered by a direct
                // read lease. All buffers remain stable until completion.
                unsafe {
                    match op {
                        BlockRequestOp::Read => device
                            .inner
                            .read_blocks_nb(block_id, request, data, response)
                            .map(SubmitOutcome::Queued),
                        BlockRequestOp::Write => device
                            .inner
                            .write_blocks_nb(block_id, request, data, response)
                            .map(SubmitOutcome::Queued),
                        BlockRequestOp::Flush => device
                            .inner
                            .flush_nb(request, response)
                            .map(|token| token.map_or(SubmitOutcome::Complete, SubmitOutcome::Queued)),
                    }
                }
            }

            fn complete<T: virtio_drivers::transport::Transport>(
                &mut self,
                device: &mut axdriver_virtio::VirtIoBlkDev<H, T>,
                token: u16,
                direct_read: Option<&mut axdriver_block::OwnedReadBufferLease>,
            ) -> DevResult {
                let op = self.op;
                let (request, data, response) = self.parts_mut(direct_read);
                // SAFETY: `token` identifies the descriptor chain submitted
                // with these exact DMA-backed buffers, and `peek_used` proved
                // that the device no longer owns the chain.
                unsafe {
                    match op {
                        BlockRequestOp::Read => device
                            .inner
                            .complete_read_blocks(token, request, data, response),
                        BlockRequestOp::Write => device
                            .inner
                            .complete_write_blocks(token, request, data, response),
                        BlockRequestOp::Flush => {
                            device.inner.complete_flush(token, request, response)
                        }
                    }
                }
                .map_err(virtio_err_to_dev)
            }
        }

        struct CompletionWake<H: VirtIoHal> {
            request_id: u64,
            request: Option<Waker>,
            extracted: Option<PendingBlockRequest<H>>,
        }

        impl<H: VirtIoHal, T: virtio_drivers::transport::Transport> VirtIoBlkState<H, T> {
            fn register_submit_waker(&mut self, waker: &Waker) {
                if !self.submit_wakers.iter().any(|entry| entry.will_wake(waker)) {
                    self.submit_wakers.push(waker.clone());
                }
            }

            fn register_request_waker(
                &mut self,
                token: u16,
                request_id: u64,
                waker: &Waker,
            ) -> bool {
                let Some((pending_id, request)) = self
                    .pending
                    .get_mut(token as usize)
                    .and_then(Option::as_mut)
                else {
                    return false;
                };
                if *pending_id != request_id {
                    return false;
                }
                if request
                    .waker
                    .as_ref()
                    .is_none_or(|registered| !registered.will_wake(waker))
                {
                    request.waker = Some(waker.clone());
                }
                true
            }

            fn complete_current_if_used(
                &mut self,
                token: u16,
                request_id: u64,
            ) -> Option<(PendingBlockRequest<H>, Vec<Waker>)> {
                if self.device.inner.peek_used() != Some(token) {
                    return None;
                }
                let wake = self.complete_one(Some(request_id))?;
                assert_eq!(
                    wake.request_id, request_id,
                    "virtio-blk token changed owner while request was pending"
                );
                let request = wake
                    .extracted
                    .expect("current virtio-blk completion was not extracted");
                Some((request, core::mem::take(&mut self.submit_wakers)))
            }

            fn take_dma(&mut self, data_len: usize) -> Option<DmaBlockRequest<H>> {
                let index = self
                    .dma_pool
                    .iter()
                    .enumerate()
                    .filter(|(_, dma)| dma.can_hold(data_len))
                    .min_by_key(|(_, dma)| dma.data_capacity)
                    .map(|(index, _)| index)?;
                let dma = self.dma_pool.swap_remove(index);
                self.dma_pool_pages -= dma.pages();
                Some(dma)
            }

            fn recycle_dma(&mut self, dma: DmaBlockRequest<H>) {
                let pages = dma.pages();
                if pages <= DMA_POOL_MAX_REQUEST_PAGES
                    && self.dma_pool.len() < VIRTIO_BLK_QUEUE_SIZE
                    && self.dma_pool_pages + pages <= DMA_POOL_MAX_PAGES
                {
                    self.dma_pool_pages += pages;
                    self.dma_pool.push(dma);
                }
            }

            fn recycle_request(&mut self, request: PendingBlockRequest<H>) {
                self.recycle_dma(request.into_dma());
            }

            fn take_completed(&mut self, request_id: u64) -> Option<PendingBlockRequest<H>> {
                let index = self
                    .completed
                    .iter()
                    .position(|(completed_id, _)| *completed_id == request_id)?;
                Some(self.completed.swap_remove(index).1)
            }

            fn complete_one(
                &mut self,
                extract_request_id: Option<u64>,
            ) -> Option<CompletionWake<H>> {
                let token = self.device.inner.peek_used()?;
                let Some(slot) = self.pending.get_mut(token as usize) else {
                    panic!("virtio-blk completed out-of-range token {}", token);
                };
                let Some((request_id, mut request)) = slot.take() else {
                    panic!("virtio-blk completed unknown token {}", token);
                };
                let direct_read = self.pending_direct_reads[token as usize].as_mut();
                request.result = Some(request.complete(&mut self.device, token, direct_read));
                // `complete` reclaimed the descriptor chain, so the device can
                // no longer access the registered destination.
                self.pending_direct_reads[token as usize].take();
                let request_waker = request.waker.take();
                let extracted = if request.detached {
                    self.recycle_request(request);
                    None
                } else if extract_request_id == Some(request_id) {
                    Some(request)
                } else {
                    debug_assert!(
                        self.completed
                            .iter()
                            .all(|(completed_id, _)| *completed_id != request_id)
                    );
                    self.completed.push((request_id, request));
                    None
                };
                Some(CompletionWake {
                    request_id,
                    request: request_waker,
                    extracted,
                })
            }
        }

        impl<H: VirtIoHal, T: virtio_drivers::transport::Transport>
            VirtIoBlkDevInner<H, T>
        {
            fn new_request(
                &self,
                op: BlockRequestOp,
                data_len: usize,
                direct_read: bool,
            ) -> virtio_drivers::Result<PendingBlockRequest<H>> {
                let dma_data_len = if direct_read { 0 } else { data_len };
                let dma = self
                    .inner
                    .lock()
                    .take_dma(dma_data_len)
                    .map(Ok)
                    .unwrap_or_else(|| DmaBlockRequest::<H>::new(dma_data_len))?;
                Ok(PendingBlockRequest::new(op, data_len, direct_read, dma))
            }

            fn recycle_request(&self, request: PendingBlockRequest<H>) {
                self.inner.lock().recycle_request(request);
            }

            fn drain_completions(
                &self,
                extract_request_id: Option<u64>,
            ) -> (usize, Option<PendingBlockRequest<H>>) {
                let (completed, extracted, request_wakers, submit_wakers) = {
                    let mut state = self.inner.lock();
                    let mut completed = 0;
                    let mut extracted =
                        extract_request_id.and_then(|request_id| state.take_completed(request_id));
                    let mut request_wakers: [Option<Waker>; VIRTIO_BLK_QUEUE_SIZE] =
                        core::array::from_fn(|_| None);
                    let mut request_waker_count = 0;
                    while completed < VIRTIO_BLK_QUEUE_SIZE {
                        let extract = if extracted.is_none() {
                            extract_request_id
                        } else {
                            None
                        };
                        let Some(wake) = state.complete_one(extract) else {
                            break;
                        };
                        if let Some(request) = wake.extracted {
                            debug_assert!(extracted.is_none());
                            extracted = Some(request);
                        }
                        if Some(wake.request_id) != extract_request_id
                            && let Some(waker) = wake.request
                        {
                            // Futures in one joined page-cache fill share the
                            // task waker. Publish every completion above, then
                            // enqueue that task only once for this IRQ batch.
                            let _ = push_unique_completion_waker(
                                &mut request_wakers,
                                &mut request_waker_count,
                                waker,
                            );
                        }
                        completed += 1;
                    }
                    let submit_wakers = if completed == 0 {
                        Vec::new()
                    } else {
                        core::mem::take(&mut state.submit_wakers)
                    };
                    (completed, extracted, request_wakers, submit_wakers)
                };
                for waker in request_wakers.into_iter().flatten() {
                    waker.wake();
                }
                for waker in submit_wakers {
                    waker.wake();
                }
                (completed, extracted)
            }

            #[cfg(all(feature = "multitask", feature = "irq"))]
            fn arm_completion_recheck(self: &Arc<Self>)
            where
                H: Send + Sync + 'static,
                T: Send + Sync + 'static,
            {
                if self
                    .completion_recheck_armed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return;
                }

                let weak = Arc::downgrade(self);
                let deadline = axhal::time::monotonic_time_nanos()
                    .saturating_add(COMPLETION_RECHECK_INTERVAL_NS);
                axtask::set_generic_timer(
                    deadline,
                    Box::new(move |_| {
                        let Some(inner) = weak.upgrade() else {
                            return;
                        };
                        inner
                            .completion_recheck_armed
                            .store(false, Ordering::Release);
                        let _ = inner.drain_completions(None);
                        let has_pending = inner
                            .inner
                            .lock()
                            .pending
                            .iter()
                            .any(Option::is_some);
                        if has_pending {
                            inner.arm_completion_recheck();
                        }
                    }),
                );
            }

            #[cfg(not(all(feature = "multitask", feature = "irq")))]
            fn arm_completion_recheck(self: &Arc<Self>) {}

            fn cancel_request(&self, token: u16, request_id: u64) {
                let mut state = self.inner.lock();
                if let Some(request) = state.take_completed(request_id) {
                    state.recycle_request(request);
                    return;
                }
                if let Some((pending_id, request)) = state
                    .pending
                    .get_mut(token as usize)
                    .and_then(Option::as_mut)
                    && *pending_id == request_id
                {
                    // VirtIO has no portable cancel command. Transfer ownership
                    // to the pending table and let the completion path release
                    // DMA after the device has stopped using it.
                    request.detached = true;
                    request.waker = None;
                }
            }
        }

        enum FutureBuffer<'a> {
            Read(&'a mut [u8]),
            Write(&'a [u8]),
            Flush(PhantomData<&'a ()>),
        }

        /// Cancellation-safe future for one VirtIO block request.
        pub struct VirtIoBlockFuture<
            'a,
            H: VirtIoHal,
            T: virtio_drivers::transport::Transport,
        > {
            inner: Arc<VirtIoBlkDevInner<H, T>>,
            block_id: u64,
            buffer: FutureBuffer<'a>,
            request: Option<PendingBlockRequest<H>>,
            direct_read: Option<axdriver_block::OwnedReadBufferLease>,
            token: Option<u16>,
            request_id: Option<u64>,
        }

        impl<H: VirtIoHal, T: virtio_drivers::transport::Transport> Unpin
            for VirtIoBlockFuture<'_, H, T>
        {
        }

        impl<'a, H: VirtIoHal, T: virtio_drivers::transport::Transport>
            VirtIoBlockFuture<'a, H, T>
        {
            fn read(inner: Arc<VirtIoBlkDevInner<H, T>>, block_id: u64, buf: &'a mut [u8]) -> Self {
                Self {
                    inner,
                    block_id,
                    buffer: FutureBuffer::Read(buf),
                    request: None,
                    direct_read: None,
                    token: None,
                    request_id: None,
                }
            }

            fn write(inner: Arc<VirtIoBlkDevInner<H, T>>, block_id: u64, buf: &'a [u8]) -> Self {
                Self {
                    inner,
                    block_id,
                    buffer: FutureBuffer::Write(buf),
                    request: None,
                    direct_read: None,
                    token: None,
                    request_id: None,
                }
            }

            fn flush(inner: Arc<VirtIoBlkDevInner<H, T>>) -> Self {
                Self {
                    inner,
                    block_id: 0,
                    buffer: FutureBuffer::Flush(PhantomData),
                    request: None,
                    direct_read: None,
                    token: None,
                    request_id: None,
                }
            }

            fn operation_and_len(&self) -> (BlockRequestOp, usize) {
                match &self.buffer {
                    FutureBuffer::Read(buf) => (BlockRequestOp::Read, buf.len()),
                    FutureBuffer::Write(buf) => (BlockRequestOp::Write, buf.len()),
                    FutureBuffer::Flush(_) => (BlockRequestOp::Flush, 0),
                }
            }

            #[cfg(feature = "multitask")]
            fn record_request_wait(&self, token: u16) {
                let context = axtask::WaitContext::new_optional(|| {
                    let reason = match self.buffer {
                        FutureBuffer::Read(_) => axtask::WaitReason::VirtioBlkRead,
                        FutureBuffer::Write(_) => axtask::WaitReason::VirtioBlkWrite,
                        FutureBuffer::Flush(_) => return None,
                    };
                    Some((
                        reason,
                        Arc::as_ptr(&self.inner) as usize as u64,
                        u64::from(token),
                    ))
                });
                if let Some(context) = context {
                    axtask::future::set_current_wait_context(context);
                }
            }

            #[cfg(feature = "multitask")]
            fn record_queue_full_wait(&self) {
                axtask::future::set_current_wait_context(axtask::WaitContext::new(|| {
                    let operation = match self.buffer {
                        FutureBuffer::Read(_) => 1,
                        FutureBuffer::Write(_) => 2,
                        FutureBuffer::Flush(_) => 3,
                    };
                    (
                        axtask::WaitReason::VirtioBlkQueueFull,
                        Arc::as_ptr(&self.inner) as usize as u64,
                        operation,
                    )
                }));
            }

            fn can_suspend() -> bool {
                #[cfg(all(feature = "multitask", feature = "irq"))]
                {
                    // User trap slow paths restore IRQ delivery while running
                    // sleepable work. Other IRQ-disabled callers keep polling
                    // so a completion interrupt cannot strand the task.
                    axhal::asm::irqs_enabled()
                }
                #[cfg(not(all(feature = "multitask", feature = "irq")))]
                {
                    false
                }
            }
        }

        impl<
            H: VirtIoHal + Send + Sync + 'static,
            T: virtio_drivers::transport::Transport + Send + Sync + 'static,
        > Future
            for VirtIoBlockFuture<'_, H, T>
        {
            type Output = DevResult;

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let this = self.as_mut().get_mut();
                loop {
                    let can_suspend = Self::can_suspend();
                    // With task suspension enabled, the interrupt handler owns
                    // the normal used-ring drain. The shared device timer
                    // drains completions when a platform loses an IRQ.
                    let completed_from_drain = if !can_suspend && this.token.is_some() {
                        this.inner.drain_completions(this.request_id).1
                    } else if !can_suspend {
                        if this.request.is_some() {
                            let _ = this.inner.drain_completions(None);
                        }
                        None
                    } else {
                        None
                    };

                    if let Some(token) = this.token {
                        let request_id = this
                            .request_id
                            .expect("submitted request must have an identifier");
                        let completed = if let Some(request) = completed_from_drain {
                            Some(request)
                        } else {
                            let mut submit_wakers_to_wake = Vec::new();
                            let mut state = this.inner.inner.lock();
                            let mut completed = state.take_completed(request_id);
                            if completed.is_none()
                                && let Some((request, submit_wakers)) =
                                    state.complete_current_if_used(token, request_id)
                            {
                                completed = Some(request);
                                submit_wakers_to_wake = submit_wakers;
                            }
                            if completed.is_none() {
                                if !state.register_request_waker(
                                    token,
                                    request_id,
                                    cx.waker(),
                                ) {
                                    axlog::error!(
                                        "virtio-blk lost request: token={}, request_id={}",
                                        token,
                                        request_id
                                    );
                                    return Poll::Ready(Err(DevError::BadState));
                                }
                                // Mirror the wait-queue condition protocol: the
                                // first check precedes waker registration and the
                                // second closes the completion/enrollment race.
                                if let Some((request, submit_wakers)) =
                                    state.complete_current_if_used(token, request_id)
                                {
                                    completed = Some(request);
                                    submit_wakers_to_wake = submit_wakers;
                                }
                            }
                            drop(state);
                            for waker in submit_wakers_to_wake {
                                waker.wake();
                            }
                            completed
                        };
                        if let Some(mut request) = completed {
                            this.token = None;
                            this.request_id = None;
                            let result = request.result.take().expect("completed request has result");
                            if result.is_ok()
                                && !request.uses_direct_read()
                                && let FutureBuffer::Read(buf) = &mut this.buffer
                            {
                                (**buf).copy_from_slice(request.dma.data());
                            }
                            this.inner.recycle_request(request);
                            return Poll::Ready(result);
                        }
                        if can_suspend {
                            // The IRQ path remains primary. The shared device
                            // timer rechecks the ring and wakes the registered
                            // request if a PCI interrupt is lost.
                            this.inner.arm_completion_recheck();
                            #[cfg(feature = "multitask")]
                            this.record_request_wait(token);
                            return Poll::Pending;
                        }
                        core::hint::spin_loop();
                        continue;
                    }

                    let mut request = if let Some(request) = this.request.take() {
                        request
                    } else {
                        let (op, len) = this.operation_and_len();
                        if op != BlockRequestOp::Flush
                            && (len == 0 || len % virtio_drivers::device::blk::SECTOR_SIZE != 0)
                        {
                            return Poll::Ready(Err(DevError::InvalidParam));
                        }
                        this.direct_read = if op == BlockRequestOp::Read {
                            match &mut this.buffer {
                                FutureBuffer::Read(buf) => axdriver_block::claim_owned_read_buffer(
                                    NonNull::from(&mut **buf),
                                ),
                                _ => None,
                            }
                        } else {
                            None
                        };
                        let mut request = match this
                            .inner
                            .new_request(op, len, this.direct_read.is_some())
                        {
                            Ok(request) => request,
                            Err(error) => return Poll::Ready(Err(virtio_err_to_dev(error))),
                        };
                        if let FutureBuffer::Write(buf) = &this.buffer {
                            request.dma.data_mut().copy_from_slice(buf);
                        }
                        request
                    };

                    let submit = {
                        let mut state = this.inner.inner.lock();
                        match request.submit(
                            &mut state.device,
                            this.block_id,
                            this.direct_read.as_mut(),
                        ) {
                            Ok(SubmitOutcome::Queued(token)) => {
                                // Install the waker only if the one-shot completion
                                // probe below misses. Fast completions can then
                                // return from this poll without cloning a Waker.
                                let request_id = state.next_request_id;
                                state.next_request_id = state
                                    .next_request_id
                                    .checked_add(1)
                                    .expect("virtio-blk request identifier exhausted");
                                let token_index = token as usize;
                                assert!(
                                    state
                                        .pending
                                        .get(token_index)
                                        .expect("virtio-blk returned an out-of-range token")
                                        .is_none(),
                                    "virtio-blk reused an in-flight token"
                                );
                                assert!(
                                    state.pending_direct_reads[token_index].is_none(),
                                    "virtio-blk reused an in-flight direct-read token"
                                );
                                state.pending_direct_reads[token_index] = this.direct_read.take();
                                state.pending[token_index] = Some((request_id, request));
                                Ok(Some((token, request_id)))
                            }
                            Ok(SubmitOutcome::Complete) => {
                                state.recycle_request(request);
                                Ok(None)
                            }
                            Err(virtio_drivers::Error::QueueFull) => {
                                state.register_submit_waker(cx.waker());
                                Err(request)
                            }
                            Err(error) => {
                                state.recycle_request(request);
                                return Poll::Ready(Err(virtio_err_to_dev(error)));
                            }
                        }
                    };
                    match submit {
                        Ok(Some((token, request_id))) => {
                            this.token = Some(token);
                            this.request_id = Some(request_id);
                            if can_suspend {
                                // Probe the request once after submission before
                                // enrolling the task in the IRQ/timer wait path.
                                continue;
                            }
                        }
                        Ok(None) => return Poll::Ready(Ok(())),
                        Err(request) => {
                            this.request = Some(request);
                            if can_suspend {
                                this.inner.arm_completion_recheck();
                                #[cfg(feature = "multitask")]
                                this.record_queue_full_wait();
                                return Poll::Pending;
                            }
                            core::hint::spin_loop();
                        }
                    }
                }
            }
        }

        impl<H: VirtIoHal, T: virtio_drivers::transport::Transport> Drop
            for VirtIoBlockFuture<'_, H, T>
        {
            fn drop(&mut self) {
                if let (Some(token), Some(request_id)) =
                    (self.token.take(), self.request_id.take())
                {
                    // The pending table retains the DMA allocation until the
                    // device completes this detached request.
                    self.inner.cancel_request(token, request_id);
                } else if let Some(request) = self.request.take() {
                    self.inner.recycle_request(request);
                }
            }
        }

        impl<H: VirtIoHal, T: virtio_drivers::transport::Transport> BaseDriverOps for VirtIoBlkDevWrapper<H, T> {
            fn device_name(&self) -> &str {
                "virtio-blk"
            }
            fn device_type(&self) -> DeviceType {
                DeviceType::Block
            }
        }

        impl<H: VirtIoHal + Send + Sync + 'static,
             T: virtio_drivers::transport::Transport + Send + Sync + 'static>
            axdriver_block::BlockDriverOps for VirtIoBlkDevWrapper<H, T> {
            fn num_blocks(&self) -> u64 {
                self.inner.inner.lock().device.num_blocks()
            }
            fn block_size(&self) -> usize {
                self.inner.inner.lock().device.block_size()
            }
            fn read_block(&mut self, block_id: u64, buf: &mut [u8]) -> DevResult {
                #[cfg(feature = "multitask")]
                return axtask::future::block_on(
                    <Self as axdriver_block::AsyncBlockDriverOps>::read_block_async(
                        self, block_id, buf,
                    ),
                );
                #[cfg(not(feature = "multitask"))]
                spin_block_on(<Self as axdriver_block::AsyncBlockDriverOps>::read_block_async(
                    self, block_id, buf,
                ))
            }

            fn write_block(&mut self, block_id: u64, buf: &[u8]) -> DevResult {
                #[cfg(feature = "multitask")]
                return axtask::future::block_on(
                    <Self as axdriver_block::AsyncBlockDriverOps>::write_block_async(
                        self, block_id, buf,
                    ),
                );
                #[cfg(not(feature = "multitask"))]
                spin_block_on(<Self as axdriver_block::AsyncBlockDriverOps>::write_block_async(
                    self, block_id, buf,
                ))
            }

            fn flush(&mut self) -> DevResult {
                #[cfg(feature = "multitask")]
                return axtask::future::block_on(
                    <Self as axdriver_block::AsyncBlockDriverOps>::flush_async(self),
                );
                #[cfg(not(feature = "multitask"))]
                spin_block_on(<Self as axdriver_block::AsyncBlockDriverOps>::flush_async(self))
            }
        }

        #[cfg(not(feature = "multitask"))]
        fn spin_block_on<F: Future>(future: F) -> F::Output {
            let mut future = core::pin::pin!(future);
            let mut context = Context::from_waker(Waker::noop());
            loop {
                if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
                    return output;
                }
                core::hint::spin_loop();
            }
        }

        #[cfg(feature = "async")]
        impl<H: VirtIoHal + Send + Sync + 'static,
             T: virtio_drivers::transport::Transport + Send + Sync + 'static>
            axdriver_block::AsyncBlockDriverOps for VirtIoBlkDevWrapper<H, T>
        {
            type ReadFuture<'a> = VirtIoBlockFuture<'a, H, T>
            where
                Self: 'a;

            type WriteFuture<'a> = VirtIoBlockFuture<'a, H, T>
            where
                Self: 'a;

            type FlushFuture<'a> = VirtIoBlockFuture<'a, H, T>
            where
                Self: 'a;

            fn read_block_async<'a>(
                &'a self,
                block_id: u64,
                buf: &'a mut [u8],
            ) -> Self::ReadFuture<'a> {
                VirtIoBlockFuture::read(self.inner.clone(), block_id, buf)
            }

            fn write_block_async<'a>(
                &'a self,
                block_id: u64,
                buf: &'a [u8],
            ) -> Self::WriteFuture<'a> {
                VirtIoBlockFuture::write(self.inner.clone(), block_id, buf)
            }

            fn flush_async(&self) -> Self::FlushFuture<'_> {
                VirtIoBlockFuture::flush(self.inner.clone())
            }
        }

        impl VirtIoDevMeta for VirtIoBlk {
            const DEVICE_TYPE: DeviceType = DeviceType::Block;
            type Device = VirtIoBlkDevWrapper<VirtIoHalImpl, VirtIoTransport>;

            fn try_new(transport: VirtIoTransport, irq: usize) -> DevResult<AxDeviceEnum> {
                Ok(AxDeviceEnum::from_block(Self::Device::try_new(transport, irq)?))
            }
        }
    }
}

cfg_if! {
    if #[cfg(display_dev = "virtio-gpu")] {
        pub struct VirtIoGpu;

        impl VirtIoDevMeta for VirtIoGpu {
            const DEVICE_TYPE: DeviceType = DeviceType::Display;
            type Device = axdriver_virtio::VirtIoGpuDev<VirtIoHalImpl, VirtIoTransport>;

            fn try_new(transport: VirtIoTransport, _irq: usize) -> DevResult<AxDeviceEnum> {
                Ok(AxDeviceEnum::from_display(Self::Device::try_new(transport)?))
            }
        }
    }
}

/// A common driver for all VirtIO devices that implements [`DriverProbe`].
pub struct VirtIoDriver<D: VirtIoDevMeta + ?Sized>(PhantomData<D>);

impl<D: VirtIoDevMeta> DriverProbe for VirtIoDriver<D> {
    #[cfg(bus = "mmio")]
    fn probe_mmio(mmio_base: usize, mmio_size: usize) -> Option<AxDeviceEnum> {
        let base_vaddr = phys_to_virt(mmio_base.into());
        if let Some((ty, transport)) =
            axdriver_virtio::probe_mmio_device(base_vaddr.as_mut_ptr(), mmio_size)
            && ty == D::DEVICE_TYPE
        {
            let irq = if cfg!(target_arch = "riscv64") && mmio_base >= 0x1000_1000 {
                (mmio_base - 0x1000_1000) / 0x1000 + 1
            } else {
                0
            };
            match D::try_new(transport, irq) {
                Ok(dev) => return Some(dev),
                Err(e) => {
                    warn!(
                        "failed to initialize MMIO device at [PA:{:#x}, PA:{:#x}): {:?}",
                        mmio_base,
                        mmio_base + mmio_size,
                        e
                    );
                    return None;
                }
            }
        }
        None
    }

    #[cfg(bus = "pci")]
    fn probe_pci(
        root: &mut PciRoot,
        bdf: DeviceFunction,
        dev_info: &DeviceFunctionInfo,
    ) -> Option<AxDeviceEnum> {
        if dev_info.vendor_id != 0x1af4 {
            return None;
        }
        match (D::DEVICE_TYPE, dev_info.device_id) {
            (DeviceType::Net, 0x1000) | (DeviceType::Net, 0x1041) => {}
            (DeviceType::Block, 0x1001) | (DeviceType::Block, 0x1042) => {}
            (DeviceType::Display, 0x1050) => {}
            _ => return None,
        }

        if let Some((ty, mut transport)) =
            axdriver_virtio::probe_pci_device::<VirtIoHalImpl>(root, bdf, dev_info)
        {
            if ty == D::DEVICE_TYPE {
                let mut irq = 0;
                let mut msix_success = false;

                #[cfg(target_arch = "loongarch64")]
                {
                    // 1. Find MSI-X capability
                    let mut msix_cap_offset = None;
                    for cap in root.capabilities(bdf) {
                        if cap.id == 0x11 {
                            // MSI-X capability ID is 0x11
                            msix_cap_offset = Some(cap.offset);
                            break;
                        }
                    }

                    if let Some(offset) = msix_cap_offset {
                        // 2. Allocate an MSI-X vector in the PCH-MSI range (EIOINTC pins 64..255)
                        // QEMU pch_msi computes: irq_num = (Msg Data & 0xff) - 64
                        // so Msg Data must be in [64, 255].
                        static NEXT_MSI_VECTOR: core::sync::atomic::AtomicUsize =
                            core::sync::atomic::AtomicUsize::new(64);
                        let msi_vector =
                            NEXT_MSI_VECTOR.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
                        if msi_vector < 256 {
                            // 3. Configure MSI-X Table
                            let cap_word0 = root.config_read_word(bdf, offset);
                            let msg_ctrl = (cap_word0 >> 16) as u16;
                            let table_word = root.config_read_word(bdf, offset + 4);
                            let table_bir = (table_word & 0x7) as u8;
                            let table_offset = (table_word & !0x7) as usize;

                            let bar_info = root.bar_info(bdf, table_bir).unwrap();
                            if let BarInfo::Memory { address, .. } = bar_info {
                                let table_paddr = address as usize + table_offset;
                                let table_vaddr = phys_to_virt(table_paddr.into()).as_usize();

                                // Write Vector 0 entry
                                // Msg Addr = 0x2ff00000 (PCH-MSI base, correct for loongarch_virt)
                                // Msg Data = msi_vector (absolute EIOINTC pin number >= 64)
                                unsafe {
                                    core::ptr::write_volatile(
                                        (table_vaddr + 0) as *mut u32,
                                        0x2ff00000,
                                    ); // Msg Addr Low (PCH-MSI base)
                                    core::ptr::write_volatile((table_vaddr + 4) as *mut u32, 0); // Msg Addr High
                                    core::ptr::write_volatile(
                                        (table_vaddr + 8) as *mut u32,
                                        msi_vector as u32,
                                    ); // Msg Data = EIOINTC pin
                                    core::ptr::write_volatile((table_vaddr + 12) as *mut u32, 0); // Vector Control (0 = unmasked)
                                }

                                // 4. Enable MSI-X in device configuration space
                                let new_msg_ctrl = msg_ctrl | (1 << 15); // Enable bit
                                let new_cap_word0 =
                                    (cap_word0 & 0xffff) | ((new_msg_ctrl as u32) << 16);
                                root.config_write_word(bdf, offset, new_cap_word0);

                                // 5. Bind VirtIO queue/config to MSI-X vector 0
                                transport.set_config_msix_vector(0);
                                transport.set_default_queue_msix_vector(0);
                                transport.set_msix_enabled(true);

                                // IRQ number = EIOINTC pin number directly (no offset)
                                irq = msi_vector;
                                msix_success = true;
                                debug!(
                                    "PCI device at {} configured to use MSI-X (eiointc_pin {}, \
                                     irq {})",
                                    bdf, msi_vector, irq
                                );
                            }
                        }
                    }
                }

                if !msix_success {
                    let word = root.config_read_word(bdf, 0x3c);
                    irq = (word & 0xff) as usize;
                    #[cfg(target_arch = "loongarch64")]
                    {
                        if irq == 0 || irq == 255 {
                            irq = 16 + (bdf.device as usize % 4);
                        }
                    }
                }

                match D::try_new(transport, irq) {
                    Ok(dev) => return Some(dev),
                    Err(e) => {
                        warn!(
                            "failed to initialize PCI device at {}({}): {:?}",
                            bdf, dev_info, e
                        );
                        return None;
                    }
                }
            }
        }
        None
    }
}

pub struct VirtIoHalImpl;

const DMA_PAGE_SIZE: usize = 0x1000;

unsafe fn zero_dma_region(vaddr: usize, size: usize) {
    // SAFETY: The caller owns `size` contiguous bytes starting at `vaddr`.
    unsafe { core::ptr::write_bytes(vaddr as *mut u8, 0, size) };
}

unsafe impl VirtIoHal for VirtIoHalImpl {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        let Some(size) = pages.checked_mul(DMA_PAGE_SIZE).filter(|_| pages > 0) else {
            return (0, NonNull::dangling());
        };
        let vaddr = if let Ok(vaddr) = global_allocator().alloc_pages(pages, DMA_PAGE_SIZE) {
            vaddr
        } else {
            return (0, NonNull::dangling());
        };
        // VirtIO may expose freshly allocated descriptor/status memory to the
        // device before every byte is initialized, so the HAL contract requires
        // DMA pages to start zeroed.
        unsafe { zero_dma_region(vaddr, size) };
        let paddr = virt_to_phys(vaddr.into());
        let ptr = NonNull::new(vaddr as _).unwrap();
        (paddr.as_usize(), ptr)
    }

    unsafe fn dma_dealloc(_paddr: PhysAddr, vaddr: NonNull<u8>, pages: usize) -> i32 {
        global_allocator().dealloc_pages(vaddr.as_ptr() as usize, pages);
        0
    }

    #[inline]
    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, _size: usize) -> NonNull<u8> {
        NonNull::new(phys_to_virt(paddr.into()).as_mut_ptr()).unwrap()
    }

    #[inline]
    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        let vaddr = buffer.as_ptr() as *mut u8 as usize;
        virt_to_phys(vaddr.into()).into()
    }

    #[inline]
    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {}

    #[inline]
    fn busy_wait_yield() {
        if axhal::asm::irqs_enabled() {
            axtask::yield_now();
        }
    }
}
