use core::marker::PhantomData;
use core::ptr::NonNull;
use alloc::sync::Arc;
use axpoll::PollSet;
use kspin::SpinNoIrq;

use axalloc::global_allocator;
use axdriver_base::{BaseDriverOps, DevResult, DevError, DeviceType};
use axdriver_virtio::{BufferDirection, PhysAddr, VirtIoHal};
use axhal::mem::{phys_to_virt, virt_to_phys};
use cfg_if::cfg_if;

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

struct VirtioInterruptInfo {
    dev_ptr: *const (),
    handler: unsafe fn(*const ()),
}

unsafe impl Send for VirtioInterruptInfo {}
unsafe impl Sync for VirtioInterruptInfo {}

static VIRTIO_INTERRUPTS: SpinNoIrq<alloc::collections::BTreeMap<usize, VirtioInterruptInfo>> = SpinNoIrq::new(alloc::collections::BTreeMap::new());

fn common_virtio_irq_handler(irq: usize) {
    let guard = VIRTIO_INTERRUPTS.lock();
    if let Some(info) = guard.get(&irq) {
        unsafe { (info.handler)(info.dev_ptr); }
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
            inner: Arc<VirtIoNetDevInner<H, T, QS>>,
            irq: usize,
        }

        unsafe impl<H: VirtIoHal, T: virtio_drivers::transport::Transport, const QS: usize> Send for VirtIoNetDevWrapper<H, T, QS> {}
        unsafe impl<H: VirtIoHal, T: virtio_drivers::transport::Transport, const QS: usize> Sync for VirtIoNetDevWrapper<H, T, QS> {}

        impl<H: VirtIoHal, T: virtio_drivers::transport::Transport, const QS: usize> VirtIoNetDevWrapper<H, T, QS> {
            pub fn try_new(transport: T, irq: usize) -> DevResult<Self> {
                let mut dev = axdriver_virtio::VirtIoNetDev::try_new(transport)?;
                dev.enable_interrupts();
                let poll_set = Arc::new(PollSet::new());
                let inner = Arc::new(VirtIoNetDevInner {
                    inner: SpinNoIrq::new(dev),
                    poll_set,
                });
                if irq > 0 {
                    let dev_ptr = Arc::as_ptr(&inner) as *const ();
                    unsafe fn handler<H: VirtIoHal, T: virtio_drivers::transport::Transport, const QS: usize>(ptr: *const ()) {
                        let w = unsafe { &*(ptr as *const VirtIoNetDevInner<H, T, QS>) };
                        let mut inner_dev = w.inner.lock();
                        if inner_dev.ack_interrupt() {
                            w.poll_set.wake();
                        }
                    }
                    VIRTIO_INTERRUPTS.lock().insert(irq, VirtioInterruptInfo {
                        dev_ptr,
                        handler: handler::<H, T, QS>,
                    });
                    axhal::irq::register(irq, common_virtio_irq_handler);
                    axhal::irq::set_enable(irq, true);
                }
                Ok(Self { inner, irq })
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

        pub struct VirtIoBlkDevInner<H: VirtIoHal, T: virtio_drivers::transport::Transport> {
            inner: SpinNoIrq<axdriver_virtio::VirtIoBlkDev<H, T>>,
            #[cfg(feature = "multitask")]
            wait_queue: axtask::WaitQueue,
        }

        pub struct VirtIoBlkDevWrapper<H: VirtIoHal, T: virtio_drivers::transport::Transport> {
            inner: Arc<VirtIoBlkDevInner<H, T>>,
            irq: usize,
        }

        unsafe impl<H: VirtIoHal, T: virtio_drivers::transport::Transport> Send for VirtIoBlkDevWrapper<H, T> {}
        unsafe impl<H: VirtIoHal, T: virtio_drivers::transport::Transport> Sync for VirtIoBlkDevWrapper<H, T> {}

        impl<H: VirtIoHal, T: virtio_drivers::transport::Transport> VirtIoBlkDevWrapper<H, T> {
            pub fn try_new(transport: T, irq: usize) -> DevResult<Self> {
                let mut dev = axdriver_virtio::VirtIoBlkDev::try_new(transport)?;
                dev.enable_interrupts();
                let inner = Arc::new(VirtIoBlkDevInner {
                    inner: SpinNoIrq::new(dev),
                    #[cfg(feature = "multitask")]
                    wait_queue: axtask::WaitQueue::new(),
                });
                if irq > 0 {
                    let dev_ptr = Arc::as_ptr(&inner) as *const ();
                    unsafe fn handler<H: VirtIoHal, T: virtio_drivers::transport::Transport>(ptr: *const ()) {
                        let w = unsafe { &*(ptr as *const VirtIoBlkDevInner<H, T>) };
                        let mut inner_dev = w.inner.lock();
                        if inner_dev.ack_interrupt() {
                            #[cfg(feature = "multitask")]
                            w.wait_queue.notify_all(true);
                        }
                    }
                    VIRTIO_INTERRUPTS.lock().insert(irq, VirtioInterruptInfo {
                        dev_ptr,
                        handler: handler::<H, T>,
                    });
                    axhal::irq::register(irq, common_virtio_irq_handler);
                    axhal::irq::set_enable(irq, true);
                }
                Ok(Self { inner, irq })
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

        impl<H: VirtIoHal, T: virtio_drivers::transport::Transport> axdriver_block::BlockDriverOps for VirtIoBlkDevWrapper<H, T> {
            fn num_blocks(&self) -> u64 {
                self.inner.inner.lock().num_blocks()
            }
            fn block_size(&self) -> usize {
                self.inner.inner.lock().block_size()
            }
            fn read_block(&mut self, block_id: u64, buf: &mut [u8]) -> DevResult {
                let mut inner = self.inner.inner.lock();
                let mut req = virtio_drivers::device::blk::BlkReq::default();
                let mut resp = virtio_drivers::device::blk::BlkResp::default();
                let token = unsafe {
                    inner.inner.read_blocks_nb(block_id as usize, &mut req, buf, &mut resp)
                }.map_err(|e| {
                    use virtio_drivers::Error::*;
                    match e {
                        QueueFull => DevError::BadState,
                        InvalidParam => DevError::InvalidParam,
                        DmaError => DevError::Io,
                        _ => DevError::Io,
                    }
                })?;
                drop(inner);

                #[cfg(feature = "multitask")]
                {
                    if axhal::asm::irqs_enabled() {
                        while self.inner.inner.lock().inner.peek_used() != Some(token) {
                            self.inner.wait_queue.wait();
                        }
                    } else {
                        while self.inner.inner.lock().inner.peek_used() != Some(token) {
                            core::hint::spin_loop();
                        }
                    }
                }
                #[cfg(not(feature = "multitask"))]
                {
                    while self.inner.inner.lock().inner.peek_used() != Some(token) {
                        core::hint::spin_loop();
                    }
                }

                let mut inner = self.inner.inner.lock();
                unsafe {
                    inner.inner.complete_read_blocks(token, &req, buf, &mut resp)
                }.map_err(|e| {
                    use virtio_drivers::Error::*;
                    match e {
                        QueueFull => DevError::BadState,
                        InvalidParam => DevError::InvalidParam,
                        DmaError => DevError::Io,
                        _ => DevError::Io,
                    }
                })?;
                Ok(())
            }

            fn write_block(&mut self, block_id: u64, buf: &[u8]) -> DevResult {
                let mut inner = self.inner.inner.lock();
                let mut req = virtio_drivers::device::blk::BlkReq::default();
                let mut resp = virtio_drivers::device::blk::BlkResp::default();
                let token = unsafe {
                    inner.inner.write_blocks_nb(block_id as usize, &mut req, buf, &mut resp)
                }.map_err(|e| {
                    use virtio_drivers::Error::*;
                    match e {
                        QueueFull => DevError::BadState,
                        InvalidParam => DevError::InvalidParam,
                        DmaError => DevError::Io,
                        _ => DevError::Io,
                    }
                })?;
                drop(inner);

                #[cfg(feature = "multitask")]
                {
                    if axhal::asm::irqs_enabled() {
                        while self.inner.inner.lock().inner.peek_used() != Some(token) {
                            self.inner.wait_queue.wait();
                        }
                    } else {
                        while self.inner.inner.lock().inner.peek_used() != Some(token) {
                            core::hint::spin_loop();
                        }
                    }
                }
                #[cfg(not(feature = "multitask"))]
                {
                    while self.inner.inner.lock().inner.peek_used() != Some(token) {
                        core::hint::spin_loop();
                    }
                }

                let mut inner = self.inner.inner.lock();
                unsafe {
                    inner.inner.complete_write_blocks(token, &req, buf, &mut resp)
                }.map_err(|e| {
                    use virtio_drivers::Error::*;
                    match e {
                        QueueFull => DevError::BadState,
                        InvalidParam => DevError::InvalidParam,
                        DmaError => DevError::Io,
                        _ => DevError::Io,
                    }
                })?;
                Ok(())
            }

            fn flush(&mut self) -> DevResult {
                self.inner.inner.lock().flush()
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
                        if cap.id == 0x11 { // MSI-X capability ID is 0x11
                            msix_cap_offset = Some(cap.offset);
                            break;
                        }
                    }

                    if let Some(offset) = msix_cap_offset {
                        // 2. Allocate an MSI-X vector (96..255)
                        static NEXT_MSI_VECTOR: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(96);
                        let msi_vector = NEXT_MSI_VECTOR.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
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
                                unsafe {
                                    core::ptr::write_volatile((table_vaddr + 0) as *mut u32, 0x2ff00000); // Msg Addr Low (PCH-MSI)
                                    core::ptr::write_volatile((table_vaddr + 4) as *mut u32, 0);          // Msg Addr High
                                    core::ptr::write_volatile((table_vaddr + 8) as *mut u32, msi_vector as u32); // Msg Data
                                    core::ptr::write_volatile((table_vaddr + 12) as *mut u32, 0);         // Vector Control (0 means unmasked)
                                }

                                // 4. Enable MSI-X in device configuration space
                                let new_msg_ctrl = msg_ctrl | (1 << 15); // Enable bit
                                let new_cap_word0 = (cap_word0 & 0xffff) | ((new_msg_ctrl as u32) << 16);
                                root.config_write_word(bdf, offset, new_cap_word0);

                                // 5. Bind VirtIO queue/config to MSI-X vector 0
                                transport.set_config_msix_vector(0);
                                for q in 0..16 {
                                    transport.set_queue_msix_vector(q, 0);
                                }
                                transport.set_msix_enabled(true);

                                // Global IRQ is 32 + msi_vector
                                irq = 32 + msi_vector;
                                msix_success = true;
                                info!("PCI device at {} configured to use MSI-X (vector {}, irq {})", bdf, msi_vector, irq);
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
                        if irq < 32 {
                            irq += 32;
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

unsafe impl VirtIoHal for VirtIoHalImpl {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        let vaddr = if let Ok(vaddr) = global_allocator().alloc_pages(pages, 0x1000) {
            vaddr
        } else {
            return (0, NonNull::dangling());
        };
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
