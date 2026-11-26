use alloc::sync::{Arc, Weak};
use core::{
    marker::PhantomData,
    ptr::NonNull,
    sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering},
};
#[cfg(feature = "guest-checks")]
use core::sync::atomic::AtomicBool;

use kernel_alloc::global_allocator;
use driver_base::{BaseDriverOps, DevError, DevResult, DeviceType};
use driver_virtio::{BufferDirection, PhysAddr, VirtIoHal};
use hal::mem::{phys_to_virt, virt_to_phys};
#[cfg(net_dev = "virtio-net")]
use poll::PollSet;
use cfg_if::cfg_if;
use kspin::SpinNoIrq;

use crate::{AxDeviceEnum, drivers::DriverProbe};

cfg_if! {
    if #[cfg(bus = "pci")] {
        use driver_pci::{PciRoot, DeviceFunction, DeviceFunctionInfo};
        type VirtIoTransport = driver_virtio::PciTransport;
    } else if #[cfg(bus =  "mmio")] {
        type VirtIoTransport = driver_virtio::MmioTransport;
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
            hal::irq::set_enable(self.irq, false);
            let _ = hal::irq::unregister(self.irq);
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
    if !guard.contains_key(&irq) && !hal::irq::register(irq, common_virtio_irq_handler) {
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
    hal::irq::set_enable(irq, true);

    Ok(VirtioIrqRegistration { irq, id })
}

fn common_virtio_irq_handler(irq: usize) {
    kernel_log::debug!("common_virtio_irq_handler: irq={}", irq);
    let infos = VIRTIO_INTERRUPTS.lock().get(&irq).cloned();
    if let Some(infos) = infos {
        kernel_log::debug!(
            "common_virtio_irq_handler: found {} handlers for irq={}",
            infos.len(),
            irq
        );
        for info in infos {
            info.handler.handle();
        }
    } else {
        kernel_log::debug!(
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

    #[cfg(all(block_dev = "virtio-blk", feature = "multitask", feature = "irq"))]
    mod virtio_blk_watchdog_tests {
        extern crate std;

        use alloc::{collections::VecDeque, sync::Arc, task::Wake, vec, vec::Vec};
        use core::{
            future::Future,
            ptr::NonNull,
            sync::atomic::{AtomicUsize, Ordering},
            task::{Context, Poll, Waker},
        };
        use std::sync::Mutex;

        use driver_virtio::{BufferDirection, PhysAddr, Transport, VirtIoHal};
        use virtio_drivers::device::blk::SECTOR_SIZE;

        use super::super::*;

        struct MockHal;

        unsafe impl VirtIoHal for MockHal {
            fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
                let layout =
                    std::alloc::Layout::from_size_align(pages * 4096, 4096).expect("valid layout");
                // SAFETY: `pages > 0` for VirtIO allocations and layout is page-aligned.
                let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
                let ptr = NonNull::new(ptr).expect("dma_alloc failed");
                (ptr.as_ptr() as usize, ptr)
            }

            unsafe fn dma_dealloc(_paddr: PhysAddr, vaddr: NonNull<u8>, pages: usize) -> i32 {
                let layout =
                    std::alloc::Layout::from_size_align(pages * 4096, 4096).expect("valid layout");
                // SAFETY: matches allocation in `dma_alloc`.
                unsafe { std::alloc::dealloc(vaddr.as_ptr(), layout) };
                0
            }

            unsafe fn mmio_phys_to_virt(paddr: PhysAddr, _size: usize) -> NonNull<u8> {
                NonNull::new(paddr as *mut u8).unwrap()
            }

            unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
                buffer.as_ptr() as *mut u8 as usize
            }

            unsafe fn unshare(
                _paddr: PhysAddr,
                _buffer: NonNull<[u8]>,
                _direction: BufferDirection,
            ) {
            }
        }

        #[repr(C)]
        struct MockBlkConfig {
            capacity_low: u32,
            capacity_high: u32,
            unused: [u32; 14],
        }

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct RawDesc {
            addr: u64,
            len: u32,
            flags: u16,
            next: u16,
        }

        #[repr(C)]
        struct RawAvail {
            flags: u16,
            idx: u16,
            ring: [u16; 16],
            used_event: u16,
        }

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct RawUsedElem {
            id: u32,
            len: u32,
        }

        #[repr(C)]
        struct RawUsed {
            flags: u16,
            idx: u16,
            ring: [RawUsedElem; 16],
            avail_event: u16,
        }

        struct MockTransportState {
            status: virtio_drivers::transport::DeviceStatus,
            desc_paddr: usize,
            avail_paddr: usize,
            used_paddr: usize,
            next_avail_idx: u16,
            notify_count: usize,
            interrupt_pending: bool,
            sectors: Vec<[u8; SECTOR_SIZE]>,
            flushes: usize,
            in_flight_heads: VecDeque<u16>,
        }

        struct MockBlkTransport {
            features: u64,
            config: alloc::boxed::Box<MockBlkConfig>,
            state: Arc<Mutex<MockTransportState>>,
        }

        impl MockBlkTransport {
            fn new(sector_count: usize, features: u64) -> (Self, Arc<Mutex<MockTransportState>>) {
                let mut sectors = vec![[0u8; SECTOR_SIZE]; sector_count];
                for (i, sec) in sectors.iter_mut().enumerate() {
                    sec.fill((i as u8).wrapping_mul(17).wrapping_add(1));
                }
                let state = Arc::new(Mutex::new(MockTransportState {
                    status: virtio_drivers::transport::DeviceStatus::empty(),
                    desc_paddr: 0,
                    avail_paddr: 0,
                    used_paddr: 0,
                    next_avail_idx: 0,
                    notify_count: 0,
                    interrupt_pending: false,
                    sectors,
                    flushes: 0,
                    in_flight_heads: VecDeque::new(),
                }));
                let config = alloc::boxed::Box::new(MockBlkConfig {
                    capacity_low: sector_count as u32,
                    capacity_high: 0,
                    unused: [0; 14],
                });
                (
                    Self {
                        features,
                        config,
                        state: state.clone(),
                    },
                    state,
                )
            }
        }

        impl Transport for MockBlkTransport {
            fn device_type(&self) -> virtio_drivers::transport::DeviceType {
                virtio_drivers::transport::DeviceType::Block
            }

            fn read_device_features(&mut self) -> u64 {
                self.features
            }

            fn write_driver_features(&mut self, _driver_features: u64) {}

            fn max_queue_size(&mut self, _queue: u16) -> u32 {
                16
            }

            fn notify(&mut self, _queue: u16) {
                let mut st = self.state.lock().unwrap();
                st.notify_count += 1;
                let avail = st.avail_paddr as *const RawAvail;
                // SAFETY: `avail_paddr` points to the active 16-entry VirtQueue avail ring.
                let avail_idx = unsafe { core::ptr::read_volatile(&(*avail).idx) };
                while st.next_avail_idx != avail_idx {
                    let slot = (st.next_avail_idx & 15) as usize;
                    let head = unsafe { core::ptr::read_volatile(&(*avail).ring[slot]) };
                    st.in_flight_heads.push_back(head);
                    st.next_avail_idx = st.next_avail_idx.wrapping_add(1);
                }
            }

            fn get_status(&self) -> virtio_drivers::transport::DeviceStatus {
                self.state.lock().unwrap().status
            }

            fn set_status(&mut self, status: virtio_drivers::transport::DeviceStatus) {
                self.state.lock().unwrap().status = status;
            }

            fn set_guest_page_size(&mut self, _guest_page_size: u32) {}

            fn requires_legacy_layout(&self) -> bool {
                false
            }

            fn queue_set(
                &mut self,
                _queue: u16,
                _size: u32,
                descriptors: PhysAddr,
                driver_area: PhysAddr,
                device_area: PhysAddr,
            ) {
                let mut st = self.state.lock().unwrap();
                st.desc_paddr = descriptors;
                st.avail_paddr = driver_area;
                st.used_paddr = device_area;
            }

            fn queue_unset(&mut self, _queue: u16) {
                let mut st = self.state.lock().unwrap();
                st.desc_paddr = 0;
                st.avail_paddr = 0;
                st.used_paddr = 0;
            }

            fn queue_used(&mut self, _queue: u16) -> bool {
                self.state.lock().unwrap().desc_paddr != 0
            }

            fn ack_interrupt(&mut self) -> bool {
                let mut st = self.state.lock().unwrap();
                let was = st.interrupt_pending;
                st.interrupt_pending = false;
                was
            }

            fn config_space<T: 'static>(&self) -> virtio_drivers::Result<NonNull<T>> {
                assert!(core::mem::size_of::<T>() <= core::mem::size_of::<MockBlkConfig>());
                Ok(NonNull::from(&*self.config).cast())
            }
        }

        fn complete_next_in_device(state: &Mutex<MockTransportState>, raise_irq: bool) -> bool {
            let mut st = state.lock().unwrap();
            let Some(head) = st.in_flight_heads.pop_front() else {
                return false;
            };
            let descs = st.desc_paddr as *const [RawDesc; 16];
            // Collect descriptor chain (direct descriptors: req, [data], resp).
            let mut chain = Vec::new();
            let mut idx = head;
            loop {
                let d = unsafe { core::ptr::read_volatile(&(*descs)[idx as usize]) };
                chain.push(d);
                if d.flags & 1 == 0 {
                    break;
                }
                idx = d.next;
            }
            #[repr(C)]
            #[derive(Clone, Copy)]
            struct RawBlkReq {
                req_type: u32,
                reserved: u32,
                sector: u64,
            }
            let req = unsafe { core::ptr::read_volatile(chain[0].addr as *const RawBlkReq) };
            let mut written_len = 1u32;
            match req.req_type {
                0 => {
                    // In (read)
                    let data_desc = chain[1];
                    let data_slice = unsafe {
                        core::slice::from_raw_parts_mut(
                            data_desc.addr as *mut u8,
                            data_desc.len as usize,
                        )
                    };
                    let sector = req.sector as usize;
                    for (chunk_idx, chunk) in data_slice.chunks_mut(SECTOR_SIZE).enumerate() {
                        chunk.copy_from_slice(&st.sectors[sector + chunk_idx]);
                    }
                    written_len += data_desc.len;
                    let resp_ptr = chain[2].addr as *mut u8;
                    unsafe { core::ptr::write_volatile(resp_ptr, 0) };
                }
                1 => {
                    // Out (write)
                    let data_desc = chain[1];
                    let data_slice = unsafe {
                        core::slice::from_raw_parts(
                            data_desc.addr as *const u8,
                            data_desc.len as usize,
                        )
                    };
                    let sector = req.sector as usize;
                    for (chunk_idx, chunk) in data_slice.chunks(SECTOR_SIZE).enumerate() {
                        st.sectors[sector + chunk_idx].copy_from_slice(chunk);
                    }
                    let resp_ptr = chain[2].addr as *mut u8;
                    unsafe { core::ptr::write_volatile(resp_ptr, 0) };
                }
                4 => {
                    // Flush
                    st.flushes += 1;
                    let resp_ptr = chain[1].addr as *mut u8;
                    unsafe { core::ptr::write_volatile(resp_ptr, 0) };
                }
                other => panic!("unexpected virtio-blk req_type {}", other),
            }
            let used = st.used_paddr as *mut RawUsed;
            unsafe {
                let cur_used = core::ptr::read_volatile(&(*used).idx);
                let slot = (cur_used & 15) as usize;
                core::ptr::write_volatile(
                    &mut (*used).ring[slot],
                    RawUsedElem {
                        id: u32::from(head),
                        len: written_len,
                    },
                );
                core::sync::atomic::fence(Ordering::SeqCst);
                core::ptr::write_volatile(&mut (*used).idx, cur_used.wrapping_add(1));
            }
            if raise_irq {
                st.interrupt_pending = true;
            }
            true
        }

        struct CountWake(AtomicUsize);
        impl Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        fn make_waker() -> (Waker, Arc<CountWake>) {
            let cw = Arc::new(CountWake(AtomicUsize::new(0)));
            (Waker::from(cw.clone()), cw)
        }

        #[test]
        fn normal_irq_coalesces_recheck_and_tick_disarms_without_callback() {
            let _guard = GLOBAL_WATCHDOG_TEST_LOCK.lock().unwrap();
            let (transport, dev_state) = MockBlkTransport::new(64, VIRTIO_BLK_F_FLUSH);
            let dev = driver_virtio::VirtIoBlkDev::<MockHal, MockBlkTransport>::try_new(transport)
                .unwrap();
            let inner = VirtIoBlkDevInner::new_for_test(dev, 10_000_000);

            let (waker1, wake_cnt1) = make_waker();
            let (waker2, wake_cnt2) = make_waker();
            let (waker3, wake_cnt3) = make_waker();
            let mut buf1 = [0u8; SECTOR_SIZE];
            let mut buf2 = [0u8; SECTOR_SIZE];
            let mut buf3 = [0u8; SECTOR_SIZE];

            {
                let mut fut1 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 0, &mut buf1));
                let mut fut2 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 1, &mut buf2));
                let mut fut3 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 2, &mut buf3));

                assert!(matches!(
                    fut1.as_mut().poll(&mut Context::from_waker(&waker1)),
                    Poll::Pending
                ));
                assert!(matches!(
                    fut2.as_mut().poll(&mut Context::from_waker(&waker2)),
                    Poll::Pending
                ));
                assert!(matches!(
                    fut3.as_mut().poll(&mut Context::from_waker(&waker3)),
                    Poll::Pending
                ));

                let s = inner.counters.snapshot();
                assert_eq!(s.submissions, 3);
                assert_eq!(s.in_flight_current, 3);
                assert_eq!(s.in_flight_max, 3);
                assert_eq!(s.recheck_armed, 1);
                assert_eq!(s.recheck_already_armed, 2);

                assert!(complete_next_in_device(&dev_state, true));
                assert!(complete_next_in_device(&dev_state, true));
                assert!(complete_next_in_device(&dev_state, true));
                let deadline = inner.recheck_watchdog.deadline_ns().expect("watchdog armed");
                inner.handle_interrupt();

                assert_eq!(wake_cnt1.0.load(Ordering::Relaxed), 1);
                assert_eq!(wake_cnt2.0.load(Ordering::Relaxed), 1);
                assert_eq!(wake_cnt3.0.load(Ordering::Relaxed), 1);

                assert!(matches!(
                    fut1.as_mut().poll(&mut Context::from_waker(&waker1)),
                    Poll::Ready(Ok(()))
                ));
                assert!(matches!(
                    fut2.as_mut().poll(&mut Context::from_waker(&waker2)),
                    Poll::Ready(Ok(()))
                ));
                assert!(matches!(
                    fut3.as_mut().poll(&mut Context::from_waker(&waker3)),
                    Poll::Ready(Ok(()))
                ));

                // First expired tick after IRQ drains lazily disarms without
                // running the lost-IRQ recheck callback.
                inner.poll_completion_recheck(deadline);
            }

            // Subsequent tick after lazy disarm must do zero work.
            assert_eq!(inner.recheck_watchdog.deadline_ns(), None);
            inner.poll_completion_recheck(hal::time::monotonic_time_nanos() + 20_000_000);
            let s = inner.counters.snapshot();
            assert_counter_invariants(&s);
            assert_eq!(s.recheck_irq_completed_before_callback, 1);
            assert_eq!(s.recheck_poll_completed_before_callback, 0);
            assert_eq!(s.recheck_callback_fired, 0);
            assert_eq!(s.irq_completions, 3);
            assert_eq!(s.in_flight_current, 0);
            assert_eq!(buf1, dev_state.lock().unwrap().sectors[0]);
            assert_eq!(buf2, dev_state.lock().unwrap().sectors[1]);
            assert_eq!(buf3, dev_state.lock().unwrap().sectors[2]);
        }

        const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
        static GLOBAL_WATCHDOG_TEST_LOCK: Mutex<()> = Mutex::new(());

        fn assert_counter_invariants(s: &crate::VirtIoBlkStats) {
            assert_eq!(
                s.completions_total,
                s.irq_completions + s.poll_completions + s.recheck_reclaimed_completions
            );
            assert_eq!(
                s.recheck_callback_fired,
                s.recheck_callback_reclaimed
                    + s.recheck_callback_already_drained
                    + s.recheck_callback_still_pending
            );
            if s.in_flight_current == 0 {
                assert_eq!(
                    s.recheck_armed,
                    s.recheck_irq_completed_before_callback
                        + s.recheck_poll_completed_before_callback
                        + (s.recheck_callback_fired - s.recheck_rearmed)
                );
            }
        }

        #[test]
        fn missing_irq_read_write_and_flush_complete_via_recheck() {
            let _guard = GLOBAL_WATCHDOG_TEST_LOCK.lock().unwrap();
            let armed_before = VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire);
            let (transport, dev_state) = MockBlkTransport::new(64, VIRTIO_BLK_F_FLUSH);
            let dev = driver_virtio::VirtIoBlkDev::<MockHal, MockBlkTransport>::try_new(transport)
                .unwrap();
            let inner = VirtIoBlkDevInner::new_for_test(dev, 10_000_000);

            let (w_r, cnt_r) = make_waker();
            let (w_w, cnt_w) = make_waker();
            let (w_f, cnt_f) = make_waker();
            let mut r_buf = [0u8; SECTOR_SIZE];
            let w_buf = [0xA5u8; SECTOR_SIZE];
            let armed_deadline;
            {
                let mut fut_r =
                    core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 0, &mut r_buf));
                let mut fut_w =
                    core::pin::pin!(VirtIoBlockFuture::write(inner.clone(), 3, &w_buf));
                let mut fut_f = core::pin::pin!(VirtIoBlockFuture::flush(inner.clone()));

                assert!(matches!(
                    fut_r.as_mut().poll(&mut Context::from_waker(&w_r)),
                    Poll::Pending
                ));
                assert!(matches!(
                    fut_w.as_mut().poll(&mut Context::from_waker(&w_w)),
                    Poll::Pending
                ));
                assert!(matches!(
                    fut_f.as_mut().poll(&mut Context::from_waker(&w_f)),
                    Poll::Pending
                ));

                armed_deadline = inner.recheck_watchdog.deadline_ns().expect("watchdog armed");
                assert_eq!(
                    VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire),
                    armed_before + 1
                );

                assert!(complete_next_in_device(&dev_state, false));
                assert!(complete_next_in_device(&dev_state, false));
                assert!(complete_next_in_device(&dev_state, false));

                // Tick strictly before deadline must not fire.
                inner.poll_completion_recheck(armed_deadline - 1);
                assert_eq!(inner.counters.snapshot().recheck_callback_fired, 0);

                // Tick at deadline rescues all three completions without IRQ.
                inner.poll_completion_recheck(armed_deadline);
                assert_eq!(cnt_r.0.load(Ordering::Relaxed), 1);
                assert_eq!(cnt_w.0.load(Ordering::Relaxed), 1);
                assert_eq!(cnt_f.0.load(Ordering::Relaxed), 1);

                assert!(matches!(
                    fut_r.as_mut().poll(&mut Context::from_waker(&w_r)),
                    Poll::Ready(Ok(()))
                ));
                assert!(matches!(
                    fut_w.as_mut().poll(&mut Context::from_waker(&w_w)),
                    Poll::Ready(Ok(()))
                ));
                assert!(matches!(
                    fut_f.as_mut().poll(&mut Context::from_waker(&w_f)),
                    Poll::Ready(Ok(()))
                ));
            }

            // Watchdog returned to IDLE; further ticks are no-ops.
            assert_eq!(inner.recheck_watchdog.deadline_ns(), None);
            assert_eq!(
                VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire),
                armed_before
            );
            inner.poll_completion_recheck(armed_deadline + 50_000_000);

            let s = inner.counters.snapshot();
            assert_counter_invariants(&s);
            assert_eq!(s.recheck_callback_fired, 1);
            assert_eq!(s.recheck_callback_reclaimed, 1);
            assert_eq!(s.recheck_reclaimed_completions, 3);
            assert_eq!(s.recheck_rearmed, 0);
            assert_eq!(s.in_flight_current, 0);
            assert_eq!(r_buf, dev_state.lock().unwrap().sectors[0]);
            assert_eq!(dev_state.lock().unwrap().sectors[3], w_buf);
            assert_eq!(dev_state.lock().unwrap().flushes, 1);
        }

        #[test]
        fn partial_completion_and_empty_tick_rearm_until_drained() {
            let _guard = GLOBAL_WATCHDOG_TEST_LOCK.lock().unwrap();
            let (transport, dev_state) = MockBlkTransport::new(64, VIRTIO_BLK_F_FLUSH);
            let dev = driver_virtio::VirtIoBlkDev::<MockHal, MockBlkTransport>::try_new(transport)
                .unwrap();
            let inner = VirtIoBlkDevInner::new_for_test(dev, 10_000_000);

            let (w1, cnt1) = make_waker();
            let (w2, cnt2) = make_waker();
            let mut b1 = [0u8; SECTOR_SIZE];
            let mut b2 = [0u8; SECTOR_SIZE];
            {
                let mut f1 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 4, &mut b1));
                let mut f2 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 5, &mut b2));

                assert!(matches!(
                    f1.as_mut().poll(&mut Context::from_waker(&w1)),
                    Poll::Pending
                ));
                assert!(matches!(
                    f2.as_mut().poll(&mut Context::from_waker(&w2)),
                    Poll::Pending
                ));

                let d1 = inner.recheck_watchdog.deadline_ns().expect("watchdog armed");
                assert!(complete_next_in_device(&dev_state, false));
                inner.poll_completion_recheck(d1);
                assert_eq!(cnt1.0.load(Ordering::Relaxed), 1);
                assert_eq!(cnt2.0.load(Ordering::Relaxed), 0);
                assert_eq!(inner.counters.snapshot().recheck_rearmed, 1);
                assert_eq!(inner.counters.snapshot().in_flight_current, 1);

                // Empty tick while second request is still in flight.
                let d2 = inner.recheck_watchdog.deadline_ns().expect("watchdog rearmed");
                inner.poll_completion_recheck(d2);
                assert_eq!(cnt2.0.load(Ordering::Relaxed), 0);
                let mid = inner.counters.snapshot();
                assert_eq!(mid.recheck_callback_still_pending, 1);
                assert_eq!(mid.recheck_callback_already_drained, 0);
                assert_eq!(mid.recheck_rearmed, 2);

                // Second request finishes without IRQ; next tick reclaims it and idles.
                let d3 = inner.recheck_watchdog.deadline_ns().expect("watchdog rearmed again");
                assert!(complete_next_in_device(&dev_state, false));
                inner.poll_completion_recheck(d3);
                assert_eq!(cnt2.0.load(Ordering::Relaxed), 1);

                assert!(matches!(
                    f1.as_mut().poll(&mut Context::from_waker(&w1)),
                    Poll::Ready(Ok(()))
                ));
                assert!(matches!(
                    f2.as_mut().poll(&mut Context::from_waker(&w2)),
                    Poll::Ready(Ok(()))
                ));
            }

            let s = inner.counters.snapshot();
            assert_counter_invariants(&s);
            assert_eq!(s.recheck_callback_fired, 3);
            assert_eq!(s.recheck_callback_reclaimed, 2);
            assert_eq!(s.recheck_callback_still_pending, 1);
            assert_eq!(s.recheck_callback_already_drained, 0);
            assert_eq!(s.recheck_reclaimed_completions, 2);
            assert_eq!(s.in_flight_current, 0);
            assert_eq!(inner.recheck_watchdog.deadline_ns(), None);
            assert_eq!(b1, dev_state.lock().unwrap().sectors[4]);
            assert_eq!(b2, dev_state.lock().unwrap().sectors[5]);
        }

        #[test]
        fn queue_full_submits_and_completes_under_missing_irq() {
            let _guard = GLOBAL_WATCHDOG_TEST_LOCK.lock().unwrap();
            // Without RING_INDIRECT_DESC, each read consumes 3 descriptors out
            // of 16, so 5 requests fill 15 descriptors and the 6th hits QueueFull.
            let (transport, dev_state) = MockBlkTransport::new(64, VIRTIO_BLK_F_FLUSH);
            let dev = driver_virtio::VirtIoBlkDev::<MockHal, MockBlkTransport>::try_new(transport)
                .unwrap();
            let inner = VirtIoBlkDevInner::new_for_test(dev, 10_000_000);

            let mut bufs = [[0u8; SECTOR_SIZE]; 6];
            let (w0, _) = make_waker();
            let (w1, _) = make_waker();
            let (w2, _) = make_waker();
            let (w3, _) = make_waker();
            let (w4, _) = make_waker();
            let (w5, cnt5) = make_waker();
            {
                let [b0, b1, b2, b3, b4, b5] = &mut bufs;

                let mut f0 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 0, b0));
                let mut f1 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 1, b1));
                let mut f2 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 2, b2));
                let mut f3 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 3, b3));
                let mut f4 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 4, b4));
                let mut f5 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 5, b5));

                assert!(matches!(f0.as_mut().poll(&mut Context::from_waker(&w0)), Poll::Pending));
                assert!(matches!(f1.as_mut().poll(&mut Context::from_waker(&w1)), Poll::Pending));
                assert!(matches!(f2.as_mut().poll(&mut Context::from_waker(&w2)), Poll::Pending));
                assert!(matches!(f3.as_mut().poll(&mut Context::from_waker(&w3)), Poll::Pending));
                assert!(matches!(f4.as_mut().poll(&mut Context::from_waker(&w4)), Poll::Pending));
                assert!(matches!(f5.as_mut().poll(&mut Context::from_waker(&w5)), Poll::Pending));

                assert_eq!(inner.counters.snapshot().queue_full_waits, 1);
                assert_eq!(inner.counters.snapshot().in_flight_current, 5);

                // Reclaim 1 slot via recheck without IRQ; submit waker for f5 must wake.
                let d1 = inner.recheck_watchdog.deadline_ns().expect("watchdog armed");
                assert!(complete_next_in_device(&dev_state, false));
                inner.poll_completion_recheck(d1);
                assert_eq!(cnt5.0.load(Ordering::Relaxed), 1);

                // Polling f5 now submits into the freed descriptor slot.
                assert!(matches!(f5.as_mut().poll(&mut Context::from_waker(&w5)), Poll::Pending));
                assert_eq!(inner.counters.snapshot().submissions, 6);

                while complete_next_in_device(&dev_state, false) {}
                let d2 = inner.recheck_watchdog.deadline_ns().expect("watchdog armed");
                inner.poll_completion_recheck(d2);

                assert!(matches!(f0.as_mut().poll(&mut Context::from_waker(&w0)), Poll::Ready(Ok(()))));
                assert!(matches!(f1.as_mut().poll(&mut Context::from_waker(&w1)), Poll::Ready(Ok(()))));
                assert!(matches!(f2.as_mut().poll(&mut Context::from_waker(&w2)), Poll::Ready(Ok(()))));
                assert!(matches!(f3.as_mut().poll(&mut Context::from_waker(&w3)), Poll::Ready(Ok(()))));
                assert!(matches!(f4.as_mut().poll(&mut Context::from_waker(&w4)), Poll::Ready(Ok(()))));
                assert!(matches!(f5.as_mut().poll(&mut Context::from_waker(&w5)), Poll::Ready(Ok(()))));
            }

            let s = inner.counters.snapshot();
            assert_counter_invariants(&s);
            assert_eq!(s.completions_total, 6);
            assert_eq!(s.in_flight_current, 0);
            for (idx, buf) in bufs.iter().enumerate() {
                assert_eq!(buf, &dev_state.lock().unwrap().sectors[idx]);
            }
        }

        #[test]
        fn global_tick_hook_reclaims_a_missing_irq_on_the_seventeenth_device() {
            let _guard = GLOBAL_WATCHDOG_TEST_LOCK.lock().unwrap();
            let armed_before = VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire);
            let mut idle_devices = Vec::new();
            for _ in 0..16 {
                let (transport, _) = MockBlkTransport::new(64, VIRTIO_BLK_F_FLUSH);
                let dev = driver_virtio::VirtIoBlkDev::<MockHal, MockBlkTransport>::try_new(transport)
                    .unwrap();
                let idle = VirtIoBlkDevInner::new_for_test(dev, 1);
                register_virtio_blk_device(Arc::downgrade(&idle) as Weak<dyn VirtIoBlkDeviceOps>);
                idle_devices.push(idle);
            }
            let (transport, dev_state) = MockBlkTransport::new(64, VIRTIO_BLK_F_FLUSH);
            let dev = driver_virtio::VirtIoBlkDev::<MockHal, MockBlkTransport>::try_new(transport)
                .unwrap();
            let inner = VirtIoBlkDevInner::new_for_test(dev, 1);
            register_virtio_blk_device(Arc::downgrade(&inner) as Weak<dyn VirtIoBlkDeviceOps>);

            // Idle tick must do nothing.
            virtio_blk_tick_recheck();
            assert_eq!(inner.counters.snapshot().recheck_callback_fired, 0);

            // Arm and complete in device without IRQ; let global tick dispatch reclaim it.
            let mut buf = [0u8; SECTOR_SIZE];
            let (w, cnt) = make_waker();
            {
                let mut fut = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 7, &mut buf));
                assert!(matches!(fut.as_mut().poll(&mut Context::from_waker(&w)), Poll::Pending));
                assert_eq!(
                    VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire),
                    armed_before + 1
                );
                assert!(complete_next_in_device(&dev_state, false));
                let deadline = inner.recheck_watchdog.deadline_ns().expect("watchdog armed");
                virtio_blk_tick_recheck_at(deadline);
                assert_eq!(cnt.0.load(Ordering::Relaxed), 1);
                assert!(matches!(
                    fut.as_mut().poll(&mut Context::from_waker(&w)),
                    Poll::Ready(Ok(()))
                ));
            }
            let s = inner.counters.snapshot();
            assert_counter_invariants(&s);
            assert_eq!(s.recheck_reclaimed_completions, 1);
            let mut all_stats = Vec::new();
            crate::for_each_virtio_blk_stats(|_, item| all_stats.push(item));
            assert_eq!(all_stats.len(), idle_devices.len() + 1);
            assert_eq!(all_stats.last(), Some(&s));
            assert!(all_stats[..idle_devices.len()].iter().all(|item| item.recheck_callback_fired == 0));
            assert_eq!(
                VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire),
                armed_before
            );
            assert_eq!(buf, dev_state.lock().unwrap().sectors[7]);
        }

        #[test]
        fn cancellation_while_pending_completed_and_queue_full_is_safe() {
            let _guard = GLOBAL_WATCHDOG_TEST_LOCK.lock().unwrap();
            let armed_before = VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire);
            let (transport, dev_state) = MockBlkTransport::new(64, VIRTIO_BLK_F_FLUSH);
            let dev = driver_virtio::VirtIoBlkDev::<MockHal, MockBlkTransport>::try_new(transport)
                .unwrap();
            let inner = VirtIoBlkDevInner::new_for_test(dev, 10_000_000);

            // (a) Cancel while pending -> detached, drained via recheck without IRQ.
            {
                let (w, _) = make_waker();
                let mut buf = [0u8; SECTOR_SIZE];
                let mut fut = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 0, &mut buf));
                assert!(matches!(fut.as_mut().poll(&mut Context::from_waker(&w)), Poll::Pending));
            }
            assert_eq!(inner.counters.snapshot().cancelled_detached, 1);
            let d = inner.recheck_watchdog.deadline_ns().expect("watchdog armed");
            assert!(complete_next_in_device(&dev_state, false));
            inner.poll_completion_recheck(d);
            assert_eq!(inner.counters.snapshot().in_flight_current, 0);
            assert_eq!(inner.recheck_watchdog.deadline_ns(), None);

            // (b) Cancel after already completed into `state.completed`.
            {
                let (w, _) = make_waker();
                let mut buf = [0u8; SECTOR_SIZE];
                let mut fut = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 1, &mut buf));
                assert!(matches!(fut.as_mut().poll(&mut Context::from_waker(&w)), Poll::Pending));
                assert!(complete_next_in_device(&dev_state, true));
                inner.handle_interrupt();
            }
            assert_eq!(inner.counters.snapshot().cancelled_completed_recycled, 1);

            // (c) Cancel pre-allocated requests stalled at QueueFull, drain, disarm,
            //     then re-arm and drop `inner` while armed to verify Drop cleanup.
            let mut b0 = [0u8; SECTOR_SIZE];
            let mut b1 = [0u8; SECTOR_SIZE];
            let mut b2 = [0u8; SECTOR_SIZE];
            let mut b3 = [0u8; SECTOR_SIZE];
            let mut b4 = [0u8; SECTOR_SIZE];
            let (w, _) = make_waker();
            let deadline;
            {
                let mut f0 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 0, &mut b0));
                let mut f1 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 1, &mut b1));
                let mut f2 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 2, &mut b2));
                let mut f3 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 3, &mut b3));
                let mut f4 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 4, &mut b4));
                assert!(matches!(f0.as_mut().poll(&mut Context::from_waker(&w)), Poll::Pending));
                assert!(matches!(f1.as_mut().poll(&mut Context::from_waker(&w)), Poll::Pending));
                assert!(matches!(f2.as_mut().poll(&mut Context::from_waker(&w)), Poll::Pending));
                assert!(matches!(f3.as_mut().poll(&mut Context::from_waker(&w)), Poll::Pending));
                assert!(matches!(f4.as_mut().poll(&mut Context::from_waker(&w)), Poll::Pending));
                {
                    let mut b_qf = [0u8; SECTOR_SIZE];
                    let mut f_qf =
                        core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 5, &mut b_qf));
                    assert!(matches!(
                        f_qf.as_mut().poll(&mut Context::from_waker(&w)),
                        Poll::Pending
                    ));
                    assert_eq!(inner.counters.snapshot().queue_full_waits, 1);
                }
                deadline = inner.recheck_watchdog.deadline_ns().expect("watchdog armed");
            }
            while complete_next_in_device(&dev_state, true) {}
            inner.handle_interrupt();
            inner.poll_completion_recheck(deadline);
            let s = inner.counters.snapshot();
            assert_counter_invariants(&s);
            assert_eq!(s.in_flight_current, 0);
            assert_eq!(inner.recheck_watchdog.deadline_ns(), None);

            {
                let mut b_drop = [0u8; SECTOR_SIZE];
                let mut f_drop =
                    core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 0, &mut b_drop));
                assert!(matches!(
                    f_drop.as_mut().poll(&mut Context::from_waker(&w)),
                    Poll::Pending
                ));
                assert_eq!(
                    VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire),
                    armed_before + 1
                );
            }
            drop(inner);
            assert_eq!(
                VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire),
                armed_before
            );
        }

        #[test]
        fn recheck_callback_racing_with_irq_counts_already_drained() {
            let _guard = GLOBAL_WATCHDOG_TEST_LOCK.lock().unwrap();
            let armed_before = VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire);
            let (transport, dev_state) = MockBlkTransport::new(64, VIRTIO_BLK_F_FLUSH);
            let dev = driver_virtio::VirtIoBlkDev::<MockHal, MockBlkTransport>::try_new(transport)
                .unwrap();
            let inner = VirtIoBlkDevInner::new_for_test(dev, 10_000_000);

            let (w, cnt) = make_waker();
            let mut buf = [0u8; SECTOR_SIZE];
            {
                let mut fut = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 2, &mut buf));
                assert!(matches!(
                    fut.as_mut().poll(&mut Context::from_waker(&w)),
                    Poll::Pending
                ));

                // Watchdog claims RUNNING just before an IRQ drains the completion.
                let deadline = inner.recheck_watchdog.deadline_ns().expect("watchdog armed");
                assert!(inner.recheck_watchdog.try_begin_recheck(deadline));
                assert!(complete_next_in_device(&dev_state, true));
                inner.handle_interrupt();
                assert_eq!(cnt.0.load(Ordering::Relaxed), 1);

                // Callback body now executes against an already-drained queue.
                inner.execute_recheck_callback(deadline);

                assert!(matches!(
                    fut.as_mut().poll(&mut Context::from_waker(&w)),
                    Poll::Ready(Ok(()))
                ));
            }

            let s = inner.counters.snapshot();
            assert_counter_invariants(&s);
            assert_eq!(s.recheck_callback_fired, 1);
            assert_eq!(s.recheck_callback_already_drained, 1);
            assert_eq!(s.recheck_callback_still_pending, 0);
            assert_eq!(s.recheck_callback_reclaimed, 0);
            assert_eq!(s.recheck_rearmed, 0);
            assert_eq!(s.recheck_irq_completed_before_callback, 0);
            assert_eq!(s.recheck_poll_completed_before_callback, 0);
            assert_eq!(inner.recheck_watchdog.deadline_ns(), None);
            assert_eq!(
                VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire),
                armed_before
            );
            assert_eq!(buf, dev_state.lock().unwrap().sectors[2]);
        }

        #[test]
        fn poll_completion_disarms_under_poll_counter_not_irq() {
            let _guard = GLOBAL_WATCHDOG_TEST_LOCK.lock().unwrap();
            let armed_before = VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire);
            let (transport, dev_state) = MockBlkTransport::new(64, VIRTIO_BLK_F_FLUSH);
            let dev = driver_virtio::VirtIoBlkDev::<MockHal, MockBlkTransport>::try_new(transport)
                .unwrap();
            let inner = VirtIoBlkDevInner::new_for_test(dev, 10_000_000);

            let (w, _) = make_waker();
            let mut buf = [0u8; SECTOR_SIZE];
            let deadline;
            {
                let mut fut = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 6, &mut buf));
                assert!(matches!(
                    fut.as_mut().poll(&mut Context::from_waker(&w)),
                    Poll::Pending
                ));
                deadline = inner.recheck_watchdog.deadline_ns().expect("watchdog armed");

                // Device finishes without IRQ, and future is polled directly.
                assert!(complete_next_in_device(&dev_state, false));
                assert!(matches!(
                    fut.as_mut().poll(&mut Context::from_waker(&w)),
                    Poll::Ready(Ok(()))
                ));
            }
            inner.poll_completion_recheck(deadline);

            let s = inner.counters.snapshot();
            assert_counter_invariants(&s);
            assert_eq!(s.poll_completions, 1);
            assert_eq!(s.irq_completions, 0);
            assert_eq!(s.recheck_poll_completed_before_callback, 1);
            assert_eq!(s.recheck_irq_completed_before_callback, 0);
            assert_eq!(s.recheck_callback_fired, 0);
            assert_eq!(inner.recheck_watchdog.deadline_ns(), None);
            assert_eq!(
                VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire),
                armed_before
            );
            assert_eq!(buf, dev_state.lock().unwrap().sectors[6]);
        }

        #[test]
        fn active_irq_progress_refreshes_watchdog_without_callback_and_idles_cleanly() {
            let _guard = GLOBAL_WATCHDOG_TEST_LOCK.lock().unwrap();
            let armed_before = VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire);
            let (transport, dev_state) = MockBlkTransport::new(64, VIRTIO_BLK_F_FLUSH);
            let dev = driver_virtio::VirtIoBlkDev::<MockHal, MockBlkTransport>::try_new(transport)
                .unwrap();
            let inner = VirtIoBlkDevInner::new_for_test(dev, 10_000_000);

            let (w1, cnt1) = make_waker();
            let (w2, cnt2) = make_waker();
            let mut b1 = [0u8; SECTOR_SIZE];
            let mut b2 = [0u8; SECTOR_SIZE];
            {
                let mut f1 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 1, &mut b1));
                let mut f2 = core::pin::pin!(VirtIoBlockFuture::read(inner.clone(), 2, &mut b2));
                assert!(matches!(f1.as_mut().poll(&mut Context::from_waker(&w1)), Poll::Pending));
                assert!(matches!(f2.as_mut().poll(&mut Context::from_waker(&w2)), Poll::Pending));
                let d1 = inner.recheck_watchdog.deadline_ns().expect("watchdog armed");

                // Read 1 completes via IRQ while read 2 remains in flight.
                assert!(complete_next_in_device(&dev_state, true));
                inner.handle_interrupt();
                assert_eq!(cnt1.0.load(Ordering::Relaxed), 1);
                assert_eq!(cnt2.0.load(Ordering::Relaxed), 0);

                // Tick observes forward progress without firing a recheck callback.
                inner.poll_completion_recheck(d1);
                let d2 = inner.recheck_watchdog.deadline_ns().expect("watchdog stays armed");
                assert!(d2 > d1);
                assert_eq!(
                    VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire),
                    armed_before + 1
                );
                assert_eq!(inner.counters.snapshot().recheck_callback_fired, 0);

                // Read 2 completes via IRQ and the next tick lazily disarms.
                assert!(complete_next_in_device(&dev_state, true));
                inner.handle_interrupt();
                assert_eq!(cnt2.0.load(Ordering::Relaxed), 1);
                inner.poll_completion_recheck(d2);

                assert!(matches!(
                    f1.as_mut().poll(&mut Context::from_waker(&w1)),
                    Poll::Ready(Ok(()))
                ));
                assert!(matches!(
                    f2.as_mut().poll(&mut Context::from_waker(&w2)),
                    Poll::Ready(Ok(()))
                ));
            }

            let s = inner.counters.snapshot();
            assert_counter_invariants(&s);
            assert_eq!(s.recheck_irq_completed_before_callback, 1);
            assert_eq!(s.recheck_callback_fired, 0);
            assert_eq!(inner.recheck_watchdog.deadline_ns(), None);
            assert_eq!(
                VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire),
                armed_before
            );
            assert_eq!(b1, dev_state.lock().unwrap().sectors[1]);
            assert_eq!(b2, dev_state.lock().unwrap().sectors[2]);
        }
    }
}

cfg_if! {
    if #[cfg(net_dev = "virtio-net")] {
        pub struct VirtIoNet;

        pub struct VirtIoNetDevInner<H: VirtIoHal, T: virtio_drivers::transport::Transport, const QS: usize> {
            inner: SpinNoIrq<driver_virtio::VirtIoNetDev<H, T, QS>>,
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
                let mut dev = driver_virtio::VirtIoNetDev::try_new(transport)?;
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

        impl<H: VirtIoHal, T: virtio_drivers::transport::Transport, const QS: usize> driver_net::NetDriverOps for VirtIoNetDevWrapper<H, T, QS> {
            fn mac_address(&self) -> driver_net::EthernetAddress {
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
            fn recycle_rx_buffer(&mut self, rx_buf: driver_net::NetBufPtr) -> DevResult {
                self.inner.inner.lock().recycle_rx_buffer(rx_buf)
            }
            fn recycle_tx_buffers(&mut self) -> DevResult {
                self.inner.inner.lock().recycle_tx_buffers()
            }
            fn transmit(&mut self, tx_buf: driver_net::NetBufPtr) -> DevResult {
                self.inner.inner.lock().transmit(tx_buf)
            }
            fn receive(&mut self) -> DevResult<driver_net::NetBufPtr> {
                self.inner.inner.lock().receive()
            }
            fn alloc_tx_buffer(&mut self, size: usize) -> DevResult<driver_net::NetBufPtr> {
                self.inner.inner.lock().alloc_tx_buffer(size)
            }
            fn poll_set(&self) -> Option<&poll::PollSet> {
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

        use alloc::vec::Vec;
        use core::{
            future::Future,
            pin::Pin,
            task::{Context, Poll, Waker},
        };
        use virtio_drivers::{
            device::blk::{BlkReq, BlkResp, VIRTIO_BLK_QUEUE_SIZE},
            Dma,
        };

        // fs fills up to 16 page-cache pages (64 KiB) per sequential read,
        // while ext4 coalesces up to 32 common 4 KiB metadata blocks (128 KiB)
        // for one asynchronous flush. Retain both request shapes: otherwise
        // every coalesced metadata flush bypasses this pool and churns a large
        // DMA allocation. Keep the previous total retention budget below.
        const DMA_POOL_RETAINED_DATA_LEN: usize = 64 * 1024;
        const DMA_POOL_MAX_DATA_LEN: usize = 128 * 1024;
        const DMA_POOL_RETAINED_REQUEST_PAGES: usize = (core::mem::size_of::<BlkReq>()
            + DMA_POOL_RETAINED_DATA_LEN
            + core::mem::size_of::<BlkResp>()
            + virtio_drivers::PAGE_SIZE
            - 1)
            / virtio_drivers::PAGE_SIZE;
        const DMA_POOL_MAX_REQUEST_PAGES: usize = (core::mem::size_of::<BlkReq>()
            + DMA_POOL_MAX_DATA_LEN
            + core::mem::size_of::<BlkResp>()
            + virtio_drivers::PAGE_SIZE
            - 1)
            / virtio_drivers::PAGE_SIZE;
        const DMA_POOL_MAX_PAGES: usize =
            VIRTIO_BLK_QUEUE_SIZE * DMA_POOL_RETAINED_REQUEST_PAGES;
        // At the default 100 Hz tick rate, inspect a busy queue after a 10 ms
        // interval with no observed completions. A tick that sees progress
        // starts another interval; actual recovery also depends on tick delivery.
        const COMPLETION_RECHECK_INTERVAL_NS: u64 = 10_000_000;

        /// Lock-free lazy-disarm epoch watchdog for one block device.
        struct RecheckWatchdog {
            deadline_ns: AtomicU64,
            observed_completions: AtomicU64,
        }

        impl RecheckWatchdog {
            const IDLE: u64 = 0;
            const RUNNING: u64 = u64::MAX;

            const fn new() -> Self {
                Self {
                    deadline_ns: AtomicU64::new(Self::IDLE),
                    observed_completions: AtomicU64::new(0),
                }
            }

            fn clamp_deadline(now_ns: u64, interval_ns: u64) -> u64 {
                now_ns
                    .saturating_add(interval_ns.max(1))
                    .clamp(1, Self::RUNNING - 1)
            }

            #[cfg(all(feature = "multitask", feature = "irq"))]
            fn try_arm(
                &self,
                interval_ns: u64,
                completions_now: u64,
                now_ns: impl FnOnce() -> u64,
            ) -> bool {
                if self.deadline_ns.load(Ordering::Acquire) != Self::IDLE {
                    return false;
                }
                let deadline = Self::clamp_deadline(now_ns(), interval_ns);
                self.observed_completions
                    .store(completions_now, Ordering::Relaxed);
                VIRTIO_BLK_ARMED_WATCHDOGS.fetch_add(1, Ordering::AcqRel);
                if self
                    .deadline_ns
                    .compare_exchange(Self::IDLE, deadline, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    VIRTIO_BLK_ARMED_WATCHDOGS.fetch_sub(1, Ordering::Release);
                    return false;
                }
                true
            }

            #[cfg(all(feature = "multitask", feature = "irq"))]
            fn try_begin_recheck(&self, now_ns: u64) -> bool {
                let deadline = self.deadline_ns.load(Ordering::Acquire);
                if deadline == Self::IDLE || deadline == Self::RUNNING || now_ns < deadline {
                    return false;
                }
                self.deadline_ns
                    .compare_exchange(deadline, Self::RUNNING, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            }

            #[cfg(all(feature = "multitask", feature = "irq"))]
            fn observed_completions(&self) -> u64 {
                self.observed_completions.load(Ordering::Relaxed)
            }

            fn refresh_progress(&self, completions_now: u64, now_ns: u64, interval_ns: u64) {
                self.observed_completions
                    .store(completions_now, Ordering::Relaxed);
                let next_deadline = Self::clamp_deadline(now_ns, interval_ns);
                self.deadline_ns.store(next_deadline, Ordering::Release);
            }

            fn finish_recheck(
                &self,
                has_pending: bool,
                completions_now: u64,
                now_ns: u64,
                interval_ns: u64,
            ) -> bool {
                if has_pending {
                    self.refresh_progress(completions_now, now_ns, interval_ns);
                    true
                } else {
                    self.deadline_ns.store(Self::IDLE, Ordering::Release);
                    VIRTIO_BLK_ARMED_WATCHDOGS.fetch_sub(1, Ordering::Release);
                    false
                }
            }

            #[cfg(test)]
            fn deadline_ns(&self) -> Option<u64> {
                match self.deadline_ns.load(Ordering::Acquire) {
                    Self::IDLE | Self::RUNNING => None,
                    deadline => Some(deadline),
                }
            }
        }

        impl Drop for RecheckWatchdog {
            fn drop(&mut self) {
                if self.deadline_ns.swap(Self::IDLE, Ordering::AcqRel) != Self::IDLE {
                    VIRTIO_BLK_ARMED_WATCHDOGS.fetch_sub(1, Ordering::Release);
                }
            }
        }
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
        fn virtio_err_to_dev(e: virtio_drivers::Error) -> driver_base::DevError {
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

        #[derive(Clone, Copy, PartialEq, Eq)]
        #[repr(u8)]
        enum CompletionSource {
            Irq = 0,
            Poll = 1,
            Recheck = 2,
        }

        impl CompletionSource {
            fn from_u8(value: u8) -> Self {
                match value {
                    0 => Self::Irq,
                    1 => Self::Poll,
                    _ => Self::Recheck,
                }
            }
        }

        struct VirtIoBlkCounters {
            submissions: AtomicU64,
            completions_total: AtomicU64,
            last_completion_source: AtomicU8,
            irq_count: AtomicU64,
            irq_completions: AtomicU64,
            poll_completions: AtomicU64,
            recheck_armed: AtomicU64,
            recheck_already_armed: AtomicU64,
            recheck_callback_fired: AtomicU64,
            recheck_irq_completed_before_callback: AtomicU64,
            recheck_poll_completed_before_callback: AtomicU64,
            recheck_callback_already_drained: AtomicU64,
            recheck_callback_still_pending: AtomicU64,
            recheck_callback_reclaimed: AtomicU64,
            recheck_reclaimed_completions: AtomicU64,
            recheck_rearmed: AtomicU64,
            in_flight_current: AtomicUsize,
            in_flight_max: AtomicUsize,
            in_flight_submit_sum: AtomicU64,
            queue_full_waits: AtomicU64,
            cancelled_detached: AtomicU64,
            cancelled_completed_recycled: AtomicU64,
        }

        impl VirtIoBlkCounters {
            const fn new() -> Self {
                Self {
                    submissions: AtomicU64::new(0),
                    completions_total: AtomicU64::new(0),
                    last_completion_source: AtomicU8::new(CompletionSource::Irq as u8),
                    irq_count: AtomicU64::new(0),
                    irq_completions: AtomicU64::new(0),
                    poll_completions: AtomicU64::new(0),
                    recheck_armed: AtomicU64::new(0),
                    recheck_already_armed: AtomicU64::new(0),
                    recheck_callback_fired: AtomicU64::new(0),
                    recheck_irq_completed_before_callback: AtomicU64::new(0),
                    recheck_poll_completed_before_callback: AtomicU64::new(0),
                    recheck_callback_already_drained: AtomicU64::new(0),
                    recheck_callback_still_pending: AtomicU64::new(0),
                    recheck_callback_reclaimed: AtomicU64::new(0),
                    recheck_reclaimed_completions: AtomicU64::new(0),
                    recheck_rearmed: AtomicU64::new(0),
                    in_flight_current: AtomicUsize::new(0),
                    in_flight_max: AtomicUsize::new(0),
                    in_flight_submit_sum: AtomicU64::new(0),
                    queue_full_waits: AtomicU64::new(0),
                    cancelled_detached: AtomicU64::new(0),
                    cancelled_completed_recycled: AtomicU64::new(0),
                }
            }

            fn record_submission(&self, pending_count: usize, in_flight_max: usize) {
                self.submissions.fetch_add(1, Ordering::Relaxed);
                self.in_flight_current
                    .store(pending_count, Ordering::Release);
                self.in_flight_max.store(in_flight_max, Ordering::Relaxed);
                self.in_flight_submit_sum
                    .fetch_add(pending_count as u64, Ordering::Relaxed);
            }

            fn record_completion(&self, source: CompletionSource, pending_count: usize) {
                self.last_completion_source
                    .store(source as u8, Ordering::Relaxed);
                self.in_flight_current
                    .store(pending_count, Ordering::Release);
                self.completions_total.fetch_add(1, Ordering::Release);
                match source {
                    CompletionSource::Irq => {
                        self.irq_completions.fetch_add(1, Ordering::Relaxed);
                    }
                    CompletionSource::Poll => {
                        self.poll_completions.fetch_add(1, Ordering::Relaxed);
                    }
                    CompletionSource::Recheck => {
                        self.recheck_reclaimed_completions
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            #[cfg(all(feature = "multitask", feature = "irq"))]
            fn last_completion_source(&self) -> CompletionSource {
                CompletionSource::from_u8(self.last_completion_source.load(Ordering::Relaxed))
            }

            fn snapshot(&self) -> crate::VirtIoBlkStats {
                crate::VirtIoBlkStats {
                    submissions: self.submissions.load(Ordering::Relaxed),
                    completions_total: self.completions_total.load(Ordering::Relaxed),
                    irq_count: self.irq_count.load(Ordering::Relaxed),
                    irq_completions: self.irq_completions.load(Ordering::Relaxed),
                    poll_completions: self.poll_completions.load(Ordering::Relaxed),
                    recheck_armed: self.recheck_armed.load(Ordering::Relaxed),
                    recheck_already_armed: self.recheck_already_armed.load(Ordering::Relaxed),
                    recheck_callback_fired: self.recheck_callback_fired.load(Ordering::Relaxed),
                    recheck_irq_completed_before_callback: self
                        .recheck_irq_completed_before_callback
                        .load(Ordering::Relaxed),
                    recheck_poll_completed_before_callback: self
                        .recheck_poll_completed_before_callback
                        .load(Ordering::Relaxed),
                    recheck_callback_already_drained: self
                        .recheck_callback_already_drained
                        .load(Ordering::Relaxed),
                    recheck_callback_still_pending: self
                        .recheck_callback_still_pending
                        .load(Ordering::Relaxed),
                    recheck_callback_reclaimed: self
                        .recheck_callback_reclaimed
                        .load(Ordering::Relaxed),
                    recheck_reclaimed_completions: self
                        .recheck_reclaimed_completions
                        .load(Ordering::Relaxed),
                    recheck_rearmed: self.recheck_rearmed.load(Ordering::Relaxed),
                    in_flight_current: self.in_flight_current.load(Ordering::Relaxed),
                    in_flight_max: self.in_flight_max.load(Ordering::Relaxed),
                    in_flight_submit_sum: self.in_flight_submit_sum.load(Ordering::Relaxed),
                    queue_full_waits: self.queue_full_waits.load(Ordering::Relaxed),
                    cancelled_detached: self.cancelled_detached.load(Ordering::Relaxed),
                    cancelled_completed_recycled: self
                        .cancelled_completed_recycled
                        .load(Ordering::Relaxed),
                }
            }
        }

        trait VirtIoBlkDeviceOps: Send + Sync {
            fn stats_snapshot(&self) -> crate::VirtIoBlkStats;
            #[cfg(all(feature = "multitask", feature = "irq"))]
            fn poll_completion_recheck(&self, now_ns: u64);
            #[cfg(feature = "guest-checks")]
            fn set_irq_suppressed(&self, suppressed: bool);
        }

        impl<
            H: VirtIoHal + Send + Sync + 'static,
            T: virtio_drivers::transport::Transport + Send + Sync + 'static,
        > VirtIoBlkDeviceOps for VirtIoBlkDevInner<H, T>
        {
            fn stats_snapshot(&self) -> crate::VirtIoBlkStats {
                self.counters.snapshot()
            }

            #[cfg(all(feature = "multitask", feature = "irq"))]
            fn poll_completion_recheck(&self, now_ns: u64) {
                VirtIoBlkDevInner::poll_completion_recheck(self, now_ns);
            }

            #[cfg(feature = "guest-checks")]
            fn set_irq_suppressed(&self, suppressed: bool) {
                self.suppress_irq_completion
                    .store(suppressed, Ordering::Release);
            }
        }

        static VIRTIO_BLK_ARMED_WATCHDOGS: AtomicUsize = AtomicUsize::new(0);
        type VirtIoBlkRegistry = Vec<Weak<dyn VirtIoBlkDeviceOps>>;
        static VIRTIO_BLK_DEVICES: SpinNoIrq<Option<Arc<VirtIoBlkRegistry>>> =
            SpinNoIrq::new(None);

        fn register_virtio_blk_device(device: Weak<dyn VirtIoBlkDeviceOps>) {
            let mut registry = VIRTIO_BLK_DEVICES.lock();
            let devices = Arc::make_mut(registry.get_or_insert_with(|| Arc::new(Vec::new())));
            devices.retain(|entry| entry.strong_count() > 0);
            devices.push(device);
        }

        fn for_each_virtio_blk_device(mut visit: impl FnMut(usize, &dyn VirtIoBlkDeviceOps)) {
            // Keep the complete registration list stable across callbacks. Only
            // registration can allocate; each device is held alive while visited.
            let snapshot = VIRTIO_BLK_DEVICES.lock().clone();
            if let Some(devices) = snapshot {
                for (index, device) in devices.iter().filter_map(Weak::upgrade).enumerate() {
                    visit(index, device.as_ref());
                }
            }
        }

        #[cfg(all(feature = "multitask", feature = "irq"))]
        fn virtio_blk_tick_recheck() {
            if VIRTIO_BLK_ARMED_WATCHDOGS.load(Ordering::Acquire) == 0 {
                return;
            }
            virtio_blk_tick_recheck_at(hal::time::monotonic_time_nanos());
        }

        #[cfg(all(feature = "multitask", feature = "irq"))]
        fn virtio_blk_tick_recheck_at(now_ns: u64) {
            for_each_virtio_blk_device(|_, device| device.poll_completion_recheck(now_ns));
        }

        pub(crate) fn for_each_virtio_blk_stats(mut visit: impl FnMut(usize, crate::VirtIoBlkStats)) {
            for_each_virtio_blk_device(|index, device| visit(index, device.stats_snapshot()));
        }

        #[cfg(feature = "guest-checks")]
        pub(crate) fn set_virtio_blk_irq_suppressed_for_test(suppressed: bool) {
            for_each_virtio_blk_device(|_, device| device.set_irq_suppressed(suppressed));
        }

        struct VirtIoBlkState<H: VirtIoHal, T: virtio_drivers::transport::Transport> {
            device: driver_virtio::VirtIoBlkDev<H, T>,
            pending: [Option<(u64, PendingBlockRequest<H>)>; VIRTIO_BLK_QUEUE_SIZE],
            pending_direct_reads:
                [Option<driver_block::OwnedReadBufferLease>; VIRTIO_BLK_QUEUE_SIZE],
            pending_direct_writes:
                [Option<driver_block::OwnedWriteBufferLease>; VIRTIO_BLK_QUEUE_SIZE],
            pending_count: usize,
            in_flight_max: usize,
            completed: Vec<(u64, PendingBlockRequest<H>)>,
            dma_pool: Vec<DmaBlockRequest<H>>,
            dma_pool_pages: usize,
            next_request_id: u64,
            submit_wakers: Vec<Waker>,
        }

        pub struct VirtIoBlkDevInner<H: VirtIoHal, T: virtio_drivers::transport::Transport> {
            inner: SpinNoIrq<VirtIoBlkState<H, T>>,
            counters: VirtIoBlkCounters,
            recheck_watchdog: RecheckWatchdog,
            recheck_interval_ns: u64,
            #[cfg(feature = "guest-checks")]
            suppress_irq_completion: AtomicBool,
        }

        impl<H: VirtIoHal, T: virtio_drivers::transport::Transport> VirtIoBlkDevInner<H, T> {
            fn with_interval(
                device: driver_virtio::VirtIoBlkDev<H, T>,
                recheck_interval_ns: u64,
            ) -> Arc<Self> {
                Arc::new(Self {
                    inner: SpinNoIrq::new(VirtIoBlkState {
                        device,
                        pending: core::array::from_fn(|_| None),
                        pending_direct_reads: core::array::from_fn(|_| None),
                        pending_direct_writes: core::array::from_fn(|_| None),
                        pending_count: 0,
                        in_flight_max: 0,
                        completed: Vec::with_capacity(VIRTIO_BLK_QUEUE_SIZE),
                        dma_pool: Vec::with_capacity(VIRTIO_BLK_QUEUE_SIZE),
                        dma_pool_pages: 0,
                        next_request_id: 0,
                        submit_wakers: Vec::with_capacity(VIRTIO_BLK_QUEUE_SIZE),
                    }),
                    counters: VirtIoBlkCounters::new(),
                    recheck_watchdog: RecheckWatchdog::new(),
                    recheck_interval_ns,
                    #[cfg(feature = "guest-checks")]
                    suppress_irq_completion: AtomicBool::new(false),
                })
            }

            #[cfg(test)]
            fn new_for_test(
                device: driver_virtio::VirtIoBlkDev<H, T>,
                recheck_interval_ns: u64,
            ) -> Arc<Self> {
                Self::with_interval(device, recheck_interval_ns)
            }
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
                let mut dev = driver_virtio::VirtIoBlkDev::try_new(transport)?;
                dev.enable_interrupts();
                let inner =
                    VirtIoBlkDevInner::with_interval(dev, COMPLETION_RECHECK_INTERVAL_NS);
                let device_ops = Arc::downgrade(&inner) as Weak<dyn VirtIoBlkDeviceOps>;
                register_virtio_blk_device(device_ops);
                #[cfg(all(feature = "multitask", feature = "irq"))]
                task::register_timer_hook(virtio_blk_tick_recheck);
                fn handler<H: VirtIoHal, T: virtio_drivers::transport::Transport>(
                    w: &VirtIoBlkDevInner<H, T>,
                ) {
                    w.handle_interrupt();
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
                direct_data: bool,
                mut dma: DmaBlockRequest<H>,
            ) -> Self {
                debug_assert!(!direct_data || op != BlockRequestOp::Flush);
                dma.prepare(if direct_data { 0 } else { data_len });
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

            fn uses_direct_write(&self) -> bool {
                self.op == BlockRequestOp::Write && self.dma.data_len == 0
            }

            fn read_parts_mut<'a>(
                &'a mut self,
                direct_read: Option<&'a mut driver_block::OwnedReadBufferLease>,
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

            fn write_parts_mut<'a>(
                &'a mut self,
                direct_write: Option<&'a driver_block::OwnedWriteBufferLease>,
            ) -> (&'a mut BlkReq, &'a [u8], &'a mut BlkResp) {
                debug_assert_eq!(self.uses_direct_write(), direct_write.is_some());
                let dma = &mut self.dma;
                let (request, bounce_data, response) = dma.parts_mut();
                let data = if let Some(direct_write) = direct_write {
                    // SAFETY: The registration contract keeps the immutable
                    // source stable, and the pending request owns its lease
                    // until the descriptor chain is reclaimed.
                    unsafe { direct_write.as_slice() }
                } else {
                    bounce_data
                };
                (request, data, response)
            }

            fn submit<T: virtio_drivers::transport::Transport>(
                &mut self,
                device: &mut driver_virtio::VirtIoBlkDev<H, T>,
                block_id: u64,
                direct_read: Option<&mut driver_block::OwnedReadBufferLease>,
                direct_write: Option<&driver_block::OwnedWriteBufferLease>,
            ) -> virtio_drivers::Result<SubmitOutcome> {
                let block_id = usize::try_from(block_id)
                    .map_err(|_| virtio_drivers::Error::InvalidParam)?;
                let op = self.op;
                // SAFETY: Request/response storage is owned by `self.dma` and
                // data is either in the same allocation or covered by a direct
                // lease. All buffers remain stable until completion.
                unsafe {
                    match op {
                        BlockRequestOp::Read => {
                            let (request, data, response) = self.read_parts_mut(direct_read);
                            device
                                .inner
                                .read_blocks_nb(block_id, request, data, response)
                                .map(SubmitOutcome::Queued)
                        }
                        BlockRequestOp::Write => {
                            let (request, data, response) = self.write_parts_mut(direct_write);
                            device
                                .inner
                                .write_blocks_nb(block_id, request, data, response)
                                .map(SubmitOutcome::Queued)
                        }
                        BlockRequestOp::Flush => {
                            let (request, _, response) = self.dma.parts_mut();
                            device
                                .inner
                                .flush_nb(request, response)
                                .map(|token| token.map_or(SubmitOutcome::Complete, SubmitOutcome::Queued))
                        }
                    }
                }
            }

            fn complete<T: virtio_drivers::transport::Transport>(
                &mut self,
                device: &mut driver_virtio::VirtIoBlkDev<H, T>,
                token: u16,
                direct_read: Option<&mut driver_block::OwnedReadBufferLease>,
                direct_write: Option<&driver_block::OwnedWriteBufferLease>,
            ) -> DevResult {
                let op = self.op;
                // SAFETY: `token` identifies the descriptor chain submitted
                // with these exact DMA-backed buffers, and `peek_used` proved
                // that the device no longer owns the chain.
                unsafe {
                    match op {
                        BlockRequestOp::Read => {
                            let (request, data, response) = self.read_parts_mut(direct_read);
                            device
                                .inner
                                .complete_read_blocks(token, request, data, response)
                        }
                        BlockRequestOp::Write => {
                            let (request, data, response) = self.write_parts_mut(direct_write);
                            device
                                .inner
                                .complete_write_blocks(token, request, data, response)
                        }
                        BlockRequestOp::Flush => {
                            let (request, _, response) = self.dma.parts_mut();
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
                counters: &VirtIoBlkCounters,
            ) -> Option<(PendingBlockRequest<H>, Vec<Waker>)> {
                if self.device.inner.peek_used() != Some(token) {
                    return None;
                }
                let wake = self.complete_one(Some(request_id), counters, CompletionSource::Poll)?;
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
                counters: &VirtIoBlkCounters,
                source: CompletionSource,
            ) -> Option<CompletionWake<H>> {
                let token = self.device.inner.peek_used()?;
                let Some(slot) = self.pending.get_mut(token as usize) else {
                    panic!("virtio-blk completed out-of-range token {}", token);
                };
                let Some((request_id, mut request)) = slot.take() else {
                    panic!("virtio-blk completed unknown token {}", token);
                };
                self.pending_count -= 1;
                counters.record_completion(source, self.pending_count);
                let direct_read = self.pending_direct_reads[token as usize].as_mut();
                let direct_write = self.pending_direct_writes[token as usize].as_ref();
                request.result = Some(request.complete(
                    &mut self.device,
                    token,
                    direct_read,
                    direct_write,
                ));
                // `complete` reclaimed the descriptor chain, so the device can
                // no longer access either registered source or destination.
                self.pending_direct_reads[token as usize].take();
                self.pending_direct_writes[token as usize].take();
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

        struct DrainBatch<H: VirtIoHal> {
            completed: usize,
            remaining_pending: usize,
            extracted: Option<PendingBlockRequest<H>>,
            request_wakers: [Option<Waker>; VIRTIO_BLK_QUEUE_SIZE],
            submit_wakers: Vec<Waker>,
        }

        struct DrainSummary<H: VirtIoHal> {
            completed: usize,
            remaining_pending: usize,
            extracted: Option<PendingBlockRequest<H>>,
        }

        impl<H: VirtIoHal, T: virtio_drivers::transport::Transport>
            VirtIoBlkDevInner<H, T>
        {
            fn new_request(
                &self,
                op: BlockRequestOp,
                data_len: usize,
                direct_data: bool,
            ) -> virtio_drivers::Result<PendingBlockRequest<H>> {
                let dma_data_len = if direct_data { 0 } else { data_len };
                let dma = self
                    .inner
                    .lock()
                    .take_dma(dma_data_len)
                    .map(Ok)
                    .unwrap_or_else(|| DmaBlockRequest::<H>::new(dma_data_len))?;
                Ok(PendingBlockRequest::new(op, data_len, direct_data, dma))
            }

            fn recycle_request(&self, request: PendingBlockRequest<H>) {
                self.inner.lock().recycle_request(request);
            }

            fn wake_completion_batch(
                request_wakers: [Option<Waker>; VIRTIO_BLK_QUEUE_SIZE],
                submit_wakers: Vec<Waker>,
            ) {
                for waker in request_wakers.into_iter().flatten() {
                    waker.wake();
                }
                for waker in submit_wakers {
                    waker.wake();
                }
            }

            fn handle_interrupt(&self) {
                kernel_log::debug!("virtio-blk interrupt handler: checking interrupt");
                self.counters.irq_count.fetch_add(1, Ordering::Relaxed);
                let batch = {
                    let mut state = self.inner.lock();
                    let acked = state.device.ack_interrupt();
                    kernel_log::debug!("virtio-blk interrupt handler: acked={}", acked);
                    #[cfg(feature = "guest-checks")]
                    if self.suppress_irq_completion.load(Ordering::Acquire) {
                        return;
                    }
                    // Notify unconditionally: for MSI-X mode, the device fires
                    // the interrupt only when I/O completes; `acked` reflects
                    // whether the legacy ISR STATUS bit was set, which is NOT
                    // reliable under MSI-X (QEMU may return false even on completion).
                    self.drain_completions_locked(&mut state, None, CompletionSource::Irq, None)
                };
                Self::wake_completion_batch(batch.request_wakers, batch.submit_wakers);
            }

            fn drain_completions_locked(
                &self,
                state: &mut VirtIoBlkState<H, T>,
                extract_request_id: Option<u64>,
                source: CompletionSource,
                recheck_now_ns: Option<u64>,
            ) -> DrainBatch<H> {
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
                    let Some(wake) = state.complete_one(extract, &self.counters, source) else {
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
                let remaining_pending = state.pending_count;
                if source == CompletionSource::Recheck {
                    let now_ns = recheck_now_ns.unwrap_or_else(hal::time::monotonic_time_nanos);
                    let completions_now = self.counters.completions_total.load(Ordering::Relaxed);
                    if self.recheck_watchdog.finish_recheck(
                        remaining_pending > 0,
                        completions_now,
                        now_ns,
                        self.recheck_interval_ns,
                    ) {
                        self.counters.recheck_rearmed.fetch_add(1, Ordering::Relaxed);
                    }
                }
                DrainBatch {
                    completed,
                    remaining_pending,
                    extracted,
                    request_wakers,
                    submit_wakers,
                }
            }

            fn drain_completions_inner(
                &self,
                extract_request_id: Option<u64>,
                source: CompletionSource,
                recheck_now_ns: Option<u64>,
            ) -> DrainSummary<H> {
                let batch = {
                    let mut state = self.inner.lock();
                    self.drain_completions_locked(
                        &mut state,
                        extract_request_id,
                        source,
                        recheck_now_ns,
                    )
                };
                Self::wake_completion_batch(batch.request_wakers, batch.submit_wakers);
                DrainSummary {
                    completed: batch.completed,
                    remaining_pending: batch.remaining_pending,
                    extracted: batch.extracted,
                }
            }

            #[cfg(all(feature = "multitask", feature = "irq"))]
            fn arm_completion_recheck_locked(&self, state: &VirtIoBlkState<H, T>) {
                if state.pending_count == 0 {
                    return;
                }
                let completions_now = self.counters.completions_total.load(Ordering::Relaxed);
                if self.recheck_watchdog.try_arm(
                    self.recheck_interval_ns,
                    completions_now,
                    hal::time::monotonic_time_nanos,
                ) {
                    self.counters.recheck_armed.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.counters
                        .recheck_already_armed
                        .fetch_add(1, Ordering::Relaxed);
                }
            }

            #[cfg(all(feature = "multitask", feature = "irq"))]
            fn poll_completion_recheck(&self, now_ns: u64) {
                if self.recheck_watchdog.try_begin_recheck(now_ns) {
                    self.run_claimed_completion_recheck(now_ns);
                }
            }

            #[cfg(all(feature = "multitask", feature = "irq"))]
            fn run_claimed_completion_recheck(&self, now_ns: u64) {
                let observed = self.recheck_watchdog.observed_completions();
                let cur_completions = self.counters.completions_total.load(Ordering::Acquire);
                let in_flight = self.counters.in_flight_current.load(Ordering::Acquire);

                // Healthy busy queue: completions kept flowing via IRQ/poll,
                // so advance the epoch without acquiring `self.inner`.
                if in_flight > 0 && cur_completions != observed {
                    self.recheck_watchdog.refresh_progress(
                        cur_completions,
                        now_ns,
                        self.recheck_interval_ns,
                    );
                    return;
                }

                // Device looks idle: confirm under `self.inner` lock before
                // lazily disarming so no in-flight submission can miss a check.
                if in_flight == 0 {
                    let state = self.inner.lock();
                    if state.pending_count == 0 {
                        let latest = self.counters.completions_total.load(Ordering::Relaxed);
                        self.recheck_watchdog.finish_recheck(
                            false,
                            latest,
                            now_ns,
                            self.recheck_interval_ns,
                        );
                        match self.counters.last_completion_source() {
                            CompletionSource::Poll => {
                                self.counters
                                    .recheck_poll_completed_before_callback
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            CompletionSource::Irq | CompletionSource::Recheck => {
                                self.counters
                                    .recheck_irq_completed_before_callback
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        return;
                    }
                    let latest = self.counters.completions_total.load(Ordering::Relaxed);
                    if latest != observed {
                        self.recheck_watchdog.refresh_progress(
                            latest,
                            now_ns,
                            self.recheck_interval_ns,
                        );
                        return;
                    }
                }

                // Stalled or suspected lost IRQ: drain the used ring.
                self.execute_recheck_callback(now_ns);
            }

            #[cfg(all(feature = "multitask", feature = "irq"))]
            fn execute_recheck_callback(&self, now_ns: u64) {
                self.counters
                    .recheck_callback_fired
                    .fetch_add(1, Ordering::Relaxed);
                let summary =
                    self.drain_completions_inner(None, CompletionSource::Recheck, Some(now_ns));
                if summary.completed > 0 {
                    self.counters
                        .recheck_callback_reclaimed
                        .fetch_add(1, Ordering::Relaxed);
                } else if summary.remaining_pending == 0 {
                    self.counters
                        .recheck_callback_already_drained
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.counters
                        .recheck_callback_still_pending
                        .fetch_add(1, Ordering::Relaxed);
                }
            }

            #[cfg(not(all(feature = "multitask", feature = "irq")))]
            fn arm_completion_recheck_locked(&self, _state: &VirtIoBlkState<H, T>) {}

            fn cancel_request(&self, token: u16, request_id: u64) {
                let mut state = self.inner.lock();
                if let Some(request) = state.take_completed(request_id) {
                    self.counters
                        .cancelled_completed_recycled
                        .fetch_add(1, Ordering::Relaxed);
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
                    self.counters
                        .cancelled_detached
                        .fetch_add(1, Ordering::Relaxed);
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
            direct_read: Option<driver_block::OwnedReadBufferLease>,
            direct_write: Option<driver_block::OwnedWriteBufferLease>,
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
                    direct_write: None,
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
                    direct_write: None,
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
                    direct_write: None,
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
                let context = task::WaitContext::new_optional(|| {
                    let reason = match self.buffer {
                        FutureBuffer::Read(_) => task::WaitReason::VirtioBlkRead,
                        FutureBuffer::Write(_) => task::WaitReason::VirtioBlkWrite,
                        FutureBuffer::Flush(_) => return None,
                    };
                    Some((
                        reason,
                        Arc::as_ptr(&self.inner) as usize as u64,
                        u64::from(token),
                    ))
                });
                if let Some(context) = context {
                    task::future::set_current_wait_context(context);
                }
            }

            #[cfg(feature = "multitask")]
            fn record_queue_full_wait(&self) {
                task::future::set_current_wait_context(task::WaitContext::new(|| {
                    let operation = match self.buffer {
                        FutureBuffer::Read(_) => 1,
                        FutureBuffer::Write(_) => 2,
                        FutureBuffer::Flush(_) => 3,
                    };
                    (
                        task::WaitReason::VirtioBlkQueueFull,
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
                    hal::asm::irqs_enabled()
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
                        this.inner
                            .drain_completions_inner(
                                this.request_id,
                                CompletionSource::Poll,
                                None,
                            )
                            .extracted
                    } else if !can_suspend {
                        if this.request.is_some() {
                            let _ = this.inner.drain_completions_inner(
                                None,
                                CompletionSource::Poll,
                                None,
                            );
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
                                && let Some((request, submit_wakers)) = state
                                    .complete_current_if_used(
                                        token,
                                        request_id,
                                        &this.inner.counters,
                                    )
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
                                    kernel_log::error!(
                                        "virtio-blk lost request: token={}, request_id={}",
                                        token,
                                        request_id
                                    );
                                    return Poll::Ready(Err(DevError::BadState));
                                }
                                // Mirror the wait-queue condition protocol: the
                                // first check precedes waker registration and the
                                // second closes the completion/enrollment race.
                                if let Some((request, submit_wakers)) = state
                                    .complete_current_if_used(
                                        token,
                                        request_id,
                                        &this.inner.counters,
                                    )
                                {
                                    completed = Some(request);
                                    submit_wakers_to_wake = submit_wakers;
                                }
                            }
                            if completed.is_none() && can_suspend {
                                // Arm while holding `state` so an IRQ draining
                                // the queue cannot race past an idle check.
                                this.inner.arm_completion_recheck_locked(&state);
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
                                FutureBuffer::Read(buf) => driver_block::claim_owned_read_buffer(
                                    NonNull::from(&mut **buf),
                                ),
                                _ => None,
                            }
                        } else {
                            None
                        };
                        this.direct_write = if op == BlockRequestOp::Write {
                            match &this.buffer {
                                FutureBuffer::Write(buf) => {
                                    driver_block::claim_owned_write_buffer(NonNull::from(&**buf))
                                }
                                _ => None,
                            }
                        } else {
                            None
                        };
                        let mut request = match this
                            .inner
                            .new_request(
                                op,
                                len,
                                this.direct_read.is_some() || this.direct_write.is_some(),
                            )
                        {
                            Ok(request) => request,
                            Err(error) => return Poll::Ready(Err(virtio_err_to_dev(error))),
                        };
                        if this.direct_write.is_none()
                            && let FutureBuffer::Write(buf) = &this.buffer
                        {
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
                            this.direct_write.as_ref(),
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
                                assert!(
                                    state.pending_direct_writes[token_index].is_none(),
                                    "virtio-blk reused an in-flight direct-write token"
                                );
                                state.pending_direct_reads[token_index] = this.direct_read.take();
                                state.pending_direct_writes[token_index] = this.direct_write.take();
                                state.pending[token_index] = Some((request_id, request));
                                state.pending_count += 1;
                                if state.pending_count > state.in_flight_max {
                                    state.in_flight_max = state.pending_count;
                                }
                                this.inner
                                    .counters
                                    .record_submission(state.pending_count, state.in_flight_max);
                                Ok(Some((token, request_id)))
                            }
                            Ok(SubmitOutcome::Complete) => {
                                state.recycle_request(request);
                                Ok(None)
                            }
                            Err(virtio_drivers::Error::QueueFull) => {
                                state.register_submit_waker(cx.waker());
                                this.inner
                                    .counters
                                    .queue_full_waits
                                    .fetch_add(1, Ordering::Relaxed);
                                if can_suspend {
                                    this.inner.arm_completion_recheck_locked(&state);
                                }
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
            driver_block::BlockDriverOps for VirtIoBlkDevWrapper<H, T> {
            fn num_blocks(&self) -> u64 {
                self.inner.inner.lock().device.num_blocks()
            }
            fn block_size(&self) -> usize {
                self.inner.inner.lock().device.block_size()
            }
            fn read_block(&mut self, block_id: u64, buf: &mut [u8]) -> DevResult {
                #[cfg(feature = "multitask")]
                return task::future::block_on(
                    <Self as driver_block::AsyncBlockDriverOps>::read_block_async(
                        self, block_id, buf,
                    ),
                );
                #[cfg(not(feature = "multitask"))]
                spin_block_on(<Self as driver_block::AsyncBlockDriverOps>::read_block_async(
                    self, block_id, buf,
                ))
            }

            fn write_block(&mut self, block_id: u64, buf: &[u8]) -> DevResult {
                #[cfg(feature = "multitask")]
                return task::future::block_on(
                    <Self as driver_block::AsyncBlockDriverOps>::write_block_async(
                        self, block_id, buf,
                    ),
                );
                #[cfg(not(feature = "multitask"))]
                spin_block_on(<Self as driver_block::AsyncBlockDriverOps>::write_block_async(
                    self, block_id, buf,
                ))
            }

            fn flush(&mut self) -> DevResult {
                #[cfg(feature = "multitask")]
                return task::future::block_on(
                    <Self as driver_block::AsyncBlockDriverOps>::flush_async(self),
                );
                #[cfg(not(feature = "multitask"))]
                spin_block_on(<Self as driver_block::AsyncBlockDriverOps>::flush_async(self))
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
            driver_block::AsyncBlockDriverOps for VirtIoBlkDevWrapper<H, T>
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
            type Device = driver_virtio::VirtIoGpuDev<VirtIoHalImpl, VirtIoTransport>;

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
            driver_virtio::probe_mmio_device(base_vaddr.as_mut_ptr(), mmio_size)
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
            driver_virtio::probe_pci_device::<VirtIoHalImpl>(root, bdf, dev_info)
        {
            if ty == D::DEVICE_TYPE {
                let irq = match hal::msix::configure_virtio_pci_msix(root, bdf, &mut transport) {
                    Ok(irq) => {
                        debug!(
                            "PCI device at {} configured to use MSI-X (irq {})",
                            bdf, irq
                        );
                        irq
                    }
                    Err(e) => {
                        let irq = (root.config_read_word(bdf, 0x3c) & 0xff) as usize;
                        if irq == 0 || irq == 255 {
                            warn!(
                                "PCI device at {} cannot configure MSI-X ({:?}) and has no usable INTx line ({})",
                                bdf, e, irq
                            );
                            return None;
                        }
                        debug!(
                            "PCI device at {} cannot configure MSI-X ({:?}), falling back to INTx (irq {})",
                            bdf, e, irq
                        );
                        irq
                    }
                };

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
        if hal::asm::irqs_enabled() {
            task::yield_now();
        }
    }
}
