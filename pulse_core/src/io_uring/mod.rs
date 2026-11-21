//! Core kernel `io_uring` instance state (`IoUringState`) and file descriptor (`IoUringObject`).
//!
//! # Lock ordering
//! `submit_lock` -> `cq_lock` -> `eventfd` -> `WaitQueue` internal lock.
//! Never acquire a higher-ranked lock while holding a lower-ranked one.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use axalloc::global_allocator;
use axerrno::{LinuxError, LinuxResult};
use axfs::FileFlags as AxFileFlags;
use axhal::paging::MappingFlags;
use axio::PollState;
use axmm::{PreparedMapping, SharedFrame};
use axpoll::IoEvents;
use axsync::Mutex;
use axtask::WaitQueue;
use kspin::SpinNoIrq;
use linux_raw_sys::general::{POLLIN, S_IFREG, stat};
use linux_raw_sys::io_uring::{
    IORING_CQ_EVENTFD_DISABLED, IORING_OFF_CQ_RING, IORING_OFF_SQ_RING, IORING_OFF_SQES,
    io_uring_op, io_uring_params,
};
use memory_addr::PAGE_SIZE_4K;
use pulse_io_uring_core::capacity::validate_and_compute_ring_geometry;
use pulse_io_uring_core::ring::{
    CompletionRingState, PostCqeOutcome, SharedRingMemory, SubmitRingState,
};
use pulse_io_uring_core::whitelist::{validate_nop_sqe, validate_sqe_v1};
use pulse_user_abi::io_uring::{IoUringCqe, IoUringSqe};

use crate::fd_table::{EventFdObject, FdEntry, FdObject, PollEventSequence, PollRegistration};

struct RegisteredEventFd {
    fd_object: Arc<dyn FdObject>,
    async_only: bool,
}

/// Shared kernel state for an `io_uring` instance.
///
/// Kept behind `Arc<IoUringState>` and separated from `IoUringObject` (`FdObject`) so
/// internal queues/registrations never form reference cycles that inhibit `Drop` on FD close.
///
/// # Field drop order invariant
/// `shared` holds non-owning raw pointers into `_rings_frame` and `_sqes_frame` and
/// does not implement `Drop`; both `Arc<SharedFrame>` fields are declared after
/// `shared` so they stay valid throughout `IoUringState` teardown.
pub struct IoUringState {
    shared: SharedRingMemory,
    rings_frame: Arc<SharedFrame>,
    sqes_frame: Arc<SharedFrame>,
    submit_lock: Mutex<SubmitRingState>,
    cq_lock: SpinNoIrq<CompletionRingState>,
    eventfd: SpinNoIrq<Option<RegisteredEventFd>>,
    dying: AtomicBool,
    inflight_count: AtomicUsize,
    pub cq_wait_queue: WaitQueue,
    teardown_wait_queue: WaitQueue,
    readable_sequence: AtomicU64,
}

pub struct InflightGuard<'a> {
    state: &'a IoUringState,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        if self.state.inflight_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.state.teardown_wait_queue.notify_all(true);
        }
    }
}

fn alloc_zeroed_shared_frame(byte_len: usize) -> LinuxResult<Arc<SharedFrame>> {
    let page_count = byte_len / PAGE_SIZE_4K;
    let vaddr = global_allocator()
        .alloc_pages(page_count, PAGE_SIZE_4K)
        .map_err(|_| LinuxError::ENOMEM)?;
    // SAFETY: `vaddr` was freshly allocated for `page_count * PAGE_SIZE_4K` bytes.
    unsafe {
        core::ptr::write_bytes(vaddr as *mut u8, 0, page_count * PAGE_SIZE_4K);
    }
    Ok(Arc::new(SharedFrame { vaddr, page_count }))
}

impl IoUringState {
    pub fn new(entries: u32, params: &mut io_uring_params) -> LinuxResult<Arc<Self>> {
        let layout = validate_and_compute_ring_geometry(entries, params)?;
        let rings_frame = alloc_zeroed_shared_frame(layout.rings_alloc_bytes)?;
        let sqes_frame = alloc_zeroed_shared_frame(layout.sqes_alloc_bytes)?;

        // SAFETY: Both `rings_frame` and `sqes_frame` hold disjoint, page-aligned,
        // zero-initialized allocations of exact sizes `layout.rings_alloc_bytes` and
        // `layout.sqes_alloc_bytes` (`<= isize::MAX`), and stay pinned inside `IoUringState`
        // for its entire lifetime (declared after `shared`).
        let mut shared = unsafe {
            SharedRingMemory::new(
                rings_frame.vaddr as *mut u8,
                layout.rings_alloc_bytes,
                sqes_frame.vaddr as *mut u8,
                layout.sqes_alloc_bytes,
                layout,
            )
        };
        shared.init_headers();

        let submit_all = (layout.flags & linux_raw_sys::io_uring::IORING_SETUP_SUBMIT_ALL) != 0;
        Ok(Arc::new(Self {
            shared,
            rings_frame,
            sqes_frame,
            submit_lock: Mutex::new(SubmitRingState::new(layout.sq_entries, submit_all)),
            cq_lock: SpinNoIrq::new(CompletionRingState::new(layout.cq_entries)),
            eventfd: SpinNoIrq::new(None),
            dying: AtomicBool::new(false),
            inflight_count: AtomicUsize::new(0),
            cq_wait_queue: WaitQueue::new(),
            teardown_wait_queue: WaitQueue::new(),
            readable_sequence: AtomicU64::new(0),
        }))
    }

    pub fn try_enter_inflight(&self) -> LinuxResult<InflightGuard<'_>> {
        self.inflight_count.fetch_add(1, Ordering::AcqRel);
        let guard = InflightGuard { state: self };
        if self.dying.load(Ordering::Acquire) {
            return Err(LinuxError::EBADF);
        }
        Ok(guard)
    }

    #[inline]
    pub fn is_dying(&self) -> bool {
        self.dying.load(Ordering::Acquire)
    }

    #[inline]
    pub fn cq_entries(&self) -> u32 {
        self.shared.layout().cq_entries
    }

    /// Publishes one CQE into the CQ ring / overflow FIFO, wakes waiters, and notifies registered eventfd.
    pub fn complete_cqe(&self, cqe: IoUringCqe, from_async: bool) -> PostCqeOutcome {
        let outcome = {
            let mut cq = self.cq_lock.lock();
            cq.post_cqe(&self.shared, cqe)
        };
        self.readable_sequence.fetch_add(1, Ordering::Release);
        self.cq_wait_queue.notify_all(true);

        if self.dying.load(Ordering::Acquire) {
            return outcome;
        }
        let cq_flags = self.shared.load_cq_flags();
        if cq_flags & IORING_CQ_EVENTFD_DISABLED == 0 {
            let ev = {
                let guard = self.eventfd.lock();
                guard
                    .as_ref()
                    .filter(|reg| !reg.async_only || from_async)
                    .map(|reg| Arc::clone(&reg.fd_object))
            };
            if let Some(fd_obj) = ev {
                if let Some(eventfd) = fd_obj.as_any().downcast_ref::<EventFdObject>() {
                    let _ = eventfd.signal_nonblocking(1);
                }
            }
        }
        outcome
    }

    /// Returns `(cq_ready_count, consumed_pending_ebadr)` after flushing overflow.
    ///
    /// Releases `cq_lock` before waking waiters (`cq_wait_queue.notify_all`), respecting ADR-0007.
    pub fn check_cq_ready_and_ebadr(&self, consume_ebadr: bool) -> (u32, bool) {
        let (flushed, ready, ebadr) = {
            let mut cq = self.cq_lock.lock();
            let flushed = cq.flush_cq_overflow(&self.shared);
            let ready = cq.ring_ready_count(&self.shared);
            let ebadr = if consume_ebadr {
                cq.take_pending_ebadr_if_empty(&self.shared)
            } else {
                false
            };
            (flushed, ready, ebadr)
        };
        if flushed > 0 {
            self.readable_sequence.fetch_add(1, Ordering::Release);
            self.cq_wait_queue.notify_all(true);
        }
        (ready, ebadr)
    }

    /// Consumes and dispatches up to `to_submit` SQEs under `submit_lock`.
    pub fn submit_sqes(&self, to_submit: u32) -> u32 {
        if to_submit == 0 || self.is_dying() {
            return 0;
        }
        let mut sq = self.submit_lock.lock();
        sq.submit_batch(&self.shared, to_submit, |sqe| self.dispatch_sqe(sqe))
    }

    fn dispatch_sqe(&self, sqe: &IoUringSqe) -> Result<(), ()> {
        if let Err(err) = validate_sqe_v1(sqe) {
            self.complete_cqe(
                IoUringCqe {
                    user_data: sqe.user_data,
                    res: -err.code(),
                    flags: 0,
                },
                false,
            );
            return Err(());
        }

        if sqe.opcode == io_uring_op::IORING_OP_NOP as u8 {
            return match validate_nop_sqe(sqe) {
                Ok(()) => {
                    self.complete_cqe(
                        IoUringCqe {
                            user_data: sqe.user_data,
                            res: 0,
                            flags: 0,
                        },
                        false,
                    );
                    Ok(())
                }
                Err(err) => {
                    self.complete_cqe(
                        IoUringCqe {
                            user_data: sqe.user_data,
                            res: -err.code(),
                            flags: 0,
                        },
                        false,
                    );
                    Err(())
                }
            };
        }

        // Remaining v1 opcodes are implemented in subsequent slices (#236-#241).
        self.complete_cqe(
            IoUringCqe {
                user_data: sqe.user_data,
                res: -LinuxError::EOPNOTSUPP.code(),
                flags: 0,
            },
            false,
        );
        Err(())
    }

    pub fn register_eventfd(&self, entry: &FdEntry, async_only: bool) -> LinuxResult<()> {
        if !entry.object.as_any().is::<EventFdObject>() {
            return Err(LinuxError::EINVAL);
        }
        let mut guard = self.eventfd.lock();
        if guard.is_some() {
            return Err(LinuxError::EBUSY);
        }
        *guard = Some(RegisteredEventFd {
            fd_object: Arc::clone(&entry.object),
            async_only,
        });
        Ok(())
    }

    pub fn unregister_eventfd(&self) -> LinuxResult<()> {
        let mut guard = self.eventfd.lock();
        if guard.take().is_none() {
            return Err(LinuxError::EINVAL);
        }
        Ok(())
    }
}

/// File descriptor wrapper around `Arc<IoUringState>`.
///
/// Closing the final `IoUringObject` deterministically initiates ring teardown (`dying = true`),
/// wakes blocked queues, waits for in-flight operations, and drops the registered eventfd.
pub struct IoUringObject {
    state: Arc<IoUringState>,
}

impl IoUringObject {
    pub fn new(entries: u32, params: &mut io_uring_params) -> LinuxResult<Self> {
        Ok(Self {
            state: IoUringState::new(entries, params)?,
        })
    }

    #[inline]
    pub fn state(&self) -> &Arc<IoUringState> {
        &self.state
    }
}

impl Drop for IoUringObject {
    fn drop(&mut self) {
        self.state.dying.store(true, Ordering::Release);
        self.state.cq_wait_queue.notify_all(true);
        self.state
            .teardown_wait_queue
            .wait_until(|| self.state.inflight_count.load(Ordering::Acquire) == 0);
        // Take under SpinNoIrq, then drop `Arc<dyn FdObject>` outside the SpinNoIrq guard (ADR-0007).
        let ev = { self.state.eventfd.lock().take() };
        drop(ev);
    }
}

impl FdObject for IoUringObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn stat(&self) -> LinuxResult<stat> {
        // SAFETY: Zeroed C `stat` struct has valid all-zero bit patterns for all fields.
        let zeroed: stat = unsafe { core::mem::zeroed() };
        Ok(stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode: S_IFREG | 0o600,
            st_blksize: 4096,
            ..zeroed
        })
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let (ready, _) = self.state.check_cq_ready_and_ebadr(false);
        Ok(PollState {
            readable: ready > 0,
            writable: false,
        })
    }

    fn poll_event_sequence(&self) -> Option<PollEventSequence> {
        Some(PollEventSequence {
            readable: self.state.readable_sequence.load(Ordering::Acquire),
            writable: 0,
        })
    }

    fn get_wait_queues<'a>(
        &'a self,
        events: i16,
        wqs: &mut Vec<&'a WaitQueue>,
    ) -> LinuxResult<bool> {
        if (events & POLLIN as i16) != 0 {
            wqs.push(&self.state.cq_wait_queue);
            return Ok(true);
        }
        Ok(events == 0)
    }

    fn register_poll(
        self: Arc<Self>,
        cx: &mut core::task::Context<'_>,
        events: IoEvents,
        registrations: &mut Vec<PollRegistration>,
    ) -> LinuxResult {
        if events.contains(IoEvents::IN) {
            // Capture only `Arc<IoUringState>`, never `Arc<IoUringObject>`, so closing the
            // last FD always triggers `IoUringObject::drop`.
            let state = Arc::clone(&self.state);
            let registration = state.cq_wait_queue.register_owned_waker(cx.waker());
            registrations.push(PollRegistration::new(move || {
                state.cq_wait_queue.unregister_waker(registration);
            }));
        }
        Ok(())
    }

    fn mmap_file_flags(&self) -> Option<AxFileFlags> {
        Some(AxFileFlags::READ | AxFileFlags::WRITE)
    }

    fn mmap_prepared(
        &self,
        size: usize,
        flags: MappingFlags,
        offset: usize,
        is_shared: bool,
    ) -> Option<LinuxResult<PreparedMapping>> {
        if !is_shared || size == 0 || size % PAGE_SIZE_4K != 0 {
            return Some(Err(LinuxError::EINVAL));
        }
        if flags.contains(MappingFlags::EXECUTE) {
            return Some(Err(LinuxError::EACCES));
        }

        let off = offset as u64;
        let frame = if off == IORING_OFF_SQ_RING as u64 || off == IORING_OFF_CQ_RING as u64 {
            &self.state.rings_frame
        } else if off == IORING_OFF_SQES as u64 {
            &self.state.sqes_frame
        } else {
            return Some(Err(LinuxError::EINVAL));
        };

        let max_bytes = frame.page_count * PAGE_SIZE_4K;
        if size > max_bytes {
            return Some(Err(LinuxError::EINVAL));
        }
        Some(PreparedMapping::shared_frame(size, flags, Arc::clone(frame)).map_err(LinuxError::from))
    }
}
