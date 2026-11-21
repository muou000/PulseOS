//! Core kernel `io_uring` instance state (`IoUringState`) and file descriptor (`IoUringObject`).
//!
//! # Lock ordering (ADR-0007)
//! `submit_lock` (sleepable) -> `Process` / `FdObject` / `axfs` / `axnet` ->
//! `inner` (`SpinNoIrq`: `CompletionRingState` + `RequestOrchestrator`) ->
//! `eventfd` (`SpinNoIrq`) -> `WaitQueue`.
//! Never invoke `Future::poll`, drop futures/FDs/processes, or notify `eventfd`/`WaitQueue`
//! while holding `inner`.

pub mod context;
mod ops;
pub mod worker_pool;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
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
use axtask::future::CancelHandle;
use kspin::SpinNoIrq;
use linux_raw_sys::general::{POLLIN, S_IFREG, stat};
use linux_raw_sys::io_uring::{
    IORING_CQ_EVENTFD_DISABLED, IORING_OFF_CQ_RING, IORING_OFF_SQ_RING, IORING_OFF_SQES,
    io_uring_params,
};
use memory_addr::PAGE_SIZE_4K;
use pulse_io_uring_core::capacity::validate_and_compute_ring_geometry;
use pulse_io_uring_core::orchestrator::{
    OrchestratorEffects, PreparedRequest, RequestId, RequestKind, RequestOrchestrator, RequestPhase,
};
use pulse_io_uring_core::ring::{
    CompletionRingState, PostCqeOutcome, SharedRingMemory, SubmitRingState,
};
use pulse_user_abi::io_uring::{
    IORING_TIMEOUT_UPDATE, IOSQE_IO_HARDLINK, IOSQE_IO_LINK, IoUringCqe,
};

use self::context::AsyncExecContext;
use self::ops::{
    PreparedOpSpec, compute_monotonic_deadline, execute_rw_request, prepare_sqe,
    spawn_accept_future, spawn_poll_add_future, spawn_timer_future,
};
use self::worker_pool::{alloc_ring_pool_id, global_worker_pool};
use crate::fd_table::{EventFdObject, FdEntry, FdObject, PollEventSequence, PollRegistration};

struct RegisteredEventFd {
    fd_object: Arc<dyn FdObject>,
    async_only: bool,
}

static ACTIVE_RINGS: SpinNoIrq<Vec<Weak<IoUringState>>> = SpinNoIrq::new(Vec::new());

struct RingInner {
    cq: CompletionRingState,
    orch: RequestOrchestrator,
    specs: BTreeMap<RequestId, (PreparedOpSpec, AsyncExecContext)>,
    cancel_handles: BTreeMap<RequestId, CancelHandle>,
}

/// Shared kernel state for an `io_uring` instance.
///
/// Kept behind `Arc<IoUringState>` and separated from `IoUringObject` (`FdObject`) so
/// internal queues/registrations never form reference cycles that inhibit `Drop` on FD close.
///
/// # Field drop order invariant
/// `shared` holds non-owning raw pointers into `rings_frame` and `sqes_frame` and
/// does not implement `Drop`; both `Arc<SharedFrame>` fields are declared after
/// `shared` so they stay valid throughout `IoUringState` teardown.
pub struct IoUringState {
    ring_id: u64,
    shared: SharedRingMemory,
    rings_frame: Arc<SharedFrame>,
    sqes_frame: Arc<SharedFrame>,
    submit_lock: Mutex<SubmitRingState>,
    inner: SpinNoIrq<RingInner>,
    eventfd: SpinNoIrq<Option<RegisteredEventFd>>,
    dying: AtomicBool,
    inflight_count: AtomicUsize,
    pub cq_wait_queue: WaitQueue,
    teardown_wait_queue: WaitQueue,
    readable_sequence: AtomicU64,
    timeout_expiries: AtomicU64,
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

pub(crate) struct OwnedInflightGuard(Arc<IoUringState>);

impl Drop for OwnedInflightGuard {
    fn drop(&mut self) {
        if self.0.inflight_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.teardown_wait_queue.notify_all(true);
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
        let ring_id = alloc_ring_pool_id();

        let state = Arc::new(Self {
            ring_id,
            shared,
            rings_frame,
            sqes_frame,
            submit_lock: Mutex::new(SubmitRingState::new(layout.sq_entries, submit_all)),
            inner: SpinNoIrq::new(RingInner {
                cq: CompletionRingState::new(layout.cq_entries),
                orch: RequestOrchestrator::new(),
                specs: BTreeMap::new(),
                cancel_handles: BTreeMap::new(),
            }),
            eventfd: SpinNoIrq::new(None),
            dying: AtomicBool::new(false),
            inflight_count: AtomicUsize::new(0),
            cq_wait_queue: WaitQueue::new(),
            teardown_wait_queue: WaitQueue::new(),
            readable_sequence: AtomicU64::new(0),
            timeout_expiries: AtomicU64::new(0),
        });
        {
            let mut active = ACTIVE_RINGS.lock();
            active.retain(|w| w.strong_count() > 0);
            active.push(Arc::downgrade(&state));
        }
        Ok(state)
    }

    #[inline]
    pub fn ring_id(&self) -> u64 {
        self.ring_id
    }

    pub fn try_enter_inflight(&self) -> LinuxResult<InflightGuard<'_>> {
        self.inflight_count.fetch_add(1, Ordering::AcqRel);
        let guard = InflightGuard { state: self };
        if self.dying.load(Ordering::Acquire) {
            return Err(LinuxError::EBADF);
        }
        Ok(guard)
    }

    pub(crate) fn try_enter_inflight_owned(self: &Arc<Self>) -> Option<OwnedInflightGuard> {
        self.inflight_count.fetch_add(1, Ordering::AcqRel);
        let guard = OwnedInflightGuard(Arc::clone(self));
        if self.dying.load(Ordering::Acquire) {
            drop(guard);
            return None;
        }
        Some(guard)
    }

    #[inline]
    pub fn is_dying(&self) -> bool {
        self.dying.load(Ordering::Acquire)
    }

    #[inline]
    pub fn cq_entries(&self) -> u32 {
        self.shared.layout().cq_entries
    }

    #[inline]
    pub fn timeout_expiries(&self) -> u64 {
        self.timeout_expiries.load(Ordering::Acquire)
    }

    pub(crate) fn has_ready_cqes_fast(&self) -> bool {
        let mut inner = self.inner.lock();
        let _ = inner.cq.flush_cq_overflow(&self.shared);
        inner.cq.ring_ready_count(&self.shared) > 0
    }

    pub(crate) fn is_request_active(&self, req_id: RequestId) -> bool {
        matches!(
            self.inner.lock().orch.request_phase(req_id),
            Some(RequestPhase::Queued | RequestPhase::Running)
        )
    }

    pub(crate) fn try_begin_completing_request(&self, req_id: RequestId) -> bool {
        self.inner.lock().orch.try_begin_completing(req_id)
    }

    pub(crate) fn install_cancel_handle_or_cancel(
        &self,
        req_id: RequestId,
        handle: CancelHandle,
    ) {
        if handle.is_done() {
            return;
        }
        let stale_handle = {
            let mut inner = self.inner.lock();
            if self.is_dying()
                || !matches!(
                    inner.orch.request_phase(req_id),
                    Some(RequestPhase::Queued | RequestPhase::Running)
                )
            {
                Some(handle)
            } else {
                let replaced = inner.cancel_handles.insert(req_id, handle);
                replaced
            }
        };
        if let Some(h) = stale_handle {
            h.cancel();
        }
    }

    fn notify_cqe_consumers(&self, count: usize, from_async: bool) {
        if count == 0 {
            return;
        }
        self.readable_sequence.fetch_add(1, Ordering::Release);
        self.cq_wait_queue.notify_all(true);

        if self.dying.load(Ordering::Acquire) {
            return;
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
    }

    /// Publishes one standalone CQE into the CQ ring / overflow FIFO, wakes waiters, and notifies registered eventfd.
    pub fn complete_cqe(&self, cqe: IoUringCqe, from_async: bool) -> PostCqeOutcome {
        let outcome = {
            let mut inner = self.inner.lock();
            inner.cq.post_cqe(&self.shared, cqe)
        };
        self.notify_cqe_consumers(1, from_async);
        outcome
    }

    fn post_cqes_and_notify(&self, cqes: &[IoUringCqe], from_async: bool) {
        if cqes.is_empty() {
            return;
        }
        {
            let mut inner = self.inner.lock();
            for cqe in cqes {
                let _ = inner.cq.post_cqe(&self.shared, *cqe);
            }
        }
        self.notify_cqe_consumers(cqes.len(), from_async);
    }

    /// Publishes CQEs and cancellation side-effects outside `SpinNoIrq`, returning
    /// the newly activated `start_requests` to execute next.
    fn publish_effects(&self, effects: OrchestratorEffects, from_async: bool) -> Vec<RequestId> {
        let OrchestratorEffects {
            cqes,
            start_requests,
            cancel_requests,
        } = effects;

        let (cqe_count, cancelled_handles, dropped_specs) = {
            let mut inner = self.inner.lock();
            for cqe in &cqes {
                let _ = inner.cq.post_cqe(&self.shared, *cqe);
            }
            let mut handles = Vec::new();
            let mut specs = Vec::new();
            for id in &cancel_requests {
                if let Some(h) = inner.cancel_handles.remove(id) {
                    handles.push(h);
                }
                if let Some(s) = inner.specs.remove(id) {
                    specs.push(s);
                }
            }
            (cqes.len(), handles, specs)
        };

        self.notify_cqe_consumers(cqe_count, from_async);
        for h in cancelled_handles {
            h.cancel();
        }
        for id in &cancel_requests {
            let _ = global_worker_pool().cancel_queued_request(self.ring_id, *id);
        }
        drop(dropped_specs);
        start_requests
    }

    /// Emits `effects` and iteratively drives any newly activated `start_requests`
    /// (avoiding recursive kernel stack growth across long synchronous link chains).
    fn apply_effects(self: &Arc<Self>, effects: OrchestratorEffects, from_async: bool) {
        let mut pending_starts: VecDeque<RequestId> =
            self.publish_effects(effects, from_async).into();

        while let Some(id) = pending_starts.pop_front() {
            if self.is_dying() {
                let (removed_spec, eff) = {
                    let mut inner = self.inner.lock();
                    let removed_spec = inner.specs.remove(&id);
                    let eff = inner
                        .orch
                        .try_claim_completion(id, -LinuxError::ECANCELED.code(), 0);
                    (removed_spec, eff)
                };
                drop(removed_spec);
                if let Some(eff) = eff {
                    pending_starts.extend(self.publish_effects(eff, from_async));
                }
                continue;
            }
            let entry = {
                let mut inner = self.inner.lock();
                inner.specs.remove(&id)
            };
            if let Some((spec, req_ctx)) = entry {
                self.execute_started_request(id, spec, &req_ctx, &mut pending_starts);
            }
        }
    }

    /// Cancels in-flight requests owned by `owner_pid` when that process exits or calls `execve`.
    pub fn cancel_requests_for_owner(self: &Arc<Self>, owner_pid: u64) {
        let eff = {
            let mut inner = self.inner.lock();
            inner.orch.cancel_requests_for_owner(owner_pid)
        };
        if !eff.cqes.is_empty()
            || !eff.start_requests.is_empty()
            || !eff.cancel_requests.is_empty()
        {
            self.apply_effects(eff, true);
        }
    }

    fn execute_started_request(
        self: &Arc<Self>,
        req_id: RequestId,
        spec: PreparedOpSpec,
        ctx: &AsyncExecContext,
        pending_starts: &mut VecDeque<RequestId>,
    ) {
        match spec {
            PreparedOpSpec::Nop => {
                if let Some(eff) = self.claim_completion_for_sync(req_id, 0, false) {
                    pending_starts.extend(eff);
                }
            }
            PreparedOpSpec::Timeout {
                generation,
                deadline,
            } => {
                spawn_timer_future(self, req_id, generation, deadline, false);
            }
            PreparedOpSpec::LinkTimeout {
                generation,
                deadline,
            } => {
                spawn_timer_future(self, req_id, generation, deadline, true);
            }
            PreparedOpSpec::TimeoutRemove {
                target_user_data,
                op_flags,
                new_duration,
            } => {
                if (op_flags & IORING_TIMEOUT_UPDATE) != 0 {
                    let mut spawn_args = None;
                    let (res, old_handle) = {
                        let mut inner = self.inner.lock();
                        let (res, info) = inner.orch.timeout_update(target_user_data, op_flags);
                        let old_h = if let Some((tid, new_gen, clock, abs, phase)) = info {
                            let deadline = new_duration
                                .map(|dur| compute_monotonic_deadline(clock, abs, dur));
                            match phase {
                                RequestPhase::Queued => {
                                    if let (Some((spec, _)), Some(dl)) =
                                        (inner.specs.get_mut(&tid), deadline)
                                    {
                                        match spec {
                                            PreparedOpSpec::Timeout {
                                                generation,
                                                deadline: d,
                                            }
                                            | PreparedOpSpec::LinkTimeout {
                                                generation,
                                                deadline: d,
                                            } => {
                                                *generation = new_gen;
                                                *d = dl;
                                            }
                                            _ => {}
                                        }
                                    }
                                    None
                                }
                                RequestPhase::Running => {
                                    if let Some(dl) = deadline {
                                        let is_lt = (op_flags
                                            & pulse_user_abi::io_uring::IORING_TIMEOUT_LINK)
                                            != 0;
                                        spawn_args = Some((tid, new_gen, dl, is_lt));
                                    }
                                    inner.cancel_handles.remove(&tid)
                                }
                                RequestPhase::Completing | RequestPhase::Completed => None,
                            }
                        } else {
                            None
                        };
                        (res, old_h)
                    };
                    if let Some(h) = old_handle {
                        h.cancel();
                    }
                    if let Some((target_id, new_gen, deadline, is_lt)) = spawn_args {
                        spawn_timer_future(self, target_id, new_gen, deadline, is_lt);
                    }
                    if let Some(eff) = self.claim_completion_for_sync(req_id, res, false) {
                        pending_starts.extend(eff);
                    }
                } else {
                    let (res, eff) = {
                        let mut inner = self.inner.lock();
                        inner.orch.timeout_remove(target_user_data)
                    };
                    pending_starts.extend(self.publish_effects(eff, false));
                    if let Some(more) = self.claim_completion_for_sync(req_id, res, false) {
                        pending_starts.extend(more);
                    }
                }
            }
            PreparedOpSpec::AsyncCancel {
                target_user_data,
                target_fd,
                cancel_flags,
            } => {
                let (res, eff) = {
                    let mut inner = self.inner.lock();
                    inner
                        .orch
                        .async_cancel(Some(req_id), target_user_data, target_fd, cancel_flags)
                };
                pending_starts.extend(self.publish_effects(eff, false));
                if let Some(more) = self.claim_completion_for_sync(req_id, res, false) {
                    pending_starts.extend(more);
                }
            }
            PreparedOpSpec::Rw {
                outcome,
                is_write,
                offset,
                force_async,
            } => match outcome {
                Ok((entry, segments)) => {
                    execute_rw_request(self, ctx, req_id, entry, is_write, segments, offset, force_async);
                }
                Err(err) => {
                    if let Some(eff) = self.claim_completion_for_sync(req_id, -err.code(), false) {
                        pending_starts.extend(eff);
                    }
                }
            },
            PreparedOpSpec::PollAdd {
                target,
                mask,
                events,
            } => {
                spawn_poll_add_future(self, req_id, target, mask, events);
            }
            PreparedOpSpec::Accept {
                entry,
                addr,
                addrlen_ptr,
                accept_flags,
            } => {
                spawn_accept_future(self, ctx, req_id, entry, addr, addrlen_ptr, accept_flags);
            }
        }
    }

    fn claim_completion_for_sync(
        self: &Arc<Self>,
        req_id: RequestId,
        res: i32,
        from_async: bool,
    ) -> Option<Vec<RequestId>> {
        let (old_spec, old_h, eff) = {
            let mut inner = self.inner.lock();
            let old_spec = inner.specs.remove(&req_id);
            let old_h = inner.cancel_handles.remove(&req_id);
            let eff = inner.orch.try_claim_completion(req_id, res, 0);
            (old_spec, old_h, eff)
        };
        drop(old_spec);
        drop(old_h);
        eff.map(|eff| self.publish_effects(eff, from_async))
    }

    pub(crate) fn complete_request(
        self: &Arc<Self>,
        req_id: RequestId,
        res: i32,
        cqe_flags: u32,
        from_async: bool,
    ) {
        let (old_h, old_spec, eff) = {
            let mut inner = self.inner.lock();
            let old_h = inner.cancel_handles.remove(&req_id);
            let old_spec = inner.specs.remove(&req_id);
            let eff = inner.orch.try_claim_completion(req_id, res, cqe_flags);
            (old_h, old_spec, eff)
        };
        drop(old_h);
        drop(old_spec);
        if let Some(eff) = eff {
            self.apply_effects(eff, from_async);
        }
    }

    pub(crate) fn finish_completing_request(
        self: &Arc<Self>,
        req_id: RequestId,
        res: i32,
        cqe_flags: u32,
        from_async: bool,
    ) {
        let (old_h, old_spec, eff) = {
            let mut inner = self.inner.lock();
            let old_h = inner.cancel_handles.remove(&req_id);
            let old_spec = inner.specs.remove(&req_id);
            let eff = inner.orch.finish_completing(req_id, res, cqe_flags);
            (old_h, old_spec, eff)
        };
        drop(old_h);
        drop(old_spec);
        self.apply_effects(eff, from_async);
    }

    pub(crate) fn on_timeout_expired(
        self: &Arc<Self>,
        req_id: RequestId,
        generation: u64,
    ) {
        let (old_h, old_spec, eff) = {
            let mut inner = self.inner.lock();
            let eff = inner.orch.expire_timeout(req_id, generation);
            let (old_h, old_spec) = if !eff.cqes.is_empty() {
                (
                    inner.cancel_handles.remove(&req_id),
                    inner.specs.remove(&req_id),
                )
            } else {
                (None, None)
            };
            (old_h, old_spec, eff)
        };
        drop(old_h);
        drop(old_spec);
        if !eff.cqes.is_empty() {
            self.timeout_expiries.fetch_add(1, Ordering::Release);
        }
        if !eff.cqes.is_empty() || !eff.start_requests.is_empty() || !eff.cancel_requests.is_empty()
        {
            self.apply_effects(eff, true);
        }
    }

    pub(crate) fn on_link_timeout_expired(
        self: &Arc<Self>,
        lt_id: RequestId,
        generation: u64,
    ) {
        let (old_h, old_spec, eff) = {
            let mut inner = self.inner.lock();
            let eff = inner.orch.expire_link_timeout(lt_id, generation);
            let (old_h, old_spec) = if !eff.cqes.is_empty() {
                (
                    inner.cancel_handles.remove(&lt_id),
                    inner.specs.remove(&lt_id),
                )
            } else {
                (None, None)
            };
            (old_h, old_spec, eff)
        };
        drop(old_h);
        drop(old_spec);
        if !eff.cqes.is_empty() || !eff.start_requests.is_empty() || !eff.cancel_requests.is_empty()
        {
            self.apply_effects(eff, true);
        }
    }

    /// Returns `(cq_ready_count, consumed_pending_ebadr)` after flushing overflow.
    ///
    /// Releases `inner` lock before waking waiters (`cq_wait_queue.notify_all`), respecting ADR-0007.
    pub fn check_cq_ready_and_ebadr(&self, consume_ebadr: bool) -> (u32, bool) {
        let (flushed, ready, ebadr) = {
            let mut inner = self.inner.lock();
            let flushed = inner.cq.flush_cq_overflow(&self.shared);
            let ready = inner.cq.ring_ready_count(&self.shared);
            let ebadr = if consume_ebadr {
                inner.cq.take_pending_ebadr_if_empty(&self.shared)
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
    ///
    /// Returns `(submitted, stopped_on_inline_error)`.
    pub fn submit_sqes(self: &Arc<Self>, to_submit: u32, exec_ctx: &AsyncExecContext) -> (u32, bool) {
        if to_submit == 0 || self.is_dying() {
            return (0, false);
        }

        let mut sq = self.submit_lock.lock();
        let submit_all = sq.is_submit_all();
        let mut open_chain: Vec<(PreparedRequest, PreparedOpSpec)> = Vec::new();
        let mut chain_broken_by_prep = false;
        let mut last_was_link_timeout = false;
        let mut stopped_on_error = false;

        let submitted = sq.submit_batch(&self.shared, to_submit, |sqe| {
            let has_link = (sqe.flags & (IOSQE_IO_LINK | IOSQE_IO_HARDLINK)) != 0;

            if chain_broken_by_prep {
                self.complete_cqe(
                    IoUringCqe {
                        user_data: sqe.user_data,
                        res: -LinuxError::ECANCELED.code(),
                        flags: 0,
                    },
                    false,
                );
                if has_link {
                    return Ok(());
                }
                chain_broken_by_prep = false;
                stopped_on_error = !submit_all;
                return Err(());
            }

            let cur_cqe_seq = self.inner.lock().orch.completion_seq();
            match prepare_sqe(
                sqe,
                exec_ctx,
                cur_cqe_seq,
                !open_chain.is_empty(),
                last_was_link_timeout,
            ) {
                Err(err) => {
                    last_was_link_timeout = false;
                    // Cancel any unstarted nodes held in this chain before committing it.
                    let abandoned = core::mem::take(&mut open_chain);
                    if !abandoned.is_empty() {
                        let mut cqes = Vec::with_capacity(abandoned.len() + 1);
                        let mut specs_to_drop = Vec::with_capacity(abandoned.len());
                        for (prep, spec) in abandoned {
                            cqes.push(IoUringCqe {
                                user_data: prep.user_data,
                                res: -LinuxError::ECANCELED.code(),
                                flags: 0,
                            });
                            specs_to_drop.push(spec);
                        }
                        cqes.push(IoUringCqe {
                            user_data: sqe.user_data,
                            res: -err.code(),
                            flags: 0,
                        });
                        self.post_cqes_and_notify(&cqes, false);
                        drop(specs_to_drop);
                    } else {
                        self.complete_cqe(
                            IoUringCqe {
                                user_data: sqe.user_data,
                                res: -err.code(),
                                flags: 0,
                            },
                            false,
                        );
                    }

                    if has_link {
                        chain_broken_by_prep = true;
                        Ok(())
                    } else {
                        stopped_on_error = !submit_all;
                        Err(())
                    }
                }
                Ok((prep, spec)) => {
                    last_was_link_timeout = matches!(prep.kind, RequestKind::LinkTimeout { .. });
                    open_chain.push((prep, spec));
                    if !has_link {
                        last_was_link_timeout = false;
                        self.commit_assembled_chain(&mut open_chain, exec_ctx);
                    }
                    Ok(())
                }
            }
        });

        // If the batch ended with a dangling link bit on the last SQE, close and commit the chain.
        if !open_chain.is_empty() {
            self.commit_assembled_chain(&mut open_chain, exec_ctx);
        }

        (submitted, stopped_on_error)
    }

    fn commit_assembled_chain(
        self: &Arc<Self>,
        open_chain: &mut Vec<(PreparedRequest, PreparedOpSpec)>,
        exec_ctx: &AsyncExecContext,
    ) {
        let items = core::mem::take(open_chain);
        let mut preps: Vec<PreparedRequest> = items.iter().map(|(p, _)| *p).collect();
        let specs: Vec<PreparedOpSpec> = items.into_iter().map(|(_, s)| s).collect();

        let commit_res = {
            let mut inner = self.inner.lock();
            match inner.orch.commit_chain_with_ids(&mut preps) {
                Ok((ids, eff)) => {
                    for (id, spec) in ids.into_iter().zip(specs) {
                        inner.specs.insert(id, (spec, exec_ctx.clone()));
                    }
                    Ok(eff)
                }
                Err(err) => Err((err, specs)),
            }
        };

        match commit_res {
            Ok(eff) => self.apply_effects(eff, false),
            Err((err, specs_to_drop)) => {
                drop(specs_to_drop);
                let mut cqes = Vec::with_capacity(preps.len());
                for (idx, prep) in preps.iter().enumerate() {
                    let res = if idx + 1 == preps.len() {
                        -err.code()
                    } else {
                        -LinuxError::ECANCELED.code()
                    };
                    cqes.push(IoUringCqe {
                        user_data: prep.user_data,
                        res,
                        flags: 0,
                    });
                }
                self.post_cqes_and_notify(&cqes, false);
            }
        }
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
/// Closing the final `IoUringObject` runs the 5-step deterministic teardown protocol:
/// 1. Set `dying = true` and wake `cq_wait_queue`.
/// 2. Cancel all queued/running requests (`RequestOrchestrator` + `CancelHandle` + Path 3 queue)
///    outside `SpinNoIrq`.
/// 3. Wait until `inflight_count == 0` (all futures & workers have exited).
/// 4. Take and drop registered `eventfd` outside `SpinNoIrq`.
/// 5. Drop `Arc<IoUringState>` (releasing shared physical frames).
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
        // Step 1: Mark dying and wake all CQ / poll waiters.
        self.state.dying.store(true, Ordering::Release);
        self.state.cq_wait_queue.notify_all(true);

        // Step 2: Claim and cancel all active/queued requests and drop handles/specs outside SpinNoIrq.
        let (handles, dropped_specs, cqe_count) = {
            let mut inner = self.state.inner.lock();
            let effects = inner.orch.cancel_all_for_teardown();
            for cqe in &effects.cqes {
                let _ = inner.cq.post_cqe(&self.state.shared, *cqe);
            }
            let handles: Vec<CancelHandle> = inner
                .cancel_handles
                .values()
                .cloned()
                .collect();
            inner.cancel_handles.clear();
            let specs: Vec<(PreparedOpSpec, AsyncExecContext)> =
                core::mem::take(&mut inner.specs).into_values().collect();
            (handles, specs, effects.cqes.len())
        };
        if cqe_count > 0 {
            self.state.readable_sequence.fetch_add(1, Ordering::Release);
            self.state.cq_wait_queue.notify_all(true);
        }
        global_worker_pool().cancel_ring_queued(self.state.ring_id);
        for h in handles {
            h.cancel();
        }
        drop(dropped_specs);

        // Step 3: Drain until all spawned futures and active workers have exited.
        self.state
            .teardown_wait_queue
            .wait_until(|| self.state.inflight_count.load(Ordering::Acquire) == 0);

        // Step 4: Take under SpinNoIrq, then drop `Arc<dyn FdObject>` outside SpinNoIrq.
        let ev = { self.state.eventfd.lock().take() };
        drop(ev);
        // Step 5: Shared frames are released when `self.state` (`Arc<IoUringState>`) drops.
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
            // Capture only `Weak<IoUringState>`, never `Arc<IoUringObject>` or `Arc<IoUringState>`,
            // so even self-referential polls can never prevent teardown on last FD close.
            let weak_state = Arc::downgrade(&self.state);
            let registration = self.state.cq_wait_queue.register_owned_waker(cx.waker());
            registrations.push(PollRegistration::new(move || {
                if let Some(state) = weak_state.upgrade() {
                    state.cq_wait_queue.unregister_waker(registration);
                }
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

/// Cancels all in-flight linked/FD requests submitted by `owner_pid` across live rings
/// when `owner_pid` exits or performs `execve` (leaving unlinked standalone timeouts active).
pub fn cancel_requests_for_process(owner_pid: u64) {
    let live_rings: Vec<Arc<IoUringState>> = {
        let mut active = ACTIVE_RINGS.lock();
        let mut live = Vec::new();
        active.retain(|weak| {
            if let Some(arc) = weak.upgrade() {
                live.push(arc);
                true
            } else {
                false
            }
        });
        live
    };
    for ring in live_rings {
        if !ring.is_dying() {
            ring.cancel_requests_for_owner(owner_pid);
        }
    }
}
