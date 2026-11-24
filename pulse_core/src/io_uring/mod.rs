//! Core kernel `io_uring` instance state (`IoUringState`) and file descriptor (`IoUringObject`).
//!
//! # Lock ordering (ADR-0007)
//! `submit_lock` -> `register_lock` (sleepable) -> `Process` / `FdObject` / `axfs` / `axnet` ->
//! `inner` / `fixed_buffers` / `fixed_files` (`SpinNoIrq`) ->
//! `eventfd` (`SpinNoIrq`) -> `WaitQueue`.
//! Never invoke `Future::poll`, pin user pages, drop futures/FDs/processes/fixed-buffer tables,
//! or notify `eventfd`/`WaitQueue` while holding `SpinNoIrq`.

pub mod context;
mod net_ops;
mod ops;
mod sqpoll;
pub mod worker_pool;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::future::Future;
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
use pulse_io_uring_core::resources::{
    FixedBufferRegistry, FixedBufferSlot, FixedBufferTable, FixedFileRegistry, UserIoSegment,
    validate_fixed_buffer_specs,
};
use pulse_io_uring_core::ring::{
    CompletionRingState, PostCqeOutcome, SharedRingMemory, SubmitRingState,
};
use pulse_user_abi::io_uring::{
    IORING_TIMEOUT_UPDATE, IOSQE_IO_HARDLINK, IOSQE_IO_LINK, IoUringCqe,
};

use self::context::AsyncExecContext;
use self::net_ops::{
    execute_accept_request, execute_connect_request, execute_send_recv_request,
    execute_sendmsg_recvmsg_request, execute_shutdown_request, execute_socket_request,
};
use self::ops::{
    PreparedOpSpec, compute_monotonic_deadline, eval_poll_target_with_context,
    execute_fsync_request, execute_rw_request, execute_sync_file_range_request, prepare_sqe,
    spawn_poll_add_future, spawn_timer_future,
};
use self::worker_pool::{alloc_ring_pool_id, global_worker_pool};
use crate::fd_table::{EventFdObject, FdEntry, FdFlags, FdObject, PollEventSequence, PollRegistration, SharedFdTable};
use crate::mm::{FixedBufferIo, FixedBufferPages, pin_fixed_buffer_pages};
use crate::task::Process;

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
    inline_deferred_starts: Vec<(RequestId, Vec<RequestId>)>,
}

struct SubmitSlot {
    sq: SubmitRingState,
    staging_cache: Vec<u8>,
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
    sqpoll: Option<Box<sqpoll::SqPoll>>,
    submit_lock: Mutex<SubmitSlot>,
    register_lock: Mutex<()>,
    inner: SpinNoIrq<RingInner>,
    fixed_buffers: SpinNoIrq<(FixedBufferRegistry<FixedBufferPages>, Option<Weak<Process>>)>,
    fixed_files: SpinNoIrq<FixedFileRegistry<FdEntry>>,
    fixed_files_gen: AtomicU64,
    eventfd: SpinNoIrq<Option<RegisteredEventFd>>,
    eventfd_registered: AtomicBool,
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
    fn new(entries: u32, params: &mut io_uring_params) -> LinuxResult<Arc<Self>> {
        let layout = validate_and_compute_ring_geometry(entries, params)?;
        let owner = (params.flags & linux_raw_sys::io_uring::IORING_SETUP_SQPOLL != 0)
            .then(AsyncExecContext::capture_current)
            .transpose()?;
        let sqpoll = owner
            .as_ref()
            .map(|ctx| sqpoll::SqPoll::new(ctx.process.pid(), params))
            .transpose()?
            .map(Box::new);
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
            sqpoll,
            ring_id,
            shared,
            rings_frame,
            sqes_frame,
            submit_lock: Mutex::new(SubmitSlot {
                sq: SubmitRingState::new(layout.sq_entries, submit_all),
                staging_cache: Vec::new(),
            }),
            register_lock: Mutex::new(()),
            inner: SpinNoIrq::new(RingInner {
                cq: CompletionRingState::new(layout.cq_entries),
                orch: RequestOrchestrator::new(),
                specs: BTreeMap::new(),
                cancel_handles: BTreeMap::new(),
                inline_deferred_starts: Vec::new(),
            }),
            fixed_buffers: SpinNoIrq::new((FixedBufferRegistry::new(), None)),
            fixed_files: SpinNoIrq::new(FixedFileRegistry::new()),
            fixed_files_gen: AtomicU64::new(0),
            eventfd: SpinNoIrq::new(None),
            eventfd_registered: AtomicBool::new(false),
            dying: AtomicBool::new(false),
            inflight_count: AtomicUsize::new(0),
            cq_wait_queue: WaitQueue::new(),
            teardown_wait_queue: WaitQueue::new(),
            readable_sequence: AtomicU64::new(0),
            timeout_expiries: AtomicU64::new(0),
        });
        if let Some(owner) = owner {
            state.start_sqpoll(params, owner)?;
            #[cfg(feature = "guest-checks")]
            state.report_user_dispatches("setup");
        }
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

    /// All native requests, including link/drain successors, inherit the ring's poll placement.
    fn spawn_native(&self, req_id: RequestId, future: impl Future<Output = ()> + Send + 'static) {
        #[cfg(feature = "guest-checks")]
        let future = {
            let ring = self.ring_id;
            axlog::info!(
                "io_uring native submit ring={ring} req={req_id} cpu={} task={}",
                axhal::percpu::this_cpu_id(),
                axtask::current().name()
            );
            async move {
                let mut future = core::pin::pin!(future);
                let mut seq = 0u64;
                core::future::poll_fn(move |cx| {
                    seq += 1;
                    let phase = if seq == 1 { "first" } else { "resume" };
                    let cpu = axhal::percpu::this_cpu_id();
                    let poll = future.as_mut().poll(cx);
                    let result = if poll.is_pending() { "pending" } else { "ready" };
                    axlog::info!(
                        "io_uring poll ring={ring} req={req_id} phase={phase} cpu={cpu} result={result} task={} seq={seq}",
                        axtask::current().name()
                    );
                    poll
                })
                .await
            }
        };
        let handle = match self.service_executor() {
            Some(executor) => executor.spawn(future),
            None => axtask::future::spawn_and_poll_once(future),
        };
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

        if self.dying.load(Ordering::Acquire) || !self.eventfd_registered.load(Ordering::Acquire) {
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

    fn flush_inline_fast_path_cqes(&self, cqes: &mut [IoUringCqe; 64], batch_len: &mut usize) {
        let count = *batch_len;
        if count == 0 {
            return;
        }
        *batch_len = 0;
        {
            let mut inner = self.inner.lock();
            inner.orch.record_inline_completions(count as u64);
            for cqe in &cqes[..count] {
                let _ = inner.cq.post_cqe(&self.shared, *cqe);
            }
        }
        self.notify_cqe_consumers(count, false);
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
        let initial = self.publish_effects(effects, from_async);
        self.drive_pending_starts(initial, from_async);
    }

    fn dispatch_completion_effects(
        self: &Arc<Self>,
        completed_id: RequestId,
        effects: OrchestratorEffects,
        from_async: bool,
    ) {
        let next_starts = self.publish_effects(effects, from_async);
        if next_starts.is_empty() {
            return;
        }
        {
            let mut inner = self.inner.lock();
            if let Some((_, deferred)) = inner
                .inline_deferred_starts
                .iter_mut()
                .rfind(|(id, _)| *id == completed_id)
            {
                deferred.extend(next_starts);
                return;
            }
        }
        self.drive_pending_starts(next_starts, from_async);
    }

    fn drive_pending_starts(
        self: &Arc<Self>,
        initial: Vec<RequestId>,
        from_async: bool,
    ) {
        let mut pending_starts: VecDeque<RequestId> = initial.into();

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
                let entry = inner.specs.remove(&id);
                if entry.is_some() {
                    inner.inline_deferred_starts.push((id, Vec::new()));
                }
                entry
            };
            if let Some((spec, req_ctx)) = entry {
                self.execute_started_request(id, spec, &req_ctx, &mut pending_starts);
                let deferred = {
                    let mut inner = self.inner.lock();
                    inner
                        .inline_deferred_starts
                        .iter()
                        .rposition(|(active_id, _)| *active_id == id)
                        .map(|pos| inner.inline_deferred_starts.swap_remove(pos).1)
                        .unwrap_or_default()
                };
                pending_starts.extend(deferred);
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
                rw_flags,
                force_async,
            } => match outcome {
                Ok(data) => {
                    execute_rw_request(self, ctx, req_id, data, is_write, rw_flags, force_async);
                }
                Err(err) => {
                    if let Some(eff) = self.claim_completion_for_sync(req_id, -err.code(), false) {
                        pending_starts.extend(eff);
                    }
                }
            },
            PreparedOpSpec::Fsync {
                outcome,
                offset,
                len,
                data_only,
                force_async,
            } => match outcome {
                Ok(entry) => {
                    execute_fsync_request(self, req_id, entry, offset, len, data_only, force_async);
                }
                Err(err) => {
                    if let Some(eff) = self.claim_completion_for_sync(req_id, -err.code(), false) {
                        pending_starts.extend(eff);
                    }
                }
            },
            PreparedOpSpec::SyncFileRange {
                outcome,
                offset,
                len,
                sync_flags,
                force_async,
            } => match outcome {
                Ok(entry) => {
                    execute_sync_file_range_request(
                        self,
                        req_id,
                        entry,
                        offset,
                        len,
                        sync_flags,
                        force_async,
                    );
                }
                Err(err) => {
                    if let Some(eff) = self.claim_completion_for_sync(req_id, -err.code(), false) {
                        pending_starts.extend(eff);
                    }
                }
            },
            PreparedOpSpec::FilesUpdate {
                outcome,
                force_async,
            } => {
                if force_async {
                    if let Some(guard) = self.try_enter_inflight_owned() {
                        let state_wk = Arc::clone(self);
                        let ctx_wk = ctx.clone();
                        global_worker_pool().submit(self, req_id, move || {
                            let _guard = guard;
                            if !state_wk.is_request_active(req_id) {
                                return;
                            }
                            let res = state_wk.execute_files_update(&ctx_wk, outcome);
                            state_wk.complete_request(req_id, res, 0, true);
                        });
                    }
                } else {
                    let res = self.execute_files_update(ctx, outcome);
                    if let Some(eff) = self.claim_completion_for_sync(req_id, res, false) {
                        pending_starts.extend(eff);
                    }
                }
            }
            PreparedOpSpec::PollAdd {
                target,
                mask,
                events,
                force_async,
            } => {
                if !force_async {
                    if let Some(revents) = eval_poll_target_with_context(&target, ctx, mask) {
                        if let Some(eff) = self.claim_completion_for_sync(req_id, revents as i32, false) {
                            pending_starts.extend(eff);
                        }
                        return;
                    }
                }
                spawn_poll_add_future(self, ctx, req_id, target, mask, events);
            }
            PreparedOpSpec::PollRemove { target_user_data } => {
                let (res, eff) = {
                    let mut inner = self.inner.lock();
                    inner.orch.poll_remove(target_user_data)
                };
                pending_starts.extend(self.publish_effects(eff, false));
                if let Some(more) = self.claim_completion_for_sync(req_id, res, false) {
                    pending_starts.extend(more);
                }
            }
            PreparedOpSpec::Socket {
                domain,
                raw_ty,
                proto,
                force_async,
            } => {
                execute_socket_request(self, ctx, req_id, domain, raw_ty, proto, force_async);
            }
            PreparedOpSpec::Accept {
                outcome,
                force_async,
            } => match outcome {
                Ok(data) => execute_accept_request(self, ctx, req_id, data, force_async),
                Err(err) => {
                    if let Some(eff) = self.claim_completion_for_sync(req_id, -err.code(), false) {
                        pending_starts.extend(eff);
                    }
                }
            },
            PreparedOpSpec::Connect {
                outcome,
                force_async,
            } => match outcome {
                Ok(data) => execute_connect_request(self, ctx, req_id, data, force_async),
                Err(err) => {
                    if let Some(eff) = self.claim_completion_for_sync(req_id, -err.code(), false) {
                        pending_starts.extend(eff);
                    }
                }
            },
            PreparedOpSpec::SendRecv {
                outcome,
                is_send,
                force_async,
            } => match outcome {
                Ok(data) => execute_send_recv_request(self, ctx, req_id, data, is_send, force_async),
                Err(err) => {
                    if let Some(eff) = self.claim_completion_for_sync(req_id, -err.code(), false) {
                        pending_starts.extend(eff);
                    }
                }
            },
            PreparedOpSpec::SendRecvMsg {
                outcome,
                is_send,
                force_async,
            } => match outcome {
                Ok(data) => {
                    execute_sendmsg_recvmsg_request(self, ctx, req_id, data, is_send, force_async)
                }
                Err(err) => {
                    if let Some(eff) = self.claim_completion_for_sync(req_id, -err.code(), false) {
                        pending_starts.extend(eff);
                    }
                }
            },
            PreparedOpSpec::Shutdown {
                outcome,
                force_async,
            } => match outcome {
                Ok((entry, how)) => execute_shutdown_request(self, req_id, entry, how, force_async),
                Err(err) => {
                    if let Some(eff) = self.claim_completion_for_sync(req_id, -err.code(), false) {
                        pending_starts.extend(eff);
                    }
                }
            },
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
            self.dispatch_completion_effects(req_id, eff, from_async);
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
        self.dispatch_completion_effects(req_id, eff, from_async);
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
            self.dispatch_completion_effects(req_id, eff, true);
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
            self.dispatch_completion_effects(lt_id, eff, true);
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
    /// Returns `(submitted, stopped_on_inline_error, all_inline_fast_path)`.
    pub fn submit_sqes(
        self: &Arc<Self>,
        to_submit: u32,
        exec_ctx: &AsyncExecContext,
    ) -> (u32, bool, bool) {
        if to_submit == 0 || self.is_dying() {
            return (0, false, false);
        }

        const ZERO_CQE: IoUringCqe = IoUringCqe {
            user_data: 0,
            res: 0,
            flags: 0,
        };
        let mut submit_slot = self.submit_lock.lock();
        let SubmitSlot { sq, staging_cache } = &mut *submit_slot;
        let submit_all = sq.is_submit_all();
        let mut open_chain: Vec<(PreparedRequest, PreparedOpSpec)> = Vec::new();
        let mut batch_cqes = [ZERO_CQE; 64];
        let mut batch_len: usize = 0;
        let mut cached_fixed_fd: Option<(u32, u64, FdEntry)> = None;
        let mut can_fast_path = self.inner.lock().orch.can_bypass_inline_fast_path();
        let mut used_slow_path = false;
        let mut chain_broken_by_prep = false;
        let mut last_was_link_timeout = false;
        let mut stopped_on_error = false;

        let submitted = sq.submit_batch(&self.shared, to_submit, |sqe| {
            #[cfg(feature = "guest-checks")]
            if self.sqpoll_service_cpu().is_some() {
                axlog::info!(
                    "SQPOLL consume ring={} user_data={} cpu={}",
                    self.ring_id,
                    sqe.user_data,
                    axhal::percpu::this_cpu_id()
                );
            }
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

            if open_chain.is_empty()
                && !has_link
                && can_fast_path
                && let Some(res) = ops::try_inline_fast_path_read(
                    self,
                    sqe,
                    exec_ctx,
                    staging_cache,
                    &mut cached_fixed_fd,
                )
            {
                #[cfg(feature = "guest-checks")]
                if self.sqpoll_service_cpu().is_some() {
                    axlog::info!(
                        "SQPOLL inline ring={} user_data={} cpu={} res={res}",
                        self.ring_id,
                        sqe.user_data,
                        axhal::percpu::this_cpu_id()
                    );
                }
                batch_cqes[batch_len] = IoUringCqe {
                    user_data: sqe.user_data,
                    res,
                    flags: 0,
                };
                batch_len += 1;
                if batch_len == batch_cqes.len() {
                    self.flush_inline_fast_path_cqes(&mut batch_cqes, &mut batch_len);
                }
                return Ok(());
            }
            used_slow_path = true;
            cached_fixed_fd = None;
            self.flush_inline_fast_path_cqes(&mut batch_cqes, &mut batch_len);

            let cur_cqe_seq = self.inner.lock().orch.completion_seq();
            match prepare_sqe(
                self,
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
                        can_fast_path = self.inner.lock().orch.can_bypass_inline_fast_path();
                    }
                    Ok(())
                }
            }
        });

        if let Some(poll) = &self.sqpoll {
            poll.publish_consumed_head(sq.kernel_sq_head());
        }

        // If the batch ended with a dangling link bit on the last SQE, close and commit the chain.
        if !open_chain.is_empty() {
            used_slow_path = true;
            cached_fixed_fd = None;
            self.flush_inline_fast_path_cqes(&mut batch_cqes, &mut batch_len);
            self.commit_assembled_chain(&mut open_chain, exec_ctx);
        }
        drop(cached_fixed_fd);
        self.flush_inline_fast_path_cqes(&mut batch_cqes, &mut batch_len);

        (submitted, stopped_on_error, submitted > 0 && !used_slow_path)
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
                    for (&id, spec) in ids.iter().zip(specs) {
                        inner.specs.insert(id, (spec, exec_ctx.clone()));
                    }
                    drop(inner);
                    #[cfg(feature = "guest-checks")]
                    if self.sqpoll_service_cpu().is_some() {
                        for (id, prep) in ids.iter().zip(&preps) {
                            axlog::info!(
                                "SQPOLL committed ring={} req={id} user_data={}",
                                self.ring_id,
                                prep.user_data
                            );
                        }
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
        self.eventfd_registered.store(true, Ordering::Release);
        Ok(())
    }

    pub fn unregister_eventfd(&self) -> LinuxResult<()> {
        let mut guard = self.eventfd.lock();
        if guard.take().is_none() {
            return Err(LinuxError::EINVAL);
        }
        self.eventfd_registered.store(false, Ordering::Release);
        Ok(())
    }

    pub fn check_can_register_buffers(&self, nr_args: usize) -> LinuxResult<()> {
        self.fixed_buffers.lock().0.check_can_register(nr_args)
    }

    pub fn register_buffers(
        &self,
        process: &Arc<Process>,
        specs: &[UserIoSegment],
    ) -> LinuxResult<()> {
        let _reg_guard = self.register_lock.lock();
        self.fixed_buffers.lock().0.check_can_register(specs.len())?;

        let plan =
            validate_fixed_buffer_specs(specs, |addr, len| process.is_user_range(addr, len))?;
        process
            .memlock_try_charge_pinned(plan.charged_bytes, process.is_root_user())
            .map_err(|_| LinuxError::ENOMEM)?;

        let mut slots = Vec::with_capacity(specs.len());
        for spec in specs {
            if spec.len == 0 {
                slots.push(Arc::new(FixedBufferSlot::empty(spec.addr)));
                continue;
            }
            match pin_fixed_buffer_pages(process, spec.addr, spec.len) {
                Ok((Some(pages), writable)) => {
                    slots.push(Arc::new(FixedBufferSlot::with_pages(
                        spec.addr,
                        spec.len,
                        writable,
                        pages,
                    )));
                }
                Ok((None, _)) => slots.push(Arc::new(FixedBufferSlot::empty(spec.addr))),
                Err(err) => {
                    drop(slots);
                    process.memlock_uncharge_pinned(plan.charged_bytes);
                    return Err(err);
                }
            }
        }

        let table = FixedBufferTable::new(slots, plan.charged_bytes);
        let install_res = {
            let mut guard = self.fixed_buffers.lock();
            match guard.0.install(table) {
                Ok(()) => {
                    guard.1 = Some(Arc::downgrade(process));
                    Ok(())
                }
                Err((err, rejected_table)) => Err((err, rejected_table)),
            }
        };
        if let Err((err, rejected_table)) = install_res {
            process.memlock_uncharge_pinned(rejected_table.charged_bytes());
            drop(rejected_table);
            return Err(err);
        }
        Ok(())
    }

    pub fn unregister_buffers(&self, arg: usize, nr_args: u32) -> LinuxResult<()> {
        let _reg_guard = self.register_lock.lock();
        let (old_table, owner_weak) = {
            let mut guard = self.fixed_buffers.lock();
            let old_table = guard.0.unregister(arg, nr_args)?;
            let owner_weak = guard.1.take();
            (old_table, owner_weak)
        };
        if let Some(proc) = owner_weak.and_then(|w| w.upgrade()) {
            proc.memlock_uncharge_pinned(old_table.charged_bytes());
        }
        drop(old_table);
        Ok(())
    }

    pub fn resolve_fixed_buffer(
        &self,
        buf_index: u16,
        addr: u64,
        len: u32,
        require_write: bool,
    ) -> LinuxResult<FixedBufferIo> {
        let slice = self
            .fixed_buffers
            .lock()
            .0
            .resolve_slice(buf_index, addr, len, require_write)?;
        Ok(FixedBufferIo::new(slice))
    }

    pub fn check_can_register_files(&self, nr_args: usize) -> LinuxResult<()> {
        self.fixed_files.lock().check_can_register(nr_args)
    }

    pub fn register_files(&self, files: &SharedFdTable, raw_fds: &[i32]) -> LinuxResult<()> {
        let _reg_guard = self.register_lock.lock();
        self.fixed_files.lock().check_can_register(raw_fds.len())?;

        let mut slots = Vec::with_capacity(raw_fds.len());
        for &fd in raw_fds {
            match FixedFileRegistry::resolve_slot_fd(fd, &mut |u| {
                resolve_fd_for_fixed(files, u)
            }) {
                Ok(slot) => slots.push(slot),
                Err(err) => {
                    drop(slots);
                    return Err(err);
                }
            }
        }

        let install_res = {
            let mut files = self.fixed_files.lock();
            self.fixed_files_gen.fetch_add(1, Ordering::AcqRel);
            files.install(slots)
        };
        if let Err((err, rejected)) = install_res {
            drop(rejected);
            return Err(err);
        }
        Ok(())
    }

    pub fn unregister_files(&self, arg: usize, nr_args: u32) -> LinuxResult<()> {
        let _reg_guard = self.register_lock.lock();
        let old_slots = {
            let mut files = self.fixed_files.lock();
            let old = files.unregister(arg, nr_args)?;
            self.fixed_files_gen.fetch_add(1, Ordering::AcqRel);
            old
        };
        drop(old_slots);
        Ok(())
    }

    pub fn validate_files_update(
        &self,
        offset: u32,
        nr_args: u32,
        resv: u32,
    ) -> LinuxResult<usize> {
        self.fixed_files.lock().validate_update(offset, nr_args, resv)
    }

    pub fn update_fixed_files(
        &self,
        files: &SharedFdTable,
        offset: u32,
        raw_fds: &[i32],
        resv: u32,
    ) -> LinuxResult<usize> {
        let _reg_guard = self.register_lock.lock();
        let start = self
            .fixed_files
            .lock()
            .validate_update(offset, raw_fds.len() as u32, resv)?;

        let mut resolved = Vec::with_capacity(raw_fds.len());
        let mut first_err = None;
        for &fd in raw_fds {
            match FixedFileRegistry::resolve_slot_fd(fd, &mut |u| {
                resolve_fd_for_fixed(files, u)
            }) {
                Ok(slot) => resolved.push(slot),
                Err(err) => {
                    first_err = Some(err);
                    break;
                }
            }
        }

        let (res, replaced) = {
            let mut files = self.fixed_files.lock();
            self.fixed_files_gen.fetch_add(1, Ordering::AcqRel);
            files.apply_resolved_update(start, resolved, first_err)
        };
        drop(replaced);
        res
    }

    #[inline]
    pub(crate) fn fixed_files_generation(&self) -> u64 {
        self.fixed_files_gen.load(Ordering::Acquire)
    }

    pub(crate) fn get_fixed_fd_entry_with_gen(&self, index: u32) -> LinuxResult<(FdEntry, u64)> {
        let files = self.fixed_files.lock();
        let files_gen = self.fixed_files_gen.load(Ordering::Acquire);
        files.get_cloned(index).map(|entry| (entry, files_gen))
    }

    pub fn get_fixed_fd_entry(&self, index: u32) -> LinuxResult<FdEntry> {
        self.fixed_files.lock().get_cloned(index)
    }

    fn execute_files_update(
        &self,
        ctx: &AsyncExecContext,
        outcome: LinuxResult<(u32, Vec<i32>)>,
    ) -> i32 {
        match outcome.and_then(|(offset, fds)| self.update_fixed_files(&ctx.files()?, offset, &fds, 0)) {
            Ok(done) => done as i32,
            Err(err) => -err.code(),
        }
    }
}

fn resolve_fd_for_fixed(files: &SharedFdTable, fd: usize) -> LinuxResult<FdEntry> {
    let entry = files.read().get_entry_cloned(fd)?;
    if entry.object.as_any().is::<IoUringObject>() {
        return Err(LinuxError::EBADF);
    }
    let mut flags = entry.flags;
    flags.remove(FdFlags::CLOEXEC);
    Ok(FdEntry::new(entry.object, flags))
}

/// File descriptor wrapper around `Arc<IoUringState>`.
///
/// Closing the final `IoUringObject` runs the 5-step deterministic teardown protocol:
/// 1. Set `dying = true`, wake waiters and join the SQ poller before cancelling requests.
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

        // A request can release the final transient ring FD from inside its poller's
        // submission. Finish on another stack before joining or taking submit_lock.
        if self.state.is_sqpoll() && crate::task::current_thread().is_err() {
            let state = self.state.clone();
            axtask::spawn(move || state.finish_teardown());
        } else {
            self.state.finish_teardown();
        }
    }
}

impl IoUringState {
    fn finish_teardown(&self) {
        self.stop_sqpoll();
        // Step 2: Claim and cancel all active/queued requests and drop handles/specs outside SpinNoIrq.
        let (handles, dropped_specs, cqe_count) = {
            let mut inner = self.inner.lock();
            let effects = inner.orch.cancel_all_for_teardown();
            for cqe in &effects.cqes {
                let _ = inner.cq.post_cqe(&self.shared, *cqe);
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
            self.readable_sequence.fetch_add(1, Ordering::Release);
            self.cq_wait_queue.notify_all(true);
        }
        global_worker_pool().cancel_ring_queued(self.ring_id);
        for h in handles {
            h.cancel();
        }
        drop(dropped_specs);

        // Step 3: Drain until all spawned futures and active workers have exited.
        self.teardown_wait_queue
            .wait_until(|| self.inflight_count.load(Ordering::Acquire) == 0);

        // Step 4: Take under SpinNoIrq, then uncharge & drop resources outside SpinNoIrq.
        self.eventfd_registered.store(false, Ordering::Release);
        self.fixed_files_gen.fetch_add(1, Ordering::Release);
        let ev = { self.eventfd.lock().take() };
        let old_files = { self.fixed_files.lock().take_for_drop() };
        let (old_buffers, old_buf_owner) = {
            let mut guard = self.fixed_buffers.lock();
            (guard.0.take_for_drop(), guard.1.take())
        };
        if let Some(table) = old_buffers {
            if let Some(proc) = old_buf_owner.and_then(|w| w.upgrade()) {
                proc.memlock_uncharge_pinned(table.charged_bytes());
            }
            drop(table);
        }
        drop(old_files);
        drop(ev);
        {
            let mut slot = self.submit_lock.lock();
            slot.staging_cache = Vec::new();
        }
        // Step 5: Shared frames are released when `self` (`Arc<IoUringState>`) drops.
        #[cfg(feature = "guest-checks")]
        self.report_user_dispatches("teardown");
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
        ring.stop_sqpoll_for_owner(owner_pid);
        if !ring.is_dying() {
            ring.cancel_requests_for_owner(owner_pid);
        }
    }
}

/// Boot-time in-kernel invariant checks for `PinnedUserBuffers`, `FixedBufferRegistry`,
/// physical frame refcount balance, `memlock` pinned-bytes accounting, and `FixedFileRegistry`.
#[cfg(feature = "guest-checks")]
pub fn run_io_uring_resource_guest_checks() -> LinuxResult<()> {
    use memory_addr::VirtAddr;

    worker_pool::check_overlapping_worker_finishes();
    axlog::ax_println!("[IO_URING_RSRC_GUEST] Starting fixed resources & frame refcount checks...");

    let process = crate::task::current_process()?;
    let aspace_handle = process.aspace_handle();
    let test_va = 0x2200_0000usize;
    let total_pages = 3usize;
    let map_size = total_pages * PAGE_SIZE_4K;

    {
        let mut aspace = aspace_handle.write();
        aspace
            .map_alloc(
                VirtAddr::from(test_va),
                map_size,
                MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
                true,
            )
            .map_err(LinuxError::from)?;
    }

    let mut page_frames = Vec::with_capacity(total_pages);
    let mut baseline_refs = Vec::with_capacity(total_pages);
    {
        let aspace = aspace_handle.read();
        for idx in 0..total_pages {
            let vaddr = VirtAddr::from(test_va + idx * PAGE_SIZE_4K);
            let paddr = aspace
                .pin_user_frame(vaddr, MappingFlags::READ | MappingFlags::WRITE)
                .map_err(LinuxError::from)?;
            // `pin_user_frame` bumped ref by 1; measure baseline just before releasing this probe pin.
            let after_probe = axalloc::frame_table()
                .try_get_ref(paddr)
                .expect("test page in frame_table");
            crate::mm::release_pinned_user_frame(paddr);
            page_frames.push(paddr);
            baseline_refs.push(after_probe - 1);
        }
    }

    // 1. Single-window PinnedUserBuffers balance check across write + read.
    let segs = [UserIoSegment::new(test_va, map_size)];
    let mut cursor = crate::mm::UserBufferCursor::default();
    let mut write_win =
        crate::mm::PinnedUserBuffers::pin_with_process(&process, &segs, &mut cursor, true)?;
    assert_eq!(write_win.len(), map_size);
    for (paddr, &base) in page_frames.iter().zip(&baseline_refs) {
        let cur = axalloc::frame_table().try_get_ref(*paddr).unwrap();
        assert_eq!(cur, base + 1, "write window should pin page once");
    }
    let pattern = alloc::vec![0x5Au8; map_size];
    write_win.copy_to_user_exact(&pattern)?;
    drop(write_win);
    for (paddr, &base) in page_frames.iter().zip(&baseline_refs) {
        assert_eq!(axalloc::frame_table().try_get_ref(*paddr).unwrap(), base);
    }

    let mut read_cursor = crate::mm::UserBufferCursor::default();
    let mut read_win =
        crate::mm::PinnedUserBuffers::pin_with_process(&process, &segs, &mut read_cursor, false)?;
    let mut read_back = alloc::vec![0u8; map_size];
    read_win.copy_from_user_exact(&mut read_back)?;
    assert!(read_back.iter().all(|&b| b == 0x5A));
    drop(read_win);
    for (paddr, &base) in page_frames.iter().zip(&baseline_refs) {
        assert_eq!(axalloc::frame_table().try_get_ref(*paddr).unwrap(), base);
    }
    axlog::ax_println!("[IO_URING_RSRC_GUEST] PinnedUserBuffers balance & direct copy: PASS");

    // 2. FixedBufferRegistry registration + inflight keep-alive across unregister_buffers + memlock.
    let mut params: io_uring_params = unsafe { core::mem::zeroed() };
    let ring = Arc::new(IoUringObject::new(8, &mut params)?);
    let state = ring.state();

    let baseline_pinned = process.memlock_pinned_bytes();
    state.register_buffers(
        &process,
        &[
            UserIoSegment::new(0, 0),
            UserIoSegment::new(test_va, map_size),
        ],
    )?;
    assert_eq!(
        process.memlock_pinned_bytes(),
        baseline_pinned + map_size,
        "memlock pinned_bytes charged"
    );
    for (paddr, &base) in page_frames.iter().zip(&baseline_refs) {
        assert_eq!(axalloc::frame_table().try_get_ref(*paddr).unwrap(), base + 1);
    }

    let mut fixed_io = state.resolve_fixed_buffer(1, test_va as u64, map_size as u32, true)?;
    let pattern2 = alloc::vec![0xA5u8; map_size];
    fixed_io.copy_to_user_exact(&pattern2)?;
    let mut fixed_read = state.resolve_fixed_buffer(1, test_va as u64, map_size as u32, false)?;
    let mut read_back2 = alloc::vec![0u8; map_size];
    fixed_read.copy_from_user_exact(&mut read_back2)?;
    assert!(read_back2.iter().all(|&b| b == 0xA5));
    drop(fixed_read);

    state.unregister_buffers(0, 0)?;
    assert_eq!(
        process.memlock_pinned_bytes(),
        baseline_pinned,
        "memlock uncharged on unregister"
    );
    // Inflight `fixed_io` still keeps frames pinned after unregister.
    for (paddr, &base) in page_frames.iter().zip(&baseline_refs) {
        assert_eq!(axalloc::frame_table().try_get_ref(*paddr).unwrap(), base + 1);
    }
    drop(fixed_io);
    for (paddr, &base) in page_frames.iter().zip(&baseline_refs) {
        assert_eq!(
            axalloc::frame_table().try_get_ref(*paddr).unwrap(),
            base,
            "frames balanced after last inflight fixed buffer drop"
        );
    }
    axlog::ax_println!("[IO_URING_RSRC_GUEST] FixedBufferRegistry pin/inflight/memlock accounting: PASS");

    // 3. FixedFileRegistry sparse slots, partial update `done`, and ring self-reference rejection.
    let (r_end, w_end) = crate::fd_table::PipeObject::new_pair();
    let r_fd = process.insert_fd_entry(FdEntry::new(Arc::new(r_end), FdFlags::empty()))?;
    let w_fd = process.insert_fd_entry(FdEntry::new(Arc::new(w_end), FdFlags::empty()))?;
    let ring_fd = process.insert_fd_entry(FdEntry::new(Arc::clone(&ring) as Arc<dyn FdObject>, FdFlags::empty()))?;
    assert_eq!(
        state.register_files(&process.fd_table(), &[ring_fd as i32]).err(),
        Some(LinuxError::EBADF)
    );
    state.register_files(&process.fd_table(), &[r_fd as i32, -1, -1])?;
    assert!(state.get_fixed_fd_entry(0).is_ok());
    assert_eq!(state.get_fixed_fd_entry(1).err(), Some(LinuxError::EBADF));
    let done = state.update_fixed_files(&process.fd_table(), 1, &[w_fd as i32, -2], 0)?;
    assert_eq!(done, 1);
    assert!(state.get_fixed_fd_entry(1).is_ok());
    state.unregister_files(0, 0)?;
    axlog::ax_println!("[IO_URING_RSRC_GUEST] FixedFileRegistry sparse slots & partial update: PASS");

    let _ = process.remove_fd_entry(ring_fd);
    let _ = process.remove_fd_entry(w_fd);
    let _ = process.remove_fd_entry(r_fd);
    drop(ring);
    let _ = aspace_handle.unmap(VirtAddr::from(test_va), map_size);

    // 4. Inflight munmap + close(ring_fd) five-step teardown physical frame refcount balance.
    let test_va_teardown = 0x2201_0000usize;
    {
        let mut aspace = aspace_handle.write();
        aspace
            .map_alloc(
                VirtAddr::from(test_va_teardown),
                map_size,
                MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
                true,
            )
            .map_err(LinuxError::from)?;
    }

    let mut td_frames = Vec::with_capacity(total_pages);
    let mut td_baseline = Vec::with_capacity(total_pages);
    {
        let aspace = aspace_handle.read();
        for idx in 0..total_pages {
            let vaddr = VirtAddr::from(test_va_teardown + idx * PAGE_SIZE_4K);
            let paddr = aspace
                .pin_user_frame(vaddr, MappingFlags::READ | MappingFlags::WRITE)
                .map_err(LinuxError::from)?;
            let after_probe = axalloc::frame_table()
                .try_get_ref(paddr)
                .expect("teardown test page in frame_table");
            crate::mm::release_pinned_user_frame(paddr);
            assert_eq!(after_probe - 1, 1, "PTE should initially own the mapped page");
            td_frames.push(paddr);
            td_baseline.push(after_probe - 1);
        }
    }

    let mut td_params: io_uring_params = unsafe { core::mem::zeroed() };
    let td_ring = Arc::new(IoUringObject::new(8, &mut td_params)?);
    td_ring
        .state()
        .register_buffers(&process, &[UserIoSegment::new(test_va_teardown, map_size)])?;
    assert_eq!(
        process.memlock_pinned_bytes(),
        baseline_pinned + map_size,
        "memlock charged before teardown"
    );

    let mut td_fixed_io =
        td_ring
            .state()
            .resolve_fixed_buffer(0, test_va_teardown as u64, map_size as u32, true)?;
    let td_segs = [UserIoSegment::new(test_va_teardown, map_size)];
    let mut td_cursor = crate::mm::UserBufferCursor::default();
    let mut td_pinned =
        crate::mm::PinnedUserBuffers::pin_with_process(&process, &td_segs, &mut td_cursor, true)?;

    for (paddr, &base) in td_frames.iter().zip(&td_baseline) {
        assert_eq!(
            axalloc::frame_table().try_get_ref(*paddr).unwrap(),
            base + 2,
            "PTE + FixedBufferSlot + PinnedUserBuffers should hold 3 refs"
        );
    }

    // Unmap user VMA while both PinnedUserBuffers and FixedBufferIo remain inflight.
    aspace_handle
        .unmap(VirtAddr::from(test_va_teardown), map_size)
        .map_err(LinuxError::from)?;
    for (paddr, &base) in td_frames.iter().zip(&td_baseline) {
        assert_eq!(
            axalloc::frame_table().try_get_ref(*paddr).unwrap(),
            base + 1,
            "unmap drops only PTE ref while inflight buffers remain pinned"
        );
    }
    td_pinned.copy_to_user_exact(&alloc::vec![0x3Cu8; map_size])?;
    let mut td_read_prefix = alloc::vec![0u8; PAGE_SIZE_4K];
    td_fixed_io.copy_from_user_exact(&mut td_read_prefix)?;
    assert!(td_read_prefix.iter().all(|&b| b == 0x3C));

    // Close the final IoUringObject FD reference (5-step teardown) while inflight buffers remain.
    let td_ring_fd =
        process.insert_fd_entry(FdEntry::new(td_ring as Arc<dyn FdObject>, FdFlags::empty()))?;
    let _ = process.remove_fd_entry(td_ring_fd)?;
    assert_eq!(
        process.memlock_pinned_bytes(),
        baseline_pinned,
        "memlock uncharged immediately on ring FD close"
    );
    for (paddr, &base) in td_frames.iter().zip(&td_baseline) {
        assert_eq!(
            axalloc::frame_table().try_get_ref(*paddr).unwrap(),
            base + 1,
            "inflight FixedBufferIo + PinnedUserBuffers survive ring close"
        );
    }

    drop(td_pinned);
    for &paddr in &td_frames {
        assert_eq!(
            axalloc::frame_table().try_get_ref(paddr).unwrap(),
            1,
            "only inflight FixedBufferIo retains the final frame ref"
        );
    }
    td_fixed_io.copy_to_user_exact(&alloc::vec![0x7Eu8; PAGE_SIZE_4K])?;

    drop(td_fixed_io);
    for &paddr in &td_frames {
        assert_eq!(
            axalloc::frame_table().try_get_ref(paddr).unwrap(),
            0,
            "frames 100% balanced to zero after final inflight buffer drops"
        );
    }
    axlog::ax_println!(
        "[IO_URING_RSRC_GUEST] Inflight munmap + close five-step teardown frame balance: PASS"
    );

    axlog::ax_println!("[IO_URING_RSRC_GUEST] Fixed resources & frame refcount checks: PASS");
    check_remote_first_poll()?;
    Ok(())
}

/// Exercise a remote first dispatch even when the ring's own Path 3 predecessors
/// already complete on the same CPU as its native executor.
#[cfg(feature = "guest-checks")]
fn check_remote_first_poll() -> LinuxResult<()> {
    use core::time::Duration;

    let original = axtask::current().cpumask();
    let Some(target) = (1..axhal::cpu_num()).find(|&cpu| axtask::is_sqpoll_service_cpu(cpu)) else {
        return Ok(());
    };
    if !original.get(0) {
        return Ok(());
    }
    let executor = axtask::future::CpuExecutor::get(target)?;
    assert!(axtask::set_current_affinity(axtask::AxCpuMask::one_shot(0)));
    let submit_cpu = axhal::percpu::this_cpu_id();
    let handle = executor.spawn(async move {
        let poll_cpu = axhal::percpu::this_cpu_id();
        axlog::ax_println!(
            "[IO_URING_CPU_GUEST] first poll submit={} target={} cpu={} task={}",
            submit_cpu, target, poll_cpu, axtask::current().name()
        );
        assert_eq!(poll_cpu, target);
    });
    assert!(axtask::set_current_affinity(original));
    let deadline = axhal::time::monotonic_time() + Duration::from_secs(5);
    while !handle.is_done() {
        assert!(axhal::time::monotonic_time() < deadline, "remote first poll timed out");
        axtask::sleep(Duration::from_millis(1));
    }
    Ok(())
}
