use alloc::sync::{Arc, Weak};
use core::{
    ops::Deref,
    sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering},
};

use axerrno::{AxError, AxResult};
use axhal::context::TrapFrame;
use axtask::{
    AxTaskRef, AxTaskWeak, TaskExtSwitch, WaitQueue, WakeContext, WakeSource, def_task_ext,
};
use linux_raw_sys::general::SCHED_NORMAL;
use spin::Mutex;

use super::{Process, SignalAltStack, ThreadSignal};

pub struct Thread {
    tid: AtomicU64,
    process_weak: Weak<Process>,
    signal: Arc<ThreadSignal>,
    exec_exit_requested: AtomicBool,
    clear_child_tid: AtomicUsize,
    set_child_tid: AtomicUsize,
    robust_list_head: AtomicUsize,
    task_ref: Mutex<Option<AxTaskWeak>>,
    pub user_time_ns: AtomicU64,
    pub sys_time_ns: AtomicU64,
    pub last_user_enter_ns: AtomicU64,
    io_buffer: Mutex<alloc::vec::Vec<u8>>,
    pub sched_policy: AtomicU32,
    pub sched_flags: AtomicU64,
    pub sched_nice: AtomicI32,
    pub sched_runtime: AtomicU64,
    pub sched_deadline: AtomicU64,
    pub sched_period: AtomicU64,
}

const IO_BUFFER_CACHE_MAX_CAPACITY: usize = 64 * 1024;

const NOT_IN_USER_MODE: u64 = u64::MAX;

pub struct ThreadHandle(Arc<Thread>);
def_task_ext!(ThreadHandle);

/// Restores a thread's signal mask when a blocking syscall completes.
///
/// `pselect6`, `ppoll`, and `epoll_pwait*` replace the mask only for the
/// duration of their wait.  Keeping the restore in the task layer prevents
/// each syscall implementation from open-coding a subtly different drop path.
pub struct SignalMaskGuard {
    thread: Arc<Thread>,
    old_mask: Option<u64>,
}

impl SignalMaskGuard {
    pub fn install(thread: Arc<Thread>, new_mask: Option<u64>) -> Self {
        let old_mask = new_mask.map(|mask| thread.set_signal_blocked_mask(mask));
        Self { thread, old_mask }
    }
}

impl Drop for SignalMaskGuard {
    fn drop(&mut self) {
        if let Some(old_mask) = self.old_mask {
            self.thread.set_signal_blocked_mask(old_mask);
        }
    }
}

impl ThreadHandle {
    pub fn new(thread: Arc<Thread>) -> Self {
        Self(thread)
    }

    pub fn thread_arc(&self) -> Arc<Thread> {
        self.0.clone()
    }
}

impl Deref for ThreadHandle {
    type Target = Thread;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl Thread {
    pub fn new(process: Arc<Process>, tid: u64) -> Arc<Self> {
        Arc::new(Self {
            tid: AtomicU64::new(tid),
            signal: ThreadSignal::new(process.signal_shared()),
            process_weak: Arc::downgrade(&process),
            exec_exit_requested: AtomicBool::new(false),
            clear_child_tid: AtomicUsize::new(0),
            set_child_tid: AtomicUsize::new(0),
            robust_list_head: AtomicUsize::new(0),
            task_ref: Mutex::new(None),
            user_time_ns: AtomicU64::new(0),
            sys_time_ns: AtomicU64::new(0),
            last_user_enter_ns: AtomicU64::new(NOT_IN_USER_MODE),
            io_buffer: Mutex::new(alloc::vec::Vec::new()),
            // New user threads start in the ordinary scheduling class, which
            // Linux exposes as SCHED_OTHER/SCHED_NORMAL rather than SCHED_RR.
            sched_policy: AtomicU32::new(SCHED_NORMAL),
            sched_flags: AtomicU64::new(0),
            sched_nice: AtomicI32::new(0),
            sched_runtime: AtomicU64::new(0),
            sched_deadline: AtomicU64::new(0),
            sched_period: AtomicU64::new(0),
        })
    }

    /// Copies scheduler attributes when a child thread is created.
    pub fn inherit_scheduler_from(&self, parent: &Self) {
        self.sched_policy.store(
            parent.sched_policy.load(Ordering::Acquire),
            Ordering::Release,
        );
        self.sched_flags.store(
            parent.sched_flags.load(Ordering::Acquire),
            Ordering::Release,
        );
        self.sched_nice
            .store(parent.sched_nice.load(Ordering::Acquire), Ordering::Release);
        self.sched_runtime.store(
            parent.sched_runtime.load(Ordering::Acquire),
            Ordering::Release,
        );
        self.sched_deadline.store(
            parent.sched_deadline.load(Ordering::Acquire),
            Ordering::Release,
        );
        self.sched_period.store(
            parent.sched_period.load(Ordering::Acquire),
            Ordering::Release,
        );
    }

    pub fn take_io_buffer(&self) -> alloc::vec::Vec<u8> {
        let mut guard = self.io_buffer.lock();
        core::mem::take(&mut *guard)
    }

    pub fn put_io_buffer(&self, mut buf: alloc::vec::Vec<u8>) {
        // Large network requests may use this temporary buffer, but retaining
        // one on every thread after a single request would turn it into an
        // unbounded per-thread cache. Normal syscall I/O is chunked at 64 KiB.
        if buf.capacity() > IO_BUFFER_CACHE_MAX_CAPACITY {
            return;
        }
        buf.clear();
        let mut guard = self.io_buffer.lock();
        *guard = buf;
    }

    pub fn tid(&self) -> u64 {
        self.tid.load(Ordering::Acquire)
    }

    pub(crate) fn set_tid_for_exec(&self, tid: u64) {
        self.tid.store(tid, Ordering::Release);
    }

    pub fn request_exec_exit(&self) {
        self.exec_exit_requested.store(true, Ordering::Release);
        self.signal.notify_waiters();
    }

    pub fn exec_exit_requested(&self) -> bool {
        self.exec_exit_requested.load(Ordering::Acquire)
    }

    pub fn exit_if_exec_requested(&self) {
        if self.exec_exit_requested() {
            self.exit_current(0);
        }
    }

    pub fn process(&self) -> Arc<Process> {
        self.process_weak
            .upgrade()
            .expect("Thread::process: process has been dropped")
    }

    pub fn process_arc(&self) -> Arc<Process> {
        self.process_weak
            .upgrade()
            .expect("Thread::process_arc: process has been dropped")
    }

    pub fn attach_task_ref(&self, task: AxTaskRef) {
        *self.task_ref.lock() = Some(Arc::downgrade(&task));
    }

    pub fn notify_signal_pending(&self, sig: usize) {
        let wake_context = WakeContext::new(|| (WakeSource::Signal, sig as u64));
        self.signal
            .wait_queue()
            .notify_all_with_context(true, wake_context);
        if self.signal.has_deliverable_pending_signal()
            && let Some(weak_task) = self.task_ref.lock().as_ref()
        {
            if let Some(task) = weak_task.upgrade() {
                axtask::interrupt_task_with_context(task, true, wake_context);
            }
        }
    }

    pub fn signal(&self) -> &ThreadSignal {
        self.signal.as_ref()
    }

    pub fn signal_blocked_mask(&self) -> u64 {
        self.signal.blocked_mask()
    }

    pub fn set_signal_blocked_mask(&self, mask: u64) -> u64 {
        self.signal.set_blocked_mask(mask)
    }

    pub fn set_signal_altstack(&self, ss: SignalAltStack) {
        self.signal.set_altstack(ss);
    }

    pub fn signal_altstack(&self) -> SignalAltStack {
        self.signal.altstack()
    }

    pub fn begin_sigsuspend(&self, new_mask: u64) {
        self.signal.begin_sigsuspend(new_mask);
    }

    pub fn has_pending_signal(&self) -> bool {
        // A group stop is task work just like a pending signal: an
        // interruptible operation must return to the user-return path so the
        // thread can join the process-wide stop.  Linux includes job-control
        // work in its pending-signal test for the same reason.
        self.exec_exit_requested()
            || self.process().group_stopped()
            || self.signal.has_deliverable_pending_signal()
    }

    pub fn has_pending_unblocked_signal_not_in_set(&self, set: u64) -> bool {
        self.signal.has_pending_unblocked_not_in_set(set)
    }

    pub fn has_waitset_signal(&self, waitset: u64) -> bool {
        self.signal.has_waitset_signal(waitset)
    }

    pub fn dequeue_waitset_signal(&self, waitset: u64) -> Option<(usize, Option<[u8; 128]>)> {
        self.signal.dequeue_waitset_with_info(waitset)
    }

    pub fn signal_wait_queue(&self) -> &WaitQueue {
        self.signal.wait_queue()
    }

    pub fn restore_from_sigreturn(&self, tf: &mut TrapFrame) -> AxResult<usize> {
        self.signal
            .restore_from_sigreturn(&self.process(), tf)
            .map_err(|_| AxError::InvalidInput)
    }

    pub fn clear_child_tid(&self) -> usize {
        self.clear_child_tid.load(Ordering::Relaxed)
    }

    pub fn set_clear_child_tid(&self, clear_child_tid: usize) {
        self.clear_child_tid
            .store(clear_child_tid, Ordering::Relaxed);
    }

    pub fn set_child_tid_addr(&self, set_child_tid: usize) {
        self.set_child_tid.store(set_child_tid, Ordering::Relaxed);
    }

    pub fn robust_list_head(&self) -> usize {
        self.robust_list_head.load(Ordering::Relaxed)
    }

    pub fn set_robust_list_head(&self, robust_list_head: usize) {
        self.robust_list_head
            .store(robust_list_head, Ordering::Relaxed);
    }

    pub fn clear_thread_tid_state(&self) {
        self.clear_child_tid.store(0, Ordering::Relaxed);
        self.set_child_tid.store(0, Ordering::Relaxed);
        self.robust_list_head.store(0, Ordering::Relaxed);
        self.signal.reset_runtime_on_exec();
    }

    pub fn write_set_child_tid_on_start(&self) -> AxResult<()> {
        let set_child_tid = self.set_child_tid.swap(0, Ordering::Relaxed);
        if set_child_tid == 0 {
            return Ok(());
        }
        let tid = self.tid();
        self.process().write_user_u32(set_child_tid, tid as u32)
    }

    pub fn prepare_for_user_entry(&self) -> AxResult<()> {
        axlog::debug!(
            "prepare_for_user_entry: tid={}, group_exiting={}",
            self.tid(),
            self.process().group_exiting()
        );
        self.exit_if_exec_requested();
        if self.process().group_exiting() {
            self.exit_current(self.process().group_exit_code());
        }
        // Filesystem syscalls synchronize this context on demand in the
        // dispatcher. Avoid touching the shared FS context for empty threads.
        self.write_set_child_tid_on_start()?;
        self.process().mark_user_resume();
        self.mark_user_resume();
        Ok(())
    }

    pub fn mark_user_resume_at(&self, now_ns: u64) {
        self.last_user_enter_ns.store(now_ns, Ordering::Release);
    }

    pub fn mark_user_resume(&self) {
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        self.mark_user_resume_at(now_ns);
    }

    pub fn on_kernel_entry_from_user(&self, now_ns: u64) {
        let last = self
            .last_user_enter_ns
            .swap(NOT_IN_USER_MODE, Ordering::AcqRel);
        if last != NOT_IN_USER_MODE {
            let delta = now_ns.saturating_sub(last);
            self.user_time_ns.fetch_add(delta, Ordering::Relaxed);
        }
    }

    pub fn add_sys_time_ns(&self, delta_ns: u64) {
        self.sys_time_ns.fetch_add(delta_ns, Ordering::Relaxed);
    }

    pub fn snapshot_cpu_time_ns(&self, now_ns: u64) -> (u64, u64) {
        let mut user = self.user_time_ns.load(Ordering::Relaxed);
        let sys = self.sys_time_ns.load(Ordering::Relaxed);
        let last = self.last_user_enter_ns.load(Ordering::Acquire);
        if last != NOT_IN_USER_MODE {
            user = user.saturating_add(now_ns.saturating_sub(last));
        }
        (user, sys)
    }

    pub fn clear_child_tid_on_exit(&self) -> AxResult<()> {
        let clear_child_tid = self.clear_child_tid.swap(0, Ordering::Relaxed);
        if clear_child_tid == 0 {
            return Ok(());
        }
        self.process().write_user_u32(clear_child_tid, 0)?;
        self.process()
            .futex_wake_no_resched(clear_child_tid, 1, true);
        self.process()
            .futex_wake_no_resched(clear_child_tid, 1, false);
        Ok(())
    }

    pub fn run_exit_hooks(&self) {
        let robust_list_head = self.robust_list_head.swap(0, Ordering::Relaxed);
        if robust_list_head != 0
            && let Err(e) = self.process().exit_robust_list(robust_list_head)
        {
            axlog::warn!("failed to exit robust list: {:?}", e);
        }
        if let Err(e) = self.clear_child_tid_on_exit() {
            axlog::warn!("failed to clear child tid on exit: {:?}", e);
        }
    }

    pub fn exit_current(&self, exit_code: i32) -> ! {
        axlog::debug!(
            "exit_current: tid={}, group_exiting={}, exit_code={}",
            self.tid(),
            self.process().group_exiting(),
            exit_code
        );
        self.run_exit_hooks();
        let final_code = if self.process().group_exiting() {
            self.process().group_exit_code()
        } else {
            exit_code
        };
        let tid = self.tid();
        self.process().finish_thread_exit(tid, final_code);
        axtask::exit(final_code);
    }

    pub fn on_enter_cpu(self: &Arc<Self>) {
        let _ = self;
    }

    pub fn on_leave_cpu(&self) {
        let _ = self;
    }
}

impl TaskExtSwitch for ThreadHandle {
    fn on_enter(&self) {
        self.0.on_enter_cpu();
    }

    fn on_leave(&self) {
        self.0.on_leave_cpu();
    }
}
