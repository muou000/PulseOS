use alloc::sync::Arc;
use core::{
    ops::Deref,
    sync::atomic::{AtomicUsize, Ordering},
};

use axerrno::{AxError, AxResult};
use axhal::context::TrapFrame;
use axtask::{AxTaskRef, TaskExtSwitch, WaitQueue, def_task_ext};
use spin::Mutex;

use super::{Process, SignalAltStack, ThreadSignal};

pub struct Thread {
    process: Arc<Process>,
    signal: Arc<ThreadSignal>,
    clear_child_tid: AtomicUsize,
    set_child_tid: AtomicUsize,
    robust_list_head: AtomicUsize,
    task_ref: Mutex<Option<AxTaskRef>>,
}

pub struct ThreadHandle(Arc<Thread>);
def_task_ext!(ThreadHandle);

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
    pub fn new(process: Arc<Process>) -> Arc<Self> {
        Arc::new(Self {
            signal: ThreadSignal::new(process.signal_shared()),
            process,
            clear_child_tid: AtomicUsize::new(0),
            set_child_tid: AtomicUsize::new(0),
            robust_list_head: AtomicUsize::new(0),
            task_ref: Mutex::new(None),
        })
    }

    pub fn tid(&self) -> u64 {
        axtask::current().id().as_u64()
    }

    pub fn process(&self) -> &Process {
        self.process.as_ref()
    }

    pub fn process_arc(&self) -> Arc<Process> {
        self.process.clone()
    }

    pub fn attach_task_ref(&self, task: AxTaskRef) {
        *self.task_ref.lock() = Some(task);
    }

    pub fn notify_signal_pending(&self) {
        self.signal.notify_waiters();
        if let Some(task) = self.task_ref.lock().clone() {
            axtask::wake_task(task, true);
        }
    }

    pub fn signal(&self) -> &ThreadSignal {
        self.signal.as_ref()
    }

    pub fn signal_blocked_mask(&self) -> u64 {
        self.signal.blocked_mask()
    }

    pub fn set_signal_blocked_mask(&self, mask: u64) {
        self.signal.set_blocked_mask(mask);
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
        self.signal.has_deliverable_pending_signal()
    }

    pub fn has_pending_unblocked_signal_not_in_set(&self, set: u64) -> bool {
        self.signal.has_pending_unblocked_not_in_set(set)
    }

    pub fn has_waitset_signal(&self, waitset: u64) -> bool {
        self.signal.has_waitset_signal(waitset)
    }

    pub fn dequeue_waitset_signal(&self, waitset: u64) -> Option<usize> {
        self.signal.dequeue_waitset(waitset)
    }

    pub fn signal_wait_queue(&self) -> &WaitQueue {
        self.signal.wait_queue()
    }

    pub fn restore_from_sigreturn(&self, tf: &mut TrapFrame) -> AxResult<usize> {
        self.signal
            .restore_from_sigreturn(self.process(), tf)
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
        self.signal.reset_on_exec();
    }

    pub fn write_set_child_tid_on_start(&self) -> AxResult<()> {
        let set_child_tid = self.set_child_tid.swap(0, Ordering::Relaxed);
        if set_child_tid == 0 {
            return Ok(());
        }
        let tid = axtask::current().id().as_u64();
        self.process.write_user_u32(set_child_tid, tid as u32)
    }

    pub fn prepare_for_user_entry(&self) -> AxResult<()> {
        axlog::debug!(
            "prepare_for_user_entry: tid={}, group_exiting={}",
            axtask::current().id().as_u64(),
            self.process.group_exiting()
        );
        if self.process.group_exiting() {
            self.exit_current(self.process.group_exit_code());
        }
        self.process.sync_fs_context();
        self.write_set_child_tid_on_start()?;
        self.process.mark_user_resume();
        Ok(())
    }

    pub fn clear_child_tid_on_exit(&self) -> AxResult<()> {
        let clear_child_tid = self.clear_child_tid.swap(0, Ordering::Relaxed);
        if clear_child_tid == 0 {
            return Ok(());
        }
        self.process.write_user_u32(clear_child_tid, 0)?;
        self.process.futex_wake_no_resched(clear_child_tid, 1);
        Ok(())
    }

    pub fn run_exit_hooks(&self) {
        let robust_list_head = self.robust_list_head.swap(0, Ordering::Relaxed);
        if robust_list_head != 0
            && let Err(e) = self.process.exit_robust_list(robust_list_head)
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
            axtask::current().id().as_u64(),
            self.process.group_exiting(),
            exit_code
        );
        self.run_exit_hooks();
        let final_code = if self.process.group_exiting() {
            self.process.group_exit_code()
        } else {
            exit_code
        };
        let tid = axtask::current().id().as_u64();
        self.process.finish_thread_exit(tid, final_code);
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
