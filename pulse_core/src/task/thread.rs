use alloc::sync::Arc;
use core::{
    ops::Deref,
    sync::atomic::{AtomicUsize, Ordering},
};

use axerrno::AxResult;
use axtask::{TaskExtSwitch, def_task_ext};

use super::Process;

pub struct Thread {
    tid: u64,
    process: Arc<Process>,
    clear_child_tid: AtomicUsize,
    set_child_tid: AtomicUsize,
    robust_list_head: AtomicUsize,
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
    pub fn new(tid: u64, process: Arc<Process>) -> Arc<Self> {
        Arc::new(Self {
            tid,
            process,
            clear_child_tid: AtomicUsize::new(0),
            set_child_tid: AtomicUsize::new(0),
            robust_list_head: AtomicUsize::new(0),
        })
    }

    pub fn tid(&self) -> u64 {
        self.tid
    }

    pub fn process(&self) -> &Process {
        self.process.as_ref()
    }

    pub fn process_arc(&self) -> Arc<Process> {
        self.process.clone()
    }

    pub fn clear_child_tid(&self) -> usize {
        self.clear_child_tid.load(Ordering::Relaxed)
    }

    pub fn set_clear_child_tid(&self, clear_child_tid: usize) {
        self.clear_child_tid.store(clear_child_tid, Ordering::Relaxed);
    }

    pub fn set_child_tid_addr(&self, set_child_tid: usize) {
        self.set_child_tid.store(set_child_tid, Ordering::Relaxed);
    }

    pub fn robust_list_head(&self) -> usize {
        self.robust_list_head.load(Ordering::Relaxed)
    }

    pub fn set_robust_list_head(&self, robust_list_head: usize) {
        self.robust_list_head.store(robust_list_head, Ordering::Relaxed);
    }

    pub fn clear_thread_tid_state(&self) {
        self.clear_child_tid.store(0, Ordering::Relaxed);
        self.set_child_tid.store(0, Ordering::Relaxed);
        self.robust_list_head.store(0, Ordering::Relaxed);
    }

    pub fn write_set_child_tid_on_start(&self) -> AxResult<()> {
        let set_child_tid = self.set_child_tid.swap(0, Ordering::Relaxed);
        if set_child_tid == 0 {
            return Ok(());
        }
        self.process.write_user_u32(set_child_tid, self.tid as u32)
    }

    pub fn prepare_for_user_entry(&self) -> AxResult<()> {
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
        self.process.futex_wake(clear_child_tid, 1);
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
        self.run_exit_hooks();
        let final_code =
            if self.process.group_exiting() { self.process.group_exit_code() } else { exit_code };
        self.process.finish_thread_exit(self.tid, final_code);
        super::unregister_thread_task(self.tid);
        super::clear_current_thread();
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
