mod exec;
mod process;
mod signal;
mod thread;
pub mod uaccess;

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};

use axerrno::{LinuxError, LinuxResult};
use kspin::SpinNoIrq;
pub use process::{CloneParams, ForkParams, Process};
pub use signal::{
    DefaultSignalAction, NSIG, SIG_DFL, SIG_IGN, SigAction, SignalAction, SignalAltStack,
    SignalDelivery, SignalShared, ThreadSignal, blocked_mask as thread_blocked_mask, can_signal,
    check_signals_and_deliver, pending_mask as thread_pending_mask, queue_signal_to_process,
    queue_signal_to_thread, resolve_action,
};
use spin::Lazy;
pub use thread::{Thread, ThreadHandle};

static PROCESS_REGISTRY: Lazy<SpinNoIrq<BTreeMap<u64, Weak<Process>>>> =
    Lazy::new(|| SpinNoIrq::new(BTreeMap::new()));

pub fn register_process(pid: u64, process: Arc<Process>) {
    PROCESS_REGISTRY
        .lock()
        .insert(pid, Arc::downgrade(&process));
}

fn prune_dead_processes(registry: &mut BTreeMap<u64, Weak<Process>>) {
    registry.retain(|_, process| process.strong_count() > 0);
}

// Per-CPU `CURRENT_THREAD` and thread registry removed. Threads are
// resolved via the `task_ext` pointer on the current task. Processes
// are tracked in `PROCESS_REGISTRY` for pid-based queries.

/// Returns the thread handle stored in a task's extension slot.
///
/// # Safety
///
/// The caller must ensure that `task.task_ext_ptr()` either returns null or
/// points to a valid `ThreadHandle` written by the task extension system, and
/// that the pointed-to handle remains alive for the duration of the borrow.
pub(super) fn thread_handle_from_task(task: &axtask::TaskInner) -> Option<&ThreadHandle> {
    let task_ext_ptr = unsafe { task.task_ext_ptr() };
    if task_ext_ptr.is_null() {
        return None;
    }

    Some(unsafe { &*(task_ext_ptr as *const ThreadHandle) })
}

pub fn current_thread() -> LinuxResult<Arc<Thread>> {
    let task = axtask::current();
    if let Some(handle) = thread_handle_from_task(&task) {
        let thread = handle.thread_arc();
        return Ok(thread);
    }

    Err(LinuxError::ESRCH)
}

/// Internal Linux error code for system call restarts.
pub const ERESTARTSYS: i32 = 512;

pub fn process_by_pid(pid: u64) -> Option<Arc<Process>> {
    let mut registry = PROCESS_REGISTRY.lock();
    prune_dead_processes(&mut registry);
    registry.get(&pid).and_then(|p| p.upgrade())
}

pub fn processes_snapshot() -> Vec<Arc<Process>> {
    let mut unique = BTreeMap::new();
    let mut registry = PROCESS_REGISTRY.lock();
    prune_dead_processes(&mut registry);
    for proc_w in registry.values() {
        if let Some(proc) = proc_w.upgrade() {
            unique.entry(proc.pid()).or_insert(proc);
        }
    }
    unique.into_values().collect()
}

pub fn current_process() -> LinuxResult<Arc<Process>> {
    current_thread().map(|thread| thread.process_arc())
}

pub fn current_have_signals() -> bool {
    if let Ok(thread) = current_thread() {
        thread.signal().has_deliverable_pending_signal()
    } else {
        false
    }
}

pub fn with_current_thread<R>(f: impl FnOnce(&Thread) -> R) -> LinuxResult<R> {
    current_thread().map(|thread| f(thread.as_ref()))
}

pub fn with_current_process<R>(f: impl FnOnce(&Process) -> R) -> LinuxResult<R> {
    current_process().map(|process| f(process.as_ref()))
}

pub fn thread_by_tid(process: &Process, tid: u64) -> Option<Arc<Thread>> {
    let task = process.task_ref_by_tid(tid)?;
    thread_handle_from_task(&task).map(|handle| handle.thread_arc())
}

/// Timer tick hook for checking itimers across all processes.
/// Called from `axtask::on_timer_tick()` in interrupt context.
/// Must not take any blocking locks.
fn itimer_tick_hook() {
    let procs = processes_snapshot();
    for proc in procs {
        if proc.is_zombie() {
            continue;
        }
        proc.check_itimer_real_tick();
    }
}

/// Register the itimer tick hook with axtask. Should be called once during
/// pulse_core initialization.
pub fn init_itimer_hook() {
    axtask::register_timer_hook(itimer_tick_hook);
}
