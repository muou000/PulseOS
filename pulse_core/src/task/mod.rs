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
pub use process::{CloneParams, ForkParams, Process};
pub use signal::{
    DefaultSignalAction, NSIG, SIG_DFL, SIG_IGN, SigAction, SignalAction, SignalAltStack,
    SignalDelivery, SignalShared, ThreadSignal, blocked_mask as thread_blocked_mask, can_signal,
    check_signals_and_deliver, pending_mask as thread_pending_mask, queue_signal_to_process,
    queue_signal_to_thread,
};
use spin::{Lazy, Mutex};
pub use thread::{Thread, ThreadHandle};

static PROCESS_REGISTRY: Lazy<Mutex<BTreeMap<u64, Weak<Process>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

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
fn thread_handle_from_task(task: &axtask::TaskInner) -> Option<&ThreadHandle> {
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
