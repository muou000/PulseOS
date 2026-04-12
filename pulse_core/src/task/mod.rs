mod exec;
mod process;
mod thread;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use axerrno::{LinuxError, LinuxResult};
use spin::{Lazy, Mutex};

pub use process::Process;
pub use thread::{Thread, ThreadHandle};

static THREAD_REGISTRY: Lazy<Mutex<BTreeMap<u64, Arc<Thread>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

#[percpu::def_percpu]
static CURRENT_THREAD: Option<Arc<Thread>> = None;

pub fn register_thread_task(task_id: u64, thread: Arc<Thread>) {
    THREAD_REGISTRY.lock().insert(task_id, thread);
}

pub fn unregister_thread_task(task_id: u64) -> Option<Arc<Thread>> {
    THREAD_REGISTRY.lock().remove(&task_id)
}

pub fn install_current_thread(thread: Arc<Thread>) {
    unsafe {
        *CURRENT_THREAD.current_ref_mut_raw() = Some(thread);
    }
}

pub fn clear_current_thread() {
    unsafe {
        *CURRENT_THREAD.current_ref_mut_raw() = None;
    }
}

pub fn current_thread() -> LinuxResult<Arc<Thread>> {
    let task = axtask::current();
    let task_id = task.id().as_u64();
    if let Some(thread) = THREAD_REGISTRY.lock().get(&task_id).cloned() {
        return Ok(thread);
    }

    let task_ext_ptr = unsafe { task.task_ext_ptr() };
    if !task_ext_ptr.is_null() {
        let handle = unsafe { &*(task_ext_ptr as *const ThreadHandle) };
        let thread = handle.thread_arc();
        register_thread_task(task_id, thread.clone());
        return Ok(thread);
    }

    unsafe { CURRENT_THREAD.current_ref_raw() }
        .as_ref()
        .cloned()
        .ok_or(LinuxError::ESRCH)
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
