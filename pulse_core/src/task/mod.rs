mod exec;
mod process;
mod thread;
pub mod uaccess;

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};

use axerrno::{LinuxError, LinuxResult};
pub use process::{CloneParams, ForkParams, Process};
use spin::{Lazy, Mutex};
pub use thread::{Thread, ThreadHandle};

static THREAD_REGISTRY: Lazy<Mutex<BTreeMap<u64, Weak<Thread>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

#[percpu::def_percpu]
static CURRENT_THREAD: Option<Arc<Thread>> = None;

pub fn register_thread_task(task_id: u64, thread: Arc<Thread>) {
    THREAD_REGISTRY
        .lock()
        .insert(task_id, Arc::downgrade(&thread));
}

fn prune_dead_threads(registry: &mut BTreeMap<u64, Weak<Thread>>) {
    registry.retain(|_, thread| thread.strong_count() > 0);
}

pub fn unregister_thread_task(task_id: u64) -> Option<Arc<Thread>> {
    THREAD_REGISTRY
        .lock()
        .remove(&task_id)
        .and_then(|thread| thread.upgrade())
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
    {
        let mut registry = THREAD_REGISTRY.lock();
        prune_dead_threads(&mut registry);
        if let Some(thread) = registry.get(&task_id).and_then(|thread| thread.upgrade()) {
            return Ok(thread);
        }
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

pub fn thread_by_tid(tid: u64) -> Option<Arc<Thread>> {
    let mut registry = THREAD_REGISTRY.lock();
    prune_dead_threads(&mut registry);
    registry.get(&tid).and_then(|thread| thread.upgrade())
}

pub fn process_by_pid(pid: u64) -> Option<Arc<Process>> {
    let mut registry = THREAD_REGISTRY.lock();
    prune_dead_threads(&mut registry);
    registry.values().find_map(|thread| {
        let thread = thread.upgrade()?;
        let process = thread.process_arc();
        (process.pid() == pid).then_some(process)
    })
}

pub fn processes_snapshot() -> Vec<Arc<Process>> {
    let mut unique = BTreeMap::new();
    let mut registry = THREAD_REGISTRY.lock();
    prune_dead_threads(&mut registry);
    for thread in registry.values() {
        if let Some(thread) = thread.upgrade() {
            let process = thread.process_arc();
            unique.entry(process.pid()).or_insert(process);
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
