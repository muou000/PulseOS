//! User processes, threads and the kernel adapters that operate on their resources.
#![no_std]

extern crate alloc;

mod aspace_lock;
pub mod bpf;
pub mod exec;
pub mod fd;
pub mod io_uring;
mod lifecycle;
#[cfg(feature = "mapping-lifecycle-test")]
pub mod lifecycle_checks;
mod process_registry;
mod procfs;
mod sampling_clock;
mod signal;
pub mod socket;
mod thread;
mod timers;
pub mod trap;
pub mod uaccess;

use alloc::{
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
#[cfg(feature = "bpf-trace")]
use core::sync::atomic::Ordering;

pub use aspace_lock::AddressSpaceLock;
use axerrno::{LinuxError, LinuxResult};
use hashbrown::HashMap;
use kspin::SpinNoIrq;
pub use lifecycle::{
    ChildWaitResult, CloneParams, Credentials, ForkParams, MAX_POSIX_TIMER_COUNT, Process,
    WaitidStatusType, ZombieSchedSnapshot, run_futex_guest_checks,
};
pub use process_registry::{
    PROCESS_REGISTRY_SHARDS, ShardedProcessRegistry, process_shard_index,
    run_process_registry_guest_checks,
};
pub use signal::{
    DefaultSignalAction, SIG_DFL, SIG_IGN, SIGRTMIN, SigAction, SignalAction, SignalAltStack,
    SignalDelivery, SignalQueueError, SignalShared, ThreadSignal,
    blocked_mask as thread_blocked_mask, can_signal, check_signals_and_deliver,
    discard_pending_if_ignored, force_signal_to_thread, force_signal_to_thread_with_info,
    pending_mask as thread_pending_mask, queue_signal_to_process,
    queue_signal_to_process_with_info, queue_signal_to_process_with_info_strict,
    queue_signal_to_thread, queue_signal_to_thread_with_info,
    queue_signal_to_thread_with_info_strict, resolve_action, signal_info_for_child,
    signal_info_for_fault,
};
use spin::Lazy;
pub use procfs::init_procfs_provider;
pub use timers::{
    adjust_absolute_timers, init_itimer_hook, is_stdin_polling_enabled, schedule_itimer_event,
    schedule_posix_timer_event, set_stdin_polling_enabled,
};
pub use thread::{SignalMaskGuard, Thread, ThreadHandle, ThreadSchedAttrs};
#[cfg(feature = "guest-checks")]
pub(crate) use thread::user_dispatches;

static PROCESS_REGISTRY: Lazy<ShardedProcessRegistry<Arc<Process>>> =
    Lazy::new(ShardedProcessRegistry::new);

/// Serializes job-control state that must agree across session/PGID mutations,
/// process lifecycle transitions, and a child's transition through exec.
///
/// The process registry owns object lifetime, while this lock protects the
/// cross-process job-control invariants that cannot be represented by one
/// process's atomics alone.
static JOB_CONTROL_LOCK: SpinNoIrq<()> = SpinNoIrq::new(());

const THREAD_REGISTRY_SHARDS: usize = 16;

static THREAD_REGISTRY: Lazy<[SpinNoIrq<HashMap<u64, Weak<Thread>>>; THREAD_REGISTRY_SHARDS]> =
    Lazy::new(|| core::array::from_fn(|_| SpinNoIrq::new(HashMap::new())));

static INIT_PROCESS: spin::Once<Arc<Process>> = spin::Once::new();

pub fn register_process(pid: u64, process: Arc<Process>) {
    INIT_PROCESS.call_once(|| process.clone());
    PROCESS_REGISTRY.insert(pid, process);
}

pub fn unregister_process(pid: u64) {
    PROCESS_REGISTRY.remove(&pid);
}

/// Runs one short, nonblocking job-control state transition atomically.
pub fn with_job_control_lock<T>(f: impl FnOnce() -> T) -> T {
    let _guard = JOB_CONTROL_LOCK.lock();
    f()
}

/// Returns whether `pgid` names a process group in `session_id`.
pub fn process_group_exists_in_session(
    mut groups: impl Iterator<Item = (u64, u64)>,
    pgid: u64,
    session_id: u64,
) -> bool {
    groups.any(|(group, session)| group == pgid && session == session_id)
}

pub fn init_process() -> Option<Arc<Process>> {
    INIT_PROCESS.get().cloned()
}

pub fn register_thread_global(tid: u64, thread: Arc<Thread>) {
    THREAD_REGISTRY[tid as usize % THREAD_REGISTRY_SHARDS]
        .lock()
        .insert(tid, Arc::downgrade(&thread));
}

pub fn unregister_thread_global(tid: u64) {
    THREAD_REGISTRY[tid as usize % THREAD_REGISTRY_SHARDS]
        .lock()
        .remove(&tid);
}

fn rebind_thread_global_for_exec(old_tid: u64, new_tid: u64, thread: &Arc<Thread>) {
    if old_tid == new_tid {
        return;
    }

    let old_shard = old_tid as usize % THREAD_REGISTRY_SHARDS;
    let new_shard = new_tid as usize % THREAD_REGISTRY_SHARDS;
    if old_shard == new_shard {
        let mut registry = THREAD_REGISTRY[old_shard].lock();
        registry.remove(&old_tid);
        registry.insert(new_tid, Arc::downgrade(thread));
        return;
    }

    if old_shard < new_shard {
        let mut old_registry = THREAD_REGISTRY[old_shard].lock();
        let mut new_registry = THREAD_REGISTRY[new_shard].lock();
        old_registry.remove(&old_tid);
        new_registry.insert(new_tid, Arc::downgrade(thread));
    } else {
        let mut new_registry = THREAD_REGISTRY[new_shard].lock();
        let mut old_registry = THREAD_REGISTRY[old_shard].lock();
        old_registry.remove(&old_tid);
        new_registry.insert(new_tid, Arc::downgrade(thread));
    }
}

pub fn thread_by_tid_global(tid: u64) -> Option<Arc<Thread>> {
    THREAD_REGISTRY[tid as usize % THREAD_REGISTRY_SHARDS]
        .lock()
        .get(&tid)
        .and_then(|t| t.upgrade())
}

// Per-CPU `CURRENT_THREAD` and thread registry removed. Threads are
// resolved via the `task_ext` pointer on the current task. Processes
// are tracked in `PROCESS_REGISTRY` for pid-based queries.

fn thread_handle_from_task(task: &task::TaskInner) -> Option<&ThreadHandle> {
    let task_ext_ptr = unsafe { task.task_ext_ptr() };
    if task_ext_ptr.is_null() {
        return None;
    }

    Some(unsafe { &*(task_ext_ptr as *const ThreadHandle) })
}

pub fn thread_ref_from_task(task: &task::TaskInner) -> LinuxResult<&Thread> {
    thread_handle_from_task(task)
        .map(|handle| &**handle)
        .ok_or(LinuxError::ESRCH)
}

pub fn current_thread() -> LinuxResult<Arc<Thread>> {
    let task = task::current();
    if let Some(handle) = thread_handle_from_task(&task) {
        let thread = handle.thread_arc();
        return Ok(thread);
    }

    Err(LinuxError::ESRCH)
}

#[cfg(feature = "bpf-trace")]
pub fn emit_bpf_task_metadata(task: &task::TaskInner, pid: u64, tid: u64) {
    task.set_bpf_identity(pid, tid);
    let name = task.name();
    task::bpf_trace::task_metadata(task.id().as_u64(), pid, tid, name.as_bytes());
}

#[cfg(feature = "bpf-trace")]
pub fn emit_current_bpf_task_metadata() {
    let task = task::current();
    if let Ok(thread) = current_thread() {
        emit_bpf_task_metadata(&task, thread.process().pid(), thread.tid());
    }
}

#[cfg(feature = "bpf-trace")]
pub fn emit_current_mapping_metadata(kind: &str, begin_ns: u64) {
    let task = task::current();
    if let Ok(thread) = current_thread() {
        let process = thread.process();
        let space = process.aspace_handle().read().observation_identity().0;
        crate::bpf::mappings::task(task.id().as_u64(), process.pid(), thread.tid(), space,
            process.exec_generation.load(Ordering::Acquire), kind, 0, &task.name(), begin_ns);
    }
}

/// Creates an unpublished user task with space for its full register state.
/// A child inherits the calling user task's vectors before it can run.
pub fn try_new_user_task(
    entry: impl FnOnce() + Send + 'static,
    name: String,
    stack_size: usize,
) -> axerrno::AxResult<task::TaskInner> {
    let inner = task::TaskInner::try_new(entry, name, stack_size)?;
    #[cfg(target_arch = "riscv64")]
    let inner = {
        let mut inner = inner;
        let vectors = cpu::riscv_vector::VectorState::capture()
            .map_err(|_| axerrno::AxError::NoMemory)?;
        inner.ctx_mut().set_user_vectors(vectors);
        inner
    };
    Ok(inner)
}

/// Binds hardware/software context (`page_table_root`, `TaskExt`, `PROCESS_REGISTRY`)
/// to a `TaskInner` before publishing it to the scheduler queue.
pub fn spawn_task_with_thread(
    inner: task::TaskInner,
    thread: Arc<Thread>,
    register_proc: bool,
) -> task::AxTaskRef {
    spawn_task_with_thread_sched(
        inner,
        thread,
        register_proc,
        task::InitialTaskSched::normal_default(),
    )
}

/// Binds hardware/software context and applies explicit pre-enqueue scheduler
/// parameters before publishing the child task to a run queue.
pub(crate) fn spawn_task_with_thread_sched(
    mut inner: task::TaskInner,
    thread: Arc<Thread>,
    register_proc: bool,
    initial_sched: task::InitialTaskSched,
) -> task::AxTaskRef {
    inner.init_user_affinity();
    let proc = thread.process();
    let pt_root = proc.page_table_root();
    let asid = proc.asid();
    inner.ctx_mut().set_page_table_root(pt_root, asid);

    if register_proc {
        register_process(proc.pid(), proc.clone());
    }

    #[cfg(feature = "bpf-trace")]
    emit_bpf_task_metadata(&inner, proc.pid(), thread.tid());
    #[cfg(feature = "bpf-trace")]
    {
        let parent = if proc.parent_pid() != 0 { task::current().id().as_u64() } else { 0 };
        let space = proc.aspace_handle().read().observation_identity().0;
        crate::bpf::mappings::task(inner.id().as_u64(), proc.pid(), thread.tid(), space,
            proc.exec_generation.load(Ordering::Acquire), if parent == 0 { "bind" } else { "fork" },
            parent, &inner.name(), hal::time::monotonic_time_nanos());
    }

    inner.init_task_ext(ThreadHandle::new(thread));

    let task = inner.into_arc_with_sched(initial_sched);
    proc.register_task_ref(task.clone());
    task::spawn_task_ref(task.clone());
    task
}

/// Internal Linux error code for system call restarts.
pub const ERESTARTSYS: i32 = 512;

pub fn process_by_pid(pid: u64) -> Option<Arc<Process>> {
    PROCESS_REGISTRY.get(&pid)
}

pub fn processes_snapshot() -> Vec<Arc<Process>> {
    let mut procs = PROCESS_REGISTRY.snapshot_values();
    procs.sort_by_key(|p| p.pid());
    procs.dedup_by_key(|p| p.pid());
    procs
}

pub fn current_process() -> LinuxResult<Arc<Process>> {
    current_thread().map(|thread| thread.process_arc())
}

pub fn current_have_signals() -> bool {
    if let Ok(thread) = current_thread() {
        thread.has_pending_signal() || thread.process().group_exiting()
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
