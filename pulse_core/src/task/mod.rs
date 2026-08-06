mod aspace_lock;
pub mod exec;
mod process;
mod signal;
mod thread;
pub mod uaccess;

use alloc::{
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::fmt::Write;

pub use aspace_lock::AddressSpaceLock;
use axerrno::{LinuxError, LinuxResult};
use hashbrown::HashMap;
use kernel_guard::NoPreemptIrqSave;
use kspin::SpinNoIrq;
pub use process::{CloneParams, ForkParams, MAX_POSIX_TIMER_COUNT, Process, WaitidStatusType};
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
use spin::{Lazy, RwLock};
pub use thread::{SignalMaskGuard, Thread, ThreadHandle};

/// An IRQ-safe map with concurrent readers and exclusive writers.
///
/// Disabling preemption and local interrupts prevents an IRQ reader from
/// deadlocking on a writer interrupted on the same CPU.
struct IrqSafeRwMap<K, V> {
    inner: RwLock<HashMap<K, V>>,
}

impl<K, V> IrqSafeRwMap<K, V>
where
    K: Eq + core::hash::Hash,
{
    fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        let _guard = NoPreemptIrqSave::new();
        self.inner.read().get(key).cloned()
    }

    fn snapshot_values(&self) -> Vec<V>
    where
        V: Clone,
    {
        let _guard = NoPreemptIrqSave::new();
        self.inner.read().values().cloned().collect()
    }

    fn insert(&self, key: K, value: V) {
        let _guard = NoPreemptIrqSave::new();
        self.inner.write().insert(key, value);
    }

    fn remove(&self, key: &K) -> Option<V> {
        let _guard = NoPreemptIrqSave::new();
        self.inner.write().remove(key)
    }
}

static PROCESS_REGISTRY: Lazy<IrqSafeRwMap<u64, Arc<Process>>> = Lazy::new(IrqSafeRwMap::new);

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

pub(super) fn rebind_thread_global_for_exec(old_tid: u64, new_tid: u64, thread: &Arc<Thread>) {
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

pub(super) fn thread_handle_from_task(task: &axtask::TaskInner) -> Option<&ThreadHandle> {
    let task_ext_ptr = unsafe { task.task_ext_ptr() };
    if task_ext_ptr.is_null() {
        return None;
    }

    Some(unsafe { &*(task_ext_ptr as *const ThreadHandle) })
}

pub fn thread_ref_from_task(task: &axtask::TaskInner) -> LinuxResult<&Thread> {
    thread_handle_from_task(task)
        .map(|handle| &**handle)
        .ok_or(LinuxError::ESRCH)
}

pub fn current_thread() -> LinuxResult<Arc<Thread>> {
    let task = axtask::current();
    if let Some(handle) = thread_handle_from_task(&task) {
        let thread = handle.thread_arc();
        return Ok(thread);
    }

    Err(LinuxError::ESRCH)
}

#[cfg(feature = "qperf-trace")]
pub fn emit_qperf_task_metadata(task: &axtask::TaskInner, pid: u64, tid: u64) {
    let name = task.name();
    axtask::qperf_trace::task_metadata(task.id().as_u64(), pid, tid, name.as_bytes());
}

#[cfg(feature = "qperf-trace")]
pub fn emit_current_qperf_task_metadata() {
    let task = axtask::current();
    if let Ok(thread) = current_thread() {
        emit_qperf_task_metadata(&task, thread.process().pid(), thread.tid());
    }
}

/// Binds hardware/software context (`page_table_root`, `TaskExt`, `PROCESS_REGISTRY`)
/// to a `TaskInner` before publishing it to the scheduler queue.
pub fn spawn_task_with_thread(
    mut inner: axtask::TaskInner,
    thread: Arc<Thread>,
    register_proc: bool,
) -> axtask::AxTaskRef {
    let proc = thread.process();
    let pt_root = proc.page_table_root();
    let asid = proc.asid();
    inner.ctx_mut().set_page_table_root(pt_root, asid);

    if register_proc {
        register_process(proc.pid(), proc.clone());
    }

    #[cfg(feature = "qperf-trace")]
    emit_qperf_task_metadata(&inner, proc.pid(), thread.tid());

    inner.init_task_ext(ThreadHandle::new(thread));

    let task = inner.into_arc();
    proc.register_task_ref(task.clone());
    axtask::spawn_task_ref(task.clone());
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

#[percpu::def_percpu]
static LAST_TICK_NS: u64 = 0;

static STDIN_POLLING_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(true);
static STDIN_POLL_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static STDIN_POLL_INTERVAL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(20);

/// Timer callbacks run with local IRQs disabled. Keep their handoff to this
/// worker atomic and bounded; all process/queue locks stay in task context.
static TIMER_WORK_WAIT: axtask::WaitQueue = axtask::WaitQueue::new();
static TIMER_WORK_PENDING: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static TIMER_PROCESS_WORK_PENDING: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static STDIN_POLL_WORK_PENDING: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static TIMER_WORKER_STARTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// A timer IRQ already knows which process owns the expired timer. Keep a
// bounded PID handoff so the worker normally performs one registry lookup
// instead of sorting and scanning every process. Collisions fall back to a
// complete scan, preserving correctness when the fixed queue is saturated.
const TIMER_PROCESS_PID_SLOTS: usize = 64;
static TIMER_PROCESS_PID_QUEUE: Lazy<[core::sync::atomic::AtomicU64; TIMER_PROCESS_PID_SLOTS]> =
    Lazy::new(|| core::array::from_fn(|_| core::sync::atomic::AtomicU64::new(0)));
static TIMER_PROCESS_PID_OVERFLOW: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub fn set_stdin_polling_enabled(enabled: bool) {
    STDIN_POLLING_ENABLED.store(enabled, core::sync::atomic::Ordering::Relaxed);
}

pub fn is_stdin_polling_enabled() -> bool {
    STDIN_POLLING_ENABLED.load(core::sync::atomic::Ordering::Relaxed)
}

fn enqueue_timer_process(pid: u64) {
    if pid == 0 {
        TIMER_PROCESS_PID_OVERFLOW.store(true, core::sync::atomic::Ordering::Release);
        return;
    }
    let start = pid as usize % TIMER_PROCESS_PID_SLOTS;
    for offset in 0..4 {
        let slot = &TIMER_PROCESS_PID_QUEUE[(start + offset) % TIMER_PROCESS_PID_SLOTS];
        let current = slot.load(core::sync::atomic::Ordering::Acquire);
        if current == pid {
            return;
        }
        if current == 0
            && slot
                .compare_exchange(
                    0,
                    pid,
                    core::sync::atomic::Ordering::AcqRel,
                    core::sync::atomic::Ordering::Acquire,
                )
                .is_ok()
        {
            return;
        }
    }
    TIMER_PROCESS_PID_OVERFLOW.store(true, core::sync::atomic::Ordering::Release);
}

fn request_timer_work(process_work: bool, process_pid: Option<u64>) {
    if process_work {
        if let Some(pid) = process_pid {
            enqueue_timer_process(pid);
        } else {
            TIMER_PROCESS_PID_OVERFLOW.store(true, core::sync::atomic::Ordering::Release);
        }
        TIMER_PROCESS_WORK_PENDING.store(true, core::sync::atomic::Ordering::Release);
    }
    if !TIMER_WORK_PENDING.swap(true, core::sync::atomic::Ordering::AcqRel) {
        TIMER_WORK_WAIT.notify_one(false);
    }
}

fn drain_timer_process_work() {
    let mut pids = Vec::new();
    for slot in TIMER_PROCESS_PID_QUEUE.iter() {
        let pid = slot.swap(0, core::sync::atomic::Ordering::AcqRel);
        if pid != 0 {
            pids.push(pid);
        }
    }

    if TIMER_PROCESS_PID_OVERFLOW.swap(false, core::sync::atomic::Ordering::AcqRel) {
        for process in processes_snapshot() {
            process.drain_deferred_timer_work();
        }
        return;
    }

    for pid in pids {
        if let Some(process) = process_by_pid(pid) {
            process.drain_deferred_timer_work();
        }
    }
}

fn timer_work_loop() {
    loop {
        TIMER_WORK_WAIT
            .wait_until(|| TIMER_WORK_PENDING.swap(false, core::sync::atomic::Ordering::AcqRel));

        loop {
            if STDIN_POLL_WORK_PENDING.swap(false, core::sync::atomic::Ordering::AcqRel) {
                crate::fd_table::poll_stdin();
                let interval = if crate::fd_table::STDIN_WAIT_QUEUE.is_empty() {
                    20
                } else {
                    5
                };
                STDIN_POLL_INTERVAL.store(interval, core::sync::atomic::Ordering::Relaxed);
            }
            if TIMER_PROCESS_WORK_PENDING.swap(false, core::sync::atomic::Ordering::AcqRel) {
                drain_timer_process_work();
            }
            if !TIMER_WORK_PENDING.swap(false, core::sync::atomic::Ordering::AcqRel) {
                break;
            }
        }
    }
}

fn start_timer_worker() {
    // Initialize the fixed handoff before the first timer IRQ can touch it.
    let _ = Lazy::force(&TIMER_PROCESS_PID_QUEUE);
    if TIMER_WORKER_STARTED
        .compare_exchange(
            false,
            true,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }
    axtask::spawn_raw(
        timer_work_loop,
        "pulse_timer_work".into(),
        axconfig::TASK_STACK_SIZE,
    );
}

fn itimer_tick_hook() {
    let now_ns = axhal::time::monotonic_time_nanos() as u64;
    let last_ns = LAST_TICK_NS.read_current();
    LAST_TICK_NS.write_current(now_ns);
    let elapsed_ns = if last_ns == 0 {
        0
    } else {
        now_ns.saturating_sub(last_ns)
    };

    let mut stdin_work = false;
    if is_stdin_polling_enabled() {
        let count = STDIN_POLL_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let poll_interval = STDIN_POLL_INTERVAL.load(core::sync::atomic::Ordering::Relaxed);
        if count % poll_interval == 0 {
            STDIN_POLL_WORK_PENDING.store(true, core::sync::atomic::Ordering::Release);
            stdin_work = true;
        }
    }

    let mut process_work = false;
    let mut process_pid = None;
    if elapsed_ns > 0 {
        if let Ok(curr) = current_process() {
            process_pid = Some(curr.pid());
            process_work |= curr.check_itimer_virt_tick(elapsed_ns);
            process_work |= curr.check_itimer_prof_tick(elapsed_ns);
        }
    }
    if process_work || stdin_work {
        request_timer_work(process_work, process_pid);
    }
}

pub fn schedule_itimer_event(pid: u64, deadline: u64) {
    let Some(process) = process_by_pid(pid) else {
        return;
    };
    let process = Arc::downgrade(&process);
    axtask::set_generic_timer(
        deadline,
        alloc::boxed::Box::new(move |_now| {
            if let Some(proc) = process.upgrade()
                && proc.mark_itimer_real_expired_from_irq(deadline)
            {
                request_timer_work(true, Some(proc.pid()));
            }
        }),
    );
}

pub fn schedule_posix_timer_event(pid: u64, timer_id: usize, deadline: u64, generation: u64) {
    let Some(process) = process_by_pid(pid) else {
        return;
    };
    let process = Arc::downgrade(&process);
    axtask::set_generic_timer(
        deadline,
        alloc::boxed::Box::new(move |_now| {
            if let Some(proc) = process.upgrade()
                && proc.mark_posix_timer_expired_from_irq(timer_id, deadline, generation)
            {
                request_timer_work(true, Some(proc.pid()));
            }
        }),
    );
}

pub fn adjust_absolute_timers() {
    let procs = processes_snapshot();
    let new_offset = axhal::time::current_epochoffset_nanos();
    for proc in procs {
        if proc.is_zombie() {
            continue;
        }
        let mut to_schedule = Vec::new();
        {
            let mut timers = proc.posix_timers.lock();
            for timer_opt in timers.iter_mut() {
                if let Some(timer) = timer_opt {
                    if timer.clock_id == 0
                        && timer.is_absolute
                        && !timer.first_expired
                        && timer.next_deadline_ns > 0
                    {
                        let sec = timer.itimer_spec.it_value.tv_sec as u64;
                        let nsec = timer.itimer_spec.it_value.tv_nsec as u64;
                        if let Some(req_ns) = sec
                            .checked_mul(1_000_000_000)
                            .and_then(|s| s.checked_add(nsec))
                        {
                            let new_deadline = req_ns.saturating_sub(new_offset);
                            timer.next_deadline_ns = new_deadline;
                            to_schedule.push((timer.id, new_deadline, timer.generation));
                        }
                    }
                }
            }
        }
        for (timer_id, new_deadline, generation) in to_schedule {
            schedule_posix_timer_event(proc.pid(), timer_id, new_deadline, generation);
        }
    }
}

/// Register the itimer tick hook with axtask. Should be called once during
/// pulse_core initialization.
pub fn init_itimer_hook() {
    start_timer_worker();
    axtask::register_timer_hook(itimer_tick_hook);
    axnet::register_have_signals_callback(current_have_signals);
}

struct PulseProcessProvider;

impl axfs::ProcfsProcessProvider for PulseProcessProvider {
    fn current_pid(&self) -> Option<u64> {
        current_process().ok().map(|p| p.pid())
    }

    fn process_exists(&self, pid: u64) -> bool {
        process_by_pid(pid).is_some()
    }

    fn process_pids(&self) -> Vec<u64> {
        processes_snapshot().iter().map(|p| p.pid()).collect()
    }

    fn cmdline(&self, pid: u64) -> Option<String> {
        let proc = process_by_pid(pid)?;
        if proc.is_zombie() {
            return Some(String::new());
        }
        let args = proc.args.read();
        if args.is_empty() {
            let mut path = proc.exec_path_or_default();
            path.push('\0');
            Some(path)
        } else {
            let total_len: usize = args.iter().map(|s| s.len() + 1).sum();
            let mut res = String::with_capacity(total_len);
            for arg in args.iter() {
                res.push_str(arg);
                res.push('\0');
            }
            Some(res)
        }
    }

    fn comm(&self, pid: u64) -> Option<String> {
        let proc = process_by_pid(pid)?;
        let mut name = proc.name();
        name.push('\n');
        Some(name)
    }

    fn status(&self, pid: u64) -> Option<String> {
        let proc = process_by_pid(pid)?;
        let name = proc.name();

        let state = if proc.is_zombie() {
            "Z (zombie)"
        } else if let Some(task) = proc.task_ref_by_tid(pid) {
            if task.is_running() || task.is_ready() {
                "R (running)"
            } else {
                "S (sleeping)"
            }
        } else {
            "S (sleeping)"
        };

        let umask = proc.umask();
        let ppid = proc.parent_pid();
        let (ruid, euid, suid) = proc.uid_snapshot();
        let (rgid, egid, sgid) = proc.gid_snapshot();
        let threads = proc.thread_count();

        let mut vm_size = 0;
        proc.aspace_handle().read().for_each_area(|start, end, _| {
            if start.as_usize() < 0x8000_0000_0000 {
                vm_size += end.as_usize() - start.as_usize();
            }
        });
        let vm_size_kb = vm_size / 1024;
        let vm_rss_kb = vm_size_kb;

        Some(alloc::format!(
            "Name:\t{}\nUmask:\t{:04o}\nState:\t{}\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\nUid:\t{} {} \
             {} {}\nGid:\t{} {} {} {}\nThreads:\t{}\nVmSize:\t{} kB\nVmRSS:\t{} kB\nVmData:\t{} \
             kB\n",
            name,
            umask,
            state,
            pid,
            pid,
            ppid,
            ruid,
            euid,
            suid,
            euid,
            rgid,
            egid,
            sgid,
            egid,
            threads,
            vm_size_kb,
            vm_rss_kb,
            vm_size_kb
        ))
    }

    fn exe(&self, pid: u64) -> Option<String> {
        let proc = process_by_pid(pid)?;
        Some(proc.exec_path_or_default())
    }

    fn stat(&self, pid: u64) -> Option<String> {
        let proc = process_by_pid(pid)?;
        let comm = proc.name();

        let state_char = if proc.is_zombie() {
            'Z'
        } else if let Some(task) = proc.task_ref_by_tid(pid) {
            if task.is_running() || task.is_ready() {
                'R'
            } else {
                'S'
            }
        } else {
            'S'
        };

        let ppid = proc.parent_pid();
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        let (utime_ns, stime_ns) = proc.snapshot_cpu_time_ns(now_ns);
        let utime = utime_ns / 10_000_000;
        let stime = stime_ns / 10_000_000;
        let cutime = proc
            .time_context
            .child_user_time_ns
            .load(core::sync::atomic::Ordering::Relaxed)
            / 10_000_000;
        let cstime = proc
            .time_context
            .child_sys_time_ns
            .load(core::sync::atomic::Ordering::Relaxed)
            / 10_000_000;
        let threads = proc.thread_count();
        let starttime = proc.start_mono_ns / 10_000_000;

        let mut vm_size = 0;
        proc.aspace_handle().read().for_each_area(|start, end, _| {
            if start.as_usize() < 0x8000_0000_0000 {
                vm_size += end.as_usize() - start.as_usize();
            }
        });
        let rss_pages = vm_size / 4096;

        Some(alloc::format!(
            "{} ({}) {} {} 0 0 0 -1 0 0 0 0 0 {} {} {} {} 20 0 {} 0 {} {} {} {} 0 0 0 0 0 0 0 0 0 \
             0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            pid,
            comm,
            state_char,
            ppid,
            utime,
            stime,
            cutime,
            cstime,
            threads,
            starttime,
            vm_size,
            rss_pages,
            u64::MAX
        ))
    }

    fn process_fds(&self, pid: u64) -> Option<Vec<u32>> {
        let proc = process_by_pid(pid)?;
        let binding = proc.fd_table();
        let fd_table = binding.read();
        let mut fds = Vec::new();
        for fd in 0..1024 {
            if fd_table.get(fd).is_some() {
                fds.push(fd as u32);
            }
        }
        Some(fds)
    }

    fn fd_path(&self, pid: u64, fd: u32) -> Option<String> {
        let proc = process_by_pid(pid)?;
        let entry = proc.get_fd_entry(fd as usize).ok()?;
        if let Some(loc) = entry.object.location() {
            Some(loc.absolute_path().ok()?.as_str().to_string())
        } else if let Ok(st) = entry.object.stat() {
            let mode = st.st_mode;
            if (mode & 0o170000) == 0o140000 {
                // S_IFSOCK
                Some(alloc::format!("socket:[{}]", st.st_ino))
            } else if (mode & 0o170000) == 0o010000 {
                // S_IFIFO
                Some(alloc::format!("pipe:[{}]", st.st_ino))
            } else {
                Some("/dev/null".to_string())
            }
        } else {
            Some("/dev/null".to_string())
        }
    }

    fn maps(&self, pid: u64) -> Option<String> {
        let proc = process_by_pid(pid)?;
        if proc.is_zombie() {
            return Some(String::new());
        }
        let aspace_handle = proc.aspace_handle();
        let mut areas = Vec::new();
        {
            let aspace = aspace_handle.read();
            aspace.for_each_area_with_backend(|start, end, flags, backend| {
                if start.as_usize() < 0x8000_0000_0000 {
                    areas.push((start, end, flags, backend.clone()));
                }
            });
        }
        let mut out = String::new();

        for (start, end, flags, backend) in areas {
            let r = if flags.contains(axhal::paging::MappingFlags::READ) {
                "r"
            } else {
                "-"
            };
            let w = if flags.contains(axhal::paging::MappingFlags::WRITE) {
                "w"
            } else {
                "-"
            };
            let x = if flags.contains(axhal::paging::MappingFlags::EXECUTE) {
                "x"
            } else {
                "-"
            };

            let mut is_shared = false;
            let mut offset = 0;
            let mut path_buf = None;
            let mut inode = 0;
            let mut dev_major = 0;
            let mut dev_minor = 0;

            let mut curr_backend = backend;
            while let axmm::Backend::Cow(cow) = &curr_backend {
                curr_backend = cow.inner().clone();
            }

            match curr_backend {
                axmm::Backend::Shared { .. } => {
                    is_shared = true;
                }
                axmm::Backend::File(mapping) => {
                    is_shared = mapping.is_shared();
                    offset = mapping.file_offset();
                    let cached_file = mapping.file();
                    let loc = cached_file.location();
                    if let Ok(meta) = axtask::future::block_on(loc.metadata()) {
                        inode = meta.inode;
                        dev_major = meta.device >> 8;
                        dev_minor = meta.device & 0xff;
                    }
                    if let Ok(path) = loc.absolute_path() {
                        path_buf = Some(path);
                    }
                }
                _ => {}
            }

            let p_char = if is_shared { "s" } else { "p" };
            if let Some(path) = path_buf.as_ref().filter(|path| !path.as_str().is_empty()) {
                core::write!(
                    out,
                    "{:x}-{:x} {}{}{}{} {:08x} {:02x}:{:02x} {:<7} {}\n",
                    start.as_usize(),
                    end.as_usize(),
                    r,
                    w,
                    x,
                    p_char,
                    offset,
                    dev_major,
                    dev_minor,
                    inode,
                    path.as_str()
                )
                .unwrap();
            } else {
                core::write!(
                    out,
                    "{:x}-{:x} {}{}{}{} {:08x} {:02x}:{:02x} {}\n",
                    start.as_usize(),
                    end.as_usize(),
                    r,
                    w,
                    x,
                    p_char,
                    offset,
                    dev_major,
                    dev_minor,
                    inode
                )
                .unwrap();
            }
        }

        Some(out)
    }

    fn pagemap(&self, pid: u64, offset: u64, buf: &mut [u8]) -> Option<usize> {
        let proc = process_by_pid(pid)?;
        if proc.is_zombie() {
            return Some(0);
        }
        let aspace_handle = proc.aspace_handle();
        let aspace = aspace_handle.read();

        let bytes_to_read = buf.len();
        if bytes_to_read == 0 {
            return Some(0);
        }

        let mut bytes_written = 0;
        let mut curr_offset = offset;

        while bytes_written < bytes_to_read {
            let entry_index = curr_offset / 8;
            let vaddr = memory_addr::VirtAddr::from(entry_index as usize * 4096);

            if vaddr.as_usize() >= 0x8000_0000_0000 {
                break;
            }

            let mut pagemap_entry: u64 = 0;
            if let Ok((paddr, flags, _page_size)) = aspace.query_vaddr(vaddr) {
                if paddr.as_usize() != 0 && !flags.is_empty() {
                    let pfn = (paddr.as_usize() / 4096) as u64;
                    pagemap_entry = (1u64 << 63) | (pfn & 0x007f_ffff_ffff_ffff);
                }
            }

            let entry_bytes = pagemap_entry.to_ne_bytes();
            let byte_in_entry = (curr_offset % 8) as usize;
            let chunk_size = core::cmp::min(8 - byte_in_entry, bytes_to_read - bytes_written);

            buf[bytes_written..bytes_written + chunk_size]
                .copy_from_slice(&entry_bytes[byte_in_entry..byte_in_entry + chunk_size]);

            bytes_written += chunk_size;
            curr_offset += chunk_size as u64;
        }

        Some(bytes_written)
    }

    fn children(&self, pid: u64) -> Option<Vec<u64>> {
        let proc = process_by_pid(pid)?;
        Some(proc.children_pids_snapshot())
    }

    fn thread_tids(&self, pid: u64) -> Option<Vec<u64>> {
        let proc = process_by_pid(pid)?;
        Some(proc.thread_ids_snapshot())
    }

    fn thread_comm(&self, pid: u64, tid: u64) -> Option<String> {
        let proc = process_by_pid(pid)?;
        let task = proc.task_ref_by_tid(tid)?;
        let mut name = task.name();
        name.push('\n');
        Some(name)
    }

    fn thread_status(&self, pid: u64, tid: u64) -> Option<String> {
        let proc = process_by_pid(pid)?;
        let task = proc.task_ref_by_tid(tid)?;
        let name = task.name();
        let state = if task.is_running() || task.is_ready() {
            "R (running)"
        } else {
            "S (sleeping)"
        };
        let umask = proc.umask();
        let ppid = proc.parent_pid();
        let (ruid, euid, suid) = proc.uid_snapshot();
        let (rgid, egid, sgid) = proc.gid_snapshot();
        let threads = proc.thread_count();

        let mut vm_size = 0;
        proc.aspace_handle().read().for_each_area(|start, end, _| {
            if start.as_usize() < 0x8000_0000_0000 {
                vm_size += end.as_usize() - start.as_usize();
            }
        });
        let vm_size_kb = vm_size / 1024;
        let vm_rss_kb = vm_size_kb;

        Some(alloc::format!(
            "Name:\t{}\nUmask:\t{:04o}\nState:\t{}\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\nUid:\t{} {} \
             {} {}\nGid:\t{} {} {} {}\nThreads:\t{}\nVmSize:\t{} kB\nVmRSS:\t{} kB\nVmData:\t{} \
             kB\n",
            name,
            umask,
            state,
            pid,
            tid,
            ppid,
            ruid,
            euid,
            suid,
            euid,
            rgid,
            egid,
            sgid,
            egid,
            threads,
            vm_size_kb,
            vm_rss_kb,
            vm_size_kb
        ))
    }

    fn thread_stat(&self, pid: u64, tid: u64) -> Option<String> {
        let proc = process_by_pid(pid)?;
        let task = proc.task_ref_by_tid(tid)?;
        let comm = task.name();

        let state_char = if task.is_running() || task.is_ready() {
            'R'
        } else {
            'S'
        };

        let handle = thread_handle_from_task(&task)?;
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        let (utime_ns, stime_ns) = handle.snapshot_cpu_time_ns(now_ns);
        let utime = utime_ns / 10_000_000;
        let stime = stime_ns / 10_000_000;
        let cutime = 0;
        let cstime = 0;
        let threads = proc.thread_count();
        let starttime = proc.start_mono_ns / 10_000_000;

        let mut vm_size = 0;
        proc.aspace_handle().read().for_each_area(|start, end, _| {
            if start.as_usize() < 0x8000_0000_0000 {
                vm_size += end.as_usize() - start.as_usize();
            }
        });
        let rss_pages = vm_size / 4096;

        Some(alloc::format!(
            "{} ({}) {} {} 0 0 0 -1 0 0 0 0 0 {} {} {} {} 20 0 {} 0 {} {} {} {} 0 0 0 0 0 0 0 0 0 \
             0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            tid,
            comm,
            state_char,
            pid, // TGID of the process
            utime,
            stime,
            cutime,
            cstime,
            threads,
            starttime,
            vm_size,
            rss_pages,
            u64::MAX
        ))
    }
}

pub fn init_procfs_provider() {
    axfs::register_process_provider(Arc::new(PulseProcessProvider));
}
