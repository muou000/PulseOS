mod exec;
mod process;
mod signal;
mod thread;
pub mod uaccess;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
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
        let args = proc.args.lock();
        if args.is_empty() {
            let path = proc.exec_path().unwrap_or_else(|| "pulse_init".to_string());
            Some(alloc::format!("{}\0", path))
        } else {
            let mut res = String::new();
            for arg in args.iter() {
                res.push_str(arg);
                res.push('\0');
            }
            Some(res)
        }
    }

    fn comm(&self, pid: u64) -> Option<String> {
        let proc = process_by_pid(pid)?;
        let name = proc.exec_path()
            .as_ref()
            .and_then(|p| p.split('/').last())
            .unwrap_or("pulse_init")
            .to_string();
        Some(alloc::format!("{}\n", name))
    }

    fn status(&self, pid: u64) -> Option<String> {
        let proc = process_by_pid(pid)?;
        let name = proc.exec_path()
            .as_ref()
            .and_then(|p| p.split('/').last())
            .unwrap_or("pulse_init")
            .to_string();

        let is_current = current_process().ok().map(|p| p.pid() == pid).unwrap_or(false);
        let state = if proc.is_zombie() {
            "Z (zombie)"
        } else if is_current {
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
        proc.aspace_handle().lock().for_each_area(|start, end, _| {
            if start.as_usize() < 0x8000_0000_0000 {
                vm_size += end.as_usize() - start.as_usize();
            }
        });
        let vm_size_kb = vm_size / 1024;
        let vm_rss_kb = vm_size_kb;

        Some(alloc::format!(
            "Name:\t{}\nUmask:\t{:04o}\nState:\t{}\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\nUid:\t{} {} {} {}\nGid:\t{} {} {} {}\nThreads:\t{}\nVmSize:\t{} kB\nVmRSS:\t{} kB\n",
            name, umask, state, pid, pid, ppid, ruid, euid, suid, euid, rgid, egid, sgid, egid, threads, vm_size_kb, vm_rss_kb
        ))
    }

    fn exe(&self, pid: u64) -> Option<String> {
        let proc = process_by_pid(pid)?;
        Some(proc.exec_path().unwrap_or_else(|| "pulse_init".to_string()))
    }

    fn process_fds(&self, pid: u64) -> Option<Vec<u32>> {
        let proc = process_by_pid(pid)?;
        let fd_table = proc.fd_table.lock();
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
        let fd_table = proc.fd_table.lock();
        let entry = fd_table.get(fd as usize)?;
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
}

pub fn init_procfs_provider() {
    axfs::register_process_provider(Arc::new(PulseProcessProvider));
}
