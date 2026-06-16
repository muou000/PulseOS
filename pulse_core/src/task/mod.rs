mod exec;
mod process;
mod signal;
mod thread;
pub mod uaccess;

use alloc::{
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use hashbrown::HashMap;

use axerrno::{LinuxError, LinuxResult};
use kspin::SpinNoIrq;
pub use process::{CloneParams, ForkParams, Process, WaitidStatusType};
pub use signal::{
    DefaultSignalAction, NSIG, SIG_DFL, SIG_IGN, SigAction, SignalAction, SignalAltStack,
    SignalDelivery, SignalShared, ThreadSignal, blocked_mask as thread_blocked_mask, can_signal,
    check_signals_and_deliver, pending_mask as thread_pending_mask, queue_signal_to_process,
    queue_signal_to_thread, resolve_action, queue_signal_to_process_with_info,
    queue_signal_to_thread_with_info,
};
use spin::Lazy;
pub use thread::{Thread, ThreadHandle};

static PROCESS_REGISTRY: Lazy<SpinNoIrq<HashMap<u64, Arc<Process>>>> =
    Lazy::new(|| SpinNoIrq::new(HashMap::new()));

static THREAD_REGISTRY: Lazy<SpinNoIrq<HashMap<u64, Weak<Thread>>>> =
    Lazy::new(|| SpinNoIrq::new(HashMap::new()));

static INIT_PROCESS: spin::Once<Arc<Process>> = spin::Once::new();

pub fn register_process(pid: u64, process: Arc<Process>) {
    INIT_PROCESS.call_once(|| process.clone());
    PROCESS_REGISTRY.lock().insert(pid, process);
}

pub fn unregister_process(pid: u64) {
    PROCESS_REGISTRY.lock().remove(&pid);
}

pub fn init_process() -> Option<Arc<Process>> {
    INIT_PROCESS.get().cloned()
}

pub fn register_thread_global(tid: u64, thread: Arc<Thread>) {
    THREAD_REGISTRY.lock().insert(tid, Arc::downgrade(&thread));
}

pub fn unregister_thread_global(tid: u64) {
    THREAD_REGISTRY.lock().remove(&tid);
}

pub fn thread_by_tid_global(tid: u64) -> Option<Arc<Thread>> {
    THREAD_REGISTRY.lock().get(&tid).and_then(|t| t.upgrade())
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
    let registry = PROCESS_REGISTRY.lock();
    registry.get(&pid).cloned()
}

pub fn processes_snapshot() -> Vec<Arc<Process>> {
    let registry = PROCESS_REGISTRY.lock();
    let mut procs: Vec<_> = registry.values().cloned().collect();
    procs.sort_by_key(|p| p.pid());
    procs
}

pub fn current_process() -> LinuxResult<Arc<Process>> {
    current_thread().map(|thread| thread.process_arc())
}

pub fn current_have_signals() -> bool {
    if let Ok(thread) = current_thread() {
        thread.signal().has_deliverable_pending_signal() || thread.process().group_exiting()
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

static NEXT_ITIMER_DEADLINE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

pub fn update_itimer_deadline(deadline: u64) {
    NEXT_ITIMER_DEADLINE.fetch_min(deadline, core::sync::atomic::Ordering::Relaxed);
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

    crate::fd_table::poll_stdin();
    
    if now_ns >= NEXT_ITIMER_DEADLINE.load(core::sync::atomic::Ordering::Relaxed) {
        NEXT_ITIMER_DEADLINE.store(u64::MAX, core::sync::atomic::Ordering::Relaxed);
        let registry = PROCESS_REGISTRY.lock();
        let mut next_min = u64::MAX;
        for proc in registry.values() {
            if !proc.is_zombie() {
                if let Some(next_deadline) = proc.check_itimer_real_tick(now_ns) {
                    if next_deadline < next_min {
                        next_min = next_deadline;
                    }
                }
            }
        }
        NEXT_ITIMER_DEADLINE.fetch_min(next_min, core::sync::atomic::Ordering::Relaxed);
    }

    if elapsed_ns > 0 {
        if let Ok(curr) = current_process() {
            curr.check_itimer_virt_tick(elapsed_ns);
            curr.check_itimer_prof_tick(elapsed_ns);
        }
    }
}

/// Register the itimer tick hook with axtask. Should be called once during
/// pulse_core initialization.
pub fn init_itimer_hook() {
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
            let path = proc.exec_path_or_default();
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
        Some(alloc::format!("{}\n", proc.name()))
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
             {} {}\nGid:\t{} {} {} {}\nThreads:\t{}\nVmSize:\t{} kB\nVmRSS:\t{} kB\nVmData:\t{} kB\n",
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
        let binding = proc.fd_table();
        let fd_table = binding.read();
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

    fn maps(&self, pid: u64) -> Option<String> {
        let proc = process_by_pid(pid)?;
        if proc.is_zombie() {
            return Some(String::new());
        }
        let aspace_handle = proc.aspace_handle();
        let aspace = aspace_handle.read();
        let mut out = String::new();

        aspace.for_each_area_with_backend(|start, end, flags, backend| {
            if start.as_usize() >= 0x8000_0000_0000 {
                return;
            }

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
            let mut path_str = String::new();
            let mut inode = 0;
            let mut dev_str = "00:00".to_string();

            let mut curr_backend = backend.clone();
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
                    if let Ok(meta) = loc.metadata() {
                        inode = meta.inode;
                        let major = meta.device >> 8;
                        let minor = meta.device & 0xff;
                        dev_str = alloc::format!("{:02x}:{:02x}", major, minor);
                    }
                    if let Ok(path) = loc.absolute_path() {
                        path_str = path.as_str().to_string();
                    }
                }
                _ => {}
            }

            let p_char = if is_shared { "s" } else { "p" };
            if path_str.is_empty() {
                out.push_str(&alloc::format!(
                    "{:x}-{:x} {}{}{}{} {:08x} {} {}\n",
                    start.as_usize(),
                    end.as_usize(),
                    r,
                    w,
                    x,
                    p_char,
                    offset,
                    dev_str,
                    inode
                ));
            } else {
                out.push_str(&alloc::format!(
                    "{:x}-{:x} {}{}{}{} {:08x} {} {:<7} {}\n",
                    start.as_usize(),
                    end.as_usize(),
                    r,
                    w,
                    x,
                    p_char,
                    offset,
                    dev_str,
                    inode,
                    path_str
                ));
            }
        });

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
}

pub fn init_procfs_provider() {
    axfs::register_process_provider(Arc::new(PulseProcessProvider));
}
