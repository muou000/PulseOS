use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::fmt::Write;

use crate::{current_process, process_by_pid, processes_snapshot, thread_handle_from_task};

struct PulseProcessProvider;

impl axfs::ProcfsProcessProvider for PulseProcessProvider {
    fn bpf_mappings(&self) -> Option<String> {
        #[cfg(feature = "bpf-trace")]
        { Some(crate::bpf::mappings::render()) }
        #[cfg(not(feature = "bpf-trace"))]
        { None }
    }

    fn bpf_stats(&self) -> Option<String> {
        let process = current_process().ok()?;
        #[cfg(not(feature = "bpf-trace"))]
        return Some(alloc::format!("PULSE_BPF_STATS version=1 pid={} available=0\nEND events=0 programs=0\n", process.pid()));
        #[cfg(feature = "bpf-trace")]
        {
            use crate::bpf::{PerfEventClock, PerfEventScope, PerfEventObject};
            use alloc::collections::BTreeMap;
            let entries = {
                let table = process.fd_table();
                let locked = table.read();
                locked.numbered_entries_snapshot()
            };
            let timer = crate::bpf::sampling::stats_snapshot();
            let trace = axtask::bpf_trace::total_drop_stats();
            let fault = axtask::bpf_trace::page_fault_stats();
            // Capability version is independent of the diagnostics row format.
            // Freeze the actual online set rather than the configured maximum.
            let mut text = alloc::format!("PULSE_BPF_STATS version=1 pid={} available=1 capabilities_version=1 online_mask={} cpu_clock=1 task_clock=1 sched=1 fault=1 min_period_ns=1 stack_context_version=3 stack_depth={} stack_bytes={} registered_events={} trace_subscriptions={}\n",
                process.pid(), axhal::online_cpu_mask(), pulse_bpf_schema::DEFAULT_STACK_DEPTH,
                pulse_bpf_schema::DEFAULT_STACK_BYTE_LIMIT, crate::bpf::registered_perf_event_count(),
                crate::bpf::tracepoint_subscription_count());
            writeln!(&mut text, "GLOBAL timer_enqueued={} timer_dequeued={} timer_full={} timer_busy={} trace_enqueued={} trace_full={} trace_recursive={} fault_started={} fault_completed={} fault_clock_errors={}",
                timer.enqueued, timer.dequeued, timer.full, timer.busy,
                trace.total_enqueued, trace.dropped_full, trace.dropped_recursive, fault.started, fault.completed, fault.clock_errors).ok()?;
            let mut programs = BTreeMap::new();
            let mut events = 0usize;
            for (fd, entry) in entries {
                let Some(object) = entry.object.as_any().downcast_ref::<PerfEventObject>() else { continue; };
                let event = object.event();
                let d = event.diagnostics();
                let (clock, config) = match d.clock {
                    PerfEventClock::CpuClock => (0, 0),
                    PerfEventClock::TaskClock => (1, 1),
                    PerfEventClock::BpfOutput => (10, 10),
                    PerfEventClock::Tracepoint(id) => (2, id.as_u32()),
                };
                let (scope, target) = match d.scope {
                    PerfEventScope::PerCpu { cpu } => ("cpu", cpu as u64),
                    PerfEventScope::Task { pid } => ("task", pid),
                };
                let live_target = object.live_target_tid();
                writeln!(&mut text, "EVENT fd={} id={} clock={} config={} scope={} target={} task_id={} period={} generation={} enabled={} inflight={} observed={} delivered={} skipped={} cancelled={} invalid={} reentry={} helper={} budget={} transport_lost={} consumer_corrupt={} consumer_bounds={} program_id={} target_alive={} current_tid={}",
                    fd, d.id, clock, config, scope, target, d.task_id, d.period, d.generation,
                    u8::from(d.enabled), d.inflight, d.runtime.observed, d.samples.delivered_samples,
                    d.runtime.skipped_periods, d.runtime.cancelled, d.runtime.invalid,
                    d.samples.re_entry_drops, d.samples.helper_failures, d.samples.budget_failures,
                    d.transport_lost, d.consumer.corrupt_records, d.consumer.out_of_bounds, d.program_id,
                    u8::from(live_target.is_some()), live_target.unwrap_or(0)).ok()?;
                let program = event.attached_prog();
                // A concurrent detach/reattach must not pair an EVENT row for
                // program A with PROGRAM counters from B. Fail this snapshot
                // explicitly; a new open can retry with fresh state.
                if program.as_ref().map_or(0, |p| p.id()) != d.program_id { return None; }
                if let Some(program) = program { programs.insert(program.id(), program); }
                events += 1;
                if text.len() > 60 * 1024 { return None; }
            }
            let count = programs.len();
            for (id, program) in programs {
                writeln!(&mut text, "PROGRAM id={} runs={} errors={}", id, program.run_cnt(), program.runtime_errors()).ok()?;
            }
            writeln!(&mut text, "END events={} programs={}", events, count).ok()?;
            (text.len() <= 64 * 1024).then_some(text)
        }
    }

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
        } else if entry.object.as_any().is::<crate::fd::StdinObject>()
            || entry.object.as_any().is::<crate::fd::StdoutObject>()
        {
            Some("/dev/tty".to_string())
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
                    #[cfg(feature = "bpf-trace")]
                    let cached_file = crate::bpf::mappings::cached_file(mapping.file().as_ref());
                    #[cfg(not(feature = "bpf-trace"))]
                    let cached_file = mapping.file().as_any().downcast_ref::<axfs::CachedFile>();
                    if let Some(cached_file) = cached_file {
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
