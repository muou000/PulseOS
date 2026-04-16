use axerrno::LinuxError;

use pulse_core::task::current_thread;

use super::common::write_user_i32;

pub fn sys_wait4(pid: isize, status: usize, options: i32, rusage: usize) -> isize {
    axlog::debug!(
        "sys_wait4: pid={}, status={:#x}, options={}, rusage={:#x}",
        pid,
        status,
        options,
        rusage
    );
    let thread = match current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();

    loop {
        if !process.has_matching_child(pid) {
            return -LinuxError::ECHILD.code() as isize;
        }

        if let Some(child_proc) = process.reap_zombie_child(pid) {
            let exited_pid = child_proc.pid() as isize;
            let exit_code = child_proc.exit_code();
            let now_ns = axhal::time::monotonic_time_nanos() as u64;
            let (child_utime_ns, child_stime_ns) = child_proc.snapshot_cpu_time_ns(now_ns);
            process.add_child_time_ns(child_utime_ns, child_stime_ns);

            if status != 0 {
                // In Linux, WIFEXITED is true and WEXITSTATUS is `exit_code & 0xff`,
                // so the status word is `(exit_code & 0xff) << 8`.
                let wait_status = (exit_code & 0xff) << 8;
                let write_result = write_user_i32(process, status, wait_status);
                if write_result < 0 {
                    process.add_child(child_proc);
                    return write_result;
                }
            }
            if rusage != 0 {
                // Not supported yet: simply ignore or zero out
            }
            child_proc.wait_task_refs_exited();
            child_proc.release_task_refs();
            // Keep a bounded cache of reaped child process objects, but release
            // heavy user resources first to prevent fork/exec workloads from
            // exhausting memory.
            if let Err(e) = child_proc.shrink_reaped_resources() {
                axlog::warn!("failed to shrink reaped child resources: {:?}", e);
            }
            process.stash_reaped_child(child_proc);
            return exited_pid;
        }

        // No matching child has exited yet.
        // options & WNOHANG == 1
        if (options & 1) != 0 {
            return 0; // WNOHANG
        }

        process.wait_for_child_exit(pid);
    }
}
