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
            let _exit_code = child_proc.exit_code();
            let now_ns = axhal::time::monotonic_time_nanos() as u64;
            let (child_utime_ns, child_stime_ns) = child_proc.snapshot_cpu_time_ns(now_ns);
            process.add_child_time_ns(child_utime_ns, child_stime_ns);
            child_proc.wait_task_refs_exited();

            if status != 0 {
                // 使用 Process 统一计算 wait status word，正确区分：
                //   正常退出: (exit_code & 0xff) << 8  → WIFEXITED 为真
                //   信号终止: signo & 0x7f             → WIFSIGNALED 为真
                //   信号终止+core dump: signo | 0x80   → WCOREDUMP 也为真
                let wait_status = child_proc.wait_status_word();
                let write_result = write_user_i32(process, status, wait_status);
                if write_result < 0 {
                    process.add_child(child_proc);
                    return write_result;
                }
            }
            if rusage != 0 {
                // Not supported yet: simply ignore or zero out
            }
            let _ = child_proc.take_task_ref_by_tid(exited_pid as u64);
            // Release heavy user resources before the final Arc drops so the
            // zombie no longer pins a large address space or fd table.
            if let Err(e) = child_proc.shrink_reaped_resources() {
                axlog::warn!("failed to shrink reaped child resources: {:?}", e);
            }
            child_proc.release_task_refs();
            return exited_pid;
        }

        // No matching child has exited yet.
        // options & WNOHANG == 1
        if (options & 1) != 0 {
            return 0; // WNOHANG
        }

        if let Err(e) = process.wait_for_child_exit_interruptible(pid) {
            return -(e as isize);
        }
    }
}
