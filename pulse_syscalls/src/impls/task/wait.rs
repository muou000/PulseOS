use axerrno::LinuxError;
use pulse_core::task::{current_thread, WaitidStatusType};

use super::common::write_user_i32;

pub fn sys_wait4(pid: isize, status: usize, options: i32, rusage: usize) -> isize {
    axlog::debug!(
        "sys_wait4: pid={}, status={:#x}, options={}, rusage={:#x}",
        pid,
        status,
        options,
        rusage
    );
    if pid as i32 == i32::MIN {
        return -LinuxError::ESRCH.code() as isize;
    }
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

pub fn sys_waitid(idtype: usize, id: usize, infop: usize, options: i32) -> isize {
    axlog::debug!(
        "sys_waitid: idtype={}, id={}, infop={:#x}, options={:#x}",
        idtype,
        id,
        infop,
        options
    );

    let wait_flags = 4 | 2 | 8; // WEXITED | WSTOPPED | WCONTINUED
    if (options & wait_flags) == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if infop == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let thread = match current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();

    loop {
        match process.waitid_find_and_reap(idtype, id, options) {
            Ok(Some((child, status_type))) => {
                let was_zombie_and_reaped = matches!(status_type, WaitidStatusType::Exited { .. }) && (options & 0x01000000) == 0;
                if was_zombie_and_reaped {
                    let exited_pid = child.pid() as isize;
                    let now_ns = axhal::time::monotonic_time_nanos() as u64;
                    let (child_utime_ns, child_stime_ns) = child.snapshot_cpu_time_ns(now_ns);
                    process.add_child_time_ns(child_utime_ns, child_stime_ns);
                    child.wait_task_refs_exited();
                    let _ = child.take_task_ref_by_tid(exited_pid as u64);
                    if let Err(e) = child.shrink_reaped_resources() {
                        axlog::warn!("failed to shrink reaped child resources: {:?}", e);
                    }
                    child.release_task_refs();
                }

                let mut raw: linux_raw_sys::general::siginfo = unsafe { core::mem::zeroed() };
                unsafe {
                    let anon1 = &mut raw.__bindgen_anon_1.__bindgen_anon_1;
                    anon1.si_signo = 17; // SIGCHLD
                    anon1.si_errno = 0;

                    match status_type {
                        WaitidStatusType::Exited { exit_code, exit_signal } => {
                            if exit_signal == 0 {
                                anon1.si_code = 1; // CLD_EXITED
                                anon1._sifields._sigchld._status = exit_code;
                            } else {
                                let is_coredump = (exit_signal & 0x100) != 0;
                                anon1.si_code = if is_coredump { 3 } else { 2 }; // CLD_DUMPED or CLD_KILLED
                                anon1._sifields._sigchld._status = exit_signal & 0x7f;
                            }
                        }
                        WaitidStatusType::Stopped { signo } => {
                            anon1.si_code = 5; // CLD_STOPPED
                            anon1._sifields._sigchld._status = signo;
                        }
                        WaitidStatusType::Continued => {
                            anon1.si_code = 6; // CLD_CONTINUED
                            anon1._sifields._sigchld._status = 18; // SIGCONT
                        }
                    }

                    anon1._sifields._sigchld._pid = child.pid() as i32;
                    anon1._sifields._sigchld._uid = child.ruid();
                }

                if let Err(_) = pulse_core::task::uaccess::write_user_plain(process, infop, &raw) {
                    if was_zombie_and_reaped {
                        process.add_child(child);
                    }
                    return -LinuxError::EFAULT.code() as isize;
                }

                return 0;
            }
            Ok(None) => {
                if (options & 1) != 0 {
                    let raw: linux_raw_sys::general::siginfo = unsafe { core::mem::zeroed() };
                    if let Err(_) = pulse_core::task::uaccess::write_user_plain(process, infop, &raw) {
                        return -LinuxError::EFAULT.code() as isize;
                    }
                    return 0;
                }

                if let Err(e) = process.wait_for_child_state_change_interruptible(idtype, id, options) {
                    return -e as isize;
                }
            }
            Err(err_code) => {
                return err_code;
            }
        }
    }
}
