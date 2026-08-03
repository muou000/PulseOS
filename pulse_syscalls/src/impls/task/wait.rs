use alloc::sync::Arc;

use axerrno::LinuxError;
use linux_raw_sys::general::{
    CLD_CONTINUED, CLD_DUMPED, CLD_EXITED, CLD_KILLED, CLD_STOPPED, P_ALL, P_PGID, P_PID,
    SIGCONT, WCONTINUED, WEXITED, WNOHANG, WNOWAIT, WUNTRACED,
};
use pulse_core::task::{Process, WaitidStatusType, current_thread, signal_info_for_child};

use super::common::write_user_i32;

fn wait4_selector(pid: isize) -> (usize, usize) {
    match pid {
        -1 => (P_ALL as usize, 0),
        0 => (P_PGID as usize, 0),
        pid if pid > 0 => (P_PID as usize, pid as usize),
        pid => (P_PGID as usize, pid.unsigned_abs()),
    }
}

fn job_control_wait4_status_word(status_type: WaitidStatusType) -> Option<i32> {
    match status_type {
        WaitidStatusType::Exited { .. } => None,
        WaitidStatusType::Stopped { signo } => Some(((signo & 0xff) << 8) | 0x7f),
        WaitidStatusType::Continued => Some(0xffff),
    }
}

fn wait4_status_word(child: &Process, status_type: WaitidStatusType) -> i32 {
    job_control_wait4_status_word(status_type).unwrap_or_else(|| child.wait_status_word())
}

fn finish_reaped_child(parent: &Process, child: Arc<Process>) {
    let exited_pid = child.pid() as isize;
    let now_ns = axhal::time::monotonic_time_nanos() as u64;
    let (child_utime_ns, child_stime_ns) = child.snapshot_cpu_time_ns(now_ns);
    parent.add_child_time_ns(child_utime_ns, child_stime_ns);
    child.wait_task_refs_exited();
    let _ = child.take_task_ref_by_tid(exited_pid as u64);
    if let Err(e) = child.shrink_reaped_resources() {
        axlog::warn!("failed to shrink reaped child resources: {:?}", e);
    }
    child.release_task_refs();
    pulse_core::task::unregister_process(exited_pid as u64);
}

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
    let (idtype, id) = wait4_selector(pid);
    let wait_options =
        WEXITED as i32 | (options & (WNOHANG | WUNTRACED | WCONTINUED) as i32);

    loop {
        match process.waitid_find_and_reap(idtype, id, wait_options) {
            Ok(Some((child, status_type))) => {
                let waited_pid = child.pid() as isize;
                let reaped = matches!(status_type, WaitidStatusType::Exited { .. });

                if status != 0 {
                    let wait_status = wait4_status_word(child.as_ref(), status_type);
                    let write_result = write_user_i32(&process, status, wait_status);
                    if write_result < 0 {
                        if reaped {
                            finish_reaped_child(process.as_ref(), child);
                        }
                        return write_result;
                    }
                }

                if reaped {
                    finish_reaped_child(process.as_ref(), child);
                }
                if rusage != 0 {
                    // Not supported yet: simply ignore or zero out.
                }
                return waited_pid;
            }
            Ok(None) => {
                if (options & WNOHANG as i32) != 0 {
                    return 0;
                }
                if let Err(e) =
                    process.wait_for_child_state_change_interruptible(idtype, id, wait_options)
                {
                    return -e as isize;
                }
            }
            Err(err_code) => return err_code,
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

    let wait_flags = (WEXITED | WUNTRACED | WCONTINUED) as i32;
    if (options & wait_flags) == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let thread = match current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();

    loop {
        match process.waitid_find_and_reap(idtype, id, options) {
            Ok(Some((child, status_type))) => {
                let was_zombie_and_reaped = matches!(status_type, WaitidStatusType::Exited { .. })
                    && (options & WNOWAIT as i32) == 0;

                let (code, status) = match status_type {
                    WaitidStatusType::Exited {
                        exit_code,
                        exit_signal,
                    } if exit_signal == 0 => (CLD_EXITED as i32, exit_code & 0xff),
                    WaitidStatusType::Exited { exit_signal, .. } => (
                        if (exit_signal & 0x100) != 0 {
                            CLD_DUMPED as i32
                        } else {
                            CLD_KILLED as i32
                        },
                        exit_signal & 0x7f,
                    ),
                    WaitidStatusType::Stopped { signo } => (CLD_STOPPED as i32, signo),
                    WaitidStatusType::Continued => (CLD_CONTINUED as i32, SIGCONT as i32),
                };
                let raw = signal_info_for_child(child.pid(), child.ruid(), code, status);

                if infop != 0
                    && process.write_user_bytes(infop, &raw).is_err()
                {
                    if was_zombie_and_reaped {
                        finish_reaped_child(process.as_ref(), child);
                    }
                    return -LinuxError::EFAULT.code() as isize;
                }

                if was_zombie_and_reaped {
                    finish_reaped_child(process.as_ref(), child);
                }

                return 0;
            }
            Ok(None) => {
                if (options & WNOHANG as i32) != 0 {
                    if infop != 0 {
                        let raw: linux_raw_sys::general::siginfo = unsafe { core::mem::zeroed() };
                        if pulse_core::task::uaccess::write_user_plain(&process, infop, &raw)
                            .is_err()
                        {
                            return -LinuxError::EFAULT.code() as isize;
                        }
                    }
                    return 0;
                }

                if let Err(e) =
                    process.wait_for_child_state_change_interruptible(idtype, id, options)
                {
                    return -e as isize;
                }
            }
            Err(err_code) => {
                return err_code;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait4_status_words_match_linux_job_control_encoding() {
        assert_eq!(
            job_control_wait4_status_word(WaitidStatusType::Stopped { signo: 19 }),
            Some(0x137f),
        );
        assert_eq!(
            job_control_wait4_status_word(WaitidStatusType::Continued),
            Some(0xffff),
        );
    }

    #[test]
    fn wait4_pid_selector_preserves_pid_and_process_group_rules() {
        assert_eq!(wait4_selector(-1), (P_ALL as usize, 0));
        assert_eq!(wait4_selector(0), (P_PGID as usize, 0));
        assert_eq!(wait4_selector(42), (P_PID as usize, 42));
        assert_eq!(wait4_selector(-42), (P_PGID as usize, 42));
    }
}
