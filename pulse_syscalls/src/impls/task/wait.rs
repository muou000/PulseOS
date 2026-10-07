use axerrno::LinuxError;
use linux_raw_sys::general::{
    CLD_CONTINUED, CLD_STOPPED, P_ALL, P_PGID, P_PID, SIGCONT, WCONTINUED, WEXITED, WNOHANG,
    WUNTRACED,
};
use pulse_core::task::{Process, WaitidStatusType, current_thread, signal_info_for_child};

use super::common::write_user_i32;
use crate::validation::wait::{
    validate_wait4_pid, validate_waitid_options, wait_status_continued, wait_status_stopped,
    wait4_selector,
};

fn job_control_wait4_status_word(status_type: WaitidStatusType) -> Option<i32> {
    match status_type {
        WaitidStatusType::Exited { .. } => None,
        WaitidStatusType::Stopped { signo } => Some(wait_status_stopped(signo)),
        WaitidStatusType::Continued => Some(wait_status_continued()),
    }
}
fn wait4_status_word(child: &Process, status_type: WaitidStatusType) -> i32 {
    job_control_wait4_status_word(status_type).unwrap_or_else(|| child.wait_status_word())
}

pub fn sys_wait4(pid: isize, status: usize, options: i32, rusage: usize) -> isize {
    axlog::debug!(
        "sys_wait4: pid={}, status={:#x}, options={}, rusage={:#x}",
        pid,
        status,
        options,
        rusage
    );
    if let Err(e) = validate_wait4_pid(pid) {
        return -e.code() as isize;
    }
    let thread = match current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();
    let (idtype, id) = wait4_selector(pid);
    let wait_options = WEXITED as i32 | (options & (WNOHANG | WUNTRACED | WCONTINUED) as i32);

    match process.wait_child(idtype, id, wait_options) {
        Ok(Some(claim)) => {
            let waited_pid = claim.child.pid() as isize;

            if status != 0 {
                let wait_status = wait4_status_word(claim.child.as_ref(), claim.status);
                let write_result = write_user_i32(&process, status, wait_status);
                if write_result < 0 {
                    if claim.reaped {
                        process.retire_reaped_child(claim.child);
                    }
                    return write_result;
                }
            }

            if claim.reaped {
                process.retire_reaped_child(claim.child);
            }
            if rusage != 0 {
                // Not supported yet: simply ignore or zero out.
            }
            waited_pid
        }
        Ok(None) => 0,
        Err(err_code) => err_code,
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

    if let Err(e) = validate_waitid_options(options) {
        return -e.code() as isize;
    }

    let thread = match current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();

    match process.wait_child(idtype, id, options) {
        Ok(Some(claim)) => {
            let (code, status) = match claim.status {
                WaitidStatusType::Exited {
                    exit_code,
                    exit_signal,
                } => Process::exit_siginfo_status(exit_code, exit_signal),
                WaitidStatusType::Stopped { signo } => (CLD_STOPPED as i32, signo),
                WaitidStatusType::Continued => (CLD_CONTINUED as i32, SIGCONT as i32),
            };
            let raw = signal_info_for_child(claim.child.pid(), claim.child.ruid(), code, status);

            if infop != 0 && process.write_user_bytes(infop, &raw).is_err() {
                if claim.reaped {
                    process.retire_reaped_child(claim.child);
                }
                return -LinuxError::EFAULT.code() as isize;
            }

            if claim.reaped {
                process.retire_reaped_child(claim.child);
            }

            0
        }
        Ok(None) => {
            if infop != 0 {
                let raw: linux_raw_sys::general::siginfo = unsafe { core::mem::zeroed() };
                if pulse_core::task::uaccess::write_user_plain(&process, infop, &raw).is_err() {
                    return -LinuxError::EFAULT.code() as isize;
                }
            }
            0
        }
        Err(err_code) => err_code,
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
