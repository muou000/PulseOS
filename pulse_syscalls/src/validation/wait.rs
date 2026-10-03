use axerrno::LinuxError;
use linux_raw_sys::general::{P_ALL, P_PGID, P_PID, WCONTINUED, WEXITED, WUNTRACED};

pub(crate) fn validate_wait4_pid(pid: isize) -> Result<(), LinuxError> {
    if pid as i32 == i32::MIN {
        Err(LinuxError::ESRCH)
    } else {
        Ok(())
    }
}

pub(crate) fn wait4_selector(pid: isize) -> (usize, usize) {
    match pid {
        -1 => (P_ALL as usize, 0),
        0 => (P_PGID as usize, 0),
        pid if pid > 0 => (P_PID as usize, pid as usize),
        pid => (P_PGID as usize, pid.unsigned_abs()),
    }
}

pub(crate) fn wait_status_stopped(signo: i32) -> i32 {
    ((signo & 0xff) << 8) | 0x7f
}

pub(crate) fn wait_status_continued() -> i32 {
    0xffff
}

pub(crate) fn validate_waitid_options(options: i32) -> Result<(), LinuxError> {
    if options & (WEXITED | WUNTRACED | WCONTINUED) as i32 == 0 {
        Err(LinuxError::EINVAL)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use linux_raw_sys::general::WNOHANG;

    use super::*;

    #[test]
    fn ltp_wait403_rejects_int_min_without_negation_overflow() {
        assert_eq!(
            validate_wait4_pid(i32::MIN as isize),
            Err(LinuxError::ESRCH)
        );
        assert_eq!(validate_wait4_pid(-42), Ok(()));
    }

    #[test]
    fn ltp_waitid02_rejects_options_without_child_state_selection() {
        assert_eq!(validate_waitid_options(0), Err(LinuxError::EINVAL));
        assert_eq!(
            validate_waitid_options(WNOHANG as i32),
            Err(LinuxError::EINVAL)
        );
        for options in [WEXITED, WUNTRACED, WCONTINUED, WEXITED | WNOHANG] {
            assert_eq!(validate_waitid_options(options as i32), Ok(()));
        }
    }

    #[test]
    fn wait4_selectors_match_linux_pid_and_process_group_rules() {
        assert_eq!(wait4_selector(-1), (P_ALL as usize, 0));
        assert_eq!(wait4_selector(0), (P_PGID as usize, 0));
        assert_eq!(wait4_selector(42), (P_PID as usize, 42));
        assert_eq!(wait4_selector(-42), (P_PGID as usize, 42));
    }

    #[test]
    fn wait_status_words_match_linux_job_control_encoding() {
        assert_eq!(wait_status_stopped(19), 0x137f);
        assert_eq!(wait_status_continued(), 0xffff);
    }
}
