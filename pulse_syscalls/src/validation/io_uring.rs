//! Host-testable syscall argument validation helpers for `io_uring`.

use core::time::Duration;

use axerrno::LinuxError;
use linux_raw_sys::io_uring::{__kernel_timespec, io_uring_getevents_arg};

use pulse_io_uring_core::whitelist::validate_enter_flags;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EnterArgKind {
    None,
    LegacySigmask { sigmask_ptr: usize },
    ExtArg { arg_ptr: usize },
}

pub(crate) fn validate_enter_args(
    flags: u32,
    argp: usize,
    argsz: usize,
) -> Result<EnterArgKind, LinuxError> {
    validate_enter_flags(flags)?;
    if flags & linux_raw_sys::io_uring::IORING_ENTER_EXT_ARG != 0 {
        if argsz != core::mem::size_of::<io_uring_getevents_arg>() {
            return Err(LinuxError::EINVAL);
        }
        if argp == 0 {
            return Err(LinuxError::EFAULT);
        }
        Ok(EnterArgKind::ExtArg { arg_ptr: argp })
    } else if argp != 0 {
        if argsz != core::mem::size_of::<u64>() {
            return Err(LinuxError::EINVAL);
        }
        Ok(EnterArgKind::LegacySigmask { sigmask_ptr: argp })
    } else {
        Ok(EnterArgKind::None)
    }
}

pub(crate) fn validate_getevents_arg(
    arg: &io_uring_getevents_arg,
) -> Result<(Option<usize>, Option<usize>), LinuxError> {
    if arg.min_wait_usec != 0 {
        return Err(LinuxError::EINVAL);
    }
    let sigmask_ptr = if arg.sigmask != 0 {
        if arg.sigmask_sz as usize != core::mem::size_of::<u64>() {
            return Err(LinuxError::EINVAL);
        }
        Some(arg.sigmask as usize)
    } else {
        None
    };
    let ts_ptr = if arg.ts != 0 {
        Some(arg.ts as usize)
    } else {
        None
    };
    Ok((sigmask_ptr, ts_ptr))
}

pub(crate) fn validate_kernel_timespec(ts: &__kernel_timespec) -> Result<Duration, LinuxError> {
    if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return Err(LinuxError::EINVAL);
    }
    Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

pub(crate) fn decide_enter_return(
    submitted: u32,
    cq_ready: u32,
    _min_complete: u32,
    wait_err: Option<LinuxError>,
    pending_ebadr: bool,
) -> Result<usize, LinuxError> {
    if submitted > 0 {
        return Ok(submitted as usize);
    }
    if cq_ready > 0 {
        return Ok(0);
    }
    if let Some(err) = wait_err {
        return Err(err);
    }
    if pending_ebadr {
        return Err(LinuxError::EBADR);
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use linux_raw_sys::io_uring::{
        IORING_ENTER_EXT_ARG, IORING_ENTER_GETEVENTS, IORING_ENTER_SQ_WAKEUP,
    };

    #[test]
    fn validates_enter_flags_and_ext_arg_envelope() {
        assert_eq!(validate_enter_args(0, 0, 999), Ok(EnterArgKind::None));
        assert_eq!(
            validate_enter_args(IORING_ENTER_GETEVENTS, 0, 123),
            Ok(EnterArgKind::None)
        );
        assert_eq!(
            validate_enter_args(0, 0x1000, 8),
            Ok(EnterArgKind::LegacySigmask {
                sigmask_ptr: 0x1000
            })
        );
        assert_eq!(
            validate_enter_args(0, 0x1000, 16),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_enter_args(IORING_ENTER_EXT_ARG, 0x2000, 24),
            Ok(EnterArgKind::ExtArg { arg_ptr: 0x2000 })
        );
        assert_eq!(
            validate_enter_args(IORING_ENTER_EXT_ARG, 0x2000, 8),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_enter_args(IORING_ENTER_EXT_ARG, 0, 24),
            Err(LinuxError::EFAULT)
        );
        assert_eq!(
            validate_enter_args(IORING_ENTER_SQ_WAKEUP, 0, 0),
            Ok(EnterArgKind::None)
        );
    }

    #[test]
    fn validates_getevents_arg_and_timespec() {
        let good = io_uring_getevents_arg {
            sigmask: 0x1000,
            sigmask_sz: 8,
            min_wait_usec: 0,
            ts: 0x2000,
        };
        assert_eq!(
            validate_getevents_arg(&good),
            Ok((Some(0x1000), Some(0x2000)))
        );

        let no_ptrs = io_uring_getevents_arg {
            sigmask: 0,
            sigmask_sz: 0,
            min_wait_usec: 0,
            ts: 0,
        };
        assert_eq!(validate_getevents_arg(&no_ptrs), Ok((None, None)));

        let bad_min_wait = io_uring_getevents_arg {
            min_wait_usec: 1,
            ..no_ptrs
        };
        assert_eq!(validate_getevents_arg(&bad_min_wait), Err(LinuxError::EINVAL));

        let bad_sig_sz = io_uring_getevents_arg {
            sigmask: 0x1000,
            sigmask_sz: 4,
            ..no_ptrs
        };
        assert_eq!(validate_getevents_arg(&bad_sig_sz), Err(LinuxError::EINVAL));

        assert_eq!(
            validate_kernel_timespec(&__kernel_timespec {
                tv_sec: 1,
                tv_nsec: 500_000_000,
            }),
            Ok(Duration::new(1, 500_000_000))
        );
        for (sec, nsec) in [(-1, 0), (0, -1), (0, 1_000_000_000)] {
            assert_eq!(
                validate_kernel_timespec(&__kernel_timespec {
                    tv_sec: sec,
                    tv_nsec: nsec,
                }),
                Err(LinuxError::EINVAL)
            );
        }
    }

    #[test]
    fn enter_return_precedence_prefers_submitted_and_satisfied_cq_over_wait_errors() {
        assert_eq!(
            decide_enter_return(3, 0, 1, Some(LinuxError::ETIME), true),
            Ok(3)
        );
        assert_eq!(
            decide_enter_return(0, 1, 1, Some(LinuxError::EINTR), true),
            Ok(0)
        );
        // Even if cq_ready < min_complete, any available CQE wins over wait_err (ADR-0002 / #231).
        assert_eq!(
            decide_enter_return(0, 1, 2, Some(LinuxError::ETIME), false),
            Ok(0)
        );
        assert_eq!(
            decide_enter_return(0, 0, 2, Some(LinuxError::ETIME), false),
            Err(LinuxError::ETIME)
        );
        assert_eq!(decide_enter_return(0, 1, 0, None, true), Ok(0));
        assert_eq!(
            decide_enter_return(0, 0, 0, None, true),
            Err(LinuxError::EBADR)
        );
        assert_eq!(decide_enter_return(0, 0, 0, None, false), Ok(0));
    }
}
