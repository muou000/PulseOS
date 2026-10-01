use core::time::Duration;

use axerrno::LinuxError;
use linux_raw_sys::general::{POLLIN, POLLOUT, timespec};

pub(crate) fn iov_len_to_usize(iov_len: u64) -> Result<usize, LinuxError> {
    let len = usize::try_from(iov_len).map_err(|_| LinuxError::EINVAL)?;
    if len > isize::MAX as usize {
        return Err(LinuxError::EINVAL);
    }
    Ok(len)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UserIoSegment {
    pub(crate) addr: usize,
    pub(crate) len: usize,
}

/// Validates the user ranges and total byte count used by a write request.
///
/// The syscall returns a signed byte count, so the aggregate request must fit
/// in `ssize_t`. Positional requests also need an offset that can cover the
/// complete request before any I/O starts.
pub(crate) fn validate_user_io_segments(
    segments: &[UserIoSegment],
    positional_offset: Option<u64>,
) -> Result<usize, LinuxError> {
    let mut total = 0usize;
    for segment in segments {
        segment
            .addr
            .checked_add(segment.len)
            .ok_or(LinuxError::EINVAL)?;
        total = total.checked_add(segment.len).ok_or(LinuxError::EINVAL)?;
        if total > isize::MAX as usize {
            return Err(LinuxError::EINVAL);
        }
    }
    if let Some(offset) = positional_offset {
        (offset as u128)
            .checked_add(total as u128)
            .filter(|end| *end <= u64::MAX as u128)
            .ok_or(LinuxError::EINVAL)?;
    }
    Ok(total)
}

pub(crate) fn validate_direct_io(
    segments: &[UserIoSegment],
    offset: u64,
    block_size: usize,
) -> Result<(), LinuxError> {
    if block_size == 0 || !(offset as usize).is_multiple_of(block_size) {
        return Err(LinuxError::EINVAL);
    }
    for segment in segments {
        if !segment.addr.is_multiple_of(block_size) || !segment.len.is_multiple_of(block_size) {
            return Err(LinuxError::EINVAL);
        }
    }
    Ok(())
}

pub(crate) fn requested_poll_revents(events: i16, readable: bool, writable: bool) -> i16 {
    let mut revents = 0;
    if readable && events & POLLIN as i16 != 0 {
        revents |= POLLIN as i16;
    }
    if writable && events & POLLOUT as i16 != 0 {
        revents |= POLLOUT as i16;
    }
    revents
}

pub(crate) fn ppoll_timeout(ts: timespec) -> Result<Duration, LinuxError> {
    super::time::timespec_to_duration(ts)
}

#[cfg(test)]
mod tests {
    use linux_raw_sys::general::{POLLPRI, POLLRDHUP};

    use super::*;

    #[test]
    fn ltp_poll01_reports_only_requested_readiness() {
        assert_eq!(
            requested_poll_revents(POLLOUT as i16, false, true),
            POLLOUT as i16
        );
        assert_eq!(
            requested_poll_revents(POLLIN as i16, true, false),
            POLLIN as i16
        );
        assert_eq!(requested_poll_revents(POLLIN as i16, false, true), 0);
        assert_eq!(requested_poll_revents(POLLOUT as i16, true, false), 0);
        assert_eq!(requested_poll_revents(0, true, true), 0);
    }

    #[test]
    fn ltp_ppoll01_regular_file_readiness_ignores_unsupported_events() {
        let events = (POLLIN | POLLPRI | POLLOUT | POLLRDHUP) as i16;
        assert_eq!(
            requested_poll_revents(events, true, true),
            (POLLIN | POLLOUT) as i16
        );
    }

    #[test]
    fn ppoll_timeout_rejects_negative_and_unnormalized_timespec() {
        for (tv_sec, tv_nsec) in [(-1, 0), (0, -1), (0, 1_000_000_000)] {
            assert_eq!(
                ppoll_timeout(timespec { tv_sec, tv_nsec }),
                Err(LinuxError::EINVAL)
            );
        }
        assert_eq!(
            ppoll_timeout(timespec {
                tv_sec: 0,
                tv_nsec: 0
            }),
            Ok(Duration::ZERO)
        );
        assert_eq!(
            ppoll_timeout(timespec {
                tv_sec: 2,
                tv_nsec: 0
            }),
            Ok(Duration::from_secs(2)),
        );
    }

    #[test]
    fn user_io_segments_reject_overflow_and_signed_count_overflow() {
        assert_eq!(
            validate_user_io_segments(
                &[UserIoSegment {
                    addr: usize::MAX,
                    len: 1,
                }],
                None,
            ),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_user_io_segments(
                &[
                    UserIoSegment {
                        addr: 0,
                        len: isize::MAX as usize,
                    },
                    UserIoSegment { addr: 0, len: 1 }
                ],
                None,
            ),
            Err(LinuxError::EINVAL)
        );
    }

    #[test]
    fn positional_user_io_segments_must_fit_the_file_offset() {
        assert_eq!(
            validate_user_io_segments(
                &[UserIoSegment {
                    addr: 0x1000,
                    len: 4096
                }],
                Some(u64::MAX - 4096),
            ),
            Ok(4096)
        );
        assert_eq!(
            validate_user_io_segments(
                &[UserIoSegment {
                    addr: 0x1000,
                    len: 4096
                }],
                Some(u64::MAX - 4095),
            ),
            Err(LinuxError::EINVAL)
        );
    }

    #[test]
    fn direct_io_alignment_applies_to_every_segment() {
        let aligned = [
            UserIoSegment {
                addr: 0x2000,
                len: 4096,
            },
            UserIoSegment {
                addr: 0x4000,
                len: 0,
            },
        ];
        assert_eq!(validate_direct_io(&aligned, 0, 4096), Ok(()));
        assert_eq!(
            validate_direct_io(&aligned, 1, 4096),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_direct_io(
                &[UserIoSegment {
                    addr: 0x2001,
                    len: 4096,
                }],
                0,
                4096,
            ),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_direct_io(
                &[UserIoSegment {
                    addr: 0x2000,
                    len: 1,
                }],
                0,
                4096,
            ),
            Err(LinuxError::EINVAL)
        );
    }
}
