use core::time::Duration;

use axerrno::LinuxError;
use linux_raw_sys::general::{
    CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC_RAW,
    CLOCK_PROCESS_CPUTIME_ID, CLOCK_REALTIME, CLOCK_REALTIME_COARSE, CLOCK_THREAD_CPUTIME_ID,
    TIMER_ABSTIME, timespec,
};

pub(crate) fn timespec_to_duration(ts: timespec) -> Result<Duration, LinuxError> {
    if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return Err(LinuxError::EINVAL);
    }
    Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

pub(crate) fn duration_to_timespec(dur: Duration) -> timespec {
    timespec {
        tv_sec: dur.as_secs() as _,
        tv_nsec: dur.subsec_nanos() as _,
    }
}

pub(crate) fn duration_to_nanos_saturating(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_mul(1_000_000_000)
        .saturating_add(duration.subsec_nanos() as u64)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClockSource {
    Realtime,
    Monotonic,
    ProcessCpu,
    ThreadCpu,
}

pub(crate) fn parse_clock(clockid: i32) -> Result<ClockSource, LinuxError> {
    match clockid as u32 {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => Ok(ClockSource::Realtime),
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => {
            Ok(ClockSource::Monotonic)
        }
        CLOCK_PROCESS_CPUTIME_ID => Ok(ClockSource::ProcessCpu),
        CLOCK_THREAD_CPUTIME_ID => Ok(ClockSource::ThreadCpu),
        _ => Err(LinuxError::EINVAL),
    }
}

pub(crate) fn validate_clock_nanosleep(clockid: i32, flags: usize) -> Result<(), LinuxError> {
    if matches!(
        clockid as u32,
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID
    ) {
        return Err(LinuxError::EOPNOTSUPP);
    }
    if !matches!(
        clockid as u32,
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME
    ) {
        return Err(LinuxError::EINVAL);
    }
    if flags != 0 && flags != TIMER_ABSTIME as usize {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use linux_raw_sys::general::{CLOCK_BOOTTIME_ALARM, CLOCK_REALTIME_ALARM, CLOCK_TAI};

    use super::*;

    #[test]
    fn ltp_clock_gettime01_clock_ids_are_supported() {
        for (clockid, source) in [
            (CLOCK_REALTIME, ClockSource::Realtime),
            (CLOCK_MONOTONIC, ClockSource::Monotonic),
            (CLOCK_PROCESS_CPUTIME_ID, ClockSource::ProcessCpu),
            (CLOCK_THREAD_CPUTIME_ID, ClockSource::ThreadCpu),
            (CLOCK_REALTIME_COARSE, ClockSource::Realtime),
            (CLOCK_MONOTONIC_COARSE, ClockSource::Monotonic),
            (CLOCK_MONOTONIC_RAW, ClockSource::Monotonic),
            (CLOCK_BOOTTIME, ClockSource::Monotonic),
        ] {
            assert_eq!(parse_clock(clockid as i32), Ok(source), "clockid={clockid}");
        }
    }

    #[test]
    fn ltp_clock_getres01_rejects_invalid_clockid() {
        assert_eq!(parse_clock(-1), Err(LinuxError::EINVAL));
        assert_eq!(parse_clock(i32::MAX), Err(LinuxError::EINVAL));
    }

    #[test]
    fn clock_getres_alarm_and_tai_clocks_remain_unsupported() {
        for clockid in [CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM, CLOCK_TAI] {
            assert_eq!(parse_clock(clockid as i32), Err(LinuxError::EINVAL));
        }
    }

    #[test]
    fn ltp_nanosleep04_rejects_negative_seconds() {
        assert_eq!(
            timespec_to_duration(timespec {
                tv_sec: -5,
                tv_nsec: 9999
            }),
            Err(LinuxError::EINVAL),
        );
    }

    #[test]
    fn ltp_nanosleep04_rejects_nanoseconds_outside_one_second() {
        for (tv_sec, tv_nsec) in [(0, 1_000_000_000), (1, -100)] {
            assert_eq!(
                timespec_to_duration(timespec { tv_sec, tv_nsec }),
                Err(LinuxError::EINVAL),
            );
        }
    }

    #[test]
    fn nanosleep_accepts_zero_and_last_valid_nanosecond() {
        for (tv_sec, tv_nsec, expected) in [
            (0, 0, Duration::ZERO),
            (0, 999_999_999, Duration::new(0, 999_999_999)),
            (1, 0, Duration::from_secs(1)),
        ] {
            assert_eq!(
                timespec_to_duration(timespec { tv_sec, tv_nsec }),
                Ok(expected)
            );
        }
    }

    #[test]
    fn timespec_round_trip_preserves_seconds_and_nanoseconds() {
        for dur in [Duration::ZERO, Duration::new(42, 123_456_789)] {
            assert_eq!(timespec_to_duration(duration_to_timespec(dur)), Ok(dur));
        }
    }

    #[test]
    fn ltp_clock_nanosleep01_rejects_invalid_nanoseconds_and_thread_clock() {
        for tv_nsec in [-1, 1_000_000_000] {
            assert_eq!(
                timespec_to_duration(timespec { tv_sec: 0, tv_nsec }),
                Err(LinuxError::EINVAL),
            );
        }
        assert_eq!(
            validate_clock_nanosleep(CLOCK_THREAD_CPUTIME_ID as i32, 0),
            Err(LinuxError::EOPNOTSUPP),
        );
    }

    #[test]
    fn clock_nanosleep_accepts_relative_and_absolute_supported_clocks() {
        for clockid in [CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_BOOTTIME] {
            for flags in [0, TIMER_ABSTIME as usize] {
                assert_eq!(validate_clock_nanosleep(clockid as i32, flags), Ok(()));
            }
        }
    }

    #[test]
    fn clock_nanosleep_rejects_invalid_clocks_and_flags() {
        for clockid in [-1, CLOCK_MONOTONIC_RAW as i32, CLOCK_REALTIME_COARSE as i32] {
            assert_eq!(
                validate_clock_nanosleep(clockid, 0),
                Err(LinuxError::EINVAL)
            );
        }
        assert_eq!(
            validate_clock_nanosleep(CLOCK_MONOTONIC as i32, usize::MAX),
            Err(LinuxError::EINVAL),
        );
        for clockid in [CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID] {
            assert_eq!(
                validate_clock_nanosleep(clockid as i32, 0),
                Err(LinuxError::EOPNOTSUPP),
            );
        }
    }

    #[test]
    fn duration_to_nanos_saturates_instead_of_wrapping() {
        assert_eq!(
            duration_to_nanos_saturating(Duration::new(2, 3)),
            2_000_000_003
        );
        assert_eq!(
            duration_to_nanos_saturating(Duration::new(u64::MAX, 999_999_999)),
            u64::MAX,
        );
    }
}
