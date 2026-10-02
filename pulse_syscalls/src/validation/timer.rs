use axerrno::LinuxError;
use linux_raw_sys::general::{timespec, timeval};
const ADJ_MICRO: u32 = 0x1000;
const ADJ_NANO: u32 = 0x2000;
const ADJ_OFFSET_SINGLESHOT: u32 = 0x8001;
const ADJ_OFFSET_SS_READ: u32 = 0xa001;

pub(crate) fn timeval_to_ns(tv: &timeval) -> Option<u64> {
    if tv.tv_sec < 0 || tv.tv_usec < 0 || tv.tv_usec >= 1_000_000 {
        return None;
    }
    let sec_ns = (tv.tv_sec as u64).checked_mul(1_000_000_000)?;
    sec_ns.checked_add((tv.tv_usec as u64).checked_mul(1_000)?)
}

pub(crate) fn ns_to_timeval(ns: u64) -> timeval {
    timeval {
        tv_sec: (ns / 1_000_000_000) as _,
        tv_usec: ((ns % 1_000_000_000) / 1_000) as _,
    }
}

pub(crate) fn ns_to_timespec(ns: u64) -> timespec {
    timespec {
        tv_sec: (ns / 1_000_000_000) as _,
        tv_nsec: (ns % 1_000_000_000) as _,
    }
}

pub(crate) fn ns_to_clk_ticks(ns: u64) -> u64 {
    ns.saturating_mul(100) / 1_000_000_000
}

pub(crate) fn valid_adjtimex_modes(modes: u32) -> bool {
    const ADJ_OFFSET: u32 = 0x0001;
    const ADJ_FREQUENCY: u32 = 0x0002;
    const ADJ_MAXERROR: u32 = 0x0004;
    const ADJ_ESTERROR: u32 = 0x0008;
    const ADJ_STATUS: u32 = 0x0010;
    const ADJ_TIMECONST: u32 = 0x0020;
    const ADJ_TICK: u32 = 0x4000;
    let mask = ADJ_OFFSET
        | ADJ_FREQUENCY
        | ADJ_MAXERROR
        | ADJ_ESTERROR
        | ADJ_STATUS
        | ADJ_TIMECONST
        | ADJ_MICRO
        | ADJ_NANO
        | ADJ_TICK;
    if modes == ADJ_OFFSET_SINGLESHOT || modes == ADJ_OFFSET_SS_READ {
        return true;
    }
    modes & !mask == 0 && modes & (ADJ_MICRO | ADJ_NANO) != (ADJ_MICRO | ADJ_NANO)
}

pub(crate) fn validate_adjtimex_tick(tick: i64) -> Result<(), LinuxError> {
    if !(9000..=11000).contains(&tick) {
        Err(LinuxError::EINVAL)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn itimer_rejects_invalid_timeval_values() {
        assert_eq!(
            timeval_to_ns(&timeval {
                tv_sec: -1,
                tv_usec: 0
            }),
            None
        );
        assert_eq!(
            timeval_to_ns(&timeval {
                tv_sec: 0,
                tv_usec: -1
            }),
            None
        );
        assert_eq!(
            timeval_to_ns(&timeval {
                tv_sec: 0,
                tv_usec: 1_000_000
            }),
            None
        );
    }

    #[test]
    fn itimer_timeval_conversion_round_trips_valid_values() {
        for ns in [0, 1_000, 1_000_000_001, u64::MAX] {
            let tv = ns_to_timeval(ns);
            assert_eq!(timeval_to_ns(&tv), Some((ns / 1_000) * 1_000));
        }
    }

    #[test]
    fn timer_timespec_conversion_keeps_subsecond_precision() {
        assert_eq!(
            {
                let value = ns_to_timespec(1_234_567_890);
                (value.tv_sec, value.tv_nsec)
            },
            (1, 234_567_890)
        );
    }

    #[test]
    fn clock_ticks_use_hundred_hz_and_saturate() {
        assert_eq!(ns_to_clk_ticks(1_000_000_000), 100);
        assert_eq!(ns_to_clk_ticks(u64::MAX), u64::MAX / 1_000_000_000);
    }

    #[test]
    fn adjtimex_rejects_unknown_and_conflicting_modes() {
        assert!(!valid_adjtimex_modes(ADJ_MICRO | ADJ_NANO));
        assert!(!valid_adjtimex_modes(1 << 31));
        assert!(valid_adjtimex_modes(ADJ_OFFSET_SINGLESHOT));
        assert!(valid_adjtimex_modes(ADJ_OFFSET_SS_READ));
    }

    #[test]
    fn ltp_adjtimex02_rejects_tick_outside_kernel_range() {
        assert_eq!(validate_adjtimex_tick(8999), Err(LinuxError::EINVAL));
        assert_eq!(validate_adjtimex_tick(11001), Err(LinuxError::EINVAL));
        assert_eq!(validate_adjtimex_tick(9000), Ok(()));
        assert_eq!(validate_adjtimex_tick(11000), Ok(()));
    }
}
