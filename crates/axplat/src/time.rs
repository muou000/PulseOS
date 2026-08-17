//! Time-related operations.

pub use core::time::Duration;

/// A measurement of the system clock.
///
/// Currently, it reuses the [`core::time::Duration`] type. But it does not
/// represent a duration, but a clock time.
pub type TimeValue = Duration;

/// Number of milliseconds in a second.
pub const MILLIS_PER_SEC: u64 = 1_000;
/// Number of microseconds in a second.
pub const MICROS_PER_SEC: u64 = 1_000_000;
/// Number of nanoseconds in a second.
pub const NANOS_PER_SEC: u64 = 1_000_000_000;
/// Number of nanoseconds in a millisecond.
pub const NANOS_PER_MILLIS: u64 = 1_000_000;
/// Number of nanoseconds in a microsecond.
pub const NANOS_PER_MICROS: u64 = 1_000;

const MIN_TIMER_TICKS: u64 = 4;
const TIMER_TICK_MASK: u64 = MIN_TIMER_TICKS - 1;

/// Computes a hardware timer interval for a one-shot deadline.
///
/// The interval is rounded up to the hardware's four-tick programming
/// granularity, clamped to the timer width, and never allowed to expire
/// immediately. Platforms can use this helper when their timer register has
/// the same minimum interval and alignment contract.
pub const fn oneshot_delta_ticks(now: u64, deadline: u64, timer_bits: usize) -> u64 {
    let aligned = align_timer_ticks(deadline.saturating_sub(now));
    let maximum = max_timer_ticks(timer_bits);
    if aligned > maximum { maximum } else { aligned }
}

const fn align_timer_ticks(ticks: u64) -> u64 {
    let ticks = if ticks < MIN_TIMER_TICKS {
        MIN_TIMER_TICKS
    } else {
        ticks
    };
    ticks.saturating_add(TIMER_TICK_MASK) & !TIMER_TICK_MASK
}

const fn max_timer_ticks(timer_bits: usize) -> u64 {
    let timer_bits = if timer_bits < 3 {
        3
    } else if timer_bits > u64::BITS as usize {
        u64::BITS as usize
    } else {
        timer_bits
    };
    let mask = if timer_bits == u64::BITS as usize {
        u64::MAX
    } else {
        (1_u64 << timer_bits) - 1
    };
    mask & !TIMER_TICK_MASK
}

#[cfg(test)]
mod tests {
    use super::oneshot_delta_ticks;

    #[test]
    fn uses_minimum_delay_for_expired_deadlines() {
        assert_eq!(oneshot_delta_ticks(100, 99, 48), 4);
        assert_eq!(oneshot_delta_ticks(100, 100, 48), 4);
        assert_eq!(oneshot_delta_ticks(100, 101, 48), 4);
    }

    #[test]
    fn rounds_deadline_up_to_tcfg_granularity() {
        assert_eq!(oneshot_delta_ticks(100, 104, 48), 4);
        assert_eq!(oneshot_delta_ticks(100, 105, 48), 8);
        assert_eq!(oneshot_delta_ticks(100, 108, 48), 8);
    }

    #[test]
    fn clamps_to_hardware_timer_width() {
        assert_eq!(oneshot_delta_ticks(0, u64::MAX, 8), 252);
        assert_eq!(oneshot_delta_ticks(0, u64::MAX, 48), (1 << 48) - 4);
        assert_eq!(oneshot_delta_ticks(0, u64::MAX, 64), u64::MAX - 3);
    }
}

/// Time-related interfaces.
#[def_plat_interface]
pub trait TimeIf {
    /// Returns the current clock time in hardware ticks.
    fn current_ticks() -> u64;

    /// Converts hardware ticks to nanoseconds.
    fn ticks_to_nanos(ticks: u64) -> u64;

    /// Converts nanoseconds to hardware ticks.
    fn nanos_to_ticks(nanos: u64) -> u64;

    /// Return epoch offset in nanoseconds (wall time offset to monotonic
    /// clock start).
    fn epochoffset_nanos() -> u64;

    /// Set a one-shot timer.
    ///
    /// A timer interrupt will be triggered at the specified monotonic time
    /// deadline (in nanoseconds).
    #[cfg(feature = "irq")]
    fn set_oneshot_timer(deadline_ns: u64);
}

/// Returns nanoseconds elapsed since system boot.
pub fn monotonic_time_nanos() -> u64 {
    ticks_to_nanos(current_ticks())
}

/// Returns the time elapsed since system boot in [`TimeValue`].
pub fn monotonic_time() -> TimeValue {
    TimeValue::from_nanos(monotonic_time_nanos())
}

/// Returns nanoseconds elapsed since epoch (also known as realtime).
pub fn wall_time_nanos() -> u64 {
    monotonic_time_nanos() + epochoffset_nanos()
}

/// Returns the time elapsed since epoch (also known as realtime) in [`TimeValue`].
pub fn wall_time() -> TimeValue {
    TimeValue::from_nanos(monotonic_time_nanos() + epochoffset_nanos())
}

/// Busy waiting for the given duration.
pub fn busy_wait(dur: Duration) {
    busy_wait_until(wall_time() + dur);
}

/// Busy waiting until reaching the given deadline.
pub fn busy_wait_until(deadline: TimeValue) {
    while wall_time() < deadline {
        core::hint::spin_loop();
    }
}
