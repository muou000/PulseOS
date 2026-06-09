//! Time-related operations.

use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "irq")]
pub use axplat::time::set_oneshot_timer;
pub use axplat::time::{
    Duration, MICROS_PER_SEC, MILLIS_PER_SEC, NANOS_PER_MICROS, NANOS_PER_MILLIS, NANOS_PER_SEC,
    TimeValue, current_ticks, epochoffset_nanos, monotonic_time,
    monotonic_time_nanos, nanos_to_ticks, ticks_to_nanos,
};

static REALTIME_OFFSET_NANOS: AtomicU64 = AtomicU64::new(u64::MAX);

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

/// Set epoch offset in nanoseconds.
pub fn set_epochoffset_nanos(offset: u64) {
    REALTIME_OFFSET_NANOS.store(offset, Ordering::Release);
}

/// Returns nanoseconds elapsed since epoch (also known as realtime).
pub fn wall_time_nanos() -> u64 {
    let mut offset = REALTIME_OFFSET_NANOS.load(Ordering::Acquire);
    if offset == u64::MAX {
        offset = epochoffset_nanos();
        REALTIME_OFFSET_NANOS.store(offset, Ordering::Release);
    }
    monotonic_time_nanos() + offset
}

/// Returns the time elapsed since epoch (also known as realtime) in [`TimeValue`].
pub fn wall_time() -> TimeValue {
    TimeValue::from_nanos(wall_time_nanos())
}

/// Returns the current realtime offset to monotonic time in nanoseconds.
pub fn current_epochoffset_nanos() -> u64 {
    let mut offset = REALTIME_OFFSET_NANOS.load(Ordering::Acquire);
    if offset == u64::MAX {
        offset = epochoffset_nanos();
        REALTIME_OFFSET_NANOS.store(offset, Ordering::Release);
    }
    offset
}
