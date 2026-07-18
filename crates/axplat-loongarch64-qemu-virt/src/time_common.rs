const MIN_TIMER_TICKS: u64 = 4;

pub const fn oneshot_delta_ticks(now: u64, deadline: u64) -> u64 {
    align_timer_ticks(deadline.saturating_sub(now))
}

const fn align_timer_ticks(ticks: u64) -> u64 {
    let ticks = if ticks < MIN_TIMER_TICKS {
        MIN_TIMER_TICKS
    } else {
        ticks
    };
    ticks.saturating_add(3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_minimum_delay_for_expired_deadlines() {
        assert_eq!(oneshot_delta_ticks(100, 99), 4);
        assert_eq!(oneshot_delta_ticks(100, 100), 4);
        assert_eq!(oneshot_delta_ticks(100, 101), 4);
    }

    #[test]
    fn rounds_deadline_up_to_tcfg_granularity() {
        assert_eq!(oneshot_delta_ticks(100, 104), 4);
        assert_eq!(oneshot_delta_ticks(100, 105), 8);
        assert_eq!(oneshot_delta_ticks(100, 108), 8);
    }

    #[test]
    fn saturates_to_largest_aligned_tick_value() {
        assert_eq!(oneshot_delta_ticks(0, u64::MAX), u64::MAX - 3);
    }
}
