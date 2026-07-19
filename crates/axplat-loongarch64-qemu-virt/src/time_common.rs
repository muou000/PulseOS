const MIN_TIMER_TICKS: u64 = 4;
const TIMER_TICK_MASK: u64 = MIN_TIMER_TICKS - 1;

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
    use super::*;

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
