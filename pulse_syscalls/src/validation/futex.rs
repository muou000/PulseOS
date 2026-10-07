use axerrno::LinuxError;
use linux_raw_sys::general::{
    CLOCK_MONOTONIC, CLOCK_REALTIME, FUTEX_32, FUTEX2_PRIVATE, FUTEX2_SIZE_MASK,
};

pub(crate) fn parse_futex2_flags(flags: u32) -> Result<bool, LinuxError> {
    let supported = FUTEX_32 | FUTEX2_PRIVATE;
    if flags & !supported != 0 || flags & FUTEX2_SIZE_MASK != FUTEX_32 {
        return Err(LinuxError::EINVAL);
    }
    Ok(flags & FUTEX2_PRIVATE != 0)
}

pub(crate) fn validate_futex2_addr(addr: usize) -> Result<(), LinuxError> {
    if addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    if addr & (core::mem::size_of::<u32>() - 1) != 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

pub(crate) fn parse_futex2_mask(mask: usize) -> Result<u32, LinuxError> {
    if mask == 0 || mask > u32::MAX as usize {
        return Err(LinuxError::EINVAL);
    }
    Ok(mask as u32)
}

pub(crate) fn parse_futex2_count(count: isize) -> Result<usize, LinuxError> {
    if count < 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok(count as usize)
}

pub(crate) fn validate_futex_word_addr(addr: usize) -> Result<(), LinuxError> {
    if addr & (core::mem::size_of::<u32>() - 1) != 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

pub(crate) fn parse_futex_bitset(bitset: usize) -> Result<u32, LinuxError> {
    // The legacy futex ABI passes val3 as a 32-bit argument.
    let bitset = bitset as u32;
    if bitset == 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok(bitset)
}

pub(crate) fn parse_futex_clock(clockid: u32) -> Result<bool, LinuxError> {
    match clockid {
        CLOCK_REALTIME => Ok(true),
        CLOCK_MONOTONIC => Ok(false),
        _ => Err(LinuxError::EINVAL),
    }
}

pub(crate) fn validate_futex_waitv(
    waiters: usize,
    nr_futexes: u32,
    flags: u32,
    clockid: u32,
) -> Result<bool, LinuxError> {
    if flags != 0
        || nr_futexes == 0
        || nr_futexes > 128
        || waiters == 0
        || !waiters.is_multiple_of(8)
    {
        return Err(LinuxError::EINVAL);
    }
    parse_futex_clock(clockid)
}

pub(crate) fn futex_deadline_remaining_ns(target_ns: u64, now_ns: u64) -> Result<u64, LinuxError> {
    if target_ns <= now_ns {
        return Err(LinuxError::ETIMEDOUT);
    }
    Ok(target_ns - now_ns)
}

#[cfg(test)]
mod tests {
    use linux_raw_sys::general::{CLOCK_TAI, FUTEX_BITSET_MATCH_ANY};

    use super::*;

    #[test]
    fn ltp_futex_waitv01_rejects_null_waiters() {
        assert_eq!(
            validate_futex_waitv(0, 1, 0, CLOCK_MONOTONIC),
            Err(LinuxError::EINVAL),
        );
    }

    #[test]
    fn ltp_futex_waitv01_rejects_invalid_clockid() {
        for clockid in [CLOCK_TAI, u32::MAX] {
            assert_eq!(
                validate_futex_waitv(0x1000, 1, 0, clockid),
                Err(LinuxError::EINVAL),
            );
        }
    }

    #[test]
    fn ltp_futex_waitv01_rejects_invalid_nr_futexes() {
        for count in [0, 129, u32::MAX] {
            assert_eq!(
                validate_futex_waitv(0x1000, count, 0, CLOCK_MONOTONIC),
                Err(LinuxError::EINVAL),
            );
        }
        for count in [1, 128] {
            assert_eq!(
                validate_futex_waitv(0x1000, count, 0, CLOCK_MONOTONIC),
                Ok(false),
            );
        }
    }

    #[test]
    fn futex_waitv_rejects_syscall_flags_and_unaligned_waiter_array() {
        assert_eq!(
            validate_futex_waitv(0x1000, 1, 1, CLOCK_MONOTONIC),
            Err(LinuxError::EINVAL),
        );
        assert_eq!(
            validate_futex_waitv(0x1001, 1, 0, CLOCK_MONOTONIC),
            Err(LinuxError::EINVAL),
        );
    }

    #[test]
    fn futex2_flags_require_32_bit_words_and_preserve_private_flag() {
        for flags in [0, FUTEX2_PRIVATE, FUTEX_32 | 0x4000] {
            assert_eq!(parse_futex2_flags(flags), Err(LinuxError::EINVAL));
        }
        assert_eq!(parse_futex2_flags(FUTEX_32), Ok(false));
        assert_eq!(parse_futex2_flags(FUTEX_32 | FUTEX2_PRIVATE), Ok(true));
    }

    #[test]
    fn futex2_word_addresses_distinguish_null_and_unaligned() {
        assert_eq!(validate_futex2_addr(0), Err(LinuxError::EFAULT));
        for addr in [1, 2, 3, 0x1001] {
            assert_eq!(validate_futex2_addr(addr), Err(LinuxError::EINVAL));
        }
        assert_eq!(validate_futex2_addr(0x1000), Ok(()));
    }

    #[test]
    fn futex2_mask_and_counts_reject_out_of_range_values() {
        assert_eq!(parse_futex2_mask(0), Err(LinuxError::EINVAL));
        assert_eq!(parse_futex2_mask(u32::MAX as usize), Ok(u32::MAX));
        if usize::BITS > 32 {
            assert_eq!(
                parse_futex2_mask(u32::MAX as usize + 1),
                Err(LinuxError::EINVAL)
            );
        }
        assert_eq!(parse_futex2_count(-1), Err(LinuxError::EINVAL));
        assert_eq!(parse_futex2_count(0), Ok(0));
        assert_eq!(parse_futex2_count(isize::MAX), Ok(isize::MAX as usize));
    }

    #[test]
    fn legacy_futex_bitsets_require_nonzero_masks() {
        assert_eq!(parse_futex_bitset(0), Err(LinuxError::EINVAL));
        assert_eq!(parse_futex_bitset(1), Ok(1));
        assert_eq!(
            parse_futex_bitset(FUTEX_BITSET_MATCH_ANY as usize),
            Ok(FUTEX_BITSET_MATCH_ANY)
        );
    }

    #[test]
    fn legacy_futex_bitsets_truncate_to_u32_before_validation() {
        if usize::BITS > 32 {
            let high_bit = u32::MAX as usize + 1;
            assert_eq!(parse_futex_bitset(high_bit), Err(LinuxError::EINVAL));
            assert_eq!(parse_futex_bitset(high_bit | 1), Ok(1));
        }
    }

    #[test]
    fn legacy_futex_bitset_addresses_require_word_alignment() {
        for addr in [1, 2, 3, 0x1001] {
            assert_eq!(validate_futex_word_addr(addr), Err(LinuxError::EINVAL));
        }
        assert_eq!(validate_futex_word_addr(0x1000), Ok(()));
    }

    #[test]
    fn futex_absolute_deadlines_reject_expired_and_equal_times() {
        assert_eq!(
            futex_deadline_remaining_ns(99, 100),
            Err(LinuxError::ETIMEDOUT)
        );
        assert_eq!(
            futex_deadline_remaining_ns(100, 100),
            Err(LinuxError::ETIMEDOUT)
        );
        assert_eq!(futex_deadline_remaining_ns(101, 100), Ok(1));
        assert_eq!(futex_deadline_remaining_ns(u64::MAX, 0), Ok(u64::MAX));
    }
}
