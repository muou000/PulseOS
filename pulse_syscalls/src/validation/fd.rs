use axerrno::LinuxError;
use linux_raw_sys::general::{O_CLOEXEC, O_NONBLOCK};

pub(crate) const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
pub(crate) const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

pub(crate) fn parse_close_range(
    first: usize,
    last: usize,
    flags: usize,
) -> Result<(usize, usize, u32), LinuxError> {
    let first = first as u32 as usize;
    let last = last as u32 as usize;
    let flags = flags as u32;
    if first > last || flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok((first, last, flags))
}

pub(crate) fn validate_pipe2(fds: usize, flags: usize) -> Result<(), LinuxError> {
    if fds == 0 {
        return Err(LinuxError::EFAULT);
    }
    if flags & !((O_NONBLOCK | O_CLOEXEC) as usize) != 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use linux_raw_sys::general::O_DIRECT;

    use super::*;

    #[test]
    fn ltp_close_range02_rejects_reversed_range() {
        assert_eq!(parse_close_range(4, 3, 0), Err(LinuxError::EINVAL));
    }

    #[test]
    fn ltp_close_range02_rejects_unknown_flags() {
        assert_eq!(
            parse_close_range(3, u32::MAX as usize, u32::MAX as usize),
            Err(LinuxError::EINVAL),
        );
    }

    #[test]
    fn ltp_close_range02_accepts_large_lower_fd() {
        let max = u32::MAX as usize;
        assert_eq!(parse_close_range(max, max, 0), Ok((max, max, 0)));
    }

    #[test]
    fn ltp_close_range01_accepts_supported_flag_combinations() {
        for flags in [
            0,
            CLOSE_RANGE_UNSHARE,
            CLOSE_RANGE_CLOEXEC,
            CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC,
        ] {
            assert_eq!(
                parse_close_range(3, u32::MAX as usize, flags as usize),
                Ok((3, u32::MAX as usize, flags)),
            );
        }
    }

    #[test]
    fn close_range_arguments_use_unsigned_32_bit_abi() {
        if usize::BITS > 32 {
            let high_bits = 1usize << 32;
            assert_eq!(
                parse_close_range(high_bits + 3, high_bits + 4, high_bits),
                Ok((3, 4, 0)),
            );
        }
    }

    #[test]
    fn ltp_pipe2_01_accepts_cloexec_and_nonblock() {
        for flags in [0, O_CLOEXEC, O_NONBLOCK, O_CLOEXEC | O_NONBLOCK] {
            assert_eq!(validate_pipe2(0x1000, flags as usize), Ok(()));
        }
    }

    #[test]
    fn pipe2_rejects_null_output_before_invalid_flags() {
        assert_eq!(validate_pipe2(0, 0), Err(LinuxError::EFAULT));
        assert_eq!(validate_pipe2(0, usize::MAX), Err(LinuxError::EFAULT));
    }

    #[test]
    fn pipe2_rejects_unsupported_packet_mode_and_unknown_flags() {
        for flags in [O_DIRECT as usize, 1, usize::MAX] {
            assert_eq!(validate_pipe2(0x1000, flags), Err(LinuxError::EINVAL));
        }
    }
}
