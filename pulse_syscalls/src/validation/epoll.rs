use axerrno::LinuxError;

pub(crate) fn validate_epoll_maxevents(maxevents: usize) -> Result<(), LinuxError> {
    if maxevents == 0 || maxevents > i32::MAX as usize {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoll_maxevents_accepts_positive_int_values() {
        assert_eq!(validate_epoll_maxevents(1), Ok(()));
        assert_eq!(validate_epoll_maxevents(10_128), Ok(()));
        assert_eq!(validate_epoll_maxevents(i32::MAX as usize), Ok(()));
    }

    #[test]
    fn epoll_maxevents_rejects_zero_and_negative_int_values() {
        assert_eq!(validate_epoll_maxevents(0), Err(LinuxError::EINVAL));
        if usize::BITS > 32 {
            assert_eq!(
                validate_epoll_maxevents(i32::MAX as usize + 1),
                Err(LinuxError::EINVAL)
            );
            assert_eq!(
                validate_epoll_maxevents(usize::MAX),
                Err(LinuxError::EINVAL)
            );
        }
    }
}
