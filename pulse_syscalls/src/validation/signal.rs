use axerrno::LinuxError;
use linux_raw_sys::general::{
    _NSIG, SA_NOCLDSTOP, SA_NOCLDWAIT, SA_NODEFER, SA_ONSTACK, SA_RESETHAND, SA_RESTART,
    SA_SIGINFO, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK, SIGKILL, SIGSTOP,
};

pub(crate) const SUPPORTED_SIGACTION_FLAGS: usize = SA_NOCLDSTOP as usize
    | SA_NOCLDWAIT as usize
    | SA_SIGINFO as usize
    | SA_ONSTACK as usize
    | SA_RESTART as usize
    | SA_NODEFER as usize
    | SA_RESETHAND as usize;

pub(crate) fn sanitize_signal_mask(mask: u64) -> u64 {
    let unmaskable = (1u64 << (SIGKILL as usize - 1)) | (1u64 << (SIGSTOP as usize - 1));
    mask & !unmaskable
}

pub(crate) fn update_signal_mask(
    current: u64,
    new_bits: u64,
    how: usize,
) -> Result<u64, LinuxError> {
    let mask = match how as u32 {
        SIG_BLOCK => current | new_bits,
        SIG_UNBLOCK => current & !new_bits,
        SIG_SETMASK => new_bits,
        _ => return Err(LinuxError::EINVAL),
    };
    Ok(sanitize_signal_mask(mask))
}

pub(crate) fn validate_sigset_size(size: usize) -> Result<(), LinuxError> {
    if size != core::mem::size_of::<u64>() {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

pub(crate) fn validate_sigaction_signum(signum: usize, installing: bool) -> Result<(), LinuxError> {
    if signum == 0
        || signum > _NSIG as usize
        || (installing && (signum == SIGKILL as usize || signum == SIGSTOP as usize))
    {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use linux_raw_sys::general::SA_UNSUPPORTED;

    use super::*;

    #[test]
    fn ltp_rt_sigprocmask01_block_unblock_and_replace_masks() {
        let current = 1u64 << 10;
        let additional = 1u64 << 11;
        assert_eq!(
            update_signal_mask(current, additional, SIG_BLOCK as usize),
            Ok(current | additional)
        );
        assert_eq!(
            update_signal_mask(current | additional, additional, SIG_UNBLOCK as usize),
            Ok(current),
        );
        assert_eq!(
            update_signal_mask(current, additional, SIG_SETMASK as usize),
            Ok(additional)
        );
        assert_eq!(
            update_signal_mask(current, additional, usize::MAX),
            Err(LinuxError::EINVAL)
        );
    }

    #[test]
    fn ltp_rt_sigprocmask02_requires_kernel_sigset_size() {
        for size in [0, 1, 7, 9, 128, usize::MAX] {
            assert_eq!(validate_sigset_size(size), Err(LinuxError::EINVAL));
        }
        assert_eq!(validate_sigset_size(8), Ok(()));
    }

    #[test]
    fn signal_masks_cannot_block_kill_or_stop() {
        let unmaskable = (1u64 << (SIGKILL - 1)) | (1u64 << (SIGSTOP - 1));
        let ordinary = 1u64 << 9;
        assert_eq!(sanitize_signal_mask(unmaskable | ordinary), ordinary);
        for how in [SIG_BLOCK, SIG_SETMASK] {
            assert_eq!(
                update_signal_mask(0, unmaskable | ordinary, how as usize),
                Ok(ordinary)
            );
        }
    }

    #[test]
    fn sigaction_cannot_install_handlers_for_kill_or_stop() {
        for signum in [0, _NSIG as usize + 1, SIGKILL as usize, SIGSTOP as usize] {
            assert_eq!(
                validate_sigaction_signum(signum, true),
                Err(LinuxError::EINVAL)
            );
        }
        assert_eq!(validate_sigaction_signum(SIGKILL as usize, false), Ok(()));
        assert_eq!(validate_sigaction_signum(SIGSTOP as usize, false), Ok(()));
        assert_eq!(validate_sigaction_signum(_NSIG as usize, true), Ok(()));
    }

    #[test]
    fn ltp_rt_sigaction01_supported_flags_exclude_sa_unsupported() {
        for flags in [SA_RESETHAND, SA_RESETHAND | SA_SIGINFO, SA_NODEFER] {
            assert_eq!(SUPPORTED_SIGACTION_FLAGS & flags as usize, flags as usize);
        }
        assert_eq!(SUPPORTED_SIGACTION_FLAGS & SA_UNSUPPORTED as usize, 0);
    }
}
