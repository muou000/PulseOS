use axerrno::LinuxError;
use linux_raw_sys::general::{
    RLIMIT_AS, RLIMIT_CORE, RLIMIT_DATA, RLIMIT_FSIZE, RLIMIT_MEMLOCK, RLIMIT_NOFILE,
    RLIMIT_SIGPENDING, RLIMIT_STACK,
};

pub(crate) const SUPPORTED_RESOURCES: [u32; 8] = [
    RLIMIT_STACK,
    RLIMIT_FSIZE,
    RLIMIT_NOFILE,
    RLIMIT_MEMLOCK,
    RLIMIT_CORE,
    RLIMIT_DATA,
    RLIMIT_AS,
    RLIMIT_SIGPENDING,
];

pub(crate) fn validate_resource(resource: usize) -> Result<u32, LinuxError> {
    let resource = resource as u32;
    if SUPPORTED_RESOURCES.contains(&resource) {
        Ok(resource)
    } else {
        Err(LinuxError::EINVAL)
    }
}

pub(crate) fn validate_limit_order(current: u64, maximum: u64) -> Result<(), LinuxError> {
    if current > maximum {
        Err(LinuxError::EINVAL)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_limit_raise(
    old_current: u64,
    old_maximum: u64,
    new_current: u64,
    new_maximum: u64,
    has_sys_resource: bool,
) -> Result<(), LinuxError> {
    validate_limit_order(new_current, new_maximum)?;
    if !has_sys_resource && (new_current > old_current || new_maximum > old_maximum) {
        return Err(LinuxError::EPERM);
    }
    Ok(())
}

pub(crate) fn validate_nofile_ceiling(
    resource: u32,
    maximum: u64,
    fd_limit: u64,
) -> Result<(), LinuxError> {
    if resource == RLIMIT_NOFILE && maximum > fd_limit {
        Err(LinuxError::EPERM)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_prlimit_pid(pid: i32, current_pid: i32) -> Result<(), LinuxError> {
    if pid != 0 && pid != current_pid {
        Err(LinuxError::ESRCH)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ltp_getrlimit02_rejects_invalid_resource() {
        assert_eq!(validate_resource(1000), Err(LinuxError::EINVAL));
        for resource in SUPPORTED_RESOURCES {
            assert_eq!(validate_resource(resource as usize), Ok(resource));
        }
    }

    #[test]
    fn ltp_setrlimit03_rejects_soft_limit_above_hard_limit() {
        assert_eq!(validate_limit_order(11, 10), Err(LinuxError::EINVAL));
        assert_eq!(validate_limit_order(10, 10), Ok(()));
        assert_eq!(validate_limit_order(9, 10), Ok(()));
    }

    #[test]
    fn resource_raise_requires_cap_sys_resource() {
        assert_eq!(
            validate_limit_raise(10, 20, 11, 20, false),
            Err(LinuxError::EPERM)
        );
        assert_eq!(
            validate_limit_raise(10, 20, 10, 21, false),
            Err(LinuxError::EPERM)
        );
        assert_eq!(validate_limit_raise(10, 20, 11, 21, true), Ok(()));
    }

    #[test]
    fn nofile_limit_cannot_exceed_kernel_fd_ceiling() {
        assert_eq!(
            validate_nofile_ceiling(RLIMIT_NOFILE, 1025, 1024),
            Err(LinuxError::EPERM)
        );
        assert_eq!(validate_nofile_ceiling(RLIMIT_NOFILE, 1024, 1024), Ok(()));
        assert_eq!(validate_nofile_ceiling(RLIMIT_CORE, u64::MAX, 1024), Ok(()));
    }

    #[test]
    fn prlimit_accepts_zero_or_current_pid_only() {
        assert_eq!(validate_prlimit_pid(0, 42), Ok(()));
        assert_eq!(validate_prlimit_pid(42, 42), Ok(()));
        assert_eq!(validate_prlimit_pid(41, 42), Err(LinuxError::ESRCH));
    }
}
