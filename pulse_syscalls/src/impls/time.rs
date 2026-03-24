use crate::LinuxError;

pub fn sys_nanosleep(req: usize, rem: usize) -> isize {
    axlog::debug!("sys_nanosleep: req={:#x}, rem={:#x}", req, rem);

    // TODO
    -LinuxError::ENOSYS.code() as isize
}

/// sys_clock_gettime - 获取时钟时间
pub fn sys_clock_gettime(clockid: i32, tp: usize) -> isize {
    axlog::debug!("sys_clock_gettime: clockid={}, tp={:#x}", clockid, tp);

    // TODO
    -LinuxError::ENOSYS.code() as isize
}
