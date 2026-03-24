//! 其他杂项系统调用

use crate::LinuxError;

/// sys_uname - 获取系统信息
pub fn sys_uname(buf: usize) -> isize {
    axlog::debug!("sys_uname: buf={:#x}", buf);

    // TODO: 实现 uname 功能
    -LinuxError::ENOSYS.code() as isize
}
