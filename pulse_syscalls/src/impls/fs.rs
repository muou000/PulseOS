use arceos_posix_api::sys_close as ax_sys_close;
use arceos_posix_api::sys_fstat as ax_sys_fstat;
use arceos_posix_api::sys_open as ax_sys_open;
use arceos_posix_api::sys_read as ax_sys_read;
use arceos_posix_api::sys_write as ax_sys_write;
use arceos_posix_api::sys_writev as ax_sys_writev;
use core::ffi::{c_char, c_void};

pub fn sys_read(fd: usize, buf: usize, count: usize) -> isize {
    ax_sys_read(fd as i32, buf as *mut c_void, count) as isize
}

pub fn sys_write(fd: usize, buf: usize, count: usize) -> isize {
    ax_sys_write(fd as i32, buf as *const c_void, count) as isize
}

pub fn sys_openat(_dirfd: i32, pathname: usize, flags: usize, mode: usize) -> isize {
    ax_sys_open(pathname as *const c_char, flags as i32, mode as u32) as isize
}

pub fn sys_close(fd: usize) -> isize {
    ax_sys_close(fd as i32) as isize
}

pub fn sys_fstat(fd: usize, statbuf: usize) -> isize {
    unsafe { ax_sys_fstat(fd as i32, statbuf as *mut arceos_posix_api::ctypes::stat) as isize }
}

pub fn sys_writev(fd: usize, iov: usize, iovcnt: usize) -> isize {
    unsafe {
        ax_sys_writev(fd as i32, iov as *const arceos_posix_api::ctypes::iovec, iovcnt as i32) as isize
    }
}
