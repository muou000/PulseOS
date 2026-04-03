use arceos_posix_api::sys_close as ax_sys_close;
use arceos_posix_api::sys_dup as ax_sys_dup;
use arceos_posix_api::sys_dup2 as ax_sys_dup2;
use arceos_posix_api::sys_fcntl as ax_sys_fcntl;
use arceos_posix_api::sys_fstat as ax_sys_fstat;
use arceos_posix_api::sys_getdents64 as ax_sys_getdents64;
use arceos_posix_api::sys_getcwd as ax_sys_getcwd;
use arceos_posix_api::sys_chdir as ax_sys_chdir;
use arceos_posix_api::sys_lseek as ax_sys_lseek;
use arceos_posix_api::sys_open as ax_sys_open;
use arceos_posix_api::sys_read as ax_sys_read;
use arceos_posix_api::sys_stat as ax_sys_stat;
use arceos_posix_api::sys_write as ax_sys_write;
use arceos_posix_api::sys_writev as ax_sys_writev;
use axerrno::LinuxError;
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

pub fn sys_getdents64(fd: usize, dirp: usize, count: usize) -> isize {
    unsafe { ax_sys_getdents64(fd as i32, dirp as *mut u8, count) as isize }
}

pub fn sys_close(fd: usize) -> isize {
    ax_sys_close(fd as i32) as isize
}

pub fn sys_fstat(fd: usize, statbuf: usize) -> isize {
    unsafe { ax_sys_fstat(fd as i32, statbuf as *mut arceos_posix_api::ctypes::stat) as isize }
}

pub fn sys_fstatat(dirfd: i32, pathname: usize, statbuf: usize, flags: usize) -> isize {
    let path_ptr = pathname as *const c_char;
    let at_empty_path = 0x1000;

    // Check if pathname is empty and AT_EMPTY_PATH is set
    unsafe {
        if (flags & at_empty_path) != 0 && *path_ptr == 0 {
            return ax_sys_fstat(dirfd as i32, statbuf as *mut arceos_posix_api::ctypes::stat)
                as isize;
        }
        ax_sys_stat(path_ptr, statbuf as *mut arceos_posix_api::ctypes::stat) as isize
    }
}

const STATX_BASIC_STATS: u32 = 0x0000_07ff;
const STATX_MNT_ID: u32 = 0x0000_1000;
const AT_EMPTY_PATH: usize = 0x1000;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct StatxTimestamp {
    tv_sec: i64,
    tv_nsec: u32,
    __reserved: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Statx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    __spare0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: StatxTimestamp,
    stx_btime: StatxTimestamp,
    stx_ctime: StatxTimestamp,
    stx_mtime: StatxTimestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    stx_dio_mem_align: u32,
    stx_dio_offset_align: u32,
    __spare3: [u64; 12],
}

fn to_statx_timestamp(ts: arceos_posix_api::ctypes::timespec) -> StatxTimestamp {
    StatxTimestamp {
        tv_sec: ts.tv_sec,
        tv_nsec: ts.tv_nsec as u32,
        __reserved: 0,
    }
}

pub fn sys_statx(
    dirfd: i32,
    pathname: usize,
    flags: usize,
    _mask: usize,
    statxbuf: usize,
) -> isize {
    if statxbuf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let path_ptr = pathname as *const c_char;
    let mut stat = arceos_posix_api::ctypes::stat::default();

    let ret = unsafe {
        if (flags & AT_EMPTY_PATH) != 0 && pathname != 0 && *path_ptr == 0 {
            ax_sys_fstat(dirfd, &mut stat)
        } else {
            ax_sys_stat(path_ptr, &mut stat)
        }
    };
    if ret < 0 {
        return ret as isize;
    }

    let statx = Statx {
        stx_mask: STATX_BASIC_STATS | STATX_MNT_ID,
        stx_blksize: stat.st_blksize as u32,
        stx_attributes: 0,
        stx_nlink: stat.st_nlink as u32,
        stx_uid: stat.st_uid,
        stx_gid: stat.st_gid,
        stx_mode: stat.st_mode as u16,
        __spare0: 0,
        stx_ino: stat.st_ino,
        stx_size: stat.st_size as u64,
        stx_blocks: stat.st_blocks as u64,
        stx_attributes_mask: 0,
        stx_atime: to_statx_timestamp(stat.st_atime),
        stx_btime: StatxTimestamp::default(),
        stx_ctime: to_statx_timestamp(stat.st_ctime),
        stx_mtime: to_statx_timestamp(stat.st_mtime),
        stx_rdev_major: 0,
        stx_rdev_minor: 0,
        stx_dev_major: 0,
        stx_dev_minor: 0,
        stx_mnt_id: 0,
        stx_dio_mem_align: 0,
        stx_dio_offset_align: 0,
        __spare3: [0; 12],
    };

    unsafe {
        *(statxbuf as *mut Statx) = statx;
    }
    0
}

pub fn sys_writev(fd: usize, iov: usize, iovcnt: usize) -> isize {
    unsafe {
        ax_sys_writev(
            fd as i32,
            iov as *const arceos_posix_api::ctypes::iovec,
            iovcnt as i32,
        ) as isize
    }
}

const O_CLOEXEC: usize = 0x80000;

pub fn sys_fcntl(fd: usize, cmd: usize, arg: usize) -> isize {
    ax_sys_fcntl(fd as i32, cmd as i32, arg) as isize
}

pub fn sys_dup(fd: usize) -> isize {
    ax_sys_dup(fd as i32) as isize
}

pub fn sys_dup3(oldfd: usize, newfd: usize, flags: usize) -> isize {
    if oldfd == newfd {
        return -LinuxError::EINVAL.code() as isize;
    }
    if (flags & !O_CLOEXEC) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    ax_sys_dup2(oldfd as i32, newfd as i32) as isize
}

pub fn sys_lseek(fd: usize, offset: usize, whence: usize) -> isize {
    ax_sys_lseek(fd as i32, offset as i64, whence as i32) as isize
}

pub fn sys_getcwd(buf: usize, size: usize) -> isize {
    if buf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if size == 0 {
        return -LinuxError::ERANGE.code() as isize;
    }
    let ret = ax_sys_getcwd(buf as *mut c_char, size) as isize;
    if ret < 0 { ret } else { buf as isize }
}

pub fn sys_chdir(path: usize) -> isize {
    ax_sys_chdir(path as *const c_char) as isize
}

const TCGETS: usize = 0x5401;
const TIOCGPGRP: usize = 0x540f;
const TIOCSPGRP: usize = 0x5410;
const TIOCGWINSZ: usize = 0x5413;

#[repr(C)]
struct WinSize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

pub fn sys_ioctl(fd: usize, cmd: usize, arg: usize) -> isize {
    axlog::debug!("sys_ioctl: fd={}, cmd={:#x}, arg={:#x}", fd, cmd, arg);
    match cmd {
        TCGETS => {
            // It's a stub to tell musl it is a terminal
            0
        }
        TIOCGPGRP => {
            if arg != 0 {
                unsafe {
                    *(arg as *mut i32) = 1; // Return a dummy process group ID
                }
            }
            0
        }
        TIOCSPGRP => 0,
        TIOCGWINSZ => {
            if arg != 0 {
                let ws = arg as *mut WinSize;
                unsafe {
                    (*ws).ws_row = 24;
                    (*ws).ws_col = 80;
                    (*ws).ws_xpixel = 0;
                    (*ws).ws_ypixel = 0;
                }
            }
            0
        }
        _ => {
            // ENOTTY
            -25
        }
    }
}
