use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

use arceos_posix_api::ctypes;
use arceos_posix_api::sys_chdir as ax_sys_chdir;
use arceos_posix_api::sys_close as ax_sys_close;
use arceos_posix_api::sys_dup as ax_sys_dup;
use arceos_posix_api::sys_dup2 as ax_sys_dup2;
use arceos_posix_api::sys_fcntl as ax_sys_fcntl;
use arceos_posix_api::sys_fstat as ax_sys_fstat;
use arceos_posix_api::sys_getcwd as ax_sys_getcwd;
use arceos_posix_api::sys_getdents64 as ax_sys_getdents64;
use arceos_posix_api::sys_lseek as ax_sys_lseek;
use arceos_posix_api::sys_mkdir as ax_sys_mkdir;
use arceos_posix_api::sys_open as ax_sys_open;
use arceos_posix_api::sys_pipe as ax_sys_pipe;
use arceos_posix_api::sys_read as ax_sys_read;
use arceos_posix_api::sys_stat as ax_sys_stat;
use arceos_posix_api::sys_write as ax_sys_write;
use arceos_posix_api::sys_writev as ax_sys_writev;
use axfs::FS_CONTEXT;

use axerrno::LinuxError;
use axtask::TaskExtRef;
use core::ffi::{CStr, c_char, c_void};
use spin::Lazy;

use pulse_core::fd_table::{FdEntry, FdFlags, RawFdObject};
use pulse_core::task::Process;

const O_NONBLOCK: usize = ctypes::O_NONBLOCK as usize;
const O_CLOEXEC: usize = ctypes::O_CLOEXEC as usize;
const AT_FDCWD: i32 = -100;
const AT_REMOVEDIR: usize = 0x200;

static MOUNTED_TARGETS: Lazy<spin::Mutex<BTreeSet<String>>> =
    Lazy::new(|| spin::Mutex::new(BTreeSet::new()));

fn with_process<R>(f: impl FnOnce(&Process) -> R) -> R {
    let curr = axtask::current();
    let proc: &Process = curr.task_ext();
    f(proc)
}

fn ensure_entry(fd: usize) {
    with_process(|process| {
        process.fd_table.lock().ensure_raw_fd(fd, fd as i32);
    });
}

fn map_fd(fd: usize) -> Result<i32, LinuxError> {
    with_process(|process| {
        let mut table = process.fd_table.lock();
        if table.get(fd).is_none() {
            table.ensure_raw_fd(fd, fd as i32);
        }
        let entry = table.get(fd).ok_or(LinuxError::EBADF)?;
        let raw = entry
            .object
            .as_any()
            .downcast_ref::<RawFdObject>()
            .map(|o| o.raw_fd)
            .ok_or(LinuxError::EBADF)?;
        Ok(raw)
    })
}

fn track_fd(fd: usize, raw_fd: i32, flags: FdFlags) {
    with_process(|process| {
        let _ = process.fd_table.lock().insert_at(
            fd,
            FdEntry {
                object: Arc::new(RawFdObject { raw_fd }),
                flags,
            },
        );
    });
}

pub fn sys_read(fd: usize, buf: usize, count: usize) -> isize {
    axlog::debug!("sys_read: fd={}, buf={:#x}, count={}", fd, buf, count);
    let raw = match map_fd(fd) {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    ax_sys_read(raw, buf as *mut c_void, count) as isize
}

pub fn sys_write(fd: usize, buf: usize, count: usize) -> isize {
    axlog::debug!("sys_write: fd={}, buf={:#x}, count={}", fd, buf, count);
    let raw = match map_fd(fd) {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    ax_sys_write(raw, buf as *const c_void, count) as isize
}

pub fn sys_openat(_dirfd: i32, pathname: usize, flags: usize, mode: usize) -> isize {
    axlog::debug!(
        "sys_openat: pathname={:#x}, flags={:#x}, mode={:#x}",
        pathname,
        flags,
        mode
    );
    let ret = ax_sys_open(pathname as *const c_char, flags as i32, mode as u32) as isize;
    if ret >= 0 {
        let fd = ret as usize;
        let mut fd_flags = FdFlags::empty();
        if (flags & O_CLOEXEC) != 0 {
            fd_flags.insert(FdFlags::CLOEXEC);
        }
        if (flags & O_NONBLOCK) != 0 {
            fd_flags.insert(FdFlags::NONBLOCK);
        }
        track_fd(fd, fd as i32, fd_flags);
    }
    ret
}

pub fn sys_mkdirat(_dirfd: i32, pathname: usize, mode: usize) -> isize {
    axlog::debug!("sys_mkdirat: pathname={:#x}, mode={:#x}", pathname, mode);
    if pathname == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    ax_sys_mkdir(pathname as *const c_char, mode as u32) as isize
}

pub fn sys_mount(
    _source: usize,
    target: usize,
    _fstype: usize,
    _flags: usize,
    _data: usize,
) -> isize {
    axlog::debug!("sys_mount: target={:#x}, flags={:#x}", target, _flags);
    if target == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let target_path = match unsafe { CStr::from_ptr(target as *const c_char) }.to_str() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    // Keep mount behavior deterministic for tests: target must exist first.
    let mut st = arceos_posix_api::ctypes::stat::default();
    let stat_ret = unsafe { ax_sys_stat(target as *const c_char, &mut st) as isize };
    if stat_ret < 0 {
        return stat_ret;
    }

    let mut mounted = MOUNTED_TARGETS.lock();
    if mounted.contains(target_path) {
        return -LinuxError::EBUSY.code() as isize;
    }
    mounted.insert(target_path.to_string());
    0
}

pub fn sys_umount2(target: usize, _flags: usize) -> isize {
    axlog::debug!("sys_umount2: target={:#x}, flags={:#x}", target, _flags);
    if target == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let target_path = match unsafe { CStr::from_ptr(target as *const c_char) }.to_str() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    let mut mounted = MOUNTED_TARGETS.lock();
    if mounted.remove(target_path) {
        0
    } else {
        -LinuxError::EINVAL.code() as isize
    }
}

pub fn sys_getdents64(fd: usize, dirp: usize, count: usize) -> isize {
    axlog::debug!(
        "sys_getdents64: fd={}, dirp={:#x}, count={}",
        fd,
        dirp,
        count
    );
    let raw = match map_fd(fd) {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    unsafe { ax_sys_getdents64(raw, dirp as *mut u8, count) as isize }
}

pub fn sys_close(fd: usize) -> isize {
    axlog::debug!("sys_close: fd={}", fd);
    if fd <= 2 {
        return 0;
    }
    let raw = match map_fd(fd) {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    let ret = ax_sys_close(raw) as isize;
    if ret == 0 {
        with_process(|process| {
            process.fd_table.lock().remove(fd);
        });
    }
    ret
}

pub fn sys_fstat(fd: usize, statbuf: usize) -> isize {
    axlog::debug!("sys_fstat: fd={}, statbuf={:#x}", fd, statbuf);
    let raw = match map_fd(fd) {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    unsafe { ax_sys_fstat(raw, statbuf as *mut ctypes::stat) as isize }
}

pub fn sys_fstatat(dirfd: i32, pathname: usize, statbuf: usize, flags: usize) -> isize {
    axlog::debug!(
        "sys_fstatat: dirfd={}, pathname={:#x}, statbuf={:#x}, flags={:#x}",
        dirfd,
        pathname,
        statbuf,
        flags
    );
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
    axlog::debug!(
        "sys_statx: dirfd={}, pathname={:#x}, flags={:#x}, statxbuf={:#x}",
        dirfd,
        pathname,
        flags,
        statxbuf
    );
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
    axlog::debug!("sys_writev: fd={}, iov={:#x}, iovcnt={}", fd, iov, iovcnt);
    let raw = match map_fd(fd) {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    unsafe { ax_sys_writev(raw, iov as *const ctypes::iovec, iovcnt as i32) as isize }
}

pub fn sys_fcntl(fd: usize, cmd: usize, arg: usize) -> isize {
    axlog::debug!("sys_fcntl: fd={}, cmd={:#x}, arg={:#x}", fd, cmd, arg);
    ensure_entry(fd);
    match cmd as u32 {
        ctypes::F_GETFD => with_process(|process| {
            let table = process.fd_table.lock();
            let Some(entry) = table.get(fd) else {
                return -LinuxError::EBADF.code() as isize;
            };
            if entry.flags.contains(FdFlags::CLOEXEC) {
                ctypes::FD_CLOEXEC as isize
            } else {
                0
            }
        }),
        ctypes::F_SETFD => with_process(|process| {
            let mut table = process.fd_table.lock();
            let Some(entry) = table.get_mut(fd) else {
                return -LinuxError::EBADF.code() as isize;
            };
            entry
                .flags
                .set(FdFlags::CLOEXEC, (arg & (ctypes::FD_CLOEXEC as usize)) != 0);
            0
        }),
        ctypes::F_SETFL => {
            with_process(|process| {
                if let Some(entry) = process.fd_table.lock().get_mut(fd) {
                    entry.flags.set(
                        FdFlags::NONBLOCK,
                        (arg & (ctypes::O_NONBLOCK as usize)) != 0,
                    );
                }
            });
            let raw = match map_fd(fd) {
                Ok(v) => v,
                Err(e) => return -e.code() as isize,
            };
            ax_sys_fcntl(raw, cmd as i32, arg) as isize
        }
        ctypes::F_DUPFD | ctypes::F_DUPFD_CLOEXEC => {
            let raw = match map_fd(fd) {
                Ok(v) => v,
                Err(e) => return -e.code() as isize,
            };
            let ret = ax_sys_fcntl(raw, cmd as i32, arg) as isize;
            if ret >= 0 {
                let new_fd = ret as usize;
                let mut flags = FdFlags::empty();
                if cmd as u32 == ctypes::F_DUPFD_CLOEXEC {
                    flags.insert(FdFlags::CLOEXEC);
                }
                track_fd(new_fd, new_fd as i32, flags);
            }
            ret
        }
        _ => {
            let raw = match map_fd(fd) {
                Ok(v) => v,
                Err(e) => return -e.code() as isize,
            };
            ax_sys_fcntl(raw, cmd as i32, arg) as isize
        }
    }
}

pub fn sys_dup(fd: usize) -> isize {
    axlog::debug!("sys_dup: fd={}", fd);
    let raw = match map_fd(fd) {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    let ret = ax_sys_dup(raw) as isize;
    if ret >= 0 {
        let new_fd = ret as usize;
        track_fd(new_fd, new_fd as i32, FdFlags::empty());
    }
    ret
}

pub fn sys_dup3(oldfd: usize, newfd: usize, flags: usize) -> isize {
    axlog::debug!(
        "sys_dup3: oldfd={}, newfd={}, flags={:#x}",
        oldfd,
        newfd,
        flags
    );
    if oldfd == newfd {
        return -LinuxError::EINVAL.code() as isize;
    }
    if (flags & !O_CLOEXEC) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let old_raw = match map_fd(oldfd) {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    let ret = ax_sys_dup2(old_raw, newfd as i32) as isize;
    if ret >= 0 {
        let mut fd_flags = FdFlags::empty();
        if (flags & O_CLOEXEC) != 0 {
            fd_flags.insert(FdFlags::CLOEXEC);
        }
        track_fd(newfd, newfd as i32, fd_flags);
    }
    ret
}

pub fn sys_pipe2(fds: usize, flags: usize) -> isize {
    axlog::debug!("sys_pipe2: fds={:#x}, flags={:#x}", fds, flags);
    if fds == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let allowed = O_NONBLOCK | O_CLOEXEC;
    if (flags & !allowed) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let fds_ptr = fds as *mut i32;
    let fds_slice = unsafe { core::slice::from_raw_parts_mut(fds_ptr, 2) };
    let ret = ax_sys_pipe(fds_slice) as isize;
    if ret == 0 {
        let mut fd_flags = FdFlags::empty();
        if (flags & O_CLOEXEC) != 0 {
            fd_flags.insert(FdFlags::CLOEXEC);
        }
        if (flags & O_NONBLOCK) != 0 {
            fd_flags.insert(FdFlags::NONBLOCK);
        }
        track_fd(fds_slice[0] as usize, fds_slice[0], fd_flags);
        track_fd(fds_slice[1] as usize, fds_slice[1], fd_flags);
    }
    ret
}

pub fn sys_lseek(fd: usize, offset: usize, whence: usize) -> isize {
    axlog::debug!(
        "sys_lseek: fd={}, offset={:#x}, whence={}",
        fd,
        offset,
        whence
    );
    let raw = match map_fd(fd) {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    ax_sys_lseek(raw, offset as i64, whence as i32) as isize
}

pub fn sys_getcwd(buf: usize, size: usize) -> isize {
    axlog::debug!("sys_getcwd: buf={:#x}, size={}", buf, size);
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
    axlog::debug!("sys_chdir: path={:#x}", path);
    let ret = ax_sys_chdir(path as *const c_char) as isize;
    if ret == 0 {
        with_process(|process| {
            process.refresh_cwd_from_fs();
        });
    }
    ret
}

pub fn sys_unlinkat(dirfd: i32, pathname: usize, flags: usize) -> isize {
    axlog::debug!(
        "sys_unlinkat: dirfd={}, pathname={:#x}, flags={:#x}",
        dirfd,
        pathname,
        flags
    );

    if pathname == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if (flags & !AT_REMOVEDIR) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let path = match unsafe { CStr::from_ptr(pathname as *const c_char) }.to_str() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    // If path is absolute, dirfd is ignored.
    if dirfd != AT_FDCWD && !path.starts_with('/') {
        return -LinuxError::EBADF.code() as isize;
    }

    if (flags & AT_REMOVEDIR) != 0 {
        return match FS_CONTEXT.lock().remove_dir(path) {
            Ok(()) => 0,
            Err(e) => {
                let errno: LinuxError = e.into();
                -errno.code() as isize
            }
        };
    }

    if pathname == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let path = match unsafe { CStr::from_ptr(pathname as *const c_char) }.to_str() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    match FS_CONTEXT.lock().remove_file(path) {
        Ok(()) => 0,
        Err(e) => {
            let errno: LinuxError = e.into();
            -errno.code() as isize
        }
    }
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
