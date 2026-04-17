use crate::impls::fs::common::{check_faccess_permission, get_fd_entry, resolve_location_at_ptr};
use crate::impls::utils::{
    read_user_timespec, timespec_to_update_time, with_process, write_user_bytes,
};

use axerrno::LinuxError;
use axfs_ng_vfs::MetadataUpdate;
use linux_raw_sys::general::*;
use pulse_core::fd_table::location_to_stat;

const STATX_BASIC_STATS: u32 = 0x0000_07ff;
const STATX_MNT_ID: u32 = 0x0000_1000;
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

fn to_statx_timestamp(tv_sec: i64, tv_nsec: i64) -> StatxTimestamp {
    StatxTimestamp {
        tv_sec,
        tv_nsec: tv_nsec as u32,
        __reserved: 0,
    }
}

pub fn sys_fstat(fd: usize, statbuf: usize) -> isize {
    axlog::debug!("sys_fstat: fd={}, statbuf={:#x}", fd, statbuf);
    if statbuf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let stat = match get_fd_entry(fd).and_then(|entry| entry.object.stat()) {
        Ok(stat) => stat,
        Err(e) => return -e.code() as isize,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            core::ptr::from_ref(&stat).cast::<u8>(),
            core::mem::size_of_val(&stat),
        )
    };
    match write_user_bytes(statbuf, bytes) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_fstatat(dirfd: i32, pathname: usize, statbuf: usize, flags: usize) -> isize {
    if statbuf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let location = match resolve_location_at_ptr(dirfd, pathname, flags) {
        Ok(loc) => loc,
        Err(e) => return -e.code() as isize,
    };
    let stat = match location_to_stat(&location) {
        Ok(stat) => stat,
        Err(e) => return -e.code() as isize,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            core::ptr::from_ref(&stat).cast::<u8>(),
            core::mem::size_of_val(&stat),
        )
    };
    match write_user_bytes(statbuf, bytes) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
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
    let location = match resolve_location_at_ptr(dirfd, pathname, flags) {
        Ok(loc) => loc,
        Err(e) => return -e.code() as isize,
    };
    let stat = match location_to_stat(&location) {
        Ok(stat) => stat,
        Err(e) => return -e.code() as isize,
    };

    let statx = Statx {
        stx_mask: STATX_BASIC_STATS | STATX_MNT_ID,
        stx_blksize: stat.st_blksize as u32,
        stx_attributes: 0,
        stx_nlink: stat.st_nlink,
        stx_uid: stat.st_uid,
        stx_gid: stat.st_gid,
        stx_mode: stat.st_mode as u16,
        __spare0: 0,
        stx_ino: stat.st_ino,
        stx_size: stat.st_size as u64,
        stx_blocks: stat.st_blocks as u64,
        stx_attributes_mask: 0,
        stx_atime: to_statx_timestamp(stat.st_atime as i64, stat.st_atime_nsec as i64),
        stx_btime: StatxTimestamp::default(),
        stx_ctime: to_statx_timestamp(stat.st_ctime as i64, stat.st_ctime_nsec as i64),
        stx_mtime: to_statx_timestamp(stat.st_mtime as i64, stat.st_mtime_nsec as i64),
        stx_rdev_major: 0,
        stx_rdev_minor: 0,
        stx_dev_major: 0,
        stx_dev_minor: 0,
        stx_mnt_id: 0,
        stx_dio_mem_align: 0,
        stx_dio_offset_align: 0,
        __spare3: [0; 12],
    };

    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&statx as *const Statx).cast::<u8>(),
            core::mem::size_of::<Statx>(),
        )
    };
    match write_user_bytes(statxbuf, bytes) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_utimensat(dirfd: i32, pathname: usize, times: usize, flags: usize) -> isize {
    axlog::debug!(
        "sys_utimensat: dirfd={}, pathname={:#x}, times={:#x}, flags={:#x}",
        dirfd,
        pathname,
        times,
        flags
    );
    let supported_flags = AT_SYMLINK_NOFOLLOW as usize | AT_EMPTY_PATH as usize;
    if (flags & !supported_flags) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let location = match resolve_location_at_ptr(dirfd, pathname, flags) {
        Ok(location) => location,
        Err(e) => return -e.code() as isize,
    };

    let now = axhal::time::wall_time();
    let (atime, mtime) = if times == 0 {
        (Some(now), Some(now))
    } else {
        let atime = match read_user_timespec(times).and_then(|ts| timespec_to_update_time(ts, now))
        {
            Ok(atime) => atime,
            Err(e) => return -e.code() as isize,
        };
        let mtime_addr = times + core::mem::size_of::<timespec>();
        let mtime =
            match read_user_timespec(mtime_addr).and_then(|ts| timespec_to_update_time(ts, now)) {
                Ok(mtime) => mtime,
                Err(e) => return -e.code() as isize,
            };
        (atime, mtime)
    };

    if atime.is_none() && mtime.is_none() {
        return 0;
    }

    let update = MetadataUpdate {
        atime,
        mtime,
        ..Default::default()
    };
    match location.update_metadata(update) {
        Ok(()) => 0,
        Err(e) => -LinuxError::from(e.canonicalize()).code() as isize,
    }
}

pub fn sys_faccessat(dirfd: i32, pathname: usize, mode: usize, flags: usize) -> isize {
    axlog::debug!(
        "sys_faccessat: dirfd={}, pathname={:#x}, mode={:#o}, flags={:#x}",
        dirfd,
        pathname,
        mode,
        flags
    );

    if (mode & !(R_OK as usize | W_OK as usize | X_OK as usize)) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let supported_flags =
        AT_SYMLINK_NOFOLLOW as usize | AT_EACCESS as usize | AT_EMPTY_PATH as usize;
    if (flags & !supported_flags) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let location = match resolve_location_at_ptr(dirfd, pathname, flags) {
        Ok(location) => location,
        Err(e) => return -e.code() as isize,
    };

    let (uid, gid) = match with_process(|process| {
        if (flags & AT_EACCESS as usize) != 0 {
            (process.euid(), process.egid())
        } else {
            (process.ruid(), process.rgid())
        }
    }) {
        Ok(ids) => ids,
        Err(e) => return -e.code() as isize,
    };

    match check_faccess_permission(&location, mode, uid, gid) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}
