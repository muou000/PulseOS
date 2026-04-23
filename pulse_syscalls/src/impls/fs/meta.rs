use axerrno::LinuxError;
use axfs_ng_vfs::{Location, MetadataUpdate};
use linux_raw_sys::general::{
    AT_EACCESS, AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, R_OK, STATX_BASIC_STATS,
    STATX_MNT_ID, W_OK, X_OK, statfs, statx, statx_timestamp, timespec,
};
use pulse_core::fd_table::location_to_stat;

use crate::impls::{
    fs::common::{check_faccess_permission, get_fd_entry, resolve_location_at_ptr},
    utils::{read_user_timespec, timespec_to_update_time, with_process, write_user_bytes},
};

fn to_statx_timestamp(tv_sec: i64, tv_nsec: i64) -> statx_timestamp {
    let mut ts: statx_timestamp = unsafe { core::mem::zeroed() };
    ts.tv_sec = tv_sec;
    ts.tv_nsec = tv_nsec as u32;
    ts
}

fn vfs_statfs_to_linux(location: &Location) -> Result<statfs, LinuxError> {
    let fs_stat = location
        .filesystem()
        .stat()
        .map_err(|e| LinuxError::from(e.canonicalize()))?;
    let mut out: statfs = unsafe { core::mem::zeroed() };
    out.f_type = fs_stat.fs_type as _;
    out.f_bsize = fs_stat.block_size as _;
    out.f_blocks = fs_stat.blocks as _;
    out.f_bfree = fs_stat.blocks_free as _;
    out.f_bavail = fs_stat.blocks_available as _;
    out.f_files = fs_stat.file_count as _;
    out.f_ffree = fs_stat.free_file_count as _;
    out.f_namelen = fs_stat.name_length as _;
    out.f_frsize = fs_stat.fragment_size as _;
    out.f_flags = fs_stat.mount_flags as _;
    Ok(out)
}

pub fn sys_statfs(pathname: usize, buf: usize) -> isize {
    if buf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let location = match resolve_location_at_ptr(AT_FDCWD as i32, pathname, 0) {
        Ok(loc) => loc,
        Err(e) => return -e.code() as isize,
    };
    let fs_stat = match vfs_statfs_to_linux(&location) {
        Ok(stat) => stat,
        Err(e) => return -e.code() as isize,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&fs_stat as *const statfs).cast::<u8>(),
            core::mem::size_of::<statfs>(),
        )
    };
    match write_user_bytes(buf, bytes) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_fstatfs(fd: usize, buf: usize) -> isize {
    if buf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let location = match get_fd_entry(fd) {
        Ok(entry) => match entry.object.location() {
            Some(loc) => loc,
            None => return -LinuxError::EBADF.code() as isize,
        },
        Err(e) => return -e.code() as isize,
    };
    let fs_stat = match vfs_statfs_to_linux(&location) {
        Ok(stat) => stat,
        Err(e) => return -e.code() as isize,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&fs_stat as *const statfs).cast::<u8>(),
            core::mem::size_of::<statfs>(),
        )
    };
    match write_user_bytes(buf, bytes) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
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

pub fn sys_readlinkat(dirfd: i32, pathname: usize, buf: usize, bufsiz: usize) -> isize {
    if buf == 0 && bufsiz != 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if bufsiz == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let location = match resolve_location_at_ptr(dirfd, pathname, AT_SYMLINK_NOFOLLOW as usize) {
        Ok(loc) => loc,
        Err(e) => return -e.code() as isize,
    };
    let target = match location.read_link() {
        Ok(target) => target,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };

    let target_bytes = target.as_bytes();
    let copy_len = core::cmp::min(target_bytes.len(), bufsiz);
    match write_user_bytes(buf, &target_bytes[..copy_len]) {
        Ok(()) => copy_len as isize,
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

    let mut new_statx: statx = unsafe { core::mem::zeroed() };
    new_statx.stx_mask = STATX_BASIC_STATS | STATX_MNT_ID;
    new_statx.stx_blksize = stat.st_blksize as u32;
    new_statx.stx_attributes = 0;
    new_statx.stx_nlink = stat.st_nlink as u32;
    new_statx.stx_uid = stat.st_uid;
    new_statx.stx_gid = stat.st_gid;
    new_statx.stx_mode = stat.st_mode as u16;
    new_statx.stx_ino = stat.st_ino;
    new_statx.stx_size = stat.st_size as u64;
    new_statx.stx_blocks = stat.st_blocks as u64;
    new_statx.stx_attributes_mask = 0;
    new_statx.stx_atime = to_statx_timestamp(stat.st_atime as i64, stat.st_atime_nsec as i64);
    new_statx.stx_btime = to_statx_timestamp(0, 0);
    new_statx.stx_ctime = to_statx_timestamp(stat.st_ctime as i64, stat.st_ctime_nsec as i64);
    new_statx.stx_mtime = to_statx_timestamp(stat.st_mtime as i64, stat.st_mtime_nsec as i64);
    new_statx.stx_rdev_major = 0;
    new_statx.stx_rdev_minor = 0;
    new_statx.stx_dev_major = 0;
    new_statx.stx_dev_minor = 0;
    new_statx.stx_mnt_id = 0;
    new_statx.stx_dio_mem_align = 0;
    new_statx.stx_dio_offset_align = 0;
    new_statx.stx_subvol = 0;
    new_statx.stx_atomic_write_unit_min = 0;
    new_statx.stx_atomic_write_unit_max = 0;
    new_statx.stx_atomic_write_segments_max = 0;
    new_statx.stx_dio_read_offset_align = 0;
    new_statx.stx_atomic_write_unit_max_opt = 0;

    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&new_statx as *const statx).cast::<u8>(),
            core::mem::size_of::<statx>(),
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
