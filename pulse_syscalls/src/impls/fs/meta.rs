use axerrno::LinuxError;
use axfs_ng_vfs::{Location, MetadataUpdate};
use linux_raw_sys::general::{
    AT_EACCESS, AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, CAP_CHOWN, R_OK, STATX_BASIC_STATS,
    STATX_MNT_ID, W_OK, X_OK, statfs, statx, statx_timestamp, timespec,
};
use pulse_core::fd_table::location_to_stat;

use crate::impls::{
    fs::common::{check_faccess_permission, get_fd_entry, resolve_location_at_ptr},
    utils::{read_user_cstring, read_user_timespec, timespec_to_update_time, with_process, write_user_bytes},
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
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let location = match entry.object.location() {
        Some(loc) => loc,
        None => return -LinuxError::EBADF.code() as isize,
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
    if bufsiz <= 1 {
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

    // 判断是否是对 FD 本身的 statx（AT_EMPTY_PATH + 路径为空或 pathname==0）
    // 对于 stdin/stdout/pipe/socket 等没有文件系统路径的匿名 FD，
    // resolve_location_at_ptr 会因为 location() 返回 None 而报 EBADF。
    // 此时应直接通过 FD object 的 stat() 方法获取信息。
    let is_empty_path = (flags & AT_EMPTY_PATH as usize) != 0 && (
        pathname == 0
        || read_user_cstring(pathname)
            .map(|s| s.as_bytes().is_empty())
            .unwrap_or(false)
    );

    let stat = if is_empty_path && dirfd >= 0 && dirfd != AT_FDCWD as i32 {
        // AT_EMPTY_PATH + 合法 FD：优先直接通过 FD object 获取 stat，
        // 以兼容 stdin/stdout/pipe 等无 VFS location 的匿名 FD。
        match get_fd_entry(dirfd as usize) {
            Ok(entry) => match entry.object.stat() {
                Ok(stat) => stat,
                Err(e) => return -e.code() as isize,
            },
            Err(e) => return -e.code() as isize,
        }
    } else {
        // 普通路径：通过 VFS location 获取 stat
        let location = match resolve_location_at_ptr(dirfd, pathname, flags) {
            Ok(loc) => loc,
            Err(e) => return -e.code() as isize,
        };
        match location_to_stat(&location) {
            Ok(stat) => stat,
            Err(e) => return -e.code() as isize,
        }
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
    let dev = axfs_ng_vfs::DeviceId(stat.st_dev as u64);
    new_statx.stx_dev_major = dev.major();
    new_statx.stx_dev_minor = dev.minor();
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
    axlog::info!(
        "sys_utimensat: dirfd={}, pathname={:#x}, times={:#x}, flags={:#x}, sizeof(timespec)={}",
        dirfd,
        pathname,
        times,
        flags,
        core::mem::size_of::<timespec>()
    );
    let supported_flags = AT_SYMLINK_NOFOLLOW as usize | AT_EMPTY_PATH as usize;
    if (flags & !supported_flags) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let location = if pathname == 0 {
        match resolve_location_at_ptr(dirfd, pathname, flags | AT_EMPTY_PATH as usize) {
            Ok(location) => location,
            Err(e) => {
                axlog::warn!("sys_utimensat: resolve_location failed for pathname=NULL: {:?}", e);
                return -e.code() as isize;
            }
        }
    } else {
        match resolve_location_at_ptr(dirfd, pathname, flags) {
            Ok(location) => location,
            Err(e) => {
                axlog::warn!("sys_utimensat: resolve_location failed: {:?}", e);
                return -e.code() as isize;
            }
        }
    };

    let now = axhal::time::wall_time();
    let (atime, mtime) = if times == 0 {
        (Some(now), Some(now))
    } else {
        let atime = match read_user_timespec(times).and_then(|ts| timespec_to_update_time(ts, now))
        {
            Ok(atime) => atime,
            Err(e) => {
                axlog::warn!("sys_utimensat: read_user_timespec(atime) failed at {:#x}: {:?}", times, e);
                return -e.code() as isize;
            }
        };
        let mtime_addr = times + core::mem::size_of::<timespec>();
        let mtime =
            match read_user_timespec(mtime_addr).and_then(|ts| timespec_to_update_time(ts, now)) {
                Ok(mtime) => mtime,
                Err(e) => {
                    axlog::warn!("sys_utimensat: read_user_timespec(mtime) failed at {:#x}: {:?}", mtime_addr, e);
                    return -e.code() as isize;
                }
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
    // Timestamps update is a write; reject on read-only filesystem.
    if crate::impls::fs::common::is_location_readonly(&location) {
        return -LinuxError::EROFS.code() as isize;
    }

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

/// `fchmodat(dirfd, pathname, mode, flags)` — 设置文件权限位。
///
/// PulseOS 不强制执行文件权限，此 stub 仅验证路径存在性后返回成功，
/// 以满足 LTP 等测试框架的 setup 阶段需求。
pub fn sys_fchmodat(dirfd: i32, pathname: usize, mode: usize, flags: usize) -> isize {
    // 尝试读取路径字符串用于日志
    let path_str = if pathname != 0 {
        crate::impls::utils::read_user_cstring(pathname)
            .map(|c| alloc::string::String::from_utf8_lossy(c.as_bytes()).into_owned())
            .unwrap_or_else(|_| "<unreadable>".into())
    } else {
        "<null>".into()
    };
    axlog::debug!(
        "sys_fchmodat: dirfd={}, pathname={:#x} (\"{}\"), mode={:#o}, flags={:#x}",
        dirfd,
        pathname,
        path_str,
        mode,
        flags
    );

    // AT_SYMLINK_NOFOLLOW 和 AT_EMPTY_PATH 是允许的 flags
    let supported_flags = AT_SYMLINK_NOFOLLOW as usize | AT_EMPTY_PATH as usize;
    if (flags & !supported_flags) != 0 {
        axlog::warn!(
            "sys_fchmodat: unsupported flags={:#x}, returning EINVAL",
            flags
        );
        return -LinuxError::EINVAL.code() as isize;
    }

    match resolve_location_at_ptr(dirfd, pathname, flags) {
        Ok(location) => {
            if crate::impls::fs::common::is_location_readonly(&location) {
                return -LinuxError::EROFS.code() as isize;
            }
            let mut perm = axfs_ng_vfs::NodePermission::from_bits_truncate(mode as u16);

            // POSIX: 若进程非 root，且文件 GID 既不匹配 EGID 也不在附属组中，
            // 则自动清除 S_ISGID，即便用户请求中包含该位。
            if perm.contains(axfs_ng_vfs::NodePermission::SET_GID) {
                let should_clear = match (
                    location.metadata(),
                    with_process(|p| (p.euid(), p.egid(), p.groups())),
                ) {
                    (Ok(meta), Ok((euid, egid, groups))) => {
                        euid != 0 && meta.gid != egid && !groups.contains(&meta.gid)
                    }
                    _ => false,
                };
                if should_clear {
                    axlog::debug!(
                        "sys_fchmodat: clearing S_ISGID on \"{}\" (non-root, GID mismatch)",
                        path_str
                    );
                    perm.remove(axfs_ng_vfs::NodePermission::SET_GID);
                }
            }

            match location.update_metadata(axfs_ng_vfs::MetadataUpdate {
                mode: Some(perm),
                ..Default::default()
            }) {
                Ok(()) => {
                    axlog::debug!(
                        "sys_fchmodat: path \"{}\" resolved and metadata updated OK, returning 0",
                        path_str
                    );
                    0
                }
                Err(e) => {
                    let err = LinuxError::from(e.canonicalize());
                    axlog::warn!(
                        "sys_fchmodat: path \"{}\" update_metadata failed: {:?}, returning {}",
                        path_str,
                        err,
                        -err.code()
                    );
                    -err.code() as isize
                }
            }
        }
        Err(e) => {
            axlog::warn!(
                "sys_fchmodat: path \"{}\" resolve failed: {:?} (code={}), returning {}",
                path_str,
                e,
                e.code(),
                -(e.code() as isize)
            );
            -e.code() as isize
        }
    }
}

/// `fchmod(fd, mode)` — 设置打开文件的权限位。
pub fn sys_fchmod(fd: usize, mode: usize) -> isize {
    axlog::debug!("sys_fchmod: fd={}, mode={:#o}", fd, mode);

    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let location = match entry.object.location() {
        Some(loc) => loc,
        None => return -LinuxError::EBADF.code() as isize,
    };

    if crate::impls::fs::common::is_location_readonly(&location) {
        return -LinuxError::EROFS.code() as isize;
    }

    let mut perm = axfs_ng_vfs::NodePermission::from_bits_truncate(mode as u16);

    // POSIX: 若进程非 root，且文件 GID 既不匹配 EGID 也不在附属组中，
    // 则自动清除 S_ISGID，即便用户请求中包含该位。
    if perm.contains(axfs_ng_vfs::NodePermission::SET_GID) {
        let should_clear = match (
            location.metadata(),
            with_process(|p| (p.euid(), p.egid(), p.groups())),
        ) {
            (Ok(meta), Ok((euid, egid, groups))) => {
                euid != 0 && meta.gid != egid && !groups.contains(&meta.gid)
            }
            _ => false,
        };
        if should_clear {
            axlog::debug!(
                "sys_fchmod: clearing S_ISGID on fd={} (non-root, GID mismatch)",
                fd
            );
            perm.remove(axfs_ng_vfs::NodePermission::SET_GID);
        }
    }

    match location.update_metadata(axfs_ng_vfs::MetadataUpdate {
        mode: Some(perm),
        ..Default::default()
    }) {
        Ok(()) => {
            axlog::debug!(
                "sys_fchmod: fd={} resolved and metadata updated OK, returning 0",
                fd
            );
            0
        }
        Err(e) => {
            let err = LinuxError::from(e.canonicalize());
            axlog::debug!(
                "sys_fchmod: fd={} update_metadata failed: {:?}, returning {}",
                fd,
                err,
                -err.code()
            );
            -err.code() as isize
        }
    }
}

/// `fchownat(dirfd, pathname, uid, gid, flags)` — 设置文件所有者。
///
/// PulseOS 不强制执行文件所有权，此 stub 仅验证路径存在性后返回成功。
pub fn sys_fchownat(dirfd: i32, pathname: usize, uid: usize, gid: usize, flags: usize) -> isize {
    let path_str = if pathname != 0 {
        crate::impls::utils::read_user_cstring(pathname)
            .map(|c| alloc::string::String::from_utf8_lossy(c.as_bytes()).into_owned())
            .unwrap_or_else(|_| "<unreadable>".into())
    } else {
        "<null>".into()
    };
    axlog::debug!(
        "sys_fchownat: dirfd={}, path=\"{}\", uid={}, gid={}, flags={:#x}",
        dirfd,
        path_str,
        uid,
        gid,
        flags
    );

    match resolve_location_at_ptr(dirfd, pathname, flags) {
        Ok(location) => {
            if crate::impls::fs::common::is_location_readonly(&location) {
                return -LinuxError::EROFS.code() as isize;
            }
            let current_meta = match location.metadata() {
                Ok(meta) => meta,
                Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
            };

            // Permission check
            let (fsuid, fsgid, groups, cap_effective) = match with_process(|process| {
                (
                    process.fsuid(),
                    process.fsgid(),
                    process.groups(),
                    process.capabilities().1,
                )
            }) {
                Ok(v) => v,
                Err(e) => return -e.code() as isize,
            };

            let has_cap_chown = fsuid == 0 || (cap_effective & (1 << CAP_CHOWN)) != 0;

            if !has_cap_chown {
                // Not root, check if changing owner
                if (uid as u32) != u32::MAX && (uid as u32) != current_meta.uid {
                    return -LinuxError::EPERM.code() as isize;
                }
                // Check if changing group
                if (gid as u32) != u32::MAX && (gid as u32) != current_meta.gid {
                    // Must be owner
                    if fsuid != current_meta.uid {
                        return -LinuxError::EPERM.code() as isize;
                    }
                    // New group must be in process groups
                    if (gid as u32) != fsgid && !groups.contains(&(gid as u32)) {
                        return -LinuxError::EPERM.code() as isize;
                    }
                }
            }

            let new_uid = if (uid as u32) != u32::MAX {
                uid as u32
            } else {
                current_meta.uid
            };
            let new_gid = if (gid as u32) != u32::MAX {
                gid as u32
            } else {
                current_meta.gid
            };

            let mut new_mode = current_meta.mode;
            if current_meta.node_type == axfs_ng_vfs::NodeType::RegularFile
                && ((uid as u32) != u32::MAX || (gid as u32) != u32::MAX)
            {
                if new_mode.contains(axfs_ng_vfs::NodePermission::SET_UID) {
                    new_mode.remove(axfs_ng_vfs::NodePermission::SET_UID);
                }
                if new_mode.contains(axfs_ng_vfs::NodePermission::SET_GID)
                    && new_mode.contains(axfs_ng_vfs::NodePermission::GROUP_EXEC)
                {
                    new_mode.remove(axfs_ng_vfs::NodePermission::SET_GID);
                }
            }

            match location.update_metadata(axfs_ng_vfs::MetadataUpdate {
                owner: Some((new_uid, new_gid)),
                mode: Some(new_mode),
                ..Default::default()
            }) {
                Ok(()) => 0,
                Err(e) => -LinuxError::from(e.canonicalize()).code() as isize,
            }
        }
        Err(e) => -e.code() as isize,
    }
}
