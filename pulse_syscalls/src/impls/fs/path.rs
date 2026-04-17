use crate::impls::fs::common::{
    MOUNTED_TARGETS, context_for_dirfd, insert_fd_entry, open_fd_flags,
};
use crate::impls::utils::read_user_cstring;
use linux_raw_sys::general::*;

use alloc::string::{String, ToString};

use axerrno::LinuxError;
use axfs::OpenOptions;
use axfs_ng_vfs::{NodePermission, path::Path};
use pulse_core::fd_table::open_result_to_entry;

fn flags_to_options(flags: usize, mode: usize) -> OpenOptions {
    let mut options = OpenOptions::new();
    match flags & (O_ACCMODE as usize) {
        x if x == O_RDONLY as usize => {
            options.read(true);
        }
        x if x == O_WRONLY as usize => {
            options.write(true);
        }
        _ => {
            options.read(true);
            options.write(true);
        }
    }
    if (flags & O_APPEND as usize) != 0 {
        options.append(true);
    }
    if (flags & O_TRUNC as usize) != 0 {
        options.truncate(true);
    }
    if (flags & O_CREAT as usize) != 0 {
        options.create(true);
    }
    if (flags & O_EXCL as usize) != 0 {
        options.create_new(true);
    }
    if (flags & O_DIRECTORY as usize) != 0 {
        options.directory(true);
    }
    if (flags & O_NOFOLLOW as usize) != 0 {
        options.no_follow(true);
    }
    if (flags & O_DIRECT as usize) != 0 {
        options.direct(true);
    }
    if (flags & O_PATH as usize) != 0 {
        options.path(true);
    }
    options.mode(mode as u32);
    options
}

fn read_user_nonempty_path(pathname: usize) -> Result<String, LinuxError> {
    if pathname == 0 {
        return Err(LinuxError::EFAULT);
    }
    let path = read_user_cstring(pathname)?;
    let path = path.to_str().map_err(|_| LinuxError::EINVAL)?;
    if path.is_empty() {
        return Err(LinuxError::EINVAL);
    }
    Ok(path.to_string())
}

fn rename_at(olddirfd: i32, oldpath: &str, newdirfd: i32, newpath: &str) -> Result<(), LinuxError> {
    let old_ctx = context_for_dirfd(olddirfd)?;
    let new_ctx = context_for_dirfd(newdirfd)?;

    let (src_dir, src_name) = old_ctx
        .resolve_parent(Path::new(oldpath))
        .map_err(|e| LinuxError::from(e.canonicalize()))?;
    let (dst_dir, dst_name) = new_ctx
        .resolve_parent(Path::new(newpath))
        .map_err(|e| LinuxError::from(e.canonicalize()))?;

    src_dir
        .rename(src_name.as_ref(), &dst_dir, dst_name.as_ref())
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

pub fn sys_openat(dirfd: i32, pathname: usize, flags: usize, mode: usize) -> isize {
    if pathname == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let ctx = match context_for_dirfd(dirfd) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };

    let path = match read_user_cstring(pathname) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };

    let path = match path.to_str() {
        Ok(path) => path,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    let options = flags_to_options(flags, mode);
    let opened = match options.open(&ctx, path) {
        Ok(opened) => opened,
        Err(e) => {
            let err = LinuxError::from(e.canonicalize());
            return -err.code() as isize;
        }
    };
    let entry = open_result_to_entry(opened, open_fd_flags(flags));
    match insert_fd_entry(entry) {
        Ok(fd) => fd as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_mkdirat(dirfd: i32, pathname: usize, mode: usize) -> isize {
    if pathname == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let ctx = match context_for_dirfd(dirfd) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };
    let path = match read_user_cstring(pathname) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };
    let path = match path.to_str() {
        Ok(path) => path,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };
    match ctx.create_dir(path, NodePermission::from_bits_truncate(mode as _)) {
        Ok(_) => 0,
        Err(e) => -LinuxError::from(e.canonicalize()).code() as isize,
    }
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

    let target = match read_user_cstring(target) {
        Ok(target) => target,
        Err(e) => return -e.code() as isize,
    };
    let target_path = match target.to_str() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    if let Err(e) = context_for_dirfd(AT_FDCWD as i32).and_then(|ctx| {
        ctx.resolve(target_path)
            .map(|_| ())
            .map_err(|err| LinuxError::from(err.canonicalize()))
    }) {
        return -e.code() as isize;
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

    let target = match read_user_cstring(target) {
        Ok(target) => target,
        Err(e) => return -e.code() as isize,
    };
    let target_path = match target.to_str() {
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
    if (flags & !(AT_REMOVEDIR as usize)) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let path = match read_user_cstring(pathname) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };
    let path = match path.to_str() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };
    let ctx = match context_for_dirfd(dirfd) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };

    if (flags & AT_REMOVEDIR as usize) != 0 {
        return match ctx.remove_dir(path) {
            Ok(()) => 0,
            Err(e) => {
                let errno = LinuxError::from(e.canonicalize());
                -errno.code() as isize
            }
        };
    }

    match ctx.remove_file(path) {
        Ok(()) => 0,
        Err(e) => {
            let errno = LinuxError::from(e.canonicalize());
            -errno.code() as isize
        }
    }
}

pub fn sys_renameat2(
    olddirfd: i32,
    oldpath: usize,
    newdirfd: i32,
    newpath: usize,
    flags: usize,
) -> isize {
    const SUPPORTED_FLAGS: usize =
        RENAME_NOREPLACE as usize | RENAME_EXCHANGE as usize | RENAME_WHITEOUT as usize;

    if (flags & !SUPPORTED_FLAGS) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if (flags & RENAME_NOREPLACE as usize) != 0 && (flags & RENAME_EXCHANGE as usize) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if (flags & RENAME_WHITEOUT as usize) != 0 && (flags & RENAME_EXCHANGE as usize) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if (flags & (RENAME_EXCHANGE as usize | RENAME_WHITEOUT as usize)) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let oldpath = match read_user_nonempty_path(oldpath) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };
    let newpath = match read_user_nonempty_path(newpath) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };

    if (flags & RENAME_NOREPLACE as usize) != 0 {
        let new_ctx = match context_for_dirfd(newdirfd) {
            Ok(ctx) => ctx,
            Err(e) => return -e.code() as isize,
        };
        match new_ctx.resolve_no_follow(newpath.as_str()) {
            Ok(_) => return -LinuxError::EEXIST.code() as isize,
            Err(e) => {
                let errno = LinuxError::from(e.canonicalize());
                if errno != LinuxError::ENOENT {
                    return -errno.code() as isize;
                }
            }
        }
    }

    match rename_at(olddirfd, oldpath.as_str(), newdirfd, newpath.as_str()) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}
