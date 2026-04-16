use crate::impls::fs::common::{
    context_for_dirfd, insert_fd_entry, open_fd_flags, MOUNTED_TARGETS,
    AT_FDCWD, AT_REMOVEDIR,
};
use crate::impls::utils::read_user_cstring;

use alloc::string::ToString;

use arceos_posix_api::ctypes;
use axerrno::LinuxError;
use axfs::OpenOptions;
use axfs_ng_vfs::NodePermission;
use pulse_core::fd_table::open_result_to_entry;

const O_NOFOLLOW: usize = ctypes::O_NOFOLLOW as usize;
const O_DIRECTORY: usize = ctypes::O_DIRECTORY as usize;
const O_DIRECT: usize = ctypes::O_DIRECT as usize;
const O_PATH: usize = ctypes::O_PATH as usize;
const O_APPEND: usize = ctypes::O_APPEND as usize;
const O_TRUNC: usize = ctypes::O_TRUNC as usize;
const O_CREAT: usize = ctypes::O_CREAT as usize;
const O_EXCL: usize = ctypes::O_EXCL as usize;
const O_ACCMODE: usize = ctypes::O_ACCMODE as usize;

fn flags_to_options(flags: usize, mode: usize) -> OpenOptions {
    let mut options = OpenOptions::new();
    match flags & O_ACCMODE {
        x if x == ctypes::O_RDONLY as usize => {
            options.read(true);
        }
        x if x == ctypes::O_WRONLY as usize => {
            options.write(true);
        }
        _ => {
            options.read(true);
            options.write(true);
        }
    }
    if (flags & O_APPEND) != 0 {
        options.append(true);
    }
    if (flags & O_TRUNC) != 0 {
        options.truncate(true);
    }
    if (flags & O_CREAT) != 0 {
        options.create(true);
    }
    if (flags & O_EXCL) != 0 {
        options.create_new(true);
    }
    if (flags & O_DIRECTORY) != 0 {
        options.directory(true);
    }
    if (flags & O_NOFOLLOW) != 0 {
        options.no_follow(true);
    }
    if (flags & O_DIRECT) != 0 {
        options.direct(true);
    }
    if (flags & O_PATH) != 0 {
        options.path(true);
    }
    options.mode(mode as u32);
    options
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

    if let Err(e) = context_for_dirfd(AT_FDCWD).and_then(|ctx| {
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
    if (flags & !AT_REMOVEDIR) != 0 {
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

    if (flags & AT_REMOVEDIR) != 0 {
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
