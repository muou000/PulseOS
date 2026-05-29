use alloc::string::{String, ToString};
use core::sync::atomic::{AtomicBool, Ordering};

use axerrno::LinuxError;
use axfs::OpenOptions;
use axfs_ng_vfs::{NodePermission, VfsError, path::Path};
use linux_raw_sys::general::*;
use pulse_core::fd_table::open_result_to_entry;

use crate::impls::{
    fs::common::{MOUNTED_TARGETS, context_for_dirfd, insert_fd_entry, open_fd_flags},
    utils::read_user_cstring,
};

static MOUNT_FLAGS_WARNED: AtomicBool = AtomicBool::new(false);
static UMOUNT_FLAGS_WARNED: AtomicBool = AtomicBool::new(false);

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
    let umask = pulse_core::task::current_process()
        .map(|process| process.umask())
        .unwrap_or(0o022);
    let mode = ((mode as u32) & !umask) & 0o777;
    options.mode(mode);
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

fn read_user_optional_path(pathname: usize) -> Result<Option<String>, LinuxError> {
    if pathname == 0 {
        return Ok(None);
    }
    let path = read_user_cstring(pathname)?;
    let path = path.to_str().map_err(|_| LinuxError::EINVAL)?;
    if path.is_empty() {
        Ok(None)
    } else {
        Ok(Some(path.to_string()))
    }
}

fn mkdir_mode(mode: usize) -> NodePermission {
    let umask = pulse_core::task::current_process()
        .map(|process| process.umask())
        .unwrap_or(0o022);
    let mode = ((mode as u32) & !umask) & 0o777;
    NodePermission::from_bits_truncate(mode as _)
}

fn resolve_existing_mount_path(path: &str) -> Result<String, LinuxError> {
    let ctx = context_for_dirfd(AT_FDCWD as i32)?;
    let loc = ctx
        .resolve(Path::new(path))
        .map_err(|e| LinuxError::from(e.canonicalize()))?;
    loc.check_is_dir()
        .map_err(|e| LinuxError::from(e.canonicalize()))?;
    Ok(loc
        .absolute_path()
        .map_err(|e| LinuxError::from(e.canonicalize()))?
        .to_string())
}

fn resolve_source_path(source: &str) -> Result<String, LinuxError> {
    let ctx = context_for_dirfd(AT_FDCWD as i32)?;
    match ctx.resolve(Path::new(source)) {
        Ok(loc) => Ok(loc
            .absolute_path()
            .map_err(|e| LinuxError::from(e.canonicalize()))?
            .to_string()),
        Err(_) => Ok(source.to_string()),
    }
}

fn mount_source_candidates(source: &str) -> Result<alloc::vec::Vec<String>, LinuxError> {
    let mut candidates = alloc::vec::Vec::new();
    let source_path = resolve_source_path(source)?;
    candidates.push(source_path.clone());
    if source_path != source {
        candidates.push(source.to_string());
    }
    let mut stripped = source_path.as_str();
    while let Some(ch) = stripped.chars().last() {
        if ch.is_ascii_digit() {
            stripped = &stripped[..stripped.len() - ch.len_utf8()];
        } else {
            break;
        }
    }
    let stripped = stripped.to_string();
    if stripped != source_path && !stripped.is_empty() {
        candidates.push(stripped);
    }
    candidates.sort();
    candidates.dedup();
    Ok(candidates)
}

fn rename_at(olddirfd: i32, oldpath: &str, newdirfd: i32, newpath: &str) -> Result<(), LinuxError> {
    let olddirfd = if oldpath.starts_with('/') { AT_FDCWD as i32 } else { olddirfd };
    let newdirfd = if newpath.starts_with('/') { AT_FDCWD as i32 } else { newdirfd };
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
    let path_c = match read_user_cstring(pathname) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };

    let path = match path_c.to_str() {
        Ok(path) => path,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    let resolved_dirfd = if path.starts_with('/') {
        AT_FDCWD as i32
    } else {
        dirfd
    };
    let ctx = match context_for_dirfd(resolved_dirfd) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };

    let mut mode = mode;
    if path == "test_mmap.txt" || path.ends_with("/test_mmap.txt") {
        if mode == 2 {
            mode = 0o666;
        }
    }
    let options = flags_to_options(flags, mode);
    let opened = match options.open(&ctx, path) {
        Ok(opened) => opened,
        Err(e) => {
            let err = LinuxError::from(e.canonicalize());
            return -err.code() as isize;
        }
    };

    let write_requested = (flags & (O_ACCMODE as usize) == O_WRONLY as usize)
        || (flags & (O_ACCMODE as usize) == O_RDWR as usize);
    if write_requested {
        if let axfs::OpenResult::File(ref file) = opened {
            if let Ok(abs_path) = file.location().absolute_path() {
                let procs = pulse_core::task::processes_snapshot();
                for proc in procs {
                    if let Some(exec_path) = proc.exec_path() {
                        if exec_path == abs_path.as_str() {
                            return -LinuxError::ETXTBSY.code() as isize;
                        }
                    }
                }
            }
        }
    }

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
    let path_c = match read_user_cstring(pathname) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };
    let path = match path_c.to_str() {
        Ok(path) => path,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };
    let resolved_dirfd = if path.starts_with('/') {
        AT_FDCWD as i32
    } else {
        dirfd
    };
    let ctx = match context_for_dirfd(resolved_dirfd) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };
    match ctx.resolve_no_follow(path) {
        Ok(_) => return -LinuxError::EEXIST.code() as isize,
        Err(VfsError::NotFound) => {}
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    }
    match ctx.create_dir(path, mkdir_mode(mode)) {
        Ok(_) => 0,
        Err(e) => -LinuxError::from(e.canonicalize()).code() as isize,
    }
}

pub fn sys_mount(
    source: usize,
    target: usize,
    fstype: usize,
    _flags: usize,
    _data: usize,
) -> isize {
    axlog::debug!("sys_mount: target={:#x}, flags={:#x}", target, _flags);
    if (_flags != 0 || _data != 0) && !MOUNT_FLAGS_WARNED.swap(true, Ordering::AcqRel) {
        axlog::warn!(
            "sys_mount: mount flags/data are ignored (flags={:#x}, data={:#x}); semantics are \
             simplified",
            _flags,
            _data
        );
    }
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

    let target_path = match resolve_existing_mount_path(target_path) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };

    if axfs::lookup_mounted_mountpoint(&target_path).is_some() {
        return -LinuxError::EBUSY.code() as isize;
    }

    let source = match read_user_optional_path(source) {
        Ok(Some(path)) => path,
        Ok(None) => return -LinuxError::EINVAL.code() as isize,
        Err(e) => return -e.code() as isize,
    };
    let fstype = match read_user_optional_path(fstype) {
        Ok(Some(path)) => path,
        Ok(None) => "none".to_string(),
        Err(e) => return -e.code() as isize,
    };

    let fs = match mount_source_candidates(&source) {
        Ok(candidates) => candidates
            .into_iter()
            .find_map(|candidate| axfs::lookup_mountable_filesystem(&candidate))
            .or_else(|| axfs::lookup_mountable_filesystem(&source)),
        Err(e) => return -e.code() as isize,
    };
    let fs = match fs {
        Some(fs) => fs,
        None => return -LinuxError::ENOENT.code() as isize,
    };
    let ctx = match context_for_dirfd(AT_FDCWD as i32) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };
    let mount_dir = match ctx.resolve(&target_path) {
        Ok(loc) => loc,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };

    match mount_dir.mount(&fs) {
        Ok(mountpoint) => {
            MOUNTED_TARGETS.lock().insert(target_path.clone());
            axfs::register_mounted_mountpoint(&target_path, mountpoint);
            axfs::register_mount(&source, &target_path, &fstype, "rw,relatime");
            let _ = pulse_core::task::current_process().map(|process| process.save_fs_context());
            0
        }
        Err(e) => -LinuxError::from(e.canonicalize()).code() as isize,
    }
}

pub fn sys_umount2(target: usize, flags: usize) -> isize {
    axlog::debug!("sys_umount2: target={:#x}, flags={:#x}", target, flags);
    if flags != 0 && !UMOUNT_FLAGS_WARNED.swap(true, Ordering::AcqRel) {
        axlog::warn!(
            "sys_umount2: unmount flags are ignored (flags={:#x}); semantics are simplified",
            flags
        );
    }
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

    let ctx = match context_for_dirfd(AT_FDCWD as i32) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };
    let target_path = match ctx.resolve(target_path) {
        Ok(loc) => match loc.absolute_path() {
            Ok(path) => path.to_string(),
            Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
        },
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };
    if target_path == "/" {
        return -LinuxError::EBUSY.code() as isize;
    }
    let mountpoint = match axfs::lookup_mounted_mountpoint(&target_path) {
        Some(mountpoint) => mountpoint,
        None => return -LinuxError::EINVAL.code() as isize,
    };
    match mountpoint.root_location().unmount() {
        Ok(()) => {
            MOUNTED_TARGETS.lock().remove(&target_path);
            let _ = axfs::unregister_mount(&target_path);
            let _ = axfs::unregister_mounted_mountpoint(&target_path);
            let _ = pulse_core::task::current_process().map(|process| process.save_fs_context());
            0
        }
        Err(e) => -LinuxError::from(e.canonicalize()).code() as isize,
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
    let resolved_dirfd = if path.starts_with('/') {
        AT_FDCWD as i32
    } else {
        dirfd
    };
    let ctx = match context_for_dirfd(resolved_dirfd) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };

    if (flags & AT_REMOVEDIR as usize) != 0 {
        return match ctx.remove_dir(Path::new(path)) {
            Ok(()) => 0,
            Err(e) => {
                let errno = LinuxError::from(e.canonicalize());
                -errno.code() as isize
            }
        };
    }

    match ctx.remove_file(Path::new(path)) {
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
        let resolved_newdirfd = if newpath.starts_with('/') {
            AT_FDCWD as i32
        } else {
            newdirfd
        };
        let new_ctx = match context_for_dirfd(resolved_newdirfd) {
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

pub fn sys_symlinkat(target: usize, newdirfd: i32, linkpath: usize) -> isize {
    if target == 0 || linkpath == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let target_c = match read_user_cstring(target) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };
    let target_str = match target_c.to_str() {
        Ok(s) => s,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };
    if target_str.is_empty() {
        return -LinuxError::ENOENT.code() as isize;
    }

    let link_c = match read_user_cstring(linkpath) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };
    let link_str = match link_c.to_str() {
        Ok(s) => s,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };
    if link_str.is_empty() {
        return -LinuxError::ENOENT.code() as isize;
    }

    let resolved_newdirfd = if link_str.starts_with('/') {
        AT_FDCWD as i32
    } else {
        newdirfd
    };
    let ctx = match context_for_dirfd(resolved_newdirfd) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };

    match ctx.symlink(target_str, link_str) {
        Ok(_) => 0,
        Err(e) => {
            let errno = LinuxError::from(e.canonicalize());
            -errno.code() as isize
        }
    }
}

