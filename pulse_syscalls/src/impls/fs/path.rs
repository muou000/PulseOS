use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, Ordering};

use axerrno::LinuxError;
use axfs::OpenOptions;
use axfs_ng_vfs::{MetadataUpdate, NodePermission, NodeType, VfsError, path::Path};
use linux_raw_sys::general::*;
use pulse_core::fd_table::open_result_to_entry;

use crate::impls::{
    fs::common::{context_for_dirfd, insert_fd_entry, open_fd_flags, resolve_location_at_ptr},
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
        if (flags & O_EXCL as usize) != 0 {
            options.create_new(true);
        }
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
    let mode = ((mode as u32) & !umask) & 0o7777;
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
    let mode = ((mode as u32) & !umask) & 0o7777;
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

fn lookup_or_probe_fs(source: &str, fstype: &str) -> Result<axfs_ng_vfs::Filesystem, LinuxError> {
    if let Some(fs) = axfs::lookup_mountable_filesystem(source) {
        return Ok(fs);
    }

    // Pseudo filesystems
    if fstype == "tmpfs" {
        return Ok(axfs::new_tmpfs());
    }
    if fstype == "proc" {
        return Ok(axfs::new_procfs());
    }

    if source.starts_with("/dev/") {
        let loc = match axfs::lookup_location(source) {
            Ok(loc) => loc,
            Err(e) => {
                // If the device node itself isn't found, it's ENOENT
                return Err(LinuxError::from(e.canonicalize()));
            }
        };
        let entry = loc.entry();

        let is_block = entry.node_type() == axfs_ng_vfs::NodeType::BlockDevice;

        match fstype {
            "ext4" => {
                #[cfg(feature = "ext4")]
                {
                    if !is_block {
                        return Err(LinuxError::ENOTBLK);
                    }
                    let node = entry
                        .downcast::<axfs::DevNode>()
                        .map_err(|_| LinuxError::ENOTBLK)?;
                    let disk = node
                        .get_block_device()
                        .map_err(|e| LinuxError::from(e.canonicalize()))?;
                    return axfs::ext4::Ext4Filesystem::new(disk)
                        .map_err(|e| LinuxError::from(e.canonicalize()));
                }
                #[cfg(not(feature = "ext4"))]
                {
                    return Err(LinuxError::ENODEV);
                }
            }

            "ext2" | "ext3" => {
                return Err(LinuxError::ENODEV);
            }

            "none" | "" => {
                if !is_block {
                    return Err(LinuxError::ENOTBLK);
                }
                // Auto-probe
                return axfs::probe_block_device(source, &loc)
                    .map_err(|e| LinuxError::from(e.canonicalize()));
            }
            _ => return Err(LinuxError::ENODEV),
        }
    }

    Err(LinuxError::ENOENT)
}

fn rename_at(olddirfd: i32, oldpath: &str, newdirfd: i32, newpath: &str) -> Result<(), LinuxError> {
    let olddirfd = if oldpath.starts_with('/') {
        AT_FDCWD as i32
    } else {
        olddirfd
    };
    let newdirfd = if newpath.starts_with('/') {
        AT_FDCWD as i32
    } else {
        newdirfd
    };
    let old_ctx = context_for_dirfd(olddirfd)?;
    let new_ctx = context_for_dirfd(newdirfd)?;

    let (src_dir, src_name) = old_ctx
        .resolve_parent(Path::new(oldpath))
        .map_err(|e| LinuxError::from(e.canonicalize()))?;
    let (dst_dir, dst_name) = new_ctx
        .resolve_parent(Path::new(newpath))
        .map_err(|e| LinuxError::from(e.canonicalize()))?;

    old_ctx.check_write_permission(&src_dir)?;
    new_ctx.check_write_permission(&dst_dir)?;

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

    // Check for read-only filesystem before opening with write/create intent
    {
        let write_requested = (flags & (O_ACCMODE as usize) == O_WRONLY as usize)
            || (flags & (O_ACCMODE as usize) == O_RDWR as usize)
            || (flags & O_TRUNC as usize) != 0;
        let create_requested = (flags & O_CREAT as usize) != 0;
        if write_requested || create_requested {
            let is_ro = match ctx.resolve_no_follow(path) {
                Ok(loc) => {
                    let ro = crate::impls::fs::common::is_location_readonly(&loc);
                    // For O_CREAT-only (no write), allow opening an existing file.
                    if !write_requested && ro {
                        // file exists on ro fs but we only want O_CREAT; allow open (no creation needed)
                        false
                    } else {
                        ro
                    }
                }
                Err(_) => {
                    // File doesn't exist; if create or write requested on ro fs → EROFS
                    if let Ok((parent_loc, _)) =
                        ctx.resolve_parent(axfs_ng_vfs::path::Path::new(path))
                    {
                        crate::impls::fs::common::is_location_readonly(&parent_loc)
                    } else {
                        false
                    }
                }
            };
            if is_ro {
                return -LinuxError::EROFS.code() as isize;
            }
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

    let metadata = match &opened {
        axfs::OpenResult::File(file) => file.location().metadata(),
        axfs::OpenResult::Dir(dir) => dir.metadata(),
    };
    if let Ok(ref meta) = metadata {
        // O_NOATIME permission check
        if (flags & (O_NOATIME as usize)) != 0 {
            let current_uid = pulse_core::task::current_process()
                .map(|process| process.fsuid())
                .unwrap_or(0);
            if current_uid != 0 && current_uid != meta.uid {
                return -LinuxError::EPERM.code() as isize;
            }
        }
        // FIFO O_NONBLOCK | O_WRONLY check
        if meta.node_type == NodeType::Fifo {
            if (flags & (O_NONBLOCK as usize)) != 0
                && (flags & (O_ACCMODE as usize)) == O_WRONLY as usize
            {
                let mut has_reader = false;
                let procs = pulse_core::task::processes_snapshot();
                for proc in procs {
                    let fd_table = proc.fd_table();
                    let fd_table_guard = fd_table.read();
                    if fd_table_guard.is_file_read_open_by_meta(meta.device, meta.inode) {
                        has_reader = true;
                        break;
                    }
                }
                if !has_reader {
                    return -LinuxError::ENXIO.code() as isize;
                }
            }
        }
        // O_NOFOLLOW symlink check
        if (flags & (O_NOFOLLOW as usize)) != 0
            && (flags & (O_PATH as usize)) == 0
            && meta.node_type == NodeType::Symlink
        {
            return -LinuxError::ELOOP.code() as isize;
        }
    }

    if (flags & O_PATH as usize) == 0 {
        let access_mode = flags & (O_ACCMODE as usize);
        let mut required_mode = 0usize;
        if access_mode == O_RDONLY as usize || access_mode == O_RDWR as usize {
            required_mode |= R_OK as usize;
        }
        if access_mode == O_WRONLY as usize || access_mode == O_RDWR as usize {
            required_mode |= W_OK as usize;
        }
        if (flags & O_TRUNC as usize) != 0 {
            required_mode |= W_OK as usize;
        }

        let location = match &opened {
            axfs::OpenResult::File(file) => file.location(),
            axfs::OpenResult::Dir(dir) => dir,
        };

        let (uid, gid) = pulse_core::task::current_process()
            .map(|process| (process.fsuid(), process.fsgid()))
            .unwrap_or((0, 0));

        if let Err(err) =
            crate::impls::fs::common::check_faccess_permission(location, required_mode, uid, gid)
        {
            return -err.code() as isize;
        }
    }

    let write_requested = (flags & (O_ACCMODE as usize) == O_WRONLY as usize)
        || (flags & (O_ACCMODE as usize) == O_RDWR as usize);
    if write_requested {
        if let axfs::OpenResult::File(ref file) = opened {
            if let Ok(abs_path) = file.location().absolute_path() {
                let procs = pulse_core::task::processes_snapshot();
                for proc in procs {
                    // Bolt: Avoid cloning the `exec_path` string for every process by checking equality inside the read lock.
                    if proc.is_exec_path(abs_path.as_str()) {
                        return -LinuxError::ETXTBSY.code() as isize;
                    }
                }
            }
        }
    }

    let is_fifo = if let Ok(ref meta) = metadata {
        meta.node_type == NodeType::Fifo
    } else {
        false
    };

    let entry = if is_fifo {
        let meta = metadata.unwrap();
        let access_mode = flags & (O_ACCMODE as usize);
        let readable = access_mode == O_RDONLY as usize || access_mode == O_RDWR as usize;
        let writable = access_mode == O_WRONLY as usize || access_mode == O_RDWR as usize;
        match pulse_core::fd_table::create_fifo_entry(
            meta.device,
            meta.inode,
            readable,
            writable,
            open_fd_flags(flags),
        ) {
            Ok(entry) => entry,
            Err(e) => return -e.code() as isize,
        }
    } else {
        open_result_to_entry(opened, open_fd_flags(flags))
    };

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

    axlog::debug!(
        "sys_mkdirat: dirfd={}, path='{}', mode={:#o}",
        dirfd,
        path,
        mode
    );

    let resolved_dirfd = if path.starts_with('/') {
        AT_FDCWD as i32
    } else {
        dirfd
    };
    let ctx = match context_for_dirfd(resolved_dirfd) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };
    // Check for read-only filesystem: resolve parent dir if path doesn't exist yet
    {
        let is_ro = match ctx.resolve_no_follow(path) {
            Ok(loc) => crate::impls::fs::common::is_location_readonly(&loc),
            Err(_) => {
                if let Ok((parent_loc, _)) = ctx.resolve_parent(axfs_ng_vfs::path::Path::new(path))
                {
                    crate::impls::fs::common::is_location_readonly(&parent_loc)
                } else {
                    false
                }
            }
        };
        if is_ro {
            return -LinuxError::EROFS.code() as isize;
        }
    }
    match ctx.resolve_no_follow(path) {
        Ok(_) => {
            axlog::debug!("sys_mkdirat: path '{}' already exists", path);
            return -LinuxError::EEXIST.code() as isize;
        }
        Err(VfsError::NotFound) => {}
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    }
    axlog::debug!("sys_mkdirat: creating directory '{}'", path);
    match ctx.create_dir(path, mkdir_mode(mode)) {
        Ok(_) => {
            axlog::debug!("sys_mkdirat: directory '{}' created successfully", path);
            0
        }
        Err(e) => {
            axlog::debug!(
                "sys_mkdirat: failed to create directory '{}': {:?}",
                path,
                e
            );
            -LinuxError::from(e.canonicalize()).code() as isize
        }
    }
}

/// Apply propagation-change flags (make-shared, make-slave, …) to an existing mount.
fn sys_mount_propagation(target_path: &str, flags: usize) -> isize {
    let mp = match axfs::lookup_mounted_mountpoint(target_path) {
        Some(mp) => mp,
        None => {
            // Target path may not be a mountpoint itself; that's OK for
            // --make-private etc. on already-mounted paths – we just succeed.
            axlog::debug!(
                "sys_mount_propagation: '{}' not a mounted mountpoint, treating as no-op",
                target_path
            );
            return 0;
        }
    };

    let is_rec = (flags & MS_REC as usize) != 0;
    let is_shared = (flags & MS_SHARED as usize) != 0;
    let is_slave = (flags & MS_SLAVE as usize) != 0;
    let is_private = (flags & MS_PRIVATE as usize) != 0;
    let is_unbindable = (flags & MS_UNBINDABLE as usize) != 0;

    axlog::debug!(
        "sys_mount_propagation: target='{}' rec={} shared={} slave={} private={} unbindable={}",
        target_path,
        is_rec,
        is_shared,
        is_slave,
        is_private,
        is_unbindable
    );

    if is_shared {
        if is_rec {
            mp.make_rshared();
        } else {
            mp.make_shared();
        }
    } else if is_slave {
        if is_rec {
            mp.make_rslave();
        } else {
            mp.make_slave();
        }
    } else if is_private {
        if is_rec {
            mp.make_rprivate();
        } else {
            mp.make_private();
        }
    } else if is_unbindable {
        if is_rec {
            mp.make_runbindable();
        } else {
            mp.make_unbindable();
        }
    }

    let _ = pulse_core::task::current_process().map(|process| process.save_fs_context());
    0
}

/// Implement `mount --move source target` (MS_MOVE).
fn sys_mount_move(source_uptr: usize, target_path: &str) -> isize {
    let source_path = match read_user_optional_path(source_uptr) {
        Ok(Some(p)) => p,
        Ok(None) => return -LinuxError::EINVAL.code() as isize,
        Err(e) => return -e.code() as isize,
    };
    let source_path = match resolve_existing_mount_path(&source_path) {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };
    axlog::debug!("sys_mount_move: '{}' -> '{}'", source_path, target_path);

    let ctx = match context_for_dirfd(AT_FDCWD as i32) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };
    // Source must be a mountpoint root.
    let source_loc = match ctx.resolve(&source_path) {
        Ok(loc) => loc,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };
    if !source_loc.is_root_of_mount() {
        return -LinuxError::EINVAL.code() as isize;
    }
    // Target must exist and not already be a mount.
    let target_loc = match ctx.resolve(target_path) {
        Ok(loc) => loc,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };

    let parent_mp = target_loc.mountpoint().clone();
    let entry_key = axfs_ng_vfs::Location::pub_entry_key(target_loc.entry());

    // Detach source from its current parent and re-attach at target.
    let new_mp = match source_loc.move_mount(&target_loc) {
        Ok(mp) => mp,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };

    // MOUNTED_TARGETS registry removed

    // Rename records in MOUNT_RECORDS and MOUNTED_MOUNTPOINTS for this path and all descendants.
    axfs::rename_mount_registry(&source_path, target_path);

    // Propagate the move to shared peers and slaves.
    let shadows = axfs_ng_vfs::propagate_new_mount(
        &parent_mp,
        entry_key,
        Some(new_mp.root_location()),
        &new_mp,
    );
    for (_peer_mp, shadow_mp) in shadows {
        if let Some(loc) = shadow_mp.location() {
            if let Ok(abs) = loc.absolute_path() {
                let p = abs.to_string();
                axlog::debug!("sys_mount_move: propagated shadow mount at '{}'", p);
                // MOUNTED_TARGETS insert removed
                axfs::register_mounted_mountpoint(&p, shadow_mp);
                axfs::register_mount(&source_path, &p, "none", "rw,bind,relatime");
            }
        }
    }

    let _ = pulse_core::task::current_process().map(|process| process.save_fs_context());
    0
}

pub fn sys_mount(
    source: usize,
    target: usize,
    fstype: usize,
    _flags: usize,
    _data: usize,
) -> isize {
    axlog::debug!("sys_mount: target={:#x}, flags={:#x}", target, _flags);
    // Only warn if data is non-zero (flags may legitimately be set for remount/rdonly)
    if _data != 0 && !MOUNT_FLAGS_WARNED.swap(true, Ordering::AcqRel) {
        axlog::warn!(
            "sys_mount: mount data is ignored (data={:#x}); semantics are simplified",
            _data
        );
    }
    let is_remount = (_flags & MS_REMOUNT as usize) != 0;
    let is_bind = (_flags & MS_BIND as usize) != 0;
    let is_rdonly = (_flags & MS_RDONLY as usize) != 0;

    // Propagation flags.
    const MS_PROPAGATION: usize =
        (MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED | MS_REC) as usize;
    let is_propagation = (_flags & MS_PROPAGATION) != 0;

    if target == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let target = match read_user_cstring(target) {
        Ok(target) => target,
        Err(e) => return -e.code() as isize,
    };
    let target_path_str = match target.to_str() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    let ctx = match context_for_dirfd(AT_FDCWD as i32) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };

    let target_loc = match ctx.resolve(Path::new(target_path_str)) {
        Ok(loc) => loc,
        Err(e) => {
            axlog::debug!(
                "sys_mount: failed to resolve target path '{}': {:?}",
                target_path_str,
                e
            );
            return -LinuxError::from(e.canonicalize()).code() as isize;
        }
    };

    if let Err(e) = target_loc.check_is_dir() {
        return -LinuxError::from(e.canonicalize()).code() as isize;
    }

    let target_path = match target_loc.absolute_path() {
        Ok(path) => path.to_string(),
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };

    if is_remount {
        // MS_REMOUNT: target must already be mounted.
        let target_mp = if let Some(mp) = axfs::lookup_mounted_mountpoint(&target_path) {
            mp
        } else {
            return -LinuxError::EINVAL.code() as isize;
        };
        // Read source/fstype for updating the mount record (may be null/none for remount).
        let source_path = match read_user_optional_path(source) {
            Ok(Some(p)) => p,
            Ok(None) => "none".to_string(),
            Err(e) => return -e.code() as isize,
        };
        let fstype_name = match read_user_optional_path(fstype) {
            Ok(Some(p)) => p,
            Ok(None) => "none".to_string(),
            Err(e) => return -e.code() as isize,
        };
        let options = if is_rdonly {
            "ro,relatime"
        } else {
            "rw,relatime"
        };
        axlog::debug!("sys_mount: remount '{}' as {}", target_path, options);
        axfs::register_mount(&source_path, &target_path, &fstype_name, options);

        // Update readonly status on the mountpoint and all its peer/slave propagation mounts!
        target_mp.set_readonly(is_rdonly);
        target_mp.set_flags(_flags);
        let peer_mps = axfs_ng_vfs::collect_propagate_unmount(&target_mp);
        for peer in peer_mps {
            peer.set_readonly(is_rdonly);
            peer.set_flags(_flags);
        }

        let _ = pulse_core::task::current_process().map(|process| process.save_fs_context());
        return 0;
    }

    // Pure propagation change (no actual filesystem operation).
    if is_propagation && !is_bind {
        return sys_mount_propagation(&target_path, _flags);
    }

    // MS_MOVE: move an existing mountpoint.
    const MS_MOVE_FLAG: usize = 0x2000;
    if (_flags & MS_MOVE_FLAG) != 0 {
        return sys_mount_move(source, &target_path);
    }

    if is_bind {
        let source_path = match read_user_optional_path(source) {
            Ok(Some(path)) => path,
            Ok(None) => return -LinuxError::EINVAL.code() as isize,
            Err(e) => return -e.code() as isize,
        };
        axlog::debug!(
            "sys_mount: bind mount '{}' to '{}'",
            source_path,
            target_path
        );
        let source_loc = match ctx.resolve(&source_path) {
            Ok(loc) => loc,
            Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
        };
        let mount_dir = target_loc;

        let parent_mp = mount_dir.mountpoint().clone();
        let entry_key = axfs_ng_vfs::Location::pub_entry_key(mount_dir.entry());

        match mount_dir.mount_bind(source_loc.clone()) {
            Ok(mountpoint) => {
                axlog::debug!("sys_mount: bind mount successful on '{}'", target_path);

                // Set readonly status
                if is_rdonly {
                    mountpoint.set_readonly(true);
                } else {
                    mountpoint.set_readonly(source_loc.mountpoint().is_readonly());
                }
                mountpoint.set_flags(_flags);

                axfs::register_mounted_mountpoint(&target_path, mountpoint.clone());
                let options = if is_rdonly {
                    "ro,bind,relatime"
                } else {
                    "rw,bind,relatime"
                };
                axfs::register_mount(&source_path, &target_path, "none", options);

                // Clone the existing subtree from source_loc to the new mountpoint
                let mut self_shadows = Vec::new();
                axfs_ng_vfs::propagate_subtree(
                    &source_loc.mountpoint(),
                    &mountpoint,
                    &mut self_shadows,
                );
                for (_peer_mp, shadow_mp) in self_shadows {
                    if let Some(loc) = shadow_mp.location() {
                        if let Ok(abs) = loc.absolute_path() {
                            let p = abs.to_string();
                            axlog::debug!("sys_mount: propagated local shadow mount at '{}'", p);
                            axfs::register_mounted_mountpoint(&p, shadow_mp);
                            axfs::register_mount(&source_path, &p, "none", options);
                        }
                    }
                }

                // Propagate to shared peers and slaves.
                let shadows = axfs_ng_vfs::propagate_new_mount(
                    &parent_mp,
                    entry_key,
                    Some(source_loc),
                    &mountpoint,
                );
                for (_peer_mp, shadow_mp) in shadows {
                    if let Some(loc) = shadow_mp.location() {
                        if let Ok(abs) = loc.absolute_path() {
                            let p = abs.to_string();
                            axlog::debug!("sys_mount: propagated shadow mount at '{}'", p);
                            axfs::register_mounted_mountpoint(&p, shadow_mp);
                            axfs::register_mount(&source_path, &p, "none", options);
                        }
                    }
                }

                let _ =
                    pulse_core::task::current_process().map(|process| process.save_fs_context());
                return 0;
            }
            Err(e) => {
                axlog::debug!("sys_mount: bind mount failed: {:?}", e);
                return -LinuxError::from(e.canonicalize()).code() as isize;
            }
        }
    }

    if axfs::lookup_mounted_mountpoint(&target_path).is_some() {
        return -LinuxError::EBUSY.code() as isize;
    }

    let source_path = match read_user_optional_path(source) {
        Ok(Some(path)) => path,
        Ok(None) => "none".to_string(),
        Err(e) => return -e.code() as isize,
    };
    let fstype_name = match read_user_optional_path(fstype) {
        Ok(Some(path)) => path,
        Ok(None) => "none".to_string(),
        Err(e) => return -e.code() as isize,
    };

    axlog::debug!(
        "sys_mount: source={}, target={}, fstype={}",
        source_path,
        target_path,
        fstype_name
    );

    let fs_res = match mount_source_candidates(&source_path) {
        Ok(candidates) => {
            let mut res = Err(LinuxError::ENOENT);
            for cand in candidates {
                axlog::debug!(
                    "sys_mount: probing candidate '{}' with fstype '{}'",
                    cand,
                    fstype_name
                );
                match lookup_or_probe_fs(&cand, &fstype_name) {
                    Ok(fs) => {
                        res = Ok(fs);
                        break;
                    }
                    Err(e) => {
                        axlog::debug!("sys_mount: probing candidate '{}' failed: {:?}", cand, e);
                        res = Err(e);
                    }
                }
            }
            if res.is_err() {
                axlog::debug!(
                    "sys_mount: falling back to source '{}' with fstype '{}'",
                    source_path,
                    fstype_name
                );
                match lookup_or_probe_fs(&source_path, &fstype_name) {
                    Ok(fs) => res = Ok(fs),
                    Err(e) => res = Err(e),
                }
            }
            res
        }
        Err(e) => return -e.code() as isize,
    };

    let fs = match fs_res {
        Ok(fs) => fs,
        Err(e) => {
            axlog::debug!(
                "sys_mount: failed to find filesystem for source '{}', fstype '{}': {:?}",
                source_path,
                fstype_name,
                e
            );
            return -e.code() as isize;
        }
    };
    axlog::debug!(
        "sys_mount: found filesystem, proceeding to mount on '{}'",
        target_path
    );
    let mount_dir = target_loc;

    axlog::debug!("sys_mount: target directory resolved, performing mount operation");
    match mount_dir.mount(&fs) {
        Ok(mountpoint) => {
            axlog::debug!("sys_mount: mount successful on '{}'", target_path);

            // Set readonly status
            mountpoint.set_readonly(is_rdonly);
            mountpoint.set_flags(_flags);

            axfs::register_mounted_mountpoint(&target_path, mountpoint);
            let options = if is_rdonly {
                "ro,relatime"
            } else {
                "rw,relatime"
            };
            axfs::register_mount(&source_path, &target_path, &fstype_name, options);
            let _ = pulse_core::task::current_process().map(|process| process.save_fs_context());
            0
        }
        Err(e) => {
            axlog::debug!("sys_mount: mount operation failed: {:?}", e);
            -LinuxError::from(e.canonicalize()).code() as isize
        }
    }
}

pub fn sys_umount2(target: usize, flags: usize) -> isize {
    axlog::debug!("sys_umount2: target={:#x}, flags={:#x}", target, flags);
    const UMOUNT_SUPPORTED_FLAGS: usize =
        (MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) as usize;
    if (flags & !UMOUNT_SUPPORTED_FLAGS) != 0 && !UMOUNT_FLAGS_WARNED.swap(true, Ordering::AcqRel) {
        axlog::warn!(
            "sys_umount2: some unmount flags are ignored (flags={:#x}); semantics are simplified",
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
    let target_path_raw = match target.to_str() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    let ctx = match context_for_dirfd(AT_FDCWD as i32) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };
    let target_loc = match ctx.resolve(target_path_raw) {
        Ok(loc) => loc,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };
    if !target_loc.is_root_of_mount() {
        return -LinuxError::EINVAL.code() as isize;
    }
    let target_path = match target_loc.absolute_path() {
        Ok(path) => path.to_string(),
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };

    if target_path == "/" {
        return -LinuxError::EBUSY.code() as isize;
    }

    // MNT_DETACH: lazy unmount – forcibly remove even if children exist.
    let is_detach = (flags & MNT_DETACH as usize) != 0;

    let target_mp = target_loc.mountpoint().clone();
    let peer_mps = axfs_ng_vfs::collect_propagate_unmount(&target_mp);

    // Unmount all propagated peer mountpoints
    for peer_mp in peer_mps {
        let root_loc = peer_mp.root_location();
        if let Ok(abs_path) = root_loc.absolute_path() {
            let peer_path = abs_path.to_string();
            axlog::debug!("sys_umount2: propagating unmount to peer '{}'", peer_path);
            let res = if is_detach {
                root_loc.unmount_all()
            } else {
                root_loc.unmount()
            };
            match res {
                Ok(()) => {
                    // MOUNTED_TARGETS remove removed
                    let _ = axfs::unregister_mount(&peer_path);
                    let _ = axfs::unregister_mounted_mountpoint(&peer_path);
                }
                Err(e) => {
                    axlog::warn!(
                        "sys_umount2: failed to unmount propagated peer '{}': {:?}",
                        peer_path,
                        e
                    );
                }
            }
        }
    }

    let result = if is_detach {
        target_loc.unmount_all()
    } else {
        target_loc.unmount()
    };

    match result {
        Ok(()) => {
            // MOUNTED_TARGETS remove removed
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

    // Check for read-only filesystem
    {
        let is_ro = match ctx.resolve_no_follow(path) {
            Ok(loc) => crate::impls::fs::common::is_location_readonly(&loc),
            Err(_) => {
                if let Ok((parent_loc, _)) = ctx.resolve_parent(axfs_ng_vfs::path::Path::new(path))
                {
                    crate::impls::fs::common::is_location_readonly(&parent_loc)
                } else {
                    false
                }
            }
        };
        if is_ro {
            return -LinuxError::EROFS.code() as isize;
        }
    }

    // 1. Resolve parent directory and child entry name
    let (parent_loc, entry_name) = match ctx.resolve_parent(Path::new(path)) {
        Ok(res) => res,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };

    // Get process credentials
    let (uid, gid) = pulse_core::task::current_process()
        .map(|process| (process.fsuid(), process.fsgid()))
        .unwrap_or((0, 0));

    // 2. Enforce execute/search permission check on parent directory
    if let Err(err) =
        crate::impls::fs::common::check_faccess_permission(&parent_loc, X_OK as usize, uid, gid)
    {
        return -err.code() as isize;
    }

    // 3. Lookup the child entry to ensure it exists (ENOENT if not found)
    let child_loc = match parent_loc.lookup_no_follow(entry_name.as_ref()) {
        Ok(loc) => loc,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };

    // 4. Enforce write permission check on parent directory
    if let Err(err) =
        crate::impls::fs::common::check_faccess_permission(&parent_loc, W_OK as usize, uid, gid)
    {
        return -err.code() as isize;
    }

    // 5. Enforce sticky bit rules if parent has STICKY bit set
    let parent_meta = match parent_loc.metadata() {
        Ok(meta) => meta,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };
    if parent_meta.mode.contains(NodePermission::STICKY) {
        let child_meta = match child_loc.metadata() {
            Ok(meta) => meta,
            Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
        };
        if uid != 0 && uid != parent_meta.uid && uid != child_meta.uid {
            return -LinuxError::EACCES.code() as isize;
        }
    }

    if (flags & AT_REMOVEDIR as usize) != 0 {
        return match ctx.remove_dir(Path::new(path)) {
            Ok(()) => {
                0
            }
            Err(e) => {
                let errno = LinuxError::from(e.canonicalize());
                -errno.code() as isize
            }
        };
    }

    match ctx.remove_file(Path::new(path)) {
        Ok(()) => {
            0
        }
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

    // Check for read-only filesystem on old or new path
    {
        let resolved_olddirfd = if oldpath.starts_with('/') {
            AT_FDCWD as i32
        } else {
            olddirfd
        };
        let resolved_newdirfd2 = if newpath.starts_with('/') {
            AT_FDCWD as i32
        } else {
            newdirfd
        };
        let old_ro = if let Ok(old_ctx) = context_for_dirfd(resolved_olddirfd) {
            match old_ctx.resolve_no_follow(oldpath.as_str()) {
                Ok(loc) => crate::impls::fs::common::is_location_readonly(&loc),
                Err(_) => false,
            }
        } else {
            false
        };
        let new_ro = if let Ok(new_ctx2) = context_for_dirfd(resolved_newdirfd2) {
            match new_ctx2.resolve_no_follow(newpath.as_str()) {
                Ok(loc) => crate::impls::fs::common::is_location_readonly(&loc),
                Err(_) => {
                    if let Ok((parent_loc, _)) =
                        new_ctx2.resolve_parent(axfs_ng_vfs::path::Path::new(newpath.as_str()))
                    {
                        crate::impls::fs::common::is_location_readonly(&parent_loc)
                    } else {
                        false
                    }
                }
            }
        } else {
            false
        };
        if old_ro || new_ro {
            return -LinuxError::EROFS.code() as isize;
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

    // Check for read-only filesystem
    {
        let is_ro = match ctx.resolve_no_follow(link_str) {
            Ok(loc) => crate::impls::fs::common::is_location_readonly(&loc),
            Err(_) => {
                if let Ok((parent_loc, _)) =
                    ctx.resolve_parent(axfs_ng_vfs::path::Path::new(link_str))
                {
                    crate::impls::fs::common::is_location_readonly(&parent_loc)
                } else {
                    false
                }
            }
        };
        if is_ro {
            return -LinuxError::EROFS.code() as isize;
        }
    }

    match ctx.symlink(target_str, link_str) {
        Ok(_) => 0,
        Err(e) => {
            let errno = LinuxError::from(e.canonicalize());
            -errno.code() as isize
        }
    }
}

pub fn sys_mknodat(dirfd: i32, pathname: usize, mode: usize, _dev: usize) -> isize {
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
    // Check for read-only filesystem
    {
        let is_ro = match ctx.resolve_no_follow(path) {
            Ok(loc) => crate::impls::fs::common::is_location_readonly(&loc),
            Err(_) => {
                if let Ok((parent_loc, _)) = ctx.resolve_parent(axfs_ng_vfs::path::Path::new(path))
                {
                    crate::impls::fs::common::is_location_readonly(&parent_loc)
                } else {
                    false
                }
            }
        };
        if is_ro {
            return -LinuxError::EROFS.code() as isize;
        }
    }
    match ctx.resolve_no_follow(path) {
        Ok(_) => return -LinuxError::EEXIST.code() as isize,
        Err(VfsError::NotFound) => {}
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    }

    let file_type = mode & (S_IFMT as usize);
    let node_type = if file_type == S_IFREG as usize || file_type == 0 {
        NodeType::RegularFile
    } else if file_type == S_IFCHR as usize {
        NodeType::CharacterDevice
    } else if file_type == S_IFBLK as usize {
        NodeType::BlockDevice
    } else if file_type == S_IFIFO as usize {
        NodeType::Fifo
    } else if file_type == S_IFSOCK as usize {
        NodeType::Socket
    } else {
        return -LinuxError::EINVAL.code() as isize;
    };

    let umask = pulse_core::task::current_process()
        .map(|process| process.umask())
        .unwrap_or(0o022);
    let perm = ((mode as u32) & !umask) & 0o7777;
    let node_permission = NodePermission::from_bits_truncate(perm as _);

    let (dir, name) = match ctx.resolve_nonexistent(Path::new(path)) {
        Ok(res) => res,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };

    let mut final_perm = node_permission;
    let mut final_credentials = ctx.credentials;
    if let Ok(parent_meta) = dir.metadata() {
        if parent_meta.mode.contains(NodePermission::SET_GID) {
            if node_type == NodeType::Directory {
                final_perm |= NodePermission::SET_GID;
            }
            if let Some((uid, _)) = final_credentials {
                final_credentials = Some((uid, parent_meta.gid));
            }
        }
    }

    let loc = match dir.create(name, node_type, final_perm) {
        Ok(loc) => loc,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };

    if let Some((uid, gid)) = final_credentials {
        let _ = loc.update_metadata(MetadataUpdate {
            owner: Some((uid, gid)),
            ..Default::default()
        });
    }

    0
}

pub fn sys_linkat(
    olddirfd: i32,
    oldpath: usize,
    newdirfd: i32,
    newpath: usize,
    flags: usize,
) -> isize {
    axlog::debug!(
        "sys_linkat: olddirfd={}, oldpath={:#x}, newdirfd={}, newpath={:#x}, flags={:#x}",
        olddirfd,
        oldpath,
        newdirfd,
        newpath,
        flags
    );

    if oldpath == 0 || newpath == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let supported_flags = AT_SYMLINK_FOLLOW as usize | AT_EMPTY_PATH as usize;
    if (flags & !supported_flags) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let oldpath_c = match read_user_cstring(oldpath) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };
    let oldpath_str = match oldpath_c.to_str() {
        Ok(s) => s,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    let newpath_c = match read_user_cstring(newpath) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };
    let newpath_str = match newpath_c.to_str() {
        Ok(s) => s,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    if newpath_str.is_empty() {
        return -LinuxError::ENOENT.code() as isize;
    }

    if oldpath_str.is_empty() && (flags & AT_EMPTY_PATH as usize) == 0 {
        return -LinuxError::ENOENT.code() as isize;
    }

    let mut resolve_flags = 0usize;
    if (flags & AT_SYMLINK_FOLLOW as usize) == 0 {
        resolve_flags |= AT_SYMLINK_NOFOLLOW as usize;
    }
    if (flags & AT_EMPTY_PATH as usize) != 0 {
        resolve_flags |= AT_EMPTY_PATH as usize;
    }

    let resolved_newdirfd = if newpath_str.starts_with('/') {
        AT_FDCWD as i32
    } else {
        newdirfd
    };
    let new_ctx = match context_for_dirfd(resolved_newdirfd) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };

    // Check for read-only filesystem
    {
        let is_ro = match new_ctx.resolve_no_follow(newpath_str) {
            Ok(loc) => crate::impls::fs::common::is_location_readonly(&loc),
            Err(_) => {
                if let Ok((parent_loc, _)) =
                    new_ctx.resolve_parent(axfs_ng_vfs::path::Path::new(newpath_str))
                {
                    crate::impls::fs::common::is_location_readonly(&parent_loc)
                } else {
                    false
                }
            }
        };
        if is_ro {
            return -LinuxError::EROFS.code() as isize;
        }
    }

    let old_loc = match resolve_location_at_ptr(olddirfd, oldpath, resolve_flags) {
        Ok(loc) => loc,
        Err(e) => return -e.code() as isize,
    };

    if old_loc.is_dir() {
        return -LinuxError::EPERM.code() as isize;
    }

    let (new_dir, new_name) = match new_ctx.resolve_parent(Path::new(newpath_str)) {
        Ok(res) => res,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };

    if new_dir.lookup_no_follow(&new_name).is_ok() {
        return -LinuxError::EEXIST.code() as isize;
    }

    if let Err(e) = new_ctx.check_write_permission(&new_dir) {
        return -LinuxError::from(e.canonicalize()).code() as isize;
    }

    match new_dir.link(&new_name, &old_loc) {
        Ok(_) => 0,
        Err(e) => {
            let errno = LinuxError::from(e.canonicalize());
            -errno.code() as isize
        }
    }
}
