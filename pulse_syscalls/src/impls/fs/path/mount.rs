use super::*;

// `FsContext` owns root/cwd/credentials; `Location` shares mount topology through Arc.
fn resolve_existing_mount_path(ctx: &axfs::FsContext, path: &str) -> Result<String, LinuxError> {
    let loc = task::future::block_on(ctx.resolve(Path::new(path)))
        .map_err(|e| LinuxError::from(e.canonicalize()))?;
    loc.check_is_dir()
        .map_err(|e| LinuxError::from(e.canonicalize()))?;
    Ok(loc
        .absolute_path()
        .map_err(|e| LinuxError::from(e.canonicalize()))?
        .to_string())
}

fn lookup_or_probe_fs(
    ctx: &axfs::FsContext,
    source: &str,
    fstype: &str,
) -> Result<axfs_ng_vfs::Filesystem, LinuxError> {
    // Pseudo filesystems
    if fstype == "tmpfs" {
        return Ok(axfs::new_tmpfs());
    }
    if fstype == "proc" {
        return Ok(axfs::new_procfs());
    }

    // Preserve the boot aliases (device0, /dev/vda) and reuse the same
    // mounted filesystem, but only for an explicitly compatible format.
    let cached = |path: &str| {
        let fs = axfs::lookup_mountable_filesystem(path)?;
        match fstype {
            "" | "none" => Some(Ok(fs)),
            "ext2" | "ext3" if fs.name() == "ext4" => Some(Ok(fs)),
            name if fs.name() == name => Some(Ok(fs)),
            // A secondary disk can have been reformatted since its boot
            // probe. Verify its current FAT volume before dropping any alias.
            #[cfg(feature = "fat")]
            "vfat" if !axfs::filesystem_is_mounted(&fs) => None,
            _ => Some(Err(LinuxError::EINVAL)),
        }
    };
    if let Some(result) = cached(source) {
        return result;
    }
    let alias = axfs::mount_device_alias(source);
    let source = alias.as_deref().unwrap_or(source);
    let loc = match task::future::block_on(ctx.resolve(Path::new(source))) {
        Ok(loc) => loc,
        Err(e) => {
            // Some rootfs images refer to /dev/vda1 for a whole-disk
            // filesystem. Use that alias only when the real node is absent.
            let whole_disk = source.trim_end_matches(|c: char| c.is_ascii_digit());
            if e.canonicalize() == axfs_ng_vfs::VfsError::NotFound
                && whole_disk != source
                && let Some(result) = cached(whole_disk)
            {
                return result;
            }
            return Err(LinuxError::from(e.canonicalize()));
        }
    };
    let path = loc
        .absolute_path()
        .map_err(|e| LinuxError::from(e.canonicalize()))?;
    if let Some(result) = cached(path.as_str()) {
        return result;
    }
    if loc.entry().node_type() != axfs_ng_vfs::NodeType::BlockDevice {
        return Err(LinuxError::ENOTBLK);
    }
    let entry = loc.entry();
    let node = entry
        .downcast::<axfs::DevNode>()
        .map_err(|_| LinuxError::ENOTBLK)?;
    match fstype {
        #[cfg(feature = "ext4")]
        "ext2" | "ext3" | "ext4" => {
            let disk = node
                .get_block_device()
                .map_err(|e| LinuxError::from(e.canonicalize()))?;
            task::future::block_on(axfs::ext4::Ext4Filesystem::new(disk))
        }
        #[cfg(feature = "fat")]
        "vfat" => {
            let volume = task::future::block_on(node.mount_fat());
            if volume.is_ok()
                && let Some(stale) = axfs::lookup_mountable_filesystem(path.as_str())
            {
                axfs::forget_mountable_filesystem(&stale);
            }
            volume
        }
        "none" | "" => axfs::probe_block_device(path.as_str(), &loc),
        _ => return Err(LinuxError::ENODEV),
    }
    .map_err(|e| LinuxError::from(e.canonicalize()))
}

fn sys_mount_propagation(target_path: &str, flags: usize) -> isize {
    let mp = match axfs::lookup_mounted_mountpoint(target_path) {
        Some(mp) => mp,
        None => {
            // Target path may not be a mountpoint itself; that's OK for
            // --make-private etc. on already-mounted paths – we just succeed.
            kernel_log::debug!(
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

    kernel_log::debug!(
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

    0
}

/// Implement `mount --move source target` (MS_MOVE).
fn sys_mount_move(ctx: &axfs::FsContext, source_uptr: usize, target_path: &str) -> isize {
    let source_path = match read_user_optional_path(source_uptr) {
        Ok(Some(p)) => p,
        Ok(None) => return -LinuxError::EINVAL.code() as isize,
        Err(e) => return -e.code() as isize,
    };
    let source_path = match resolve_existing_mount_path(ctx, &source_path) {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };
    kernel_log::debug!("sys_mount_move: '{}' -> '{}'", source_path, target_path);

    // Source must be a mountpoint root.
    let source_loc = match task::future::block_on(ctx.resolve(&source_path)) {
        Ok(loc) => loc,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };
    if !source_loc.is_root_of_mount() {
        return -LinuxError::EINVAL.code() as isize;
    }
    // Target must exist and not already be a mount.
    let target_loc = match task::future::block_on(ctx.resolve(target_path)) {
        Ok(loc) => loc,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };

    match axfs::move_filesystem(&source_loc, &target_loc) {
        Ok(_) => 0,
        Err(e) => -LinuxError::from(e.canonicalize()).code() as isize,
    }
}

pub fn sys_mount(source: usize, target: usize, fstype: usize, flags: usize, _data: usize) -> isize {
    // Older mount(8) versions pass this signature in the upper flag bits.
    // Strip it before interpreting those same bits as propagation options.
    let flags = if flags & MS_MGC_MSK as usize == MS_MGC_VAL as usize {
        flags & !(MS_MGC_MSK as usize)
    } else {
        flags
    };
    kernel_log::debug!("sys_mount: target={:#x}, flags={:#x}", target, flags);
    // Only warn if data is non-zero (flags may legitimately be set for remount/rdonly)
    if _data != 0 && !MOUNT_FLAGS_WARNED.swap(true, Ordering::AcqRel) {
        kernel_log::warn!(
            "sys_mount: mount data is ignored (data={:#x}); semantics are simplified",
            _data
        );
    }
    let is_remount = (flags & MS_REMOUNT as usize) != 0;
    let is_bind = (flags & MS_BIND as usize) != 0;
    let is_rdonly = (flags & MS_RDONLY as usize) != 0;

    // Propagation flags.
    const MS_PROPAGATION: usize =
        (MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED | MS_REC) as usize;
    let is_propagation = (flags & MS_PROPAGATION) != 0;

    if target == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let mut target_buf = [core::mem::MaybeUninit::<u8>::uninit(); USER_PATH_MAX];
    let target_len = match crate::impls::utils::read_user_cstring_to_slice(target, &mut target_buf)
    {
        Ok(l) => l,
        Err(e) => return -e.code() as isize,
    };
    let target_path_str = match core::str::from_utf8(unsafe {
        core::slice::from_raw_parts(target_buf.as_ptr().cast::<u8>(), target_len)
    }) {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    let ctx = match context_for_dirfd(AT_FDCWD as i32) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };

    let target_loc = match task::future::block_on(ctx.resolve(Path::new(target_path_str))) {
        Ok(loc) => loc,
        Err(e) => {
            kernel_log::debug!(
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
        // A remount of a bind mount replaces its record. Preserve the bind
        // identity so unmount does not mistake it for a real filesystem mount.
        let is_bind_mount = is_bind || axfs::mountpoint_is_bind(&target_mp);
        let options = match (is_rdonly, is_bind_mount) {
            (true, true) => "ro,bind,relatime",
            (false, true) => "rw,bind,relatime",
            (true, false) => "ro,relatime",
            (false, false) => "rw,relatime",
        };
        kernel_log::debug!("sys_mount: remount '{}' as {}", target_path, options);
        axfs::register_mount_for_mountpoint(
            &source_path,
            &target_path,
            &fstype_name,
            options,
            target_mp.clone(),
        );

        // Update readonly status on the mountpoint and all its peer/slave propagation mounts!
        target_mp.set_readonly(is_rdonly);
        target_mp.set_flags(flags);
        let peer_mps = axfs_ng_vfs::collect_propagate_unmount(&target_mp);
        for peer in peer_mps {
            peer.set_readonly(is_rdonly);
            peer.set_flags(flags);
        }

        return 0;
    }

    // Pure propagation change (no actual filesystem operation).
    if is_propagation && !is_bind {
        return sys_mount_propagation(&target_path, flags);
    }

    // MS_MOVE: move an existing mountpoint.
    if (flags & (MS_MOVE as usize)) != 0 {
        return sys_mount_move(&ctx, source, &target_path);
    }

    if is_bind {
        let source_path = match read_user_optional_path(source) {
            Ok(Some(path)) => path,
            Ok(None) => return -LinuxError::EINVAL.code() as isize,
            Err(e) => return -e.code() as isize,
        };
        kernel_log::debug!(
            "sys_mount: bind mount '{}' to '{}'",
            source_path,
            target_path
        );
        let source_loc = match task::future::block_on(ctx.resolve(&source_path)) {
            Ok(loc) => loc,
            Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
        };
        return match axfs::mount_bind(&target_loc, source_loc, &source_path, flags) {
            Ok(_) => 0,
            Err(e) => -LinuxError::from(e.canonicalize()).code() as isize,
        };
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

    kernel_log::debug!(
        "sys_mount: source={}, target={}, fstype={}",
        source_path,
        target_path,
        fstype_name
    );

    let result = axfs::mount_filesystem(&target_loc, &source_path, &fstype_name, flags, || {
        lookup_or_probe_fs(&ctx, &source_path, &fstype_name).map_err(axfs_ng_vfs::VfsError::from)
    });
    match result {
        Ok(_) => 0,
        Err(e) => {
            kernel_log::debug!("sys_mount: mount operation failed: {:?}", e);
            -LinuxError::from(e.canonicalize()).code() as isize
        }
    }
}

pub fn sys_umount2(target: usize, flags: usize) -> isize {
    kernel_log::debug!("sys_umount2: target={:#x}, flags={:#x}", target, flags);
    const UMOUNT_SUPPORTED_FLAGS: usize =
        (MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) as usize;
    if (flags & !UMOUNT_SUPPORTED_FLAGS) != 0 && !UMOUNT_FLAGS_WARNED.swap(true, Ordering::AcqRel) {
        kernel_log::warn!(
            "sys_umount2: some unmount flags are ignored (flags={:#x}); semantics are simplified",
            flags
        );
    }
    if target == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let mut target_buf = [core::mem::MaybeUninit::<u8>::uninit(); USER_PATH_MAX];
    let target_len = match crate::impls::utils::read_user_cstring_to_slice(target, &mut target_buf)
    {
        Ok(l) => l,
        Err(e) => return -e.code() as isize,
    };
    let target_path_raw = match core::str::from_utf8(unsafe {
        core::slice::from_raw_parts(target_buf.as_ptr().cast::<u8>(), target_len)
    }) {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    let ctx = match context_for_dirfd(AT_FDCWD as i32) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };
    let target_loc = match task::future::block_on(ctx.resolve(target_path_raw)) {
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

    let result = task::future::block_on(axfs::flush_and_unmount(&target_loc, is_detach));

    match result {
        Ok(()) => 0,
        Err(e) => -LinuxError::from(e.canonicalize()).code() as isize,
    }
}
