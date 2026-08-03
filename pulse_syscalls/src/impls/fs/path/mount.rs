use super::*;

fn resolve_existing_mount_path(path: &str) -> Result<String, LinuxError> {
    let ctx = context_for_dirfd(AT_FDCWD as i32)?;
    let loc = axtask::future::block_on(ctx.resolve(Path::new(path)))
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
    match axtask::future::block_on(ctx.resolve(Path::new(source))) {
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
                    return axtask::future::block_on(axfs::ext4::Ext4Filesystem::new(disk))
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
    let source_loc = match axtask::future::block_on(ctx.resolve(&source_path)) {
        Ok(loc) => loc,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };
    if !source_loc.is_root_of_mount() {
        return -LinuxError::EINVAL.code() as isize;
    }
    // Target must exist and not already be a mount.
    let target_loc = match axtask::future::block_on(ctx.resolve(target_path)) {
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

    let mut target_buf = [0u8; USER_PATH_MAX];
    let target_len = match crate::impls::utils::read_user_cstring_to_slice(target, &mut target_buf)
    {
        Ok(l) => l,
        Err(e) => return -e.code() as isize,
    };
    let target_path_str = match core::str::from_utf8(&target_buf[..target_len]) {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    let ctx = match context_for_dirfd(AT_FDCWD as i32) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };

    let target_loc = match axtask::future::block_on(ctx.resolve(Path::new(target_path_str))) {
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
    if (_flags & (MS_MOVE as usize)) != 0 {
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
        let source_loc = match axtask::future::block_on(ctx.resolve(&source_path)) {
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

    let mut target_buf = [0u8; USER_PATH_MAX];
    let target_len = match crate::impls::utils::read_user_cstring_to_slice(target, &mut target_buf)
    {
        Ok(l) => l,
        Err(e) => return -e.code() as isize,
    };
    let target_path_raw = match core::str::from_utf8(&target_buf[..target_len]) {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    let ctx = match context_for_dirfd(AT_FDCWD as i32) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };
    let target_loc = match axtask::future::block_on(ctx.resolve(target_path_raw)) {
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
