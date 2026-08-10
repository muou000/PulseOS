use super::*;

fn rename_at(
    olddirfd: i32,
    oldpath: &str,
    newdirfd: i32,
    newpath: &str,
    flags: usize,
) -> Result<(), LinuxError> {
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

    let (src_dir, src_name) = axtask::future::block_on(old_ctx.resolve_parent(Path::new(oldpath)))
        .map_err(|e| LinuxError::from(e.canonicalize()))?;
    let (dst_dir, dst_name) = axtask::future::block_on(new_ctx.resolve_parent(Path::new(newpath)))
        .map_err(|e| LinuxError::from(e.canonicalize()))?;

    if (flags & RENAME_NOREPLACE as usize) != 0 {
        match axtask::future::block_on(dst_dir.lookup_no_follow(dst_name.as_ref())) {
            Ok(_) => return Err(LinuxError::EEXIST),
            Err(e) if e.canonicalize() == VfsError::NotFound => {}
            Err(e) => return Err(LinuxError::from(e.canonicalize())),
        }
    }

    if crate::impls::fs::common::is_location_readonly(&src_dir)
        || crate::impls::fs::common::is_location_readonly(&dst_dir)
    {
        return Err(LinuxError::EROFS);
    }

    axtask::future::block_on(old_ctx.check_write_permission(&src_dir))?;
    axtask::future::block_on(new_ctx.check_write_permission(&dst_dir))?;

    axtask::future::block_on(src_dir.rename(src_name.as_ref(), &dst_dir, dst_name.as_ref()))
        .map_err(|e| LinuxError::from(e.canonicalize()))
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

    let res = crate::impls::utils::with_user_path_str(pathname, |path| {
        if path.is_empty() {
            return Err(LinuxError::EINVAL);
        }
        let resolved_dirfd = if path.starts_with('/') {
            AT_FDCWD as i32
        } else {
            dirfd
        };
        let ctx = context_for_dirfd(resolved_dirfd)?;

        // 1. Resolve parent directory and child entry name
        let (parent_loc, entry_name) =
            axtask::future::block_on(ctx.resolve_parent(Path::new(path)))
                .map_err(|e| LinuxError::from(e.canonicalize()))?;

        if crate::impls::fs::common::is_location_readonly(&parent_loc) {
            return Err(LinuxError::EROFS);
        }

        // Get process credentials
        let (uid, gid) = pulse_core::task::current_process()
            .map(|process| (process.fsuid(), process.fsgid()))
            .unwrap_or((0, 0));

        // 2. Enforce execute/search permission check on parent directory
        crate::impls::fs::common::check_faccess_permission(&parent_loc, X_OK as usize, uid, gid)?;

        // 3. Lookup the child entry to ensure it exists (ENOENT if not found)
        let child_loc = axtask::future::block_on(parent_loc.lookup_no_follow(entry_name.as_ref()))
            .map_err(|e| LinuxError::from(e.canonicalize()))?;

        if crate::impls::fs::common::is_location_readonly(&child_loc) {
            return Err(LinuxError::EROFS);
        }

        // 4. Enforce write permission check on parent directory
        crate::impls::fs::common::check_faccess_permission(&parent_loc, W_OK as usize, uid, gid)?;

        // 5. Enforce sticky bit rules if parent has STICKY bit set
        let parent_meta = axtask::future::block_on(parent_loc.metadata())
            .map_err(|e| LinuxError::from(e.canonicalize()))?;
        if parent_meta.mode.contains(NodePermission::STICKY) {
            let child_meta = axtask::future::block_on(child_loc.metadata())
                .map_err(|e| LinuxError::from(e.canonicalize()))?;
            if uid != 0 && uid != parent_meta.uid && uid != child_meta.uid {
                return Err(LinuxError::EACCES);
            }
        }

        if (flags & AT_REMOVEDIR as usize) != 0 {
            axtask::future::block_on(parent_loc.unlink(entry_name.as_ref(), true))
                .map_err(|e| LinuxError::from(e.canonicalize()))?;
            return Ok(0isize);
        }

        axtask::future::block_on(parent_loc.unlink(entry_name.as_ref(), false))
            .map_err(|e| LinuxError::from(e.canonicalize()))?;
        Ok(0isize)
    });
    match res {
        Ok(code) => code,
        Err(e) => -e.code() as isize,
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

    match rename_at(olddirfd, oldpath.as_str(), newdirfd, newpath.as_str(), flags) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_symlinkat(target: usize, newdirfd: i32, linkpath: usize) -> isize {
    if target == 0 || linkpath == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let mut target_buf = [core::mem::MaybeUninit::<u8>::uninit(); USER_PATH_MAX];
    let target_len = match crate::impls::utils::read_user_cstring_to_slice(target, &mut target_buf)
    {
        Ok(l) => l,
        Err(e) => return -e.code() as isize,
    };
    let target_str = match core::str::from_utf8(unsafe {
        core::slice::from_raw_parts(target_buf.as_ptr().cast::<u8>(), target_len)
    }) {
        Ok(s) => s,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };
    if target_str.is_empty() {
        return -LinuxError::ENOENT.code() as isize;
    }

    let mut link_buf = [core::mem::MaybeUninit::<u8>::uninit(); USER_PATH_MAX];
    let link_len = match crate::impls::utils::read_user_cstring_to_slice(linkpath, &mut link_buf) {
        Ok(l) => l,
        Err(e) => return -e.code() as isize,
    };
    let link_str = match core::str::from_utf8(unsafe {
        core::slice::from_raw_parts(link_buf.as_ptr().cast::<u8>(), link_len)
    }) {
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
        let is_ro = match axtask::future::block_on(ctx.resolve_no_follow(link_str)) {
            Ok(loc) => crate::impls::fs::common::is_location_readonly(&loc),
            Err(_) => {
                if let Ok((parent_loc, _)) = axtask::future::block_on(
                    ctx.resolve_parent(axfs_ng_vfs::path::Path::new(link_str)),
                ) {
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

    match axtask::future::block_on(ctx.symlink(target_str, link_str)) {
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
    let mut buf = [core::mem::MaybeUninit::<u8>::uninit(); USER_PATH_MAX];
    let len = match crate::impls::utils::read_user_cstring_to_slice(pathname, &mut buf) {
        Ok(l) => l,
        Err(e) => return -e.code() as isize,
    };
    let path = match core::str::from_utf8(unsafe {
        core::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), len)
    }) {
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
        let is_ro = match axtask::future::block_on(ctx.resolve_no_follow(path)) {
            Ok(loc) => crate::impls::fs::common::is_location_readonly(&loc),
            Err(_) => {
                if let Ok((parent_loc, _)) =
                    axtask::future::block_on(ctx.resolve_parent(axfs_ng_vfs::path::Path::new(path)))
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
    match axtask::future::block_on(ctx.resolve_no_follow(path)) {
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

    let (dir, name) = match axtask::future::block_on(ctx.resolve_nonexistent(Path::new(path))) {
        Ok(res) => res,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };

    let mut final_perm = node_permission;
    let mut final_credentials = ctx.credentials;
    if let Ok(parent_meta) = axtask::future::block_on(dir.metadata()) {
        if parent_meta.mode.contains(NodePermission::SET_GID) {
            if node_type == NodeType::Directory {
                final_perm |= NodePermission::SET_GID;
            }
            if let Some((uid, _)) = final_credentials {
                final_credentials = Some((uid, parent_meta.gid));
            }
        }
    }

    let loc = match axtask::future::block_on(dir.create(name, node_type, final_perm)) {
        Ok(loc) => loc,
        Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
    };

    if let Some((uid, gid)) = final_credentials {
        let _ = axtask::future::block_on(loc.update_metadata(MetadataUpdate {
            owner: Some((uid, gid)),
            ..Default::default()
        }));
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

    let mut old_buf = [core::mem::MaybeUninit::<u8>::uninit(); USER_PATH_MAX];
    let old_len = match crate::impls::utils::read_user_cstring_to_slice(oldpath, &mut old_buf) {
        Ok(l) => l,
        Err(e) => return -e.code() as isize,
    };
    let oldpath_str = match core::str::from_utf8(unsafe {
        core::slice::from_raw_parts(old_buf.as_ptr().cast::<u8>(), old_len)
    }) {
        Ok(s) => s,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    let mut new_buf = [core::mem::MaybeUninit::<u8>::uninit(); USER_PATH_MAX];
    let new_len = match crate::impls::utils::read_user_cstring_to_slice(newpath, &mut new_buf) {
        Ok(l) => l,
        Err(e) => return -e.code() as isize,
    };
    let newpath_str = match core::str::from_utf8(unsafe {
        core::slice::from_raw_parts(new_buf.as_ptr().cast::<u8>(), new_len)
    }) {
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
        let is_ro = match axtask::future::block_on(new_ctx.resolve_no_follow(newpath_str)) {
            Ok(loc) => crate::impls::fs::common::is_location_readonly(&loc),
            Err(_) => {
                if let Ok((parent_loc, _)) = axtask::future::block_on(
                    new_ctx.resolve_parent(axfs_ng_vfs::path::Path::new(newpath_str)),
                ) {
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

    let (new_dir, new_name) =
        match axtask::future::block_on(new_ctx.resolve_parent(Path::new(newpath_str))) {
            Ok(res) => res,
            Err(e) => return -LinuxError::from(e.canonicalize()).code() as isize,
        };

    if axtask::future::block_on(new_dir.lookup_no_follow(&new_name)).is_ok() {
        return -LinuxError::EEXIST.code() as isize;
    }

    if let Err(e) = axtask::future::block_on(new_ctx.check_write_permission(&new_dir)) {
        return -LinuxError::from(e.canonicalize()).code() as isize;
    }

    match axtask::future::block_on(new_dir.link(&new_name, &old_loc)) {
        Ok(_) => 0,
        Err(e) => {
            let errno = LinuxError::from(e.canonicalize());
            -errno.code() as isize
        }
    }
}
