use super::*;

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

fn mkdir_mode(mode: usize) -> NodePermission {
    let umask = pulse_core::task::current_process()
        .map(|process| process.umask())
        .unwrap_or(0o022);
    let mode = ((mode as u32) & !umask) & 0o7777;
    NodePermission::from_bits_truncate(mode as _)
}
pub fn sys_openat(dirfd: i32, pathname: usize, flags: usize, mode: usize) -> isize {
    let result = crate::impls::utils::with_user_path_str(pathname, |path| {
        let resolved_dirfd = if path.starts_with('/') {
            AT_FDCWD as i32
        } else {
            dirfd
        };
        let ctx = context_for_dirfd(resolved_dirfd)?;

        let options = flags_to_options(flags, mode);
        let (opened, metadata) =
            match axtask::future::block_on(options.open_with_metadata(&ctx, path)) {
                Ok(opened) => opened,
                Err(e) => {
                    let err = LinuxError::from(e.canonicalize());
                    return Err(err);
                }
            };

        let (uid, gid) = pulse_core::task::current_process()
            .map(|process| (process.fsuid(), process.fsgid()))
            .unwrap_or((0, 0));

        // O_NOATIME permission check
        if (flags & (O_NOATIME as usize)) != 0 {
            if uid != 0 && uid != metadata.uid {
                return Err(LinuxError::EPERM);
            }
        }
        // O_NOFOLLOW symlink check
        if (flags & (O_NOFOLLOW as usize)) != 0
            && (flags & (O_PATH as usize)) == 0
            && metadata.node_type == NodeType::Symlink
        {
            return Err(LinuxError::ELOOP);
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

            if let Err(err) = crate::impls::fs::common::check_faccess_permission_with_metadata(
                location,
                &metadata,
                required_mode,
                uid,
                gid,
            ) {
                return Err(err);
            }
        }

        let is_fifo = metadata.node_type == NodeType::Fifo;

        let entry = if is_fifo {
            let access_mode = flags & (O_ACCMODE as usize);
            let readable = access_mode == O_RDONLY as usize || access_mode == O_RDWR as usize;
            let writable = access_mode == O_WRONLY as usize || access_mode == O_RDWR as usize;
            pulse_core::fd_table::create_fifo_entry(
                metadata.device,
                metadata.inode,
                readable,
                writable,
                open_fd_flags(flags),
            )?
        } else {
            open_result_to_entry(opened, open_fd_flags(flags))
        };

        insert_fd_entry(entry)
    });

    match result {
        Ok(fd) => fd as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_mkdirat(dirfd: i32, pathname: usize, mode: usize) -> isize {
    let res = crate::impls::utils::with_user_path_str(pathname, |path| {
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
        let ctx = context_for_dirfd(resolved_dirfd)?;
        // Check for read-only filesystem: resolve parent dir if path doesn't exist yet
        {
            let is_ro = match axtask::future::block_on(ctx.resolve_no_follow(path)) {
                Ok(loc) => crate::impls::fs::common::is_location_readonly(&loc),
                Err(_) => {
                    if let Ok((parent_loc, _)) = axtask::future::block_on(
                        ctx.resolve_parent(axfs_ng_vfs::path::Path::new(path)),
                    ) {
                        crate::impls::fs::common::is_location_readonly(&parent_loc)
                    } else {
                        false
                    }
                }
            };
            if is_ro {
                return Err(LinuxError::EROFS);
            }
        }
        match axtask::future::block_on(ctx.resolve_no_follow(path)) {
            Ok(_) => {
                axlog::debug!("sys_mkdirat: path '{}' already exists", path);
                return Err(LinuxError::EEXIST);
            }
            Err(VfsError::NotFound) => {}
            Err(e) => return Err(LinuxError::from(e.canonicalize())),
        }
        axlog::debug!("sys_mkdirat: creating directory '{}'", path);
        match axtask::future::block_on(ctx.create_dir(path, mkdir_mode(mode))) {
            Ok(_) => {
                axlog::debug!("sys_mkdirat: directory '{}' created successfully", path);
                Ok(0isize)
            }
            Err(e) => {
                axlog::debug!(
                    "sys_mkdirat: failed to create directory '{}': {:?}",
                    path,
                    e
                );
                Err(LinuxError::from(e.canonicalize()))
            }
        }
    });
    match res {
        Ok(code) => code,
        Err(e) => -e.code() as isize,
    }
}
