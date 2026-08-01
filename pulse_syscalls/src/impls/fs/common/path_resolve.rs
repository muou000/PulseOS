use core::ffi::CStr;

use axerrno::LinuxError;
use axfs::FsContext;
use axfs_ng_vfs::Location;
use linux_raw_sys::general::*;

use crate::impls::utils::with_process;

pub(crate) fn context_for_dirfd(dirfd: i32) -> Result<FsContext, LinuxError> {
    let base = with_process(|process| {
        let mut fs = process.fs_context_handle().lock().clone();
        fs.credentials = Some((process.fsuid(), process.fsgid()));
        fs
    })?;
    if dirfd == AT_FDCWD as i32 {
        return Ok(base);
    }
    if dirfd < 0 {
        return Err(LinuxError::EBADF);
    }
    let entry = with_process(|process| process.get_fd_entry(dirfd as usize))??;
    let location = entry.object.location().ok_or(LinuxError::ENOTDIR)?;
    if !location.is_dir() {
        return Err(LinuxError::ENOTDIR);
    }
    base.with_current_dir(location)
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

pub(crate) fn resolve_location_at_ptr(
    dirfd: i32,
    pathname: usize,
    flags: usize,
) -> Result<Location, LinuxError> {
    if pathname == 0 {
        if (flags & AT_EMPTY_PATH as usize) != 0 {
            if dirfd < 0 {
                return Err(LinuxError::EBADF);
            }
            return with_process(|process| process.get_fd_location(dirfd as usize))?;
        }
        return Err(LinuxError::EFAULT);
    }

    crate::impls::utils::with_user_path_str(pathname, |path_str| {
        resolve_location_at_str(dirfd, path_str, flags)
    })
}

#[allow(dead_code)]
pub(crate) fn resolve_location_at_cstr(
    dirfd: i32,
    path: &CStr,
    flags: usize,
) -> Result<Location, LinuxError> {
    let path_str = path.to_str().map_err(|_| LinuxError::EINVAL)?;
    resolve_location_at_str(dirfd, path_str, flags)
}

pub(crate) fn resolve_location_at_str(
    dirfd: i32,
    path: &str,
    flags: usize,
) -> Result<Location, LinuxError> {
    if path.is_empty() {
        if (flags & AT_EMPTY_PATH as usize) != 0 {
            if dirfd < 0 {
                return Err(LinuxError::EBADF);
            }
            return with_process(|process| process.get_fd_location(dirfd as usize))?;
        }
        if dirfd == AT_FDCWD as i32 {
            return Err(LinuxError::ENOENT);
        }
        if dirfd < 0 {
            return Err(LinuxError::EBADF);
        }
        return with_process(|process| process.get_fd_location(dirfd as usize))?;
    }

    let is_absolute = path.starts_with('/');
    let dirfd = if is_absolute { AT_FDCWD as i32 } else { dirfd };
    axlog::debug!(
        "resolve_location_at_ptr: dirfd={}, path=\"{}\", flags={:#x}",
        dirfd,
        path,
        flags
    );
    if let Some(result) = try_resolve_location_fast(dirfd, path, flags) {
        match &result {
            Ok(_loc) => axlog::debug!(
                "resolve_location_at_ptr: fast path resolved OK for \"{}\"",
                path
            ),
            Err(e) => axlog::debug!(
                "resolve_location_at_ptr: fast path failed for \"{}\": {:?}",
                path,
                e
            ),
        }
        return result;
    }
    let ctx = context_for_dirfd(dirfd)?;
    let result = if (flags & AT_SYMLINK_NOFOLLOW as usize) != 0 {
        axtask::future::block_on(ctx.resolve_no_follow(path))
            .map_err(|e| LinuxError::from(e.canonicalize()))
    } else {
        axtask::future::block_on(ctx.resolve(path))
            .map_err(|e| LinuxError::from(e.canonicalize()))
    };
    match &result {
        Ok(_loc) => axlog::debug!("resolve_location_at_ptr: resolved OK for \"{}\"", path),
        Err(e) => axlog::debug!(
            "resolve_location_at_ptr: resolve failed for \"{}\": {:?}",
            path,
            e
        ),
    }
    result
}

fn try_resolve_location_fast(
    dirfd: i32,
    path: &str,
    flags: usize,
) -> Option<Result<Location, LinuxError>> {
    if dirfd == AT_FDCWD as i32 {
        return None;
    }
    if dirfd < 0 {
        return Some(Err(LinuxError::EBADF));
    }
    if flags != AT_SYMLINK_NOFOLLOW as usize {
        return None;
    }
    if path.is_empty() || path.starts_with('/') || path.contains('/') {
        return None;
    }
    let base = match with_process(|process| process.get_fd_location(dirfd as usize)) {
        Ok(Ok(loc)) => loc,
        Ok(Err(e)) | Err(e) => return Some(Err(e)),
    };
    if !base.is_dir() {
        return Some(Err(LinuxError::ENOTDIR));
    }
    Some(
        axtask::future::block_on(base.lookup_no_follow(path))
            .map_err(|e| LinuxError::from(e.canonicalize())),
    )
}
