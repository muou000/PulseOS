use axerrno::LinuxError;
use axfs::FsContext;
use axfs_ng_vfs::Location;

use crate::impls::utils::{read_user_cstring, with_process};
use super::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW};

pub(crate) fn context_for_dirfd(dirfd: i32) -> Result<FsContext, LinuxError> {
    let base = with_process(|process| process.fs_context.lock().clone())?;
    if dirfd == AT_FDCWD {
        return Ok(base);
    }
    if dirfd < 0 {
        return Err(LinuxError::EBADF);
    }
    let location = with_process(|process| process.fd_table.lock().get_location(dirfd as usize))??;
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
    if (flags & AT_EMPTY_PATH) != 0 {
        if pathname == 0 {
            if dirfd < 0 {
                return Err(LinuxError::EBADF);
            }
            return with_process(|process| process.fd_table.lock().get_location(dirfd as usize))?;
        }
        let path = read_user_cstring(pathname)?;
        if path.as_bytes().is_empty() {
            if dirfd < 0 {
                return Err(LinuxError::EBADF);
            }
            return with_process(|process| process.fd_table.lock().get_location(dirfd as usize))?;
        }
    }

    if pathname == 0 {
        return Err(LinuxError::EFAULT);
    }
    let path = read_user_cstring(pathname)?;
    let path = path.as_c_str().to_string_lossy();
    if let Some(result) = try_resolve_location_fast(dirfd, path.as_ref(), flags) {
        return result;
    }
    let ctx = context_for_dirfd(dirfd)?;
    if (flags & AT_SYMLINK_NOFOLLOW) != 0 {
        ctx.resolve_no_follow(path.as_ref())
            .map_err(|e| LinuxError::from(e.canonicalize()))
    } else {
        ctx.resolve(path.as_ref())
            .map_err(|e| LinuxError::from(e.canonicalize()))
    }
}

fn try_resolve_location_fast(
    dirfd: i32,
    path: &str,
    flags: usize,
) -> Option<Result<Location, LinuxError>> {
    if dirfd == AT_FDCWD {
        return None;
    }
    if dirfd < 0 {
        return Some(Err(LinuxError::EBADF));
    }
    if flags != AT_SYMLINK_NOFOLLOW {
        return None;
    }
    if path.is_empty() || path.starts_with('/') || path.contains('/') {
        return None;
    }
    let base = match with_process(|process| process.fd_table.lock().get_location(dirfd as usize)) {
        Ok(Ok(loc)) => loc,
        Ok(Err(e)) | Err(e) => return Some(Err(e)),
    };
    if !base.is_dir() {
        return Some(Err(LinuxError::ENOTDIR));
    }
    Some(
        base.lookup_no_follow(path)
            .map_err(|e| LinuxError::from(e.canonicalize())),
    )
}
