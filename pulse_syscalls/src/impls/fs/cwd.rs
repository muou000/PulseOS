use axerrno::LinuxError;
use linux_raw_sys::general::X_OK;

use crate::impls::{
    fs::common::{check_faccess_permission, get_fd_entry},
    utils::{alloc_zeroed_bytes, read_user_cstring, with_process, write_user_bytes},
};

pub fn sys_getcwd(buf: usize, size: usize) -> isize {
    axlog::debug!("sys_getcwd: buf={:#x}, size={}", buf, size);
    if buf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if size == 0 {
        return -LinuxError::ERANGE.code() as isize;
    }
    let cwd = match with_process(|process| process.fs_context_handle().lock().current_dir().absolute_path())
    {
        Ok(Ok(path)) => path,
        Ok(Err(e)) => return -LinuxError::from(e.canonicalize()).code() as isize,
        Err(e) => return -e.code() as isize,
    };
    let cwd = cwd.as_bytes();
    if cwd.len() + 1 > size {
        return -LinuxError::ERANGE.code() as isize;
    }
    let mut tmp = match alloc_zeroed_bytes(cwd.len() + 1, "sys_getcwd.tmp") {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    tmp[..cwd.len()].copy_from_slice(cwd);
    match write_user_bytes(buf, &tmp) {
        Ok(()) => buf as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_chdir(path: usize) -> isize {
    axlog::debug!("sys_chdir: path={:#x}", path);
    let path = match read_user_cstring(path) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };
    let path = match path.to_str() {
        Ok(path) => path,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };
    match with_process(|process| -> Result<(), LinuxError> {
        let dir = {
            let fs = process.fs_context_handle().lock().clone();
            fs.resolve(path)
                .map_err(|e| LinuxError::from(e.canonicalize()))?
        };
        dir.check_is_dir()
            .map_err(|e| LinuxError::from(e.canonicalize()))?;
        let uid = process.euid();
        let gid = process.egid();
        check_faccess_permission(&dir, X_OK as usize, uid, gid)?;
        process
            .fs_context_handle()
            .lock()
            .set_current_dir(dir)
            .map_err(|e| LinuxError::from(e.canonicalize()))?;
        process.sync_fs_context();
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(e)) | Err(e) => -e.code() as isize,
    }
}

pub fn sys_fchdir(fd: usize) -> isize {
    axlog::debug!("sys_fchdir: fd={}", fd);
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    let dir = match entry.object.location() {
        Some(loc) => loc,
        None => return -LinuxError::ENOTDIR.code() as isize,
    };

    match with_process(|process| -> Result<(), LinuxError> {
        dir.check_is_dir()
            .map_err(|e| LinuxError::from(e.canonicalize()))?;
        let uid = process.euid();
        let gid = process.egid();
        check_faccess_permission(&dir, X_OK as usize, uid, gid)?;
        process
            .fs_context_handle()
            .lock()
            .set_current_dir(dir)
            .map_err(|e| LinuxError::from(e.canonicalize()))?;
        process.sync_fs_context();
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(e)) | Err(e) => -e.code() as isize,
    }
}
