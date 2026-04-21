use axerrno::LinuxError;

use crate::impls::utils::{alloc_zeroed_bytes, read_user_cstring, with_process, write_user_bytes};

pub fn sys_getcwd(buf: usize, size: usize) -> isize {
    axlog::debug!("sys_getcwd: buf={:#x}, size={}", buf, size);
    if buf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if size == 0 {
        return -LinuxError::ERANGE.code() as isize;
    }
    let cwd = match with_process(|process| process.fs_context.lock().current_dir().absolute_path())
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
            let fs = process.fs_context.lock().clone();
            fs.resolve(path).map_err(|e| LinuxError::from(e.canonicalize()))?
        };
        process
            .fs_context
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
