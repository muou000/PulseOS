use super::*;

pub fn sys_umask(mask: usize) -> isize {
    axlog::debug!("sys_umask: mask={:#o}", mask);
    match pulse_core::task::current_process() {
        Ok(process) => process.set_umask((mask as u32) & 0o777) as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_set_tid_address(tidptr: usize) -> isize {
    axlog::debug!("sys_set_tid_address: tidptr={:#x}", tidptr);
    match pulse_core::task::current_thread() {
        Ok(thread) => {
            thread.set_clear_child_tid(tidptr);
            thread.tid() as isize
        }
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_gettid() -> isize {
    axlog::debug!("sys_gettid");
    match pulse_core::task::current_thread() {
        Ok(thread) => thread.tid() as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_set_robust_list(head: usize, len: usize) -> isize {
    axlog::debug!("sys_set_robust_list: head={:#x}, len={}", head, len);
    if len != core::mem::size_of::<usize>() * 3 {
        return -LinuxError::EINVAL.code() as isize;
    }
    match pulse_core::task::current_thread() {
        Ok(thread) => {
            thread.set_robust_list_head(head);
            0
        }
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_get_robust_list(pid: usize, head_ptr: usize, len_ptr: usize) -> isize {
    axlog::debug!(
        "sys_get_robust_list: pid={}, head_ptr={:#x}, len_ptr={:#x}",
        pid,
        head_ptr,
        len_ptr
    );
    if head_ptr == 0 || len_ptr == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let thread = match pulse_core::task::current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    if pid != 0 && pid != thread.tid() as usize {
        return -LinuxError::ESRCH.code() as isize;
    }

    let process = thread.process();
    process
        .write_user_usize(head_ptr, thread.robust_list_head())
        .and_then(|_| process.write_user_usize(len_ptr, core::mem::size_of::<usize>() * 3))
        .map(|_| 0)
        .unwrap_or_else(|_| -LinuxError::EFAULT.code() as isize)
}
pub fn sys_setpgid(pid: isize, pgid: isize) -> isize {
    axlog::debug!("sys_setpgid: pid={}, pgid={}", pid, pgid);
    if pid < 0 || pgid < 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let caller = match pulse_core::task::current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };

    let target_proc = if pid == 0 {
        caller.clone()
    } else {
        match pulse_core::task::process_by_pid(pid as u64) {
            Some(p) => {
                if p.pid() != caller.pid() && p.parent_pid() != caller.pid() {
                    return -LinuxError::ESRCH.code() as isize;
                }
                p
            }
            None => return -LinuxError::ESRCH.code() as isize,
        }
    };

    let target_pgid = if pgid == 0 {
        target_proc.pid()
    } else {
        pgid as u64
    };

    target_proc.set_pgid(target_pgid);
    0
}

pub fn sys_getpgid(pid: isize) -> isize {
    axlog::debug!("sys_getpgid: pid={}", pid);
    if pid < 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let caller = match pulse_core::task::current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };

    let target_proc = if pid == 0 {
        caller
    } else {
        match pulse_core::task::process_by_pid(pid as u64) {
            Some(p) => p,
            None => return -LinuxError::ESRCH.code() as isize,
        }
    };

    target_proc.pgid() as isize
}

pub fn sys_getsid(pid: isize) -> isize {
    axlog::debug!("sys_getsid: pid={}", pid);
    if pid < 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let caller = match pulse_core::task::current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };

    let target_proc = if pid == 0 {
        caller
    } else {
        match pulse_core::task::process_by_pid(pid as u64) {
            Some(p) => p,
            None => return -LinuxError::ESRCH.code() as isize,
        }
    };

    // Since we don't fully track sessions yet and setsid returns 1 as a stub,
    // we return the pgid as a fallback for getsid.
    target_proc.pgid() as isize
}
