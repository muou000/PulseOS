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

fn process_group_id_in_use(mut groups: impl Iterator<Item = u64>, pgid: u64) -> bool {
    groups.any(|group| group == pgid)
}

fn process_group_exists_in_session(
    mut groups: impl Iterator<Item = (u64, u64)>,
    pgid: u64,
    sid: u64,
) -> bool {
    groups.any(|(group, session)| group == pgid && session == sid)
}

pub fn sys_setsid() -> isize {
    let process = match pulse_core::task::current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };

    pulse_core::task::with_job_control_lock(|| {
        // Linux rejects setsid when the caller's PID already names any
        // process group, not only when the caller itself is its leader.
        if process_group_id_in_use(
            pulse_core::task::processes_snapshot()
                .into_iter()
                .map(|process| process.pgid()),
            process.pid(),
        ) {
            return -LinuxError::EPERM.code() as isize;
        }

        process.set_session_and_group(process.pid(), process.pid());
        process.pid() as isize
    })
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

    pulse_core::task::with_job_control_lock(|| {
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

        let target_is_child = target_proc.pid() != caller.pid();
        if target_is_child && target_proc.has_execed() {
            return -LinuxError::EACCES.code() as isize;
        }
        if target_proc.sid() != caller.sid() || target_proc.sid() == target_proc.pid() {
            return -LinuxError::EPERM.code() as isize;
        }

        let target_pgid = if pgid == 0 {
            target_proc.pid()
        } else {
            pgid as u64
        };

        // Joining a group is valid only when the group exists in the target
        // process's session. A zero pgid (and pgid == pid) instead creates a
        // group led by the target process itself.
        if target_pgid != target_proc.pid()
            && !process_group_exists_in_session(
                pulse_core::task::processes_snapshot()
                    .into_iter()
                    .map(|process| (process.pgid(), process.sid())),
                target_pgid,
                target_proc.sid(),
            )
        {
            return -LinuxError::EPERM.code() as isize;
        }

        target_proc.set_pgid(target_pgid);
        0
    })
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

    target_proc.sid() as isize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setsid_rejects_a_pid_that_is_already_a_process_group_id() {
        assert!(process_group_id_in_use([7, 42, 99].into_iter(), 42));
        assert!(!process_group_id_in_use([7, 42, 99].into_iter(), 100));
    }

    #[test]
    fn setpgid_requires_an_existing_group_in_the_target_session() {
        let groups = [(10, 1), (20, 2), (30, 2)];

        assert!(process_group_exists_in_session(groups.into_iter(), 20, 2));
        assert!(!process_group_exists_in_session(groups.into_iter(), 20, 1));
        assert!(!process_group_exists_in_session(groups.into_iter(), 99, 2));
    }
}
