use axerrno::LinuxError;
use pulse_core::task::{
    can_signal, current_process, process_by_pid, processes_snapshot, queue_signal_to_process,
    queue_signal_to_thread,
};

const NSIG: isize = 64;

fn is_valid_signal(sig: isize) -> bool {
    sig == 0 || (1..=NSIG).contains(&sig)
}

pub fn sys_getpid() -> isize {
    axlog::debug!("sys_getpid");
    match current_process() {
        Ok(process) => process.pid() as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_getppid() -> isize {
    match current_process() {
        Ok(process) => process.parent_pid() as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_getuid() -> isize {
    match current_process() {
        Ok(process) => {
            let uid = process.ruid() as isize;
            axlog::debug!("sys_getuid: {}", uid);
            uid
        }
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_geteuid() -> isize {
    match current_process() {
        Ok(process) => {
            let euid = process.euid() as isize;
            axlog::debug!("sys_geteuid: {}", euid);
            euid
        }
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_getgid() -> isize {
    match current_process() {
        Ok(process) => {
            let gid = process.rgid() as isize;
            axlog::debug!("sys_getgid: {}", gid);
            gid
        }
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_getegid() -> isize {
    match current_process() {
        Ok(process) => {
            let egid = process.egid() as isize;
            axlog::debug!("sys_getegid: {}", egid);
            egid
        }
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_kill(pid: isize, sig: isize) -> isize {
    axlog::debug!("sys_kill: pid={}, sig={}", pid, sig);

    if !is_valid_signal(sig) {
        return -LinuxError::EINVAL.code() as isize;
    }

    let caller = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };

    let mut targets = alloc::vec::Vec::new();
    match pid {
        p if p > 0 => {
            if let Some(target) = process_by_pid(p as u64) {
                targets.push(target);
            }
        }
        0 => {
            let pgid = caller.pgid();
            for proc in processes_snapshot() {
                if proc.pgid() == pgid {
                    targets.push(proc);
                }
            }
        }
        -1 => {
            for proc in processes_snapshot() {
                if proc.pid() == 1 {
                    continue;
                }
                if proc.pid() == caller.pid() {
                    continue;
                }
                targets.push(proc);
            }
        }
        p if p < -1 => {
            let pgid = (-p) as u64;
            for proc in processes_snapshot() {
                if proc.pgid() == pgid {
                    targets.push(proc);
                }
            }
        }
        _ => return -LinuxError::EINVAL.code() as isize,
    }

    if targets.is_empty() {
        return -LinuxError::ESRCH.code() as isize;
    }

    if !targets.iter().any(|target| can_signal(&caller, target)) {
        return -LinuxError::EPERM.code() as isize;
    }

    if sig == 0 {
        return 0;
    }

    for target in targets {
        if !can_signal(&caller, &target) {
            continue;
        }
        let _ = queue_signal_to_process(target.as_ref(), sig as usize);
    }
    0
}

pub fn sys_tkill(tid: isize, sig: isize) -> isize {
    if tid <= 0 || !is_valid_signal(sig) {
        return -LinuxError::EINVAL.code() as isize;
    }
    let caller = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let Some(target_thread) = pulse_core::task::thread_by_tid_global(tid as u64) else {
        return -LinuxError::ESRCH.code() as isize;
    };
    let target_proc = target_thread.process_arc();
    if !can_signal(&caller, target_proc.as_ref()) {
        return -LinuxError::EPERM.code() as isize;
    }
    if sig == 0 {
        return 0;
    }
    let _ = queue_signal_to_thread(target_thread.as_ref(), sig as usize);
    0
}

pub fn sys_tgkill(tgid: isize, tid: isize, sig: isize) -> isize {
    if tgid <= 0 || tid <= 0 || !is_valid_signal(sig) {
        return -LinuxError::EINVAL.code() as isize;
    }
    let caller = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let Some(target_thread) = pulse_core::task::thread_by_tid_global(tid as u64) else {
        return -LinuxError::ESRCH.code() as isize;
    };
    let target_proc = target_thread.process_arc();
    if target_proc.pid() != tgid as u64 {
        return -LinuxError::ESRCH.code() as isize;
    }
    if !can_signal(&caller, target_proc.as_ref()) {
        return -LinuxError::EPERM.code() as isize;
    }
    if sig == 0 {
        return 0;
    }
    let _ = queue_signal_to_thread(target_thread.as_ref(), sig as usize);
    0
}

pub fn sys_getresuid(ruid_ptr: usize, euid_ptr: usize, suid_ptr: usize) -> isize {
    let process = match current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };
    let (ruid, euid, suid) = process.uid_snapshot();
    if ruid_ptr != 0 {
        if let Err(e) = process.write_user_u32(ruid_ptr, ruid) {
            let errno: LinuxError = e.into();
            return -errno.code() as isize;
        }
    }
    if euid_ptr != 0 {
        if let Err(e) = process.write_user_u32(euid_ptr, euid) {
            let errno: LinuxError = e.into();
            return -errno.code() as isize;
        }
    }
    if suid_ptr != 0 {
        if let Err(e) = process.write_user_u32(suid_ptr, suid) {
            let errno: LinuxError = e.into();
            return -errno.code() as isize;
        }
    }
    0
}

pub fn sys_getresgid(rgid_ptr: usize, egid_ptr: usize, sgid_ptr: usize) -> isize {
    let process = match current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };
    let (rgid, egid, sgid) = process.gid_snapshot();
    if rgid_ptr != 0 {
        if let Err(e) = process.write_user_u32(rgid_ptr, rgid) {
            let errno: LinuxError = e.into();
            return -errno.code() as isize;
        }
    }
    if egid_ptr != 0 {
        if let Err(e) = process.write_user_u32(egid_ptr, egid) {
            let errno: LinuxError = e.into();
            return -errno.code() as isize;
        }
    }
    if sgid_ptr != 0 {
        if let Err(e) = process.write_user_u32(sgid_ptr, sgid) {
            let errno: LinuxError = e.into();
            return -errno.code() as isize;
        }
    }
    0
}




