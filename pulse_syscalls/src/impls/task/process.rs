use axerrno::LinuxError;
use pulse_core::task::{
    can_signal, current_process, process_by_pid, processes_snapshot, queue_signal_to_process,
    queue_signal_to_thread, thread_by_tid,
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
            targets.push(caller.clone());
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
                if proc.pid() == pgid {
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
    let target_proc = process_by_pid(tid as u64).or_else(|| {
        for proc in processes_snapshot() {
            if proc.thread_ids_snapshot().contains(&(tid as u64)) {
                return Some(proc);
            }
        }
        None
    });
    let Some(target_proc) = target_proc else {
        return -LinuxError::ESRCH.code() as isize;
    };
    if !can_signal(&caller, target_proc.as_ref()) {
        return -LinuxError::EPERM.code() as isize;
    }
    if sig == 0 {
        return 0;
    }
    let Some(target_thread) = thread_by_tid(target_proc.as_ref(), tid as u64) else {
        return -LinuxError::ESRCH.code() as isize;
    };
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
    let Some(target_proc) = process_by_pid(tgid as u64) else {
        return -LinuxError::ESRCH.code() as isize;
    };
    if !can_signal(&caller, target_proc.as_ref()) {
        return -LinuxError::EPERM.code() as isize;
    }
    if !target_proc.thread_ids_snapshot().contains(&(tid as u64)) {
        return -LinuxError::ESRCH.code() as isize;
    }
    if sig == 0 {
        return 0;
    }
    let Some(target_thread) = thread_by_tid(target_proc.as_ref(), tid as u64) else {
        return -LinuxError::ESRCH.code() as isize;
    };
    let _ = queue_signal_to_thread(target_thread.as_ref(), sig as usize);
    0
}
