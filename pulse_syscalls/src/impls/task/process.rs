use axerrno::LinuxError;
use linux_raw_sys::general::SIGCONT;
use pulse_core::task::{current_process, current_thread, process_by_pid, processes_snapshot};

const NSIG: isize = 64;

fn can_signal(caller: &pulse_core::task::Process, target: &pulse_core::task::Process) -> bool {
    let caller_euid = caller.euid();
    caller_euid == 0 || caller_euid == target.ruid() || caller_euid == target.euid()
}

fn is_valid_signal(sig: isize) -> bool {
    sig == 0 || (1..=NSIG).contains(&sig)
}

fn should_exit_for_signal(sig: isize) -> bool {
    if sig == 0 {
        return false;
    }

    // We do not have a full signal-dispatch path yet.
    // Treat real signals as a termination request, except SIGCONT which is a no-op here.
    !matches!(sig as u32, SIGCONT)
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
    let mut hit_self = false;
    match pid {
        p if p > 0 => {
            if let Some(target) = process_by_pid(p as u64) {
                hit_self = target.pid() == caller.pid();
                targets.push(target);
            }
        }
        0 => {
            hit_self = true;
            targets.push(caller.clone());
        }
        -1 => {
            for proc in processes_snapshot() {
                if proc.pid() == 1 {
                    continue;
                }
                if proc.pid() == caller.pid() {
                    hit_self = true;
                }
                targets.push(proc);
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

    if !should_exit_for_signal(sig) {
        return 0;
    }

    let exit_code = 128 + sig as i32;
    for target in targets {
        if !can_signal(&caller, &target) {
            continue;
        }
        target.begin_group_exit(exit_code);
    }

    if hit_self {
        match current_thread() {
            Ok(thread) => thread.exit_current(exit_code),
            Err(e) => return -e.code() as isize,
        }
    }

    0
}
