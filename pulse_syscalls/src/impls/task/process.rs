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

pub fn sys_prctl(option: i32, arg2: usize, _arg3: usize, _arg4: usize, _arg5: usize) -> isize {
    const PR_SET_PDEATHSIG: i32 = 1;
    const PR_GET_PDEATHSIG: i32 = 2;
    const PR_GET_DUMPABLE: i32 = 3;
    const PR_SET_DUMPABLE: i32 = 4;
    const PR_SET_NAME: i32 = 15;
    const PR_GET_NAME: i32 = 16;

    let process = match current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };

    match option {
        PR_SET_NAME => match super::common::read_user_cstring(&process, arg2) {
            Ok(name) => {
                let name = if name.len() > 15 { &name[..15] } else { &name };
                axtask::current().set_name(name);
                0
            }
            Err(e) => e,
        },
        PR_GET_NAME => {
            let name = axtask::current().name();
            let mut bytes = [0u8; 16];
            let len = core::cmp::min(name.len(), 15);
            bytes[..len].copy_from_slice(&name.as_bytes()[..len]);
            match pulse_core::task::uaccess::write_user_bytes(&process, arg2, &bytes) {
                Ok(_) => 0,
                Err(e) => -e.code() as isize,
            }
        }
        PR_SET_PDEATHSIG => {
            let sig = arg2 as isize;
            if !is_valid_signal(sig) {
                return -LinuxError::EINVAL.code() as isize;
            }
            process.set_pdeath_sig(sig as i32);
            0
        }
        PR_GET_PDEATHSIG => {
            let sig = process.pdeath_sig();
            match process.write_user_i32(arg2, sig) {
                Ok(_) => 0,
                Err(e) => -e.code() as isize,
            }
        }
        PR_GET_DUMPABLE => {
            process.dumpable() as isize
        }
        PR_SET_DUMPABLE => {
            let dumpable = arg2 as i32;
            if dumpable < 0 || dumpable > 2 {
                return -LinuxError::EINVAL.code() as isize;
            }
            process.set_dumpable(dumpable);
            0
        }
        _ => {
            axlog::warn!("sys_prctl: unsupported option {}", option);
            -LinuxError::EINVAL.code() as isize
        }
    }
}

pub fn sys_pidfd_open(pid: isize, flags: usize) -> isize {
    axlog::debug!("sys_pidfd_open: pid={}, flags={}", pid, flags);

    // We only support flags being 0 or PIDFD_NONBLOCK (0x800 / O_NONBLOCK).
    if (flags & !0x800) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if pid <= 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let caller = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };

    // Check if target process exists
    let Some(_) = process_by_pid(pid as u64) else {
        return -LinuxError::ESRCH.code() as isize;
    };

    // Allocate a new fd for PidfdObject
    let entry = pulse_core::fd_table::FdEntry::new(
        alloc::sync::Arc::new(pulse_core::fd_table::PidfdObject { pid: pid as u64 }),
        pulse_core::fd_table::FdFlags::empty(),
    );

    match caller.insert_fd_entry(entry) {
        Ok(fd) => fd as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_pidfd_send_signal(pidfd: isize, sig: isize, info_ptr: usize, flags: usize) -> isize {
    axlog::debug!("sys_pidfd_send_signal: pidfd={}, sig={}, info_ptr={:#x}, flags={}", pidfd, sig, info_ptr, flags);

    if flags != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if !is_valid_signal(sig) {
        return -LinuxError::EINVAL.code() as isize;
    }

    let caller = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };

    // Retrieve the fd entry
    let fd_entry = match caller.get_fd_entry(pidfd as usize) {
        Ok(entry) => entry,
        Err(_) => return -LinuxError::EBADF.code() as isize,
    };

    // Check if it's a PidfdObject
    let pidfd_obj = match fd_entry.object.as_any().downcast_ref::<pulse_core::fd_table::PidfdObject>() {
        Some(obj) => obj,
        None => return -LinuxError::EBADF.code() as isize,
    };

    let Some(target) = process_by_pid(pidfd_obj.pid) else {
        return -LinuxError::ESRCH.code() as isize;
    };

    if !can_signal(&caller, target.as_ref()) {
        return -LinuxError::EPERM.code() as isize;
    }

    if sig == 0 {
        return 0;
    }

    // Read siginfo if provided
    let info = if info_ptr != 0 {
        let mut info_bytes = [0u8; 128];
        if let Err(e) = caller.read_user_bytes(info_ptr, &mut info_bytes) {
            return -e.code() as isize;
        }
        Some(info_bytes)
    } else {
        None
    };

    // Deliver signal to process
    let _ = pulse_core::task::queue_signal_to_process_with_info(target.as_ref(), sig as usize, info);
    0
}




