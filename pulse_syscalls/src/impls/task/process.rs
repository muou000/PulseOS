use axerrno::LinuxError;
use linux_raw_sys::{
    general::{_NSIG, CAP_SYS_PTRACE, O_NONBLOCK, SI_TKILL, SI_USER, siginfo},
    prctl::{
        PR_GET_DUMPABLE, PR_GET_NAME, PR_GET_PDEATHSIG, PR_SET_DUMPABLE, PR_SET_NAME,
        PR_SET_PDEATHSIG,
    },
};
use pulse_core::task::{
    can_signal, current_process, current_thread, process_by_pid, processes_snapshot,
    queue_signal_to_process_with_info, queue_signal_to_process_with_info_strict,
    queue_signal_to_thread_with_info, queue_signal_to_thread_with_info_strict, Process, SIGRTMIN,
};

const SIGINFO_SIZE: usize = 128;
const _: [(); SIGINFO_SIZE] = [(); core::mem::size_of::<siginfo>()];
const KCMP_FILE: i32 = 0;

fn is_valid_signal(sig: isize) -> bool {
    sig == 0 || (1..=(_NSIG as isize)).contains(&sig)
}

fn read_user_siginfo(process: &Process, addr: usize) -> Result<siginfo, LinuxError> {
    if addr == 0 {
        return Err(LinuxError::EFAULT);
    }

    let mut bytes = [0u8; SIGINFO_SIZE];
    process
        .read_user_bytes(addr, &mut bytes)
        .map_err(|_| LinuxError::EFAULT)?;
    Ok(unsafe { core::mem::transmute::<[u8; SIGINFO_SIZE], siginfo>(bytes) })
}

fn siginfo_bytes(info: siginfo) -> [u8; SIGINFO_SIZE] {
    unsafe { core::mem::transmute::<siginfo, [u8; SIGINFO_SIZE]>(info) }
}

fn siginfo_code(info: &siginfo) -> i32 {
    unsafe { info.__bindgen_anon_1.__bindgen_anon_1.si_code }
}

fn set_siginfo_signo(info: &mut siginfo, sig: isize) {
    info.__bindgen_anon_1.__bindgen_anon_1.si_signo = sig as linux_raw_sys::ctypes::c_int;
}

fn siginfo_signo(info: &siginfo) -> i32 {
    unsafe { info.__bindgen_anon_1.__bindgen_anon_1.si_signo }
}

/// Linux reserves `EAGAIN` for real-time signals whose detailed sigqueue
/// record was requested by a non-`SI_USER` sender. `kill(2)` remains
/// best-effort and may fall back to a pending bit without the supplied info.
fn needs_realtime_queue_slot(sig: isize, si_code: i32) -> bool {
    sig >= SIGRTMIN as isize && si_code != SI_USER as i32
}

/// User space may supply arbitrary queued-signal data only when the ABI target
/// is the calling thread. In particular, privileged callers must not fabricate
/// kernel or kill-family signal origins for a different task.
fn may_supply_siginfo_to_target(info: &siginfo, sender_tid: u64, target_id: u64) -> bool {
    sender_tid == target_id || {
        let code = siginfo_code(info);
        code < 0 && code != SI_TKILL
    }
}

/// Implements the credential and dumpability portion of
/// PTRACE_MODE_ATTACH_REALCREDS used by pidfd_getfd(2). PulseOS does not yet
/// have user namespaces or an LSM hook, so those policy layers are absent.
fn may_ptrace_attach_realcreds(caller: &Process, target: &Process) -> bool {
    if caller.has_capability(CAP_SYS_PTRACE) {
        return true;
    }
    if target.dumpable() != 1 {
        return false;
    }

    let caller_uid = caller.ruid();
    let caller_gid = caller.rgid();
    let (target_ruid, target_euid, target_suid) = target.uid_snapshot();
    let (target_rgid, target_egid, target_sgid) = target.gid_snapshot();
    caller_uid == target_ruid
        && caller_uid == target_euid
        && caller_uid == target_suid
        && caller_gid == target_rgid
        && caller_gid == target_egid
        && caller_gid == target_sgid
}

fn make_user_signal_info(sig: isize, code: i32, pid: u64, uid: u32) -> [u8; 128] {
    let mut info: siginfo = unsafe { core::mem::zeroed() };
    unsafe {
        let header = &mut info.__bindgen_anon_1.__bindgen_anon_1;
        header.si_signo = sig as linux_raw_sys::ctypes::c_int;
        header.si_errno = 0;
        header.si_code = code;
        header._sifields._kill._pid = pid as _;
        header._sifields._kill._uid = uid as _;
    }
    siginfo_bytes(info)
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
                if proc.pid() == 1 || proc.pid() == caller.pid() {
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

    if !targets
        .iter()
        .any(|target| can_signal(&caller, target, sig as usize))
    {
        return -LinuxError::EPERM.code() as isize;
    }

    if sig == 0 {
        return 0;
    }

    let info = make_user_signal_info(sig, SI_USER as i32, caller.pid(), caller.ruid());
    for target in targets {
        if !can_signal(&caller, &target, sig as usize) {
            continue;
        }
        let _ = queue_signal_to_process_with_info(target.as_ref(), sig as usize, Some(info));
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
    if !can_signal(&caller, target_proc.as_ref(), sig as usize) {
        return -LinuxError::EPERM.code() as isize;
    }
    if sig == 0 {
        return 0;
    }
    let info = make_user_signal_info(sig, SI_TKILL, caller.pid(), caller.ruid());
    if needs_realtime_queue_slot(sig, SI_TKILL) {
        if queue_signal_to_thread_with_info_strict(target_thread.as_ref(), sig as usize, Some(info))
            .is_err()
        {
            return -LinuxError::EAGAIN.code() as isize;
        }
    } else {
        let _ = queue_signal_to_thread_with_info(target_thread.as_ref(), sig as usize, Some(info));
    }
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
    if !can_signal(&caller, target_proc.as_ref(), sig as usize) {
        return -LinuxError::EPERM.code() as isize;
    }
    if sig == 0 {
        return 0;
    }
    let info = make_user_signal_info(sig, SI_TKILL, caller.pid(), caller.ruid());
    if needs_realtime_queue_slot(sig, SI_TKILL) {
        if queue_signal_to_thread_with_info_strict(target_thread.as_ref(), sig as usize, Some(info))
            .is_err()
        {
            return -LinuxError::EAGAIN.code() as isize;
        }
    } else {
        let _ = queue_signal_to_thread_with_info(target_thread.as_ref(), sig as usize, Some(info));
    }
    0
}

pub fn sys_rt_sigqueueinfo(pid: isize, sig: isize, info_ptr: usize) -> isize {
    let caller = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let caller_tid = match current_thread() {
        Ok(thread) => thread.tid(),
        Err(e) => return -e.code() as isize,
    };
    let mut info = match read_user_siginfo(&caller, info_ptr) {
        Ok(info) => info,
        Err(e) => return -e.code() as isize,
    };

    // Linux copies the ABI payload before do_rt_sigqueueinfo() validates the
    // target and signal number, so an invalid user pointer wins over EINVAL.
    if pid <= 0 || !is_valid_signal(sig) {
        return -LinuxError::EINVAL.code() as isize;
    }

    if !may_supply_siginfo_to_target(&info, caller_tid, pid as u64) {
        return -LinuxError::EPERM.code() as isize;
    }

    let Some(target) = process_by_pid(pid as u64) else {
        return -LinuxError::ESRCH.code() as isize;
    };
    if !can_signal(&caller, target.as_ref(), sig as usize) {
        return -LinuxError::EPERM.code() as isize;
    }

    // Unlike pidfd_send_signal, the rt_sigqueueinfo ABI overwrites the user
    // supplied signo with the syscall argument before queueing it.
    set_siginfo_signo(&mut info, sig);
    if sig != 0 {
        let info_code = siginfo_code(&info);
        let info = siginfo_bytes(info);
        if needs_realtime_queue_slot(sig, info_code) {
            if queue_signal_to_process_with_info_strict(
                target.as_ref(),
                sig as usize,
                Some(info),
            )
            .is_err()
            {
                return -LinuxError::EAGAIN.code() as isize;
            }
        } else {
            let _ = queue_signal_to_process_with_info(target.as_ref(), sig as usize, Some(info));
        }
    }
    0
}

pub fn sys_rt_tgsigqueueinfo(tgid: isize, tid: isize, sig: isize, info_ptr: usize) -> isize {
    let caller = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let caller_tid = match current_thread() {
        Ok(thread) => thread.tid(),
        Err(e) => return -e.code() as isize,
    };
    let mut info = match read_user_siginfo(&caller, info_ptr) {
        Ok(info) => info,
        Err(e) => return -e.code() as isize,
    };

    if tgid <= 0 || tid <= 0 || !is_valid_signal(sig) {
        return -LinuxError::EINVAL.code() as isize;
    }

    if !may_supply_siginfo_to_target(&info, caller_tid, tid as u64) {
        return -LinuxError::EPERM.code() as isize;
    }

    let Some(target_thread) = pulse_core::task::thread_by_tid_global(tid as u64) else {
        return -LinuxError::ESRCH.code() as isize;
    };
    let target_process = target_thread.process_arc();
    if target_process.pid() != tgid as u64 {
        return -LinuxError::ESRCH.code() as isize;
    }
    if !can_signal(&caller, target_process.as_ref(), sig as usize) {
        return -LinuxError::EPERM.code() as isize;
    }

    set_siginfo_signo(&mut info, sig);
    if sig != 0 {
        let info_code = siginfo_code(&info);
        let info = siginfo_bytes(info);
        if needs_realtime_queue_slot(sig, info_code) {
            if queue_signal_to_thread_with_info_strict(
                target_thread.as_ref(),
                sig as usize,
                Some(info),
            )
            .is_err()
            {
                return -LinuxError::EAGAIN.code() as isize;
            }
        } else {
            let _ = queue_signal_to_thread_with_info(target_thread.as_ref(), sig as usize, Some(info));
        }
    }
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
    let process = match current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };

    match option as u32 {
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
        PR_GET_DUMPABLE => process.dumpable() as isize,
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

    if (flags & !(O_NONBLOCK as usize)) != 0 {
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

    let mut fd_flags = pulse_core::fd_table::FdFlags::CLOEXEC;
    if (flags & (O_NONBLOCK as usize)) != 0 {
        fd_flags.insert(pulse_core::fd_table::FdFlags::NONBLOCK);
    }

    let entry = pulse_core::fd_table::FdEntry::new(
        alloc::sync::Arc::new(pulse_core::fd_table::PidfdObject::new(pid as u64)),
        fd_flags,
    );

    match caller.insert_fd_entry(entry) {
        Ok(fd) => fd as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_pidfd_getfd(pidfd: isize, targetfd: isize, flags: usize) -> isize {
    if flags as u32 != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if pidfd < 0 || targetfd < 0 {
        return -LinuxError::EBADF.code() as isize;
    }

    let caller = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let pidfd_entry = match caller.get_fd_entry(pidfd as usize) {
        Ok(entry) => entry,
        Err(_) => return -LinuxError::EBADF.code() as isize,
    };
    let Some(pidfd_object) = pidfd_entry
        .object
        .as_any()
        .downcast_ref::<pulse_core::fd_table::PidfdObject>()
    else {
        return -LinuxError::EBADF.code() as isize;
    };
    let Some(target) = process_by_pid(pidfd_object.pid()) else {
        return -LinuxError::ESRCH.code() as isize;
    };
    if !may_ptrace_attach_realcreds(caller.as_ref(), target.as_ref()) {
        return -LinuxError::EPERM.code() as isize;
    }

    let target_entry = match target.get_fd_entry(targetfd as usize) {
        Ok(entry) => entry,
        Err(_) => return -LinuxError::EBADF.code() as isize,
    };
    let mut fd_flags = target_entry.flags;
    fd_flags.insert(pulse_core::fd_table::FdFlags::CLOEXEC);
    match caller.insert_fd_entry(target_entry.duplicate(fd_flags)) {
        Ok(fd) => fd as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_kcmp(pid1: isize, pid2: isize, comparison_type: i32, idx1: usize, idx2: usize) -> isize {
    if comparison_type != KCMP_FILE {
        return -LinuxError::EINVAL.code() as isize;
    }
    if pid1 <= 0 || pid2 <= 0 {
        return -LinuxError::ESRCH.code() as isize;
    }

    let caller = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let Some(first) = process_by_pid(pid1 as u64) else {
        return -LinuxError::ESRCH.code() as isize;
    };
    let Some(second) = process_by_pid(pid2 as u64) else {
        return -LinuxError::ESRCH.code() as isize;
    };
    if !may_ptrace_attach_realcreds(caller.as_ref(), first.as_ref())
        || !may_ptrace_attach_realcreds(caller.as_ref(), second.as_ref())
    {
        return -LinuxError::EPERM.code() as isize;
    }

    let first_entry = match first.get_fd_entry(idx1) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    let second_entry = match second.get_fd_entry(idx2) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    match first_entry.ofd_owner().cmp(&second_entry.ofd_owner()) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

pub fn sys_pidfd_send_signal(pidfd: isize, sig: isize, info_ptr: usize, flags: usize) -> isize {
    axlog::debug!(
        "sys_pidfd_send_signal: pidfd={}, sig={}, info_ptr={:#x}, flags={}",
        pidfd,
        sig,
        info_ptr,
        flags
    );

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
    let caller_tid = match current_thread() {
        Ok(thread) => thread.tid(),
        Err(e) => return -e.code() as isize,
    };

    // Retrieve the fd entry
    let fd_entry = match caller.get_fd_entry(pidfd as usize) {
        Ok(entry) => entry,
        Err(_) => return -LinuxError::EBADF.code() as isize,
    };

    // Check if it's a PidfdObject
    let pidfd_obj = match fd_entry
        .object
        .as_any()
        .downcast_ref::<pulse_core::fd_table::PidfdObject>()
    {
        Some(obj) => obj,
        None => return -LinuxError::EBADF.code() as isize,
    };

    let target_pid = pidfd_obj.pid();
    let (info, info_code) = if info_ptr != 0 {
        let info = match read_user_siginfo(&caller, info_ptr) {
            Ok(info) => info,
            Err(e) => return -e.code() as isize,
        };
        if siginfo_signo(&info) != sig as linux_raw_sys::ctypes::c_int {
            return -LinuxError::EINVAL.code() as isize;
        }
        if !may_supply_siginfo_to_target(&info, caller_tid, target_pid) {
            return -LinuxError::EPERM.code() as isize;
        }
        let info_code = siginfo_code(&info);
        (siginfo_bytes(info), info_code)
    } else {
        (
            make_user_signal_info(sig, SI_USER as i32, caller.pid(), caller.ruid()),
            SI_USER as i32,
        )
    };

    let Some(target) = process_by_pid(target_pid) else {
        return -LinuxError::ESRCH.code() as isize;
    };
    if !can_signal(&caller, target.as_ref(), sig as usize) {
        return -LinuxError::EPERM.code() as isize;
    }

    if sig != 0 {
        if needs_realtime_queue_slot(sig, info_code) {
            if queue_signal_to_process_with_info_strict(target.as_ref(), sig as usize, Some(info))
                .is_err()
            {
                return -LinuxError::EAGAIN.code() as isize;
            }
        } else {
            let _ = queue_signal_to_process_with_info(target.as_ref(), sig as usize, Some(info));
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use linux_raw_sys::general::SI_QUEUE;

    fn test_siginfo(signo: i32, code: i32) -> siginfo {
        let mut info: siginfo = unsafe { core::mem::zeroed() };
        unsafe {
            let header = &mut info.__bindgen_anon_1.__bindgen_anon_1;
            header.si_signo = signo;
            header.si_code = code;
        }
        info
    }

    #[test]
    fn rt_sigqueueinfo_rewrites_the_queued_signal_number() {
        let mut info = test_siginfo(1, SI_QUEUE);
        set_siginfo_signo(&mut info, 42);
        assert_eq!(siginfo_signo(&info), 42);
    }

    #[test]
    fn arbitrary_siginfo_is_limited_to_the_sending_thread() {
        let user_info = test_siginfo(10, SI_USER as i32);
        let queued_info = test_siginfo(10, SI_QUEUE);
        let tkill_info = test_siginfo(10, SI_TKILL);

        assert!(!may_supply_siginfo_to_target(&user_info, 1, 2));
        assert!(!may_supply_siginfo_to_target(&tkill_info, 1, 2));
        assert!(may_supply_siginfo_to_target(&queued_info, 1, 2));
        // The low-level ABI compares against task_pid_vnr(current), not the
        // caller's thread-group ID.
        assert!(may_supply_siginfo_to_target(&user_info, 1, 1));
        assert!(!may_supply_siginfo_to_target(&user_info, 2, 1));
    }

    #[test]
    fn eagain_is_reserved_for_non_user_realtime_queue_records() {
        assert!(!needs_realtime_queue_slot(SIGRTMIN as isize - 1, SI_QUEUE));
        assert!(!needs_realtime_queue_slot(SIGRTMIN as isize, SI_USER as i32));
        assert!(needs_realtime_queue_slot(SIGRTMIN as isize, SI_QUEUE));
        assert!(needs_realtime_queue_slot(SIGRTMIN as isize, SI_TKILL));
    }
}
