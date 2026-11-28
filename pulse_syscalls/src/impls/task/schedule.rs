use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::Ordering;

use axerrno::LinuxError;
use linux_raw_sys::general::{
    CAP_SYS_NICE, PRIO_PGRP, PRIO_PROCESS, PRIO_USER, RLIMIT_NICE, RLIMIT_RTPRIO, SCHED_FIFO,
    SCHED_RR, timespec,
};
use process::{
    Process, Thread, current_process, current_thread, processes_snapshot, thread_by_tid_global,
};

use crate::{
    impls::utils::{
        alloc_zeroed_bytes, read_user_bytes, read_user_value, write_user_bytes, write_user_value,
    },
    validation::schedule::{
        CallerCreds, RT_PRIORITY_MAX, RT_PRIORITY_MIN, SCHED_ATTR_SIZE_VER0, SchedAttr,
        SchedChangeRequest, TargetSchedSnapshot, authorize_sched_change,
        check_zeroed_extension_bytes, decode_sched_setattr_size, eevdf_priority_for_request,
        format_sched_attr_for_policy, is_nice_reduction, is_rt_policy, sched_priority_max,
        sched_priority_min, validate_sched_getattr_args, validate_sched_setattr,
        validate_sched_setattr_args, validate_sched_setparam, validate_sched_setscheduler,
    },
};

fn kernel_cpumask_bytes() -> usize {
    let usize_bits = core::mem::size_of::<usize>() * 8;
    hal::cpu_num().div_ceil(usize_bits) * core::mem::size_of::<usize>()
}

struct SchedTarget {
    thread: Arc<Thread>,
    task: task::AxTaskRef,
}

fn signed_sched_pid(pid: usize, negative_errno: LinuxError) -> Result<u64, LinuxError> {
    // Linux exposes pid_t as a signed 32-bit value even though syscall
    // arguments arrive in a native-width register.
    let signed_pid = pid as i32 as i64;
    if signed_pid < 0 {
        return Err(negative_errno);
    }
    Ok(signed_pid as u64)
}

fn resolve_sched_target_with_negative(
    pid: usize,
    negative_errno: LinuxError,
) -> Result<SchedTarget, LinuxError> {
    let signed_pid = signed_sched_pid(pid, negative_errno)?;

    let current = current_thread()?;
    let current_tid = current.tid();
    let thread = if signed_pid == 0 || signed_pid as u64 == current_tid {
        current.clone()
    } else {
        thread_by_tid_global(signed_pid as u64).ok_or(LinuxError::ESRCH)?
    };
    let process = thread.try_process().ok_or(LinuxError::ESRCH)?;
    let task = if thread.tid() == current_tid {
        task::current().as_task_ref().clone()
    } else {
        process
            .task_ref_by_tid(thread.tid())
            .ok_or(LinuxError::ESRCH)?
    };
    if task.try_join().is_some() {
        return Err(LinuxError::ESRCH);
    }
    Ok(SchedTarget { thread, task })
}

fn resolve_sched_target(pid: usize) -> Result<SchedTarget, LinuxError> {
    resolve_sched_target_with_negative(pid, LinuxError::EINVAL)
}

fn caller_creds() -> Result<CallerCreds, LinuxError> {
    let caller = current_process()?;
    Ok(CallerCreds {
        euid: caller.euid(),
        has_cap_sys_nice: caller.has_capability(CAP_SYS_NICE),
    })
}

fn may_set_sched_target(target: &SchedTarget) -> Result<(), LinuxError> {
    let caller = caller_creds()?;
    if caller.has_cap_sys_nice {
        return Ok(());
    }
    let target_process = target.thread.try_process().ok_or(LinuxError::ESRCH)?;
    if caller.euid != target_process.ruid() && caller.euid != target_process.euid() {
        return Err(LinuxError::EPERM);
    }
    Ok(())
}

fn target_rt_priority(target: &SchedTarget, policy: u32) -> u32 {
    let prio = target.task.priority();
    if is_rt_policy(policy) && (RT_PRIORITY_MIN..=RT_PRIORITY_MAX).contains(&prio) {
        prio as u32
    } else {
        0
    }
}

fn snapshot_target_sched(target: &SchedTarget) -> Result<TargetSchedSnapshot, LinuxError> {
    let target_proc = target.thread.try_process().ok_or(LinuxError::ESRCH)?;
    let policy = target.thread.sched_policy.load(Ordering::Acquire);
    let nice = target.thread.sched_nice.load(Ordering::Acquire);
    let rt_priority = target_rt_priority(target, policy);
    let rlim_nice = target_proc
        .get_rlimit(RLIMIT_NICE)
        .map(|r| r.rlim_cur)
        .unwrap_or(0);
    let rlim_rtprio = target_proc
        .get_rlimit(RLIMIT_RTPRIO)
        .map(|r| r.rlim_cur)
        .unwrap_or(0);
    let (ruid, euid, _) = target_proc.uid_snapshot();
    Ok(TargetSchedSnapshot {
        policy,
        rt_priority,
        nice,
        ruid,
        euid,
        rlim_nice,
        rlim_rtprio,
    })
}

fn apply_target_rt_policy(target: &SchedTarget, policy: u32) {
    let Some(policy) = (match policy {
        SCHED_FIFO => Some(task::RtPolicy::Fifo),
        SCHED_RR => Some(task::RtPolicy::RoundRobin),
        _ => None,
    }) else {
        return;
    };
    task::set_task_rt_policy(target.task.clone(), policy);
}

fn commit_sched_change(
    target: &SchedTarget,
    req: &SchedChangeRequest,
    update_policy_and_meta: bool,
) -> Result<(), LinuxError> {
    let task_prio = eevdf_priority_for_request(req);
    if !task::set_task_priority(target.task.clone(), task_prio) {
        return Err(LinuxError::EINVAL);
    }
    if update_policy_and_meta {
        apply_target_rt_policy(target, req.policy);
        target.thread.sched_policy.store(req.policy, Ordering::Release);
        target.thread.sched_flags.store(req.flags, Ordering::Release);
        if req.update_nice {
            target.thread.sched_nice.store(req.nice, Ordering::Release);
        }
        target.thread.sched_runtime.store(req.runtime, Ordering::Release);
        target.thread.sched_deadline.store(req.deadline, Ordering::Release);
        target.thread.sched_period.store(req.period, Ordering::Release);
    }
    Ok(())
}

fn selected_priority_threads(
    which: i32,
    who: i32,
    caller: &Arc<Process>,
) -> Result<Vec<Arc<Thread>>, LinuxError> {
    let mut threads = Vec::new();
    match which as u32 {
        PRIO_PROCESS => {
            let tid = if who == 0 {
                current_thread()?.tid()
            } else if who > 0 {
                who as u64
            } else {
                return Err(LinuxError::ESRCH);
            };
            if let Some(thread) = thread_by_tid_global(tid) {
                threads.push(thread);
            }
        }
        PRIO_PGRP => {
            let pgid = if who == 0 {
                caller.pgid()
            } else if who > 0 {
                who as u64
            } else {
                return Err(LinuxError::ESRCH);
            };
            for process in processes_snapshot() {
                if process.is_zombie() || process.pgid() != pgid {
                    continue;
                }
                for tid in process.task_tids_snapshot() {
                    if let Some(thread) = thread_by_tid_global(tid) {
                        threads.push(thread);
                    }
                }
            }
        }
        PRIO_USER => {
            let uid = if who == 0 {
                caller.ruid()
            } else if who > 0 {
                who as u32
            } else {
                return Err(LinuxError::ESRCH);
            };
            for process in processes_snapshot() {
                if process.is_zombie() || process.ruid() != uid {
                    continue;
                }
                for tid in process.task_tids_snapshot() {
                    if let Some(thread) = thread_by_tid_global(tid) {
                        threads.push(thread);
                    }
                }
            }
        }
        _ => return Err(LinuxError::EINVAL),
    }

    if threads.is_empty() {
        Err(LinuxError::ESRCH)
    } else {
        Ok(threads)
    }
}

fn may_set_priority(caller: &Process, target: &Thread, nice: i32) -> Result<(), LinuxError> {
    if caller.has_capability(CAP_SYS_NICE) {
        return Ok(());
    }

    let target_process = target.process();
    let caller_euid = caller.euid();
    if caller_euid != target_process.ruid() && caller_euid != target_process.euid() {
        return Err(LinuxError::EPERM);
    }
    let current_nice = target.sched_nice.load(Ordering::Acquire);
    let rlim_nice = target_process
        .get_rlimit(RLIMIT_NICE)
        .map(|r| r.rlim_cur)
        .unwrap_or(0);
    if nice < current_nice && !is_nice_reduction(rlim_nice, nice) {
        return Err(LinuxError::EACCES);
    }
    Ok(())
}

fn apply_thread_nice(thread: &Thread, nice: i32) {
    let priority = nice as isize - 100;
    let is_current = current_thread()
        .map(|current| current.tid() == thread.tid())
        .unwrap_or(false);
    if is_current {
        let _ = task::set_priority(priority);
    } else if let Some(task) = thread.process().task_ref_by_tid(thread.tid()) {
        // A blocked task is not owned by a run queue, so the EEVDF priority
        // can be updated directly before the next wakeup enqueues it.
        if !task.is_ready() && !task.is_running() {
            let _ = task.set_priority(priority);
        }
    }
    thread
        .sched_nice
        .store(nice, core::sync::atomic::Ordering::Release);
}

pub fn sys_setpriority(which: i32, who: i32, priority: i32) -> isize {
    if !(-20..=19).contains(&priority) {
        return -LinuxError::EINVAL.code() as isize;
    }
    let caller = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    // PID 1 is reserved for the kernel init task, which has no user Thread
    // entry in the process registry. Preserve Linux's permission result for
    // an unprivileged attempt to alter that protected target.
    if which as u32 == PRIO_PROCESS && who == 1 && !caller.has_capability(CAP_SYS_NICE) {
        return -LinuxError::EPERM.code() as isize;
    }
    let threads = match selected_priority_threads(which, who, &caller) {
        Ok(threads) => threads,
        Err(e) => return -e.code() as isize,
    };
    let nice = priority;
    for thread in &threads {
        if let Err(e) = may_set_priority(caller.as_ref(), thread.as_ref(), nice) {
            return -e.code() as isize;
        }
    }
    for thread in threads {
        apply_thread_nice(thread.as_ref(), nice);
    }
    0
}

pub fn sys_getpriority(which: i32, who: i32) -> isize {
    let caller = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let threads = match selected_priority_threads(which, who, &caller) {
        Ok(threads) => threads,
        Err(e) => return -e.code() as isize,
    };
    let best_nice = threads
        .iter()
        .map(|thread| {
            thread
                .sched_nice
                .load(core::sync::atomic::Ordering::Acquire)
        })
        .min()
        .expect("nonempty priority target set");

    // The raw Linux syscall returns 20 - nice; libc translates this back to
    // the documented [-20, 19] range and can therefore distinguish success
    // from a negative errno value.
    (20 - best_nice) as isize
}

pub fn sys_sched_getaffinity(pid: usize, cpusetsize: usize, mask: usize) -> isize {
    let kernel_mask_bytes = kernel_cpumask_bytes();
    if cpusetsize < kernel_mask_bytes || cpusetsize % core::mem::size_of::<usize>() != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let target = match resolve_sched_target_with_negative(pid, LinuxError::ESRCH) {
        Ok(target) => target,
        Err(e) => return -e.code() as isize,
    };

    let cpumask = target.task.cpumask();
    let mut mask_bytes = match alloc_zeroed_bytes(kernel_mask_bytes, "sys_sched_getaffinity.mask") {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    for (idx, byte) in cpumask.as_bytes().iter().enumerate() {
        if idx < mask_bytes.len() {
            mask_bytes[idx] = *byte;
        }
    }
    if write_user_bytes(mask, &mask_bytes).is_err() {
        return -LinuxError::EFAULT.code() as isize;
    }

    kernel_mask_bytes as isize
}

pub fn sys_sched_setaffinity(pid: usize, cpusetsize: usize, mask: usize) -> isize {
    let size = cpusetsize.min(kernel_cpumask_bytes());
    let mut user_mask = match alloc_zeroed_bytes(size, "sys_sched_setaffinity.user_mask") {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    if size != 0 && read_user_bytes(mask, &mut user_mask).is_err() {
        return -LinuxError::EFAULT.code() as isize;
    }

    let target = match resolve_sched_target_with_negative(pid, LinuxError::ESRCH) {
        Ok(target) => target,
        Err(e) => return -e.code() as isize,
    };
    if let Err(e) = may_set_sched_target(&target) {
        return -e.code() as isize;
    }

    let mut cpumask = task::AxCpuMask::new();
    for cpu_id in 0..hal::cpu_num() {
        let byte_idx = cpu_id / 8;
        if byte_idx >= user_mask.len() {
            break;
        }
        let bit = 1u8 << (cpu_id % 8);
        if user_mask[byte_idx] & bit != 0 {
            cpumask.set(cpu_id, true);
        }
    }

    if task::set_task_affinity(target.task, cpumask) {
        0
    } else {
        -LinuxError::EINVAL.code() as isize
    }
}

pub fn sys_sched_getscheduler(pid: usize) -> isize {
    kernel_log::debug!("sys_sched_getscheduler: pid={}", pid);
    let target = match resolve_sched_target(pid) {
        Ok(target) => target,
        Err(e) => return -e.code() as isize,
    };
    target.thread.sched_policy.load(Ordering::Acquire) as isize
}

fn read_sched_attr_from_user(attr_ptr: usize) -> Result<SchedAttr, LinuxError> {
    let raw_size: u32 = read_user_value(attr_ptr).map_err(|_| LinuxError::EFAULT)?;
    let effective_size = match decode_sched_setattr_size(raw_size) {
        Ok(size) => size,
        Err(e) => {
            let _ = write_user_value(attr_ptr, &SCHED_ATTR_SIZE_VER0);
            return Err(e);
        }
    };
    let user_attr: SchedAttr = read_user_value(attr_ptr).map_err(|_| LinuxError::EFAULT)?;
    let tail_len = effective_size - SCHED_ATTR_SIZE_VER0 as usize;
    if tail_len > 0 {
        let mut tail_addr = attr_ptr
            .checked_add(SCHED_ATTR_SIZE_VER0 as usize)
            .ok_or(LinuxError::EFAULT)?;
        let mut remaining = tail_len;
        let mut buf = [0u8; 64];
        while remaining > 0 {
            let chunk = remaining.min(buf.len());
            read_user_bytes(tail_addr, &mut buf[..chunk]).map_err(|_| LinuxError::EFAULT)?;
            if check_zeroed_extension_bytes(&buf[..chunk]).is_err() {
                let _ = write_user_value(attr_ptr, &SCHED_ATTR_SIZE_VER0);
                return Err(LinuxError::E2BIG);
            }
            tail_addr = tail_addr.checked_add(chunk).ok_or(LinuxError::EFAULT)?;
            remaining -= chunk;
        }
    }
    Ok(user_attr)
}

fn do_sched_setparam(pid: usize, param_ptr: usize) -> Result<(), LinuxError> {
    signed_sched_pid(pid, LinuxError::EINVAL)?;
    if param_ptr == 0 {
        return Err(LinuxError::EINVAL);
    }
    let sched_priority: i32 = read_user_value(param_ptr).map_err(|_| LinuxError::EFAULT)?;
    let target = resolve_sched_target(pid)?;
    let snap = snapshot_target_sched(&target)?;
    let req = validate_sched_setparam(snap.policy, snap.nice, sched_priority)?;
    authorize_sched_change(caller_creds()?, &snap, &req)?;
    commit_sched_change(&target, &req, false)
}

pub fn sys_sched_setparam(pid: usize, param_ptr: usize) -> isize {
    do_sched_setparam(pid, param_ptr)
        .map(|_| 0)
        .unwrap_or_else(|e| -e.code() as isize)
}

fn do_sched_setscheduler(pid: usize, policy: usize, param_ptr: usize) -> Result<(), LinuxError> {
    if (policy as i32) < 0 {
        return Err(LinuxError::EINVAL);
    }
    signed_sched_pid(pid, LinuxError::EINVAL)?;
    if param_ptr == 0 {
        return Err(LinuxError::EINVAL);
    }
    let sched_priority: i32 = read_user_value(param_ptr).map_err(|_| LinuxError::EFAULT)?;
    let target = resolve_sched_target(pid)?;
    let snap = snapshot_target_sched(&target)?;
    let req = validate_sched_setscheduler(policy, sched_priority, snap.nice)?;
    authorize_sched_change(caller_creds()?, &snap, &req)?;
    commit_sched_change(&target, &req, true)
}

pub fn sys_sched_setscheduler(pid: usize, policy: usize, param_ptr: usize) -> isize {
    kernel_log::debug!(
        "sys_sched_setscheduler: pid={}, policy={}, param_ptr={:#x}",
        pid,
        policy,
        param_ptr
    );
    do_sched_setscheduler(pid, policy, param_ptr)
        .map(|_| 0)
        .unwrap_or_else(|e| -e.code() as isize)
}

fn do_sched_getparam(pid: usize, param_ptr: usize) -> Result<(), LinuxError> {
    signed_sched_pid(pid, LinuxError::EINVAL)?;
    if param_ptr == 0 {
        return Err(LinuxError::EINVAL);
    }
    let target = resolve_sched_target(pid)?;
    let policy = target.thread.sched_policy.load(Ordering::Acquire);
    let rt_prio = target_rt_priority(&target, policy) as i32;
    write_user_value(param_ptr, &rt_prio)
}

pub fn sys_sched_getparam(pid: usize, param_ptr: usize) -> isize {
    do_sched_getparam(pid, param_ptr)
        .map(|_| 0)
        .unwrap_or_else(|e| -e.code() as isize)
}

pub fn sys_sched_get_priority_max(policy: usize) -> isize {
    sched_priority_max(policy).unwrap_or_else(|e| -e.code() as isize)
}

pub fn sys_sched_get_priority_min(policy: usize) -> isize {
    sched_priority_min(policy).unwrap_or_else(|e| -e.code() as isize)
}

pub fn sys_sched_rr_get_interval(pid: usize, interval: usize) -> isize {
    if let Err(e) = resolve_sched_target(pid) {
        return -e.code() as isize;
    }
    let ts = timespec {
        tv_sec: (task::rt_time_slice_ns() / 1_000_000_000) as _,
        tv_nsec: (task::rt_time_slice_ns() % 1_000_000_000) as _,
    };
    write_user_value(interval, &ts)
        .map(|_| 0)
        .unwrap_or_else(|e| -e.code() as isize)
}

fn do_sched_setattr(pid: usize, attr: usize, flags: usize) -> Result<(), LinuxError> {
    validate_sched_setattr_args(pid, attr, flags)?;
    let user_attr = read_sched_attr_from_user(attr)?;
    if (user_attr.sched_policy as i32) < 0 {
        return Err(LinuxError::EINVAL);
    }
    let target = resolve_sched_target(pid)?;
    let snap = snapshot_target_sched(&target)?;
    let req = validate_sched_setattr(user_attr, snap.nice)?;
    authorize_sched_change(caller_creds()?, &snap, &req)?;
    commit_sched_change(&target, &req, true)
}

pub fn sys_sched_setattr(pid: usize, attr: usize, flags: usize) -> isize {
    kernel_log::debug!(
        "sys_sched_setattr: pid={}, attr={:#x}, flags={:#x}",
        pid,
        attr,
        flags
    );
    do_sched_setattr(pid, attr, flags)
        .map(|_| 0)
        .unwrap_or_else(|e| -e.code() as isize)
}

fn do_sched_getattr(pid: usize, attr: usize, size: usize, flags: usize) -> Result<(), LinuxError> {
    let usize_len = validate_sched_getattr_args(pid, attr, size, flags)?;
    let target = resolve_sched_target(pid)?;
    let policy = target.thread.sched_policy.load(Ordering::Acquire);
    let sched_attr = format_sched_attr_for_policy(
        policy,
        target.thread.sched_flags.load(Ordering::Acquire),
        target.thread.sched_nice.load(Ordering::Acquire),
        target_rt_priority(&target, policy),
        target.thread.sched_runtime.load(Ordering::Acquire),
        target.thread.sched_deadline.load(Ordering::Acquire),
        target.thread.sched_period.load(Ordering::Acquire),
    );
    write_user_value(attr, &sched_attr)?;

    let tail_len = usize_len - SCHED_ATTR_SIZE_VER0 as usize;
    if tail_len > 0 {
        let zeros = [0u8; 64];
        let mut tail_addr = attr
            .checked_add(SCHED_ATTR_SIZE_VER0 as usize)
            .ok_or(LinuxError::EFAULT)?;
        let mut remaining = tail_len;
        while remaining > 0 {
            let chunk = remaining.min(zeros.len());
            write_user_bytes(tail_addr, &zeros[..chunk]).map_err(|_| LinuxError::EFAULT)?;
            tail_addr = tail_addr.checked_add(chunk).ok_or(LinuxError::EFAULT)?;
            remaining -= chunk;
        }
    }
    Ok(())
}

pub fn sys_sched_getattr(pid: usize, attr: usize, size: usize, flags: usize) -> isize {
    kernel_log::debug!(
        "sys_sched_getattr: pid={}, attr={:#x}, size={}, flags={:#x}",
        pid,
        attr,
        size,
        flags
    );
    do_sched_getattr(pid, attr, size, flags)
        .map(|_| 0)
        .unwrap_or_else(|e| -e.code() as isize)
}

pub fn sys_getcpu(cpu_ptr: usize, node_ptr: usize, _tcache: usize) -> isize {
    kernel_log::debug!(
        "sys_getcpu: cpu_ptr={:#x}, node_ptr={:#x}, tcache={:#x}",
        cpu_ptr,
        node_ptr,
        _tcache
    );

    if cpu_ptr != 0 {
        let cpu_id = hal::percpu::this_cpu_id() as u32;
        if let Err(e) = write_user_value(cpu_ptr, &cpu_id) {
            return -e.code() as isize;
        }
    }

    if node_ptr != 0 {
        let node_id = 0u32;
        if let Err(e) = write_user_value(node_ptr, &node_id) {
            return -e.code() as isize;
        }
    }

    0
}
