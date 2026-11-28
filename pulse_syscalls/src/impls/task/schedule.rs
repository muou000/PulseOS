use alloc::{sync::Arc, vec::Vec};

use axerrno::LinuxError;
use linux_raw_sys::general::{
    CAP_SYS_NICE, PRIO_PGRP, PRIO_PROCESS, PRIO_USER, SCHED_BATCH, SCHED_DEADLINE, SCHED_FIFO,
    SCHED_IDLE, SCHED_NORMAL, SCHED_RR, timespec,
};
use process::{
    Process, Thread, current_process, current_thread, processes_snapshot, thread_by_tid_global,
};

use crate::impls::utils::{
    alloc_zeroed_bytes, read_user_bytes, read_user_value, write_user_bytes, write_user_value,
};

const RT_PRIORITY_MIN: isize = 1;
const RT_PRIORITY_MAX: isize = 99;
const SCHED_ATTR_SIZE: u32 = core::mem::size_of::<SchedAttr>() as u32;

#[repr(C)]
#[derive(Clone, Copy)]
struct SchedAttr {
    size: u32,
    sched_policy: u32,
    sched_flags: u64,
    sched_nice: i32,
    sched_priority: u32,
    sched_runtime: u64,
    sched_deadline: u64,
    sched_period: u64,
}

pulse_user_abi::impl_user_abi_struct! {
    for SchedAttr, size = 48 => {
        size: u32,
        sched_policy: u32,
        sched_flags: u64,
        sched_nice: i32,
        sched_priority: u32,
        sched_runtime: u64,
        sched_deadline: u64,
        sched_period: u64,
    }
}

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

fn may_set_sched_target(target: &SchedTarget) -> Result<(), LinuxError> {
    let caller = current_process()?;
    let target_process = target.thread.try_process().ok_or(LinuxError::ESRCH)?;
    if caller.has_capability(CAP_SYS_NICE) {
        return Ok(());
    }
    let caller_euid = caller.euid();
    if caller_euid != target_process.ruid() && caller_euid != target_process.euid() {
        return Err(LinuxError::EPERM);
    }
    Ok(())
}

fn validate_rt_priority(policy: u32, priority: u32) -> Result<Option<isize>, LinuxError> {
    match policy {
        SCHED_FIFO | SCHED_RR => {
            if (RT_PRIORITY_MIN as u32..=RT_PRIORITY_MAX as u32).contains(&priority) {
                Ok(Some(priority as isize))
            } else {
                Err(LinuxError::EINVAL)
            }
        }
        _ => Ok(None),
    }
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
    if nice
        < target
            .sched_nice
            .load(core::sync::atomic::Ordering::Acquire)
    {
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
    target
        .thread
        .sched_policy
        .load(core::sync::atomic::Ordering::Relaxed) as isize
}

pub fn sys_sched_setparam(pid: usize, param_ptr: usize) -> isize {
    if let Err(e) = signed_sched_pid(pid, LinuxError::EINVAL) {
        return -e.code() as isize;
    }
    if param_ptr == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let sched_priority: i32 = match read_user_value(param_ptr) {
        Ok(priority) => priority,
        Err(_) => return -LinuxError::EFAULT.code() as isize,
    };
    let target = match resolve_sched_target(pid) {
        Ok(target) => target,
        Err(e) => return -e.code() as isize,
    };
    if sched_priority < 0 || sched_priority > 99 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if let Err(e) = may_set_sched_target(&target) {
        return -e.code() as isize;
    }

    let priority = if sched_priority > 0 {
        sched_priority as isize
    } else {
        -100
    };
    if !task::set_task_priority(target.task, priority) {
        return -LinuxError::EINVAL.code() as isize;
    }
    0
}

pub fn sys_sched_setscheduler(pid: usize, policy: usize, param_ptr: usize) -> isize {
    kernel_log::debug!(
        "sys_sched_setscheduler: pid={}, policy={}, param_ptr={:#x}",
        pid,
        policy,
        param_ptr
    );
    if let Err(e) = signed_sched_pid(pid, LinuxError::EINVAL) {
        return -e.code() as isize;
    }
    if (policy as i32) < 0 || param_ptr == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let sched_priority: i32 = match read_user_value(param_ptr) {
        Ok(priority) => priority,
        Err(_) => return -LinuxError::EFAULT.code() as isize,
    };
    let target = match resolve_sched_target(pid) {
        Ok(target) => target,
        Err(e) => return -e.code() as isize,
    };
    if !is_supported_policy(policy) {
        return -LinuxError::EINVAL.code() as isize;
    }

    let priority = if sched_priority >= 0 {
        if let Ok(Some(priority)) = validate_rt_priority(policy as u32, sched_priority as u32) {
            priority
        } else if policy as u32 == SCHED_FIFO || policy as u32 == SCHED_RR {
            return -LinuxError::EINVAL.code() as isize;
        } else if sched_priority != 0 {
            return -LinuxError::EINVAL.code() as isize;
        } else {
            -100
        }
    } else {
        if policy as u32 == SCHED_FIFO || policy as u32 == SCHED_RR || sched_priority != 0 {
            return -LinuxError::EINVAL.code() as isize;
        }
        -100
    };
    if let Err(e) = may_set_sched_target(&target) {
        return -e.code() as isize;
    }

    if !task::set_task_priority(target.task.clone(), priority) {
        return -LinuxError::EINVAL.code() as isize;
    }
    apply_target_rt_policy(&target, policy as u32);
    target
        .thread
        .sched_policy
        .store(policy as u32, core::sync::atomic::Ordering::Relaxed);
    0
}

pub fn sys_sched_getparam(pid: usize, param_ptr: usize) -> isize {
    if let Err(e) = signed_sched_pid(pid, LinuxError::EINVAL) {
        return -e.code() as isize;
    }
    if param_ptr == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let target = match resolve_sched_target(pid) {
        Ok(target) => target,
        Err(e) => return -e.code() as isize,
    };
    let prio = target.task.priority();
    let rt_prio = if (1..=99).contains(&prio) {
        prio as i32
    } else {
        0
    };
    write_user_value(param_ptr, &rt_prio)
        .map(|_| 0)
        .unwrap_or_else(|e| -e.code() as isize)
}

pub fn sys_sched_get_priority_max(policy: usize) -> isize {
    match policy as u32 {
        SCHED_FIFO | SCHED_RR => RT_PRIORITY_MAX,
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE => 0,
        _ => -LinuxError::EINVAL.code() as isize,
    }
}

pub fn sys_sched_get_priority_min(policy: usize) -> isize {
    match policy as u32 {
        SCHED_FIFO | SCHED_RR => RT_PRIORITY_MIN,
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE => 0,
        _ => -LinuxError::EINVAL.code() as isize,
    }
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

pub fn sys_sched_setattr(pid: usize, attr: usize, flags: usize) -> isize {
    kernel_log::debug!(
        "sys_sched_setattr: pid={}, attr={:#x}, flags={:#x}",
        pid,
        attr,
        flags
    );
    if flags != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if let Err(e) = signed_sched_pid(pid, LinuxError::EINVAL) {
        return -e.code() as isize;
    }
    if attr == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let user_attr: SchedAttr = match read_user_value(attr) {
        Ok(attr) => attr,
        Err(_) => return -LinuxError::EFAULT.code() as isize,
    };

    if user_attr.size < SCHED_ATTR_SIZE {
        return -LinuxError::EINVAL.code() as isize;
    }
    if !is_supported_policy(user_attr.sched_policy as usize) {
        return -LinuxError::EINVAL.code() as isize;
    }

    let policy = user_attr.sched_policy;
    let priority = user_attr.sched_priority;
    let task_priority = if let Ok(Some(priority)) = validate_rt_priority(policy, priority) {
        priority
    } else if policy == SCHED_FIFO || policy == SCHED_RR {
        return -LinuxError::EINVAL.code() as isize;
    } else if policy == SCHED_DEADLINE {
        if priority != 0
            || user_attr.sched_runtime == 0
            || user_attr.sched_deadline == 0
            || user_attr.sched_period == 0
            || user_attr.sched_runtime > user_attr.sched_deadline
            || user_attr.sched_deadline > user_attr.sched_period
        {
            return -LinuxError::EINVAL.code() as isize;
        }
        -100
    } else {
        if priority != 0 || user_attr.sched_nice < -20 || user_attr.sched_nice > 19 {
            return -LinuxError::EINVAL.code() as isize;
        }
        user_attr.sched_nice as isize - 100
    };

    let target = match resolve_sched_target(pid) {
        Ok(target) => target,
        Err(e) => return -e.code() as isize,
    };
    if let Err(e) = may_set_sched_target(&target) {
        return -e.code() as isize;
    }

    if !task::set_task_priority(target.task.clone(), task_priority) {
        return -LinuxError::EINVAL.code() as isize;
    }
    apply_target_rt_policy(&target, policy);

    target
        .thread
        .sched_policy
        .store(policy, core::sync::atomic::Ordering::Relaxed);
    target
        .thread
        .sched_flags
        .store(user_attr.sched_flags, core::sync::atomic::Ordering::Relaxed);
    target
        .thread
        .sched_nice
        .store(user_attr.sched_nice, core::sync::atomic::Ordering::Relaxed);
    target.thread.sched_runtime.store(
        user_attr.sched_runtime,
        core::sync::atomic::Ordering::Relaxed,
    );
    target.thread.sched_deadline.store(
        user_attr.sched_deadline,
        core::sync::atomic::Ordering::Relaxed,
    );
    target.thread.sched_period.store(
        user_attr.sched_period,
        core::sync::atomic::Ordering::Relaxed,
    );

    0
}

pub fn sys_sched_getattr(pid: usize, attr: usize, size: usize, flags: usize) -> isize {
    kernel_log::debug!(
        "sys_sched_getattr: pid={}, attr={:#x}, size={}, flags={:#x}",
        pid,
        attr,
        size,
        flags
    );
    if flags != 0 || size < SCHED_ATTR_SIZE as usize {
        return -LinuxError::EINVAL.code() as isize;
    }
    if let Err(e) = signed_sched_pid(pid, LinuxError::EINVAL) {
        return -e.code() as isize;
    }
    if attr == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let target = match resolve_sched_target(pid) {
        Ok(target) => target,
        Err(e) => return -e.code() as isize,
    };
    let prio = target.task.priority();
    let rt_prio = if (1..=99).contains(&prio) {
        prio as u32
    } else {
        0
    };

    let sched_attr = SchedAttr {
        size: SCHED_ATTR_SIZE,
        sched_policy: target
            .thread
            .sched_policy
            .load(core::sync::atomic::Ordering::Relaxed),
        sched_flags: target
            .thread
            .sched_flags
            .load(core::sync::atomic::Ordering::Relaxed),
        sched_nice: target
            .thread
            .sched_nice
            .load(core::sync::atomic::Ordering::Relaxed),
        sched_priority: rt_prio,
        sched_runtime: target
            .thread
            .sched_runtime
            .load(core::sync::atomic::Ordering::Relaxed),
        sched_deadline: target
            .thread
            .sched_deadline
            .load(core::sync::atomic::Ordering::Relaxed),
        sched_period: target
            .thread
            .sched_period
            .load(core::sync::atomic::Ordering::Relaxed),
    };
    write_user_value(attr, &sched_attr)
        .map(|_| 0)
        .unwrap_or_else(|e| -e.code() as isize)
}

fn is_supported_policy(policy: usize) -> bool {
    matches!(
        policy as u32,
        SCHED_NORMAL | SCHED_FIFO | SCHED_RR | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE
    )
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
