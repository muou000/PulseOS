use axerrno::LinuxError;
use linux_raw_sys::general::{
    SCHED_BATCH, SCHED_DEADLINE, SCHED_FIFO, SCHED_IDLE, SCHED_NORMAL, SCHED_RR, timespec,
};
use pulse_core::task::current_thread;

use crate::impls::utils::{alloc_zeroed_bytes, read_user_bytes, write_user_bytes};

const DEFAULT_SCHED_POLICY: u32 = SCHED_RR;
const DEFAULT_RT_PRIORITY: u32 = 1;
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

fn kernel_cpumask_bytes() -> usize {
    let usize_bits = core::mem::size_of::<usize>() * 8;
    axhal::cpu_num().div_ceil(usize_bits) * core::mem::size_of::<usize>()
}

fn current_tid() -> Result<usize, LinuxError> {
    current_thread()?;
    Ok(axtask::current().id().as_u64() as usize)
}

fn check_pid(pid: usize) -> Result<(), LinuxError> {
    let tid = current_tid()?;
    if pid != 0 && pid != tid {
        return Err(LinuxError::EPERM);
    }
    Ok(())
}

fn write_plain<T: Copy>(user_addr: usize, value: &T) -> Result<(), LinuxError> {
    let bytes = unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
    };
    write_user_bytes(user_addr, bytes)
}

pub fn sys_sched_getaffinity(pid: usize, cpusetsize: usize, mask: usize) -> isize {
    let kernel_mask_bytes = kernel_cpumask_bytes();
    if cpusetsize < kernel_mask_bytes {
        return -LinuxError::EINVAL.code() as isize;
    }

    if let Err(e) = check_pid(pid) {
        return -e.code() as isize;
    }

    let cpumask = axtask::current().cpumask();
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
    if cpusetsize < kernel_cpumask_bytes() {
        return -LinuxError::EINVAL.code() as isize;
    }
    if let Err(e) = check_pid(pid) {
        return -e.code() as isize;
    }

    let size = cpusetsize.min(axhal::cpu_num().div_ceil(8));
    let mut user_mask = match alloc_zeroed_bytes(size, "sys_sched_setaffinity.user_mask") {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    if size != 0 && read_user_bytes(mask, &mut user_mask).is_err() {
        return -LinuxError::EFAULT.code() as isize;
    }

    let mut cpumask = axtask::AxCpuMask::new();
    for cpu_id in 0..axhal::cpu_num() {
        let byte_idx = cpu_id / 8;
        if byte_idx >= user_mask.len() {
            break;
        }
        let bit = 1u8 << (cpu_id % 8);
        if user_mask[byte_idx] & bit != 0 {
            cpumask.set(cpu_id, true);
        }
    }

    if cpumask.is_empty() {
        return -LinuxError::EINVAL.code() as isize;
    }

    if axtask::set_current_affinity(cpumask) {
        0
    } else {
        -LinuxError::EINVAL.code() as isize
    }
}

pub fn sys_sched_getscheduler(pid: usize) -> isize {
    axlog::warn!(
        "sys_sched_getscheduler (stub): reporting SCHED_RR without per-task scheduler state"
    );
    if let Err(e) = check_pid(pid) {
        return -e.code() as isize;
    }
    DEFAULT_SCHED_POLICY as isize
}

pub fn sys_sched_setparam(pid: usize, param_ptr: usize) -> isize {
    axlog::warn!(
        "sys_sched_setparam (stub): pid={}, param={:#x}; request accepted without scheduler state",
        pid,
        param_ptr
    );
    if let Err(e) = check_pid(pid) {
        return -e.code() as isize;
    }
    if param_ptr == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    0
}

pub fn sys_sched_setscheduler(pid: usize, policy: usize, param_ptr: usize) -> isize {
    axlog::warn!(
        "sys_sched_setscheduler (stub): pid={}, policy={}, param={:#x}; request ignored",
        pid,
        policy,
        param_ptr
    );
    if let Err(e) = check_pid(pid) {
        return -e.code() as isize;
    }
    if param_ptr == 0 || !is_supported_policy(policy) {
        return -LinuxError::EINVAL.code() as isize;
    }
    0
}

pub fn sys_sched_getparam(pid: usize, param: usize) -> isize {
    axlog::warn!(
        "sys_sched_getparam (stub): pid={}, param={:#x}; reporting fixed RT priority",
        pid,
        param
    );
    if let Err(e) = check_pid(pid) {
        return -e.code() as isize;
    }
    write_plain(param, &(DEFAULT_RT_PRIORITY as i32))
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
    if let Err(e) = check_pid(pid) {
        return -e.code() as isize;
    }
    let ts = timespec {
        tv_sec: 0,
        tv_nsec: 10_000_000,
    };
    write_plain(interval, &ts)
        .map(|_| 0)
        .unwrap_or_else(|e| -e.code() as isize)
}

pub fn sys_sched_setattr(pid: usize, attr: usize, flags: usize) -> isize {
    axlog::warn!(
        "sys_sched_setattr (stub): pid={}, attr={:#x}, flags={:#x}; request accepted without \
         scheduler state",
        pid,
        attr,
        flags
    );
    if flags != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if let Err(e) = check_pid(pid) {
        return -e.code() as isize;
    }
    if attr == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    0
}

pub fn sys_sched_getattr(pid: usize, attr: usize, size: usize, flags: usize) -> isize {
    axlog::warn!(
        "sys_sched_getattr (stub): pid={}, attr={:#x}, size={}, flags={:#x}; reporting fixed RT \
         attributes",
        pid,
        attr,
        size,
        flags
    );
    if flags != 0 || size < SCHED_ATTR_SIZE as usize {
        return -LinuxError::EINVAL.code() as isize;
    }
    if let Err(e) = check_pid(pid) {
        return -e.code() as isize;
    }
    let sched_attr = SchedAttr {
        size: SCHED_ATTR_SIZE,
        sched_policy: DEFAULT_SCHED_POLICY,
        sched_flags: 0,
        sched_nice: 0,
        sched_priority: DEFAULT_RT_PRIORITY,
        sched_runtime: 0,
        sched_deadline: 0,
        sched_period: 0,
    };
    write_plain(attr, &sched_attr)
        .map(|_| 0)
        .unwrap_or_else(|e| -e.code() as isize)
}

fn is_supported_policy(policy: usize) -> bool {
    matches!(
        policy as u32,
        SCHED_NORMAL | SCHED_FIFO | SCHED_RR | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE
    )
}
