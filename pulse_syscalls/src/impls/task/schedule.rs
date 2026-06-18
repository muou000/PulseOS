use axerrno::LinuxError;
use linux_raw_sys::general::{
    SCHED_BATCH, SCHED_DEADLINE, SCHED_FIFO, SCHED_IDLE, SCHED_NORMAL, SCHED_RR, timespec,
};
use pulse_core::task::current_thread;

use crate::impls::utils::{alloc_zeroed_bytes, read_user_bytes, write_user_bytes};

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
    axlog::debug!("sys_sched_getscheduler: pid={}", pid);
    if let Err(e) = check_pid(pid) {
        return -e.code() as isize;
    }
    let thread = match current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };
    thread.sched_policy.load(core::sync::atomic::Ordering::Relaxed) as isize
}

pub fn sys_sched_setparam(pid: usize, param_ptr: usize) -> isize {
    if let Err(e) = check_pid(pid) {
        return -e.code() as isize;
    }
    if param_ptr == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let mut sched_priority: i32 = 0;
    if read_user_bytes(param_ptr, unsafe {
        core::slice::from_raw_parts_mut(
            &mut sched_priority as *mut i32 as *mut u8,
            core::mem::size_of::<i32>(),
        )
    })
    .is_err()
    {
        return -LinuxError::EFAULT.code() as isize;
    }

    if sched_priority < 0 || sched_priority > 99 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if sched_priority > 0 {
        axtask::set_priority(sched_priority as isize);
    } else {
        axtask::set_priority(-100);
    }
    0
}

pub fn sys_sched_setscheduler(pid: usize, policy: usize, param_ptr: usize) -> isize {
    axlog::debug!(
        "sys_sched_setscheduler: pid={}, policy={}, param_ptr={:#x}",
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

    let mut sched_priority: i32 = 0;
    if read_user_bytes(param_ptr, unsafe {
        core::slice::from_raw_parts_mut(
            &mut sched_priority as *mut i32 as *mut u8,
            core::mem::size_of::<i32>(),
        )
    })
    .is_err()
    {
        return -LinuxError::EFAULT.code() as isize;
    }

    if policy as u32 == SCHED_FIFO || policy as u32 == SCHED_RR {
        if sched_priority < 1 || sched_priority > 99 {
            return -LinuxError::EINVAL.code() as isize;
        }
        axtask::set_priority(sched_priority as isize);
    } else {
        if sched_priority != 0 {
            return -LinuxError::EINVAL.code() as isize;
        }
        axtask::set_priority(-100);
    }

    let thread = match current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };
    thread.sched_policy.store(policy as u32, core::sync::atomic::Ordering::Relaxed);
    0
}

pub fn sys_sched_getparam(pid: usize, param_ptr: usize) -> isize {
    if let Err(e) = check_pid(pid) {
        return -e.code() as isize;
    }
    if param_ptr == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let prio = axtask::current().as_task_ref().priority();
    let rt_prio = if (1..=99).contains(&prio) {
        prio as i32
    } else {
        0
    };
    write_plain(param_ptr, &rt_prio)
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
    axlog::debug!("sys_sched_setattr: pid={}, attr={:#x}, flags={:#x}", pid, attr, flags);
    if flags != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if let Err(e) = check_pid(pid) {
        return -e.code() as isize;
    }
    if attr == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let mut user_attr = SchedAttr {
        size: 0,
        sched_policy: 0,
        sched_flags: 0,
        sched_nice: 0,
        sched_priority: 0,
        sched_runtime: 0,
        sched_deadline: 0,
        sched_period: 0,
    };
    if read_user_bytes(attr, unsafe {
        core::slice::from_raw_parts_mut(
            &mut user_attr as *mut SchedAttr as *mut u8,
            core::mem::size_of::<SchedAttr>(),
        )
    })
    .is_err()
    {
        return -LinuxError::EFAULT.code() as isize;
    }

    if user_attr.size < SCHED_ATTR_SIZE {
        return -LinuxError::EINVAL.code() as isize;
    }
    if !is_supported_policy(user_attr.sched_policy as usize) {
        return -LinuxError::EINVAL.code() as isize;
    }

    let policy = user_attr.sched_policy;
    let priority = user_attr.sched_priority;

    if policy == SCHED_FIFO || policy == SCHED_RR || policy == SCHED_DEADLINE {
        if policy == SCHED_DEADLINE {
            if priority != 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
            if user_attr.sched_runtime == 0 || user_attr.sched_deadline == 0 || user_attr.sched_period == 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
            if user_attr.sched_runtime > user_attr.sched_deadline || user_attr.sched_deadline > user_attr.sched_period {
                return -LinuxError::EINVAL.code() as isize;
            }
        } else {
            if priority < 1 || priority > 99 {
                return -LinuxError::EINVAL.code() as isize;
            }
        }
        axtask::set_priority(priority as isize);
    } else {
        if priority != 0 {
            return -LinuxError::EINVAL.code() as isize;
        }
        if user_attr.sched_nice < -20 || user_attr.sched_nice > 19 {
            return -LinuxError::EINVAL.code() as isize;
        }
        axtask::set_priority(-100);
    }

    let thread = match current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };
    thread.sched_policy.store(policy, core::sync::atomic::Ordering::Relaxed);
    thread.sched_flags.store(user_attr.sched_flags, core::sync::atomic::Ordering::Relaxed);
    thread.sched_nice.store(user_attr.sched_nice, core::sync::atomic::Ordering::Relaxed);
    thread.sched_runtime.store(user_attr.sched_runtime, core::sync::atomic::Ordering::Relaxed);
    thread.sched_deadline.store(user_attr.sched_deadline, core::sync::atomic::Ordering::Relaxed);
    thread.sched_period.store(user_attr.sched_period, core::sync::atomic::Ordering::Relaxed);

    0
}

pub fn sys_sched_getattr(pid: usize, attr: usize, size: usize, flags: usize) -> isize {
    axlog::debug!(
        "sys_sched_getattr: pid={}, attr={:#x}, size={}, flags={:#x}",
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

    let thread = match current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };

    let prio = axtask::current().as_task_ref().priority();
    let rt_prio = if (1..=99).contains(&prio) {
        prio as u32
    } else {
        0
    };

    let sched_attr = SchedAttr {
        size: SCHED_ATTR_SIZE,
        sched_policy: thread.sched_policy.load(core::sync::atomic::Ordering::Relaxed),
        sched_flags: thread.sched_flags.load(core::sync::atomic::Ordering::Relaxed),
        sched_nice: thread.sched_nice.load(core::sync::atomic::Ordering::Relaxed),
        sched_priority: rt_prio,
        sched_runtime: thread.sched_runtime.load(core::sync::atomic::Ordering::Relaxed),
        sched_deadline: thread.sched_deadline.load(core::sync::atomic::Ordering::Relaxed),
        sched_period: thread.sched_period.load(core::sync::atomic::Ordering::Relaxed),
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

pub fn sys_getcpu(cpu_ptr: usize, node_ptr: usize, _tcache: usize) -> isize {
    axlog::debug!(
        "sys_getcpu: cpu_ptr={:#x}, node_ptr={:#x}, tcache={:#x}",
        cpu_ptr,
        node_ptr,
        _tcache
    );

    if cpu_ptr != 0 {
        let cpu_id = axhal::percpu::this_cpu_id() as u32;
        if let Err(e) = write_plain(cpu_ptr, &cpu_id) {
            return -e.code() as isize;
        }
    }

    if node_ptr != 0 {
        let node_id = 0u32;
        if let Err(e) = write_plain(node_ptr, &node_id) {
            return -e.code() as isize;
        }
    }

    0
}
