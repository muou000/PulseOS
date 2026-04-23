use axerrno::LinuxError;
use linux_raw_sys::general::SCHED_RR;
use pulse_core::task::current_thread;

use crate::impls::utils::{alloc_zeroed_bytes, read_user_bytes, write_user_bytes};

pub fn sys_sched_getaffinity(pid: usize, cpusetsize: usize, mask: usize) -> isize {
    let Some(mask_bits) = cpusetsize.checked_mul(8) else {
        return -LinuxError::EINVAL.code() as isize;
    };
    if mask_bits < axhal::cpu_num() {
        return -LinuxError::EINVAL.code() as isize;
    }

    let current_tid = match current_thread() {
        Ok(thread) => thread.tid() as usize,
        Err(e) => return -e.code() as isize,
    };

    if pid != 0 && pid != current_tid {
        return -LinuxError::EPERM.code() as isize;
    }

    let cpumask = axtask::current().cpumask();
    let mask_bytes = cpumask.as_bytes();
    if write_user_bytes(mask, mask_bytes).is_err() {
        return -LinuxError::EFAULT.code() as isize;
    }

    mask_bytes.len() as isize
}

pub fn sys_sched_setaffinity(pid: usize, cpusetsize: usize, mask: usize) -> isize {
    let current_tid = match current_thread() {
        Ok(thread) => thread.tid() as usize,
        Err(e) => return -e.code() as isize,
    };

    if pid != 0 && pid != current_tid {
        return -LinuxError::EPERM.code() as isize;
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

pub fn sys_sched_getscheduler(_pid: usize) -> isize {
    SCHED_RR as isize
}

pub fn sys_sched_setscheduler(_pid: usize, _policy: usize, _param_ptr: usize) -> isize {
    0
}

pub fn sys_sched_getparam(_pid: usize, _param: usize) -> isize {
    0
}
