use axerrno::LinuxError;

pub const PERF_TYPE_HARDWARE: u32 = 0;
pub const PERF_TYPE_SOFTWARE: u32 = 1;
pub const PERF_TYPE_TRACEPOINT: u32 = 2;
pub const PERF_TYPE_HW_CACHE: u32 = 3;
pub const PERF_TYPE_RAW: u32 = 4;
pub const PERF_TYPE_BREAKPOINT: u32 = 5;

pub const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;
pub const PERF_COUNT_SW_TASK_CLOCK: u64 = 1;
pub const PERF_COUNT_SW_PAGE_FAULTS: u64 = 2;
pub const PERF_COUNT_SW_CONTEXT_SWITCHES: u64 = 3;
pub const PERF_COUNT_SW_CPU_MIGRATIONS: u64 = 4;
pub const PERF_COUNT_SW_PAGE_FAULTS_MIN: u64 = 5;
pub const PERF_COUNT_SW_PAGE_FAULTS_MAJ: u64 = 6;
pub const PERF_COUNT_SW_ALIGNMENT_FAULTS: u64 = 7;
pub const PERF_COUNT_SW_EMULATION_FAULTS: u64 = 8;
pub const PERF_COUNT_SW_DUMMY: u64 = 9;
pub const PERF_COUNT_SW_BPF_OUTPUT: u64 = 10;
pub const PERF_COUNT_SW_CGROUP_SWITCHES: u64 = 11;

pub const PERF_COUNT_HW_INSTRUCTIONS: u64 = 0;
pub const PERF_COUNT_HW_CYCLES: u64 = 1;
pub const PERF_COUNT_HW_CACHE_REFERENCES: u64 = 2;
pub const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
pub const PERF_COUNT_HW_BRANCH_INSTRUCTIONS: u64 = 4;
pub const PERF_COUNT_HW_BRANCH_MISSES: u64 = 5;
pub const PERF_COUNT_HW_BUS_CYCLES: u64 = 6;
pub const PERF_COUNT_HW_STALLED_CYCLES_FRONTEND: u64 = 7;
pub const PERF_COUNT_HW_STALLED_CYCLES_BACKEND: u64 = 8;
pub const PERF_COUNT_HW_REF_CPU_CYCLES: u64 = 9;

pub const PERF_ATTR_SIZE_VER0: usize = 64;
pub const PERF_ATTR_SIZE_VER1: usize = 72;
pub const PERF_ATTR_SIZE_VER2: usize = 80;
pub const PERF_ATTR_SIZE_VER3: usize = 96;
pub const PERF_ATTR_SIZE_VER4: usize = 104;
pub const PERF_ATTR_SIZE_VER5: usize = 112;
pub const PERF_ATTR_SIZE_VER6: usize = 120;
pub const PERF_ATTR_SIZE_VER7: usize = 128;
pub const PERF_ATTR_SIZE_MAX: usize = 4096;

pub const PERF_FLAG_FD_NO_GROUP: usize = 1 << 0;
pub const PERF_FLAG_FD_OUTPUT: usize = 1 << 1;
pub const PERF_FLAG_PID_CGROUP: usize = 1 << 2;
pub const PERF_FLAG_FD_CLOEXEC: usize = 1 << 3;

pub const PERF_ATTR_FLAG_DISABLED: u64 = 1 << 0;
pub const PERF_ATTR_FLAG_INHERIT: u64 = 1 << 1;
pub const PERF_ATTR_FLAG_PINNED: u64 = 1 << 2;
pub const PERF_ATTR_FLAG_EXCLUSIVE: u64 = 1 << 3;
pub const PERF_ATTR_FLAG_EXCLUDE_USER: u64 = 1 << 4;
pub const PERF_ATTR_FLAG_EXCLUDE_KERNEL: u64 = 1 << 5;
pub const PERF_ATTR_FLAG_EXCLUDE_HV: u64 = 1 << 6;
pub const PERF_ATTR_FLAG_EXCLUDE_IDLE: u64 = 1 << 7;
pub const PERF_ATTR_FLAG_MMAP: u64 = 1 << 8;
pub const PERF_ATTR_FLAG_COMM: u64 = 1 << 9;
pub const PERF_ATTR_FLAG_FREQ: u64 = 1 << 10;
pub const PERF_ATTR_FLAG_INHERIT_STAT: u64 = 1 << 11;
pub const PERF_ATTR_FLAG_ENABLE_ON_EXEC: u64 = 1 << 12;
pub const PERF_ATTR_FLAG_TASK: u64 = 1 << 13;
pub const PERF_ATTR_FLAG_WATERMARK: u64 = 1 << 14;
pub const PERF_ATTR_FLAG_NAMESPACES: u64 = 1 << 28;
pub const PERF_ATTR_FLAG_BPF_EVENT: u64 = 1 << 30;
pub const PERF_ATTR_FLAG_CGROUP: u64 = 1 << 32;

pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_PERFMON: u32 = 38;

#[cfg(target_os = "none")]
pub use pulse_core::bpf::{
    PerfEvent, PerfEventClock, PerfEventScope, PerfEventSpec,
    PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_REFRESH,
    PERF_EVENT_IOC_RESET, PERF_EVENT_IOC_PERIOD,
};

#[cfg(not(target_os = "none"))]
#[path = "../../../../pulse_core/src/bpf/perf_event.rs"]
mod core_perf_event;

#[cfg(not(target_os = "none"))]
pub use core_perf_event::*;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PerfEventAttr {
    pub event_type: u32,
    pub size: u32,
    pub config: u64,
    pub sample_period_or_freq: u64,
    pub sample_type: u64,
    pub read_format: u64,
    pub flags: u64,
    pub wakeup_events_or_watermark: u32,
    pub bp_type: u32,
    pub config1: u64,
    pub config2: u64,
    pub branch_sample_type: u64,
    pub sample_regs_user: u64,
    pub sample_stack_user: u32,
    pub clockid: i32,
    pub sample_regs_intr: u64,
    pub aux_watermark: u32,
    pub sample_max_stack: u16,
    pub reserved_2: u16,
    pub aux_sample_size: u32,
    pub reserved_3: u32,
    pub sig_data: u64,
    pub config3: u64,
}

pub fn validate_perf_event_attr(
    attr: &PerfEventAttr,
    raw_size: usize,
) -> Result<PerfEventClock, LinuxError> {
    if raw_size < PERF_ATTR_SIZE_VER0 || raw_size > PERF_ATTR_SIZE_MAX {
        return Err(LinuxError::EINVAL);
    }
    if attr.size as usize != raw_size {
        return Err(LinuxError::EINVAL);
    }

    // Check event type and config
    let clock = match attr.event_type {
        PERF_TYPE_SOFTWARE => match attr.config {
            PERF_COUNT_SW_CPU_CLOCK => PerfEventClock::CpuClock,
            PERF_COUNT_SW_TASK_CLOCK => PerfEventClock::TaskClock,
            _ => return Err(LinuxError::EOPNOTSUPP),
        },
        PERF_TYPE_HARDWARE | PERF_TYPE_HW_CACHE | PERF_TYPE_RAW | PERF_TYPE_BREAKPOINT => {
            return Err(LinuxError::EOPNOTSUPP);
        }
        _ => return Err(LinuxError::ENOENT),
    };

    // Bitfield validations
    if (attr.flags & PERF_ATTR_FLAG_FREQ) != 0 {
        return Err(LinuxError::EOPNOTSUPP);
    }
    if (attr.flags & PERF_ATTR_FLAG_INHERIT) != 0 {
        return Err(LinuxError::EOPNOTSUPP);
    }
    if (attr.flags & PERF_ATTR_FLAG_CGROUP) != 0 {
        return Err(LinuxError::EOPNOTSUPP);
    }
    if (attr.flags & PERF_ATTR_FLAG_NAMESPACES) != 0 {
        return Err(LinuxError::EOPNOTSUPP);
    }
    if (attr.flags & PERF_ATTR_FLAG_BPF_EVENT) != 0 {
        return Err(LinuxError::EOPNOTSUPP);
    }

    Ok(clock)
}

#[derive(Clone, Copy, Debug)]
pub struct ScopeValidationParams<'a, F: Fn(u64) -> bool> {
    pub pid: i32,
    pub cpu: i32,
    pub is_root: bool,
    pub current_pid: u64,
    pub max_cpus: usize,
    pub process_exists: &'a F,
}

pub fn validate_perf_event_scope<F: Fn(u64) -> bool>(
    params: ScopeValidationParams<F>,
) -> Result<PerfEventScope, LinuxError> {
    let ScopeValidationParams {
        pid,
        cpu,
        is_root,
        current_pid,
        max_cpus,
        process_exists,
    } = params;

    if pid == -1 && cpu >= 0 {
        if !is_root {
            return Err(LinuxError::EACCES);
        }
        let cpu_idx = cpu as usize;
        if cpu_idx >= max_cpus {
            return Err(LinuxError::EINVAL);
        }
        Ok(PerfEventScope::PerCpu { cpu: cpu_idx })
    } else if pid >= 0 && cpu == -1 {
        let target_pid = if pid == 0 {
            current_pid
        } else {
            pid as u64
        };
        if !process_exists(target_pid) {
            return Err(LinuxError::ESRCH);
        }
        Ok(PerfEventScope::Task { pid: target_pid })
    } else if pid == -1 && cpu == -1 {
        Err(LinuxError::EINVAL)
    } else if pid >= 0 && cpu >= 0 {
        Err(LinuxError::EOPNOTSUPP)
    } else {
        Err(LinuxError::EINVAL)
    }
}

pub fn validate_perf_event_coupling(
    clock: PerfEventClock,
    scope: &PerfEventScope,
) -> Result<(), LinuxError> {
    match (clock, scope) {
        (PerfEventClock::CpuClock, PerfEventScope::PerCpu { .. }) => Ok(()),
        (PerfEventClock::TaskClock, PerfEventScope::Task { .. }) => Ok(()),
        _ => Err(LinuxError::EINVAL),
    }
}

pub fn validate_perf_event_group_fd(group_fd: i32) -> Result<(), LinuxError> {
    if group_fd == -1 {
        Ok(())
    } else {
        Err(LinuxError::EINVAL)
    }
}

pub fn validate_perf_event_flags(flags: usize) -> Result<bool, LinuxError> {
    if (flags & PERF_FLAG_PID_CGROUP) != 0 {
        return Err(LinuxError::EOPNOTSUPP);
    }
    let valid_mask = PERF_FLAG_FD_CLOEXEC | PERF_FLAG_FD_NO_GROUP;
    if (flags & !valid_mask) != 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok((flags & PERF_FLAG_FD_CLOEXEC) != 0)
}

#[cfg(target_os = "none")]
pub fn sys_perf_event_open(
    attr_uptr: usize,
    pid: i32,
    cpu: i32,
    group_fd: i32,
    flags: usize,
) -> isize {
    let cloexec = match validate_perf_event_flags(flags) {
        Ok(c) => c,
        Err(e) => return -e.code() as isize,
    };

    if let Err(e) = validate_perf_event_group_fd(group_fd) {
        return -e.code() as isize;
    }

    if attr_uptr == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let process = match pulse_core::task::current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };

    let mut size_bytes = [0u8; 4];
    let size_offset = core::mem::offset_of!(PerfEventAttr, size);
    if let Err(e) = process
        .read_user_bytes(attr_uptr + size_offset, &mut size_bytes)
        .map_err(|_| LinuxError::EFAULT)
    {
        return -e.code() as isize;
    }
    let raw_size = u32::from_ne_bytes(size_bytes) as usize;
    if raw_size < PERF_ATTR_SIZE_VER0 || raw_size > PERF_ATTR_SIZE_MAX {
        return -LinuxError::EINVAL.code() as isize;
    }

    let mut attr = PerfEventAttr::default();
    let copy_size = core::cmp::min(raw_size, core::mem::size_of::<PerfEventAttr>());
    let attr_bytes = unsafe {
        core::slice::from_raw_parts_mut(&mut attr as *mut PerfEventAttr as *mut u8, copy_size)
    };
    if let Err(e) = process
        .read_user_bytes(attr_uptr, attr_bytes)
        .map_err(|_| LinuxError::EFAULT)
    {
        return -e.code() as isize;
    }

    if raw_size > core::mem::size_of::<PerfEventAttr>() {
        let mut trailing = [0u8; 128];
        let mut offset = core::mem::size_of::<PerfEventAttr>();
        while offset < raw_size {
            let chunk = core::cmp::min(raw_size - offset, trailing.len());
            if let Err(e) = process
                .read_user_bytes(attr_uptr + offset, &mut trailing[..chunk])
                .map_err(|_| LinuxError::EFAULT)
            {
                return -e.code() as isize;
            }
            if trailing[..chunk].iter().any(|&b| b != 0) {
                return -LinuxError::E2BIG.code() as isize;
            }
            offset += chunk;
        }
    }

    let clock = match validate_perf_event_attr(&attr, raw_size) {
        Ok(c) => c,
        Err(e) => return -e.code() as isize,
    };

    let is_root = process.is_root_user()
        || process.has_capability(CAP_SYS_ADMIN)
        || process.has_capability(CAP_PERFMON);
    let current_pid = process.pid();
    let max_cpus = axconfig::plat::MAX_CPU_NUM;

    let scope_params = ScopeValidationParams {
        pid,
        cpu,
        is_root,
        current_pid,
        max_cpus,
        process_exists: &|target_pid| pulse_core::task::process_by_pid(target_pid).is_some(),
    };

    let scope = match validate_perf_event_scope(scope_params) {
        Ok(s) => s,
        Err(e) => return -e.code() as isize,
    };

    if let Err(e) = validate_perf_event_coupling(clock, &scope) {
        return -e.code() as isize;
    }

    let disabled = (attr.flags & PERF_ATTR_FLAG_DISABLED) != 0;
    let sample_period = attr.sample_period_or_freq;

    let spec = PerfEventSpec {
        clock,
        scope,
        sample_period,
        disabled,
        cloexec,
    };

    let now_ns = pulse_core::bpf::PerfEventObject::current_time_ns_for_spec(&spec);
    let event = alloc::sync::Arc::new(pulse_core::bpf::PerfEvent::new(spec, now_ns));
    let object = alloc::sync::Arc::new(pulse_core::bpf::PerfEventObject::new(event));
    let fd_flags = if cloexec {
        pulse_core::fd_table::FdFlags::CLOEXEC
    } else {
        pulse_core::fd_table::FdFlags::empty()
    };
    let entry = pulse_core::fd_table::FdEntry::new(object, fd_flags);
    match process.insert_fd_entry(entry) {
        Ok(fd) => fd as isize,
        Err(e) => -e.code() as isize,
    }
}
