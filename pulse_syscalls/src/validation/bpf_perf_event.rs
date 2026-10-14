//! Validation tests for perf_event_open and PerfEvent control plane (#97).

#[cfg(test)]
mod tests {
    use axerrno::LinuxError;
    use crate::impls::bpf::perf_event::*;

    fn sample_attr(event_type: u32, config: u64) -> PerfEventAttr {
        let mut attr = PerfEventAttr::default();
        attr.event_type = event_type;
        attr.size = PERF_ATTR_SIZE_VER0 as u32;
        attr.config = config;
        attr
    }

    #[test]
    fn perf_event_attr_size_validation() {
        let mut attr = sample_attr(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK);

        // Size less than PERF_ATTR_SIZE_VER0 (64) must be rejected with EINVAL
        attr.size = 63;
        assert_eq!(validate_perf_event_attr(&attr, 63), Err(LinuxError::EINVAL));

        // Size larger than 4096 (page size) must be rejected with EINVAL
        attr.size = 4097;
        assert_eq!(validate_perf_event_attr(&attr, 4097), Err(LinuxError::EINVAL));

        // Size matching standard version boundaries must be accepted
        for &sz in &[64, 72, 80, 96, 104, 112, 120, 128] {
            attr.size = sz as u32;
            assert!(validate_perf_event_attr(&attr, sz).is_ok(), "size {} should be accepted", sz);
        }
    }

    #[test]
    fn perf_event_attr_type_and_config_validation() {
        // PERF_TYPE_SOFTWARE with PERF_COUNT_SW_CPU_CLOCK and PERF_COUNT_SW_TASK_CLOCK supported
        let cpu_clock = sample_attr(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK);
        assert_eq!(validate_perf_event_attr(&cpu_clock, 64), Ok(PerfEventClock::CpuClock));

        let task_clock = sample_attr(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK);
        assert_eq!(validate_perf_event_attr(&task_clock, 64), Ok(PerfEventClock::TaskClock));

        // Unsupported software configs rejected with EOPNOTSUPP
        let sw_page_faults = sample_attr(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS);
        assert_eq!(validate_perf_event_attr(&sw_page_faults, 64), Err(LinuxError::EOPNOTSUPP));

        let sw_context_switches = sample_attr(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES);
        assert_eq!(validate_perf_event_attr(&sw_context_switches, 64), Err(LinuxError::EOPNOTSUPP));

        // Hardware PMU / cache / raw events rejected with EOPNOTSUPP
        let hw_instructions = sample_attr(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS);
        assert_eq!(validate_perf_event_attr(&hw_instructions, 64), Err(LinuxError::EOPNOTSUPP));

        let hw_cache_ref = sample_attr(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES);
        assert_eq!(validate_perf_event_attr(&hw_cache_ref, 64), Err(LinuxError::EOPNOTSUPP));

        let hw_cache_miss = sample_attr(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES);
        assert_eq!(validate_perf_event_attr(&hw_cache_miss, 64), Err(LinuxError::EOPNOTSUPP));

        let hw_branch_inst = sample_attr(PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS);
        assert_eq!(validate_perf_event_attr(&hw_branch_inst, 64), Err(LinuxError::EOPNOTSUPP));

        let hw_branch_miss = sample_attr(PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES);
        assert_eq!(validate_perf_event_attr(&hw_branch_miss, 64), Err(LinuxError::EOPNOTSUPP));

        let cache_type = sample_attr(PERF_TYPE_HW_CACHE, 0);
        assert_eq!(validate_perf_event_attr(&cache_type, 64), Err(LinuxError::EOPNOTSUPP));

        let raw_type = sample_attr(PERF_TYPE_RAW, 0);
        assert_eq!(validate_perf_event_attr(&raw_type, 64), Err(LinuxError::EOPNOTSUPP));

        let bp_type = sample_attr(PERF_TYPE_BREAKPOINT, 0);
        assert_eq!(validate_perf_event_attr(&bp_type, 64), Err(LinuxError::EOPNOTSUPP));

        // Unknown type rejected with ENOENT
        let unknown_type = sample_attr(999, 0);
        assert_eq!(validate_perf_event_attr(&unknown_type, 64), Err(LinuxError::ENOENT));
    }

    #[test]
    fn perf_event_attr_flags_validation() {
        let mut attr = sample_attr(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK);

        // freq == 1 rejected with EOPNOTSUPP
        attr.flags = PERF_ATTR_FLAG_FREQ;
        assert_eq!(validate_perf_event_attr(&attr, 64), Err(LinuxError::EOPNOTSUPP));

        // inherit == 1 rejected with EOPNOTSUPP
        attr.flags = PERF_ATTR_FLAG_INHERIT;
        assert_eq!(validate_perf_event_attr(&attr, 64), Err(LinuxError::EOPNOTSUPP));

        // cgroup == 1 rejected with EOPNOTSUPP
        attr.flags = PERF_ATTR_FLAG_CGROUP;
        assert_eq!(validate_perf_event_attr(&attr, 64), Err(LinuxError::EOPNOTSUPP));

        // namespaces == 1 rejected with EOPNOTSUPP
        attr.flags = PERF_ATTR_FLAG_NAMESPACES;
        assert_eq!(validate_perf_event_attr(&attr, 64), Err(LinuxError::EOPNOTSUPP));

        // bpf_event == 1 rejected with EOPNOTSUPP
        attr.flags = PERF_ATTR_FLAG_BPF_EVENT;
        assert_eq!(validate_perf_event_attr(&attr, 64), Err(LinuxError::EOPNOTSUPP));
    }

    #[test]
    fn perf_event_scope_matrix_validation() {
        let max_cpus = 8;
        let current_pid = 42;
        let process_exists = |pid| pid == 42 || pid == 100;

        let scope_check = |pid, cpu, is_root| {
            validate_perf_event_scope(ScopeValidationParams {
                pid,
                cpu,
                is_root,
                current_pid,
                max_cpus,
                process_exists: &process_exists,
            })
        };

        // 1. per-CPU event: pid = -1, cpu >= 0 (requires privilege)
        assert_eq!(scope_check(-1, 0, true), Ok(PerfEventScope::PerCpu { cpu: 0 }));
        assert_eq!(scope_check(-1, 7, true), Ok(PerfEventScope::PerCpu { cpu: 7 }));
        // Without privilege -> EACCES
        assert_eq!(scope_check(-1, 0, false), Err(LinuxError::EACCES));
        // CPU out of range -> EINVAL
        assert_eq!(scope_check(-1, 8, true), Err(LinuxError::EINVAL));

        // 2. selected task event: pid >= 0, cpu = -1
        // pid = 0 resolves to current_pid
        assert_eq!(scope_check(0, -1, false), Ok(PerfEventScope::Task { pid: current_pid }));
        // pid > 0 existing process
        assert_eq!(scope_check(100, -1, true), Ok(PerfEventScope::Task { pid: 100 }));
        // pid > 0 non-existent process -> ESRCH
        assert_eq!(scope_check(999, -1, true), Err(LinuxError::ESRCH));

        // 3. invalid combinations
        // pid = -1, cpu = -1 -> EINVAL
        assert_eq!(scope_check(-1, -1, true), Err(LinuxError::EINVAL));
        // pid >= 0, cpu >= 0 -> EOPNOTSUPP
        assert_eq!(scope_check(0, 0, true), Err(LinuxError::EOPNOTSUPP));
        // negative invalid pid/cpu
        assert_eq!(scope_check(-2, -1, true), Err(LinuxError::EINVAL));
        assert_eq!(scope_check(-1, -2, true), Err(LinuxError::EINVAL));
    }

    #[test]
    fn perf_event_clock_and_scope_coupling() {
        // CpuClock requires PerCpu scope
        assert_eq!(
            validate_perf_event_coupling(PerfEventClock::CpuClock, &PerfEventScope::PerCpu { cpu: 0 }),
            Ok(())
        );
        assert_eq!(
            validate_perf_event_coupling(PerfEventClock::CpuClock, &PerfEventScope::Task { pid: 1 }),
            Err(LinuxError::EINVAL)
        );

        // TaskClock requires Task scope
        assert_eq!(
            validate_perf_event_coupling(PerfEventClock::TaskClock, &PerfEventScope::Task { pid: 1 }),
            Ok(())
        );
        assert_eq!(
            validate_perf_event_coupling(PerfEventClock::TaskClock, &PerfEventScope::PerCpu { cpu: 0 }),
            Err(LinuxError::EINVAL)
        );
    }

    #[test]
    fn perf_event_open_syscall_args_validation() {
        // group_fd must be -1
        assert_eq!(validate_perf_event_flags(0), Ok(false));
        assert_eq!(validate_perf_event_group_fd(-1), Ok(()));
        assert_eq!(validate_perf_event_group_fd(0), Err(LinuxError::EINVAL));
        assert_eq!(validate_perf_event_group_fd(3), Err(LinuxError::EINVAL));

        // flags
        assert_eq!(validate_perf_event_flags(PERF_FLAG_FD_CLOEXEC), Ok(true));
        assert_eq!(validate_perf_event_flags(PERF_FLAG_FD_NO_GROUP), Ok(false));
        assert_eq!(
            validate_perf_event_flags(PERF_FLAG_FD_CLOEXEC | PERF_FLAG_FD_NO_GROUP),
            Ok(true)
        );
        // cgroup flag rejected with EOPNOTSUPP
        assert_eq!(
            validate_perf_event_flags(PERF_FLAG_PID_CGROUP),
            Err(LinuxError::EOPNOTSUPP)
        );
        // unknown flags rejected with EINVAL
        assert_eq!(validate_perf_event_flags(0x100), Err(LinuxError::EINVAL));
    }

    #[test]
    fn perf_event_initial_state() {
        let spec = PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 0 },
            sample_period: 0,
            disabled: true,
            cloexec: true,
        };
        let event = PerfEvent::new(spec, 1000);
        assert!(!event.is_enabled());
        assert_eq!(event.read_counter_at(1000), 0);
        assert_eq!(event.read_counter_at(5000), 0);

        // Created in enabled state: last_enabled_ns initialized to creation now_ns (1000)
        let enabled_spec = PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 0 },
            sample_period: 0,
            disabled: false,
            cloexec: false,
        };
        let event2 = PerfEvent::new(enabled_spec, 1000);
        assert!(event2.is_enabled());
        // At creation time (1000), elapsed is 0
        assert_eq!(event2.read_counter_at(1000), 0);
        // At 1500, elapsed is 500 (NOT 1500 from 0)
        assert_eq!(event2.read_counter_at(1500), 500);
    }

    #[test]
    fn perf_event_enable_accumulates_time() {
        let spec = PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 0 },
            sample_period: 0,
            disabled: true,
            cloexec: true,
        };
        let event = PerfEvent::new(spec, 0);

        event.enable_at(1000);
        assert!(event.is_enabled());

        assert_eq!(event.read_counter_at(2500), 1500);
        assert_eq!(event.read_counter_at(4000), 3000);
    }

    #[test]
    fn perf_event_disable_pauses_accumulation() {
        let spec = PerfEventSpec {
            clock: PerfEventClock::TaskClock,
            scope: PerfEventScope::Task { pid: 42 },
            sample_period: 0,
            disabled: true,
            cloexec: false,
        };
        let event = PerfEvent::new(spec, 0);

        event.enable_at(1000);
        assert_eq!(event.read_counter_at(3000), 2000);

        event.disable_at(4500);
        assert!(!event.is_enabled());

        // While disabled, counter remains constant
        assert_eq!(event.read_counter_at(10000), 3500);
        assert_eq!(event.read_counter_at(20000), 3500);

        // Re-enabling resumes accumulation from current time
        event.enable_at(25000);
        assert!(event.is_enabled());
        assert_eq!(event.read_counter_at(27000), 5500);
    }

    #[test]
    fn perf_event_reset_clears_counter() {
        let spec = PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 0 },
            sample_period: 0,
            disabled: true,
            cloexec: false,
        };
        let event = PerfEvent::new(spec, 0);

        event.enable_at(1000);
        assert_eq!(event.read_counter_at(5000), 4000);

        // Reset while enabled resets counter to 0 and re-baselines
        event.reset_at(6000);
        assert_eq!(event.read_counter_at(6000), 0);
        assert_eq!(event.read_counter_at(7500), 1500);

        // Reset while disabled
        event.disable_at(8000);
        assert_eq!(event.read_counter_at(9000), 2000);
        event.reset_at(9500);
        assert_eq!(event.read_counter_at(10000), 0);
        assert_eq!(event.read_counter_at(12000), 0);
    }

    #[test]
    fn perf_event_read_buffer_validation() {
        let spec = PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 0 },
            sample_period: 0,
            disabled: true,
            cloexec: false,
        };
        let event = PerfEvent::new(spec, 0);
        event.enable_at(100);

        // Buffer smaller than 8 bytes returns EINVAL
        let mut buf7 = [0u8; 7];
        assert_eq!(event.read_into_at(&mut buf7, 500), Err(LinuxError::EINVAL));

        // Buffer of 8 bytes returns Ok(8) with little-endian count
        let mut buf8 = [0u8; 8];
        assert_eq!(event.read_into_at(&mut buf8, 500), Ok(8));
        assert_eq!(u64::from_ne_bytes(buf8), 400);

        // Buffer larger than 8 bytes writes 8 bytes and returns Ok(8)
        let mut buf16 = [0xffu8; 16];
        assert_eq!(event.read_into_at(&mut buf16, 700), Ok(8));
        let mut expected = [0xffu8; 16];
        expected[..8].copy_from_slice(&600u64.to_ne_bytes());
        assert_eq!(buf16, expected);
    }

    #[test]
    fn perf_event_ioctl_dispatch() {
        let spec = PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 0 },
            sample_period: 1000,
            disabled: true,
            cloexec: false,
        };
        let event = PerfEvent::new(spec, 0);

        // Enable via ioctl
        assert_eq!(event.ioctl_at(PERF_EVENT_IOC_ENABLE, 0, 1000), Ok(0));
        assert!(event.is_enabled());

        // Read counter
        assert_eq!(event.read_counter_at(2000), 1000);

        // Disable via ioctl
        assert_eq!(event.ioctl_at(PERF_EVENT_IOC_DISABLE, 0, 2500), Ok(0));
        assert!(!event.is_enabled());
        assert_eq!(event.read_counter_at(5000), 1500);

        // Reset via ioctl
        assert_eq!(event.ioctl_at(PERF_EVENT_IOC_RESET, 0, 5000), Ok(0));
        assert_eq!(event.read_counter_at(6000), 0);

        // Update period via ioctl
        assert_eq!(event.ioctl_at(PERF_EVENT_IOC_PERIOD, 50000, 6000), Ok(0));
        assert_eq!(event.sample_period(), 50000);

        // Unknown or unsupported ioctls return ENOTTY
        assert_eq!(event.ioctl_at(0x9999, 0, 6000), Err(LinuxError::ENOTTY));
        assert_eq!(event.ioctl_at(0x80082407, 0, 6000), Err(LinuxError::ENOTTY)); // PERF_EVENT_IOC_ID
        assert_eq!(event.ioctl_at(0x40042408, 0, 6000), Err(LinuxError::ENOTTY)); // PERF_EVENT_IOC_SET_BPF
    }
}
