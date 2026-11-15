//! Host validation tests for BPF Link objects and attach lifecycle (#98).

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/insn.rs"]
pub mod core_insn;

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/map.rs"]
pub mod core_map;

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/interpreter.rs"]
pub mod core_interpreter;

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/program.rs"]
pub mod core_program;

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/perf_event.rs"]
pub mod core_perf_event;

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/link.rs"]
pub mod core_link;

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/verifier.rs"]
pub mod core_verifier;

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/ring_buffer.rs"]
pub mod core_ring_buffer;

#[cfg(test)]
pub use core_insn as insn;
#[cfg(test)]
pub use core_map as map;
#[cfg(test)]
pub use core_interpreter as interpreter;
#[cfg(test)]
pub use core_program as program;
#[cfg(test)]
pub use core_perf_event as perf_event;
#[cfg(test)]
#[allow(unused_imports)]
pub use core_ring_buffer as ring_buffer;
#[cfg(test)]
pub use core_map::BPF_OBJ_NAME_LEN;

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::mem::{align_of, offset_of, size_of};

    use axerrno::LinuxError;

    use super::{
        core_insn::*, core_link::*, core_map, core_perf_event::*, core_program::*,
    };
    use crate::impls::bpf::abi::{
        BpfAttr, BpfCmd, BpfLinkCreateAttr, BpfLinkDetachAttr, check_attr_unused_tail,
    };

    #[test]
    fn bpf_link_abi_layout_matches_linux() {
        assert_eq!(size_of::<BpfLinkCreateAttr>(), 64);
        assert_eq!(align_of::<BpfLinkCreateAttr>(), 8);
        assert_eq!(size_of::<BpfLinkDetachAttr>(), 4);
        assert_eq!(align_of::<BpfLinkDetachAttr>(), 4);

        assert_eq!(size_of::<BpfLinkInfo>(), 64);
        assert_eq!(align_of::<BpfLinkInfo>(), 8);
        assert_eq!(offset_of!(BpfLinkInfo, link_type), 0);
        assert_eq!(offset_of!(BpfLinkInfo, id), 4);
        assert_eq!(offset_of!(BpfLinkInfo, prog_id), 8);
        assert_eq!(offset_of!(BpfLinkInfo, perf_event_type), 16);
        assert_eq!(offset_of!(BpfLinkInfo, config), 24);
        assert_eq!(offset_of!(BpfLinkInfo, event_type), 32);
    }

    #[test]
    fn bpf_link_cmd_metadata_and_not_deferred() {
        assert_eq!(BpfCmd::LinkCreate.min_attr_size(), 16);
        assert_eq!(BpfCmd::LinkCreate.attr_used_size(), 64);
        assert!(!BpfCmd::LinkCreate.is_deferred());

        assert_eq!(BpfCmd::LinkDetach.min_attr_size(), 4);
        assert_eq!(BpfCmd::LinkDetach.attr_used_size(), 4);
        assert!(!BpfCmd::LinkDetach.is_deferred());
    }

    #[test]
    fn bpf_link_attr_unused_tail_rejection() {
        let mut attr = BpfAttr::default();
        attr.link_create = BpfLinkCreateAttr {
            prog_fd: 3,
            target_fd: 4,
            attach_type: BPF_PERF_EVENT,
            flags: 0,
            target_btf_id_or_cookie: 0,
            extra: [0u8; 40],
        };
        assert!(check_attr_unused_tail(BpfCmd::LinkCreate, &attr).is_ok());

        // Corrupting bytes past the end of BpfLinkCreateAttr (offset 64..144) must return EINVAL
        unsafe {
            attr.raw[64] = 1;
        }
        assert_eq!(
            check_attr_unused_tail(BpfCmd::LinkCreate, &attr),
            Err(LinuxError::EINVAL)
        );

        let mut detach_attr = BpfAttr::default();
        detach_attr.link_detach = BpfLinkDetachAttr { link_fd: 5 };
        assert!(check_attr_unused_tail(BpfCmd::LinkDetach, &detach_attr).is_ok());

        // Corrupting bytes past offset 4 must return EINVAL
        unsafe {
            detach_attr.raw[4] = 1;
        }
        assert_eq!(
            check_attr_unused_tail(BpfCmd::LinkDetach, &detach_attr),
            Err(LinuxError::EINVAL)
        );
    }

    fn dummy_prog(prog_type: BpfProgType) -> Arc<BpfProgram> {
        let insns = Arc::new([
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ]);
        Arc::new(BpfProgram::new(prog_type, [0u8; 16], insns, alloc::vec::Vec::new()))
    }

    fn dummy_perf_event(clock: PerfEventClock) -> Arc<PerfEvent> {
        let spec = PerfEventSpec {
            clock,
            scope: match clock {
                PerfEventClock::CpuClock => PerfEventScope::PerCpu { cpu: 0 },
                PerfEventClock::TaskClock => PerfEventScope::Task { pid: 1 },
                PerfEventClock::Tracepoint(_) => PerfEventScope::PerCpu { cpu: 0 },
                PerfEventClock::BpfOutput => PerfEventScope::PerCpu { cpu: 0 },
            },
            sample_period: 0,
            disabled: true,
            cloexec: false,
        };
        Arc::new(PerfEvent::new(spec, 0))
    }

    #[test]
    fn bpf_link_lifecycle_and_target_compatibility() {
        let sw_event = dummy_perf_event(PerfEventClock::CpuClock);
        let tp_event = dummy_perf_event(PerfEventClock::Tracepoint(pulse_bpf_schema::TracepointId::SchedSwitch));

        let prog_perf = dummy_prog(BpfProgType::PerfEvent);
        let prog_tp = dummy_prog(BpfProgType::Tracepoint);

        // 1. Program type mismatch: Tracepoint prog cannot attach to CPU clock perf event
        assert_eq!(
            BpfLink::new(prog_tp.clone(), sw_event.clone()).map(|_| ()),
            Err(LinuxError::EINVAL)
        );
        assert!(sw_event.attached_prog().is_none());

        // 2. Program type match: PerfEvent prog attaches to CPU clock perf event
        let link1 = BpfLink::new(prog_perf.clone(), sw_event.clone()).expect("valid link must succeed");
        assert_eq!(link1.link_type(), BPF_LINK_TYPE_PERF_EVENT);
        assert!(!link1.is_detached());
        assert!(sw_event.attached_prog().is_some());

        // 3. Duplicate attachment returns EBUSY
        assert_eq!(
            BpfLink::new(prog_perf.clone(), sw_event.clone()).map(|_| ()),
            Err(LinuxError::EBUSY)
        );

        // 4. Explicit detach detaches from target
        assert!(link1.detach().is_ok());
        assert!(link1.is_detached());
        assert!(sw_event.attached_prog().is_none());

        // 5. Redundant detach returns EINVAL
        assert_eq!(link1.detach(), Err(LinuxError::EINVAL));

        // 6. After detach, target can be re-attached
        let link2 = BpfLink::new(prog_perf.clone(), sw_event.clone()).expect("re-attach must succeed");
        assert!(sw_event.attached_prog().is_some());

        // 7. Dropping link automatically detaches
        drop(link2);
        assert!(sw_event.attached_prog().is_none());

        // 8. Tracepoint perf event accepts Tracepoint program
        let link_tp = BpfLink::new(prog_tp.clone(), tp_event.clone()).expect("tp attach must succeed");
        assert!(tp_event.attached_prog().is_some());
        drop(link_tp);
        assert!(tp_event.attached_prog().is_none());
    }

    #[test]
    fn bpf_link_info_query() {
        let sw_event = dummy_perf_event(PerfEventClock::CpuClock);
        let prog_perf = dummy_prog(BpfProgType::PerfEvent);
        let link = BpfLink::new(prog_perf.clone(), sw_event.clone()).unwrap();

        let info = link.info();
        assert_eq!(info.link_type, BPF_LINK_TYPE_PERF_EVENT);
        assert_eq!(info.id, link.id());
        assert_eq!(info.prog_id, prog_perf.id());
        assert_eq!(info.perf_event_type, BPF_PERF_EVENT_EVENT);
        assert_eq!(info.config, PERF_COUNT_SW_CPU_CLOCK);
        assert_eq!(info.event_type, PERF_TYPE_SOFTWARE);

        let tp_event = dummy_perf_event(PerfEventClock::Tracepoint(pulse_bpf_schema::TracepointId::SchedSwitch));
        let prog_tp = dummy_prog(BpfProgType::Tracepoint);
        let link_tp = BpfLink::new(prog_tp.clone(), tp_event.clone()).unwrap();

        let tp_info = link_tp.info();
        assert_eq!(tp_info.link_type, BPF_LINK_TYPE_PERF_EVENT);
        assert_eq!(tp_info.id, link_tp.id());
        assert_eq!(tp_info.prog_id, prog_tp.id());
        assert_eq!(tp_info.perf_event_type, BPF_PERF_EVENT_TRACEPOINT);
        assert_eq!(tp_info.config, pulse_bpf_schema::TracepointId::SchedSwitch.as_u32() as u64);
        assert_eq!(tp_info.event_type, PERF_TYPE_TRACEPOINT);
    }

    #[test]
    fn perf_event_attach_program_ioctl_path() {
        let event = dummy_perf_event(PerfEventClock::CpuClock);
        let prog = dummy_prog(BpfProgType::PerfEvent);

        // 1. Initial state has no attached program
        assert!(event.attached_prog().is_none());

        // 2. Attach program succeeds
        assert!(event.attach_program(prog.clone()).is_ok());
        assert!(event.attached_prog().is_some());

        // 3. Double attach returns EBUSY
        assert_eq!(event.attach_program(prog.clone()), Err(LinuxError::EBUSY));

        // 4. Detaching matching program succeeds
        assert!(event.detach_program(&prog).is_ok());
        assert!(event.attached_prog().is_none());

        // 5. Redundant detach returns EINVAL
        assert_eq!(event.detach_program(&prog), Err(LinuxError::EINVAL));
    }

    #[test]
    fn bpf_link_and_object_reference_retention() {
        // Create map
        let req = core_map::BpfMapCreateRequest {
            map_type: core_map::BPF_MAP_TYPE_ARRAY,
            key_size: 4,
            value_size: 8,
            max_entries: 1,
            ..Default::default()
        };
        let map = Arc::new(core_map::BpfMap::create(core_map::BpfMapSpec::validate(&req).unwrap()).unwrap());
        let map_weak = Arc::downgrade(&map);

        // Create prog holding map reference
        let insns = Arc::new([
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ]);
        let prog = Arc::new(BpfProgram::new(
            BpfProgType::PerfEvent,
            [0u8; 16],
            insns,
            alloc::vec![map.clone()],
        ));
        let prog_weak = Arc::downgrade(&prog);

        let event = dummy_perf_event(PerfEventClock::CpuClock);
        let event_weak = Arc::downgrade(&event);

        // Create Link
        let link = BpfLink::new(prog.clone(), event.clone()).unwrap();
        let link_weak = Arc::downgrade(&link);

        // Drop the caller's direct references to map, prog, and event
        // (simulating user calling close(map_fd), close(prog_fd), close(perf_event_fd))
        drop(map);
        drop(prog);
        drop(event);

        // The Link must keep the PerfEvent, BpfProgram, and BpfMap alive!
        assert!(link_weak.upgrade().is_some());
        assert!(prog_weak.upgrade().is_some());
        assert!(map_weak.upgrade().is_some());
        assert!(event_weak.upgrade().is_some());

        // Simulate dup: duplicate reference to link
        let link_dup = link.clone();
        drop(link); // close first link FD
        // Program and Map must still remain alive
        assert!(prog_weak.upgrade().is_some());
        assert!(map_weak.upgrade().is_some());

        // Explicit detach
        assert!(link_dup.detach().is_ok());
        // Program and Map still stay alive while link_dup FD is open!
        assert!(prog_weak.upgrade().is_some());
        assert!(map_weak.upgrade().is_some());

        // Finally close link_dup
        drop(link_dup);

        // Now that the final link reference is dropped, program and map should be dropped!
        assert!(link_weak.upgrade().is_none());
        assert!(prog_weak.upgrade().is_none());
        assert!(map_weak.upgrade().is_none());
    }

    #[test]
    fn bpf_tracepoint_name_and_id_discovery() {
        assert_eq!(
            discover_tracepoint("sched/sched_switch"),
            Ok(pulse_bpf_schema::TracepointId::SchedSwitch)
        );
        assert_eq!(
            discover_tracepoint("sched_switch"),
            Ok(pulse_bpf_schema::TracepointId::SchedSwitch)
        );
        assert_eq!(
            discover_tracepoint("task/task_metadata"),
            Ok(pulse_bpf_schema::TracepointId::TaskMetadata)
        );
        assert_eq!(
            discover_tracepoint("sched/non_existent"),
            Err(LinuxError::ENOENT)
        );
        assert_eq!(
            discover_tracepoint("unknown_event"),
            Err(LinuxError::ENOENT)
        );
    }

    #[test]
    fn bpf_link_rejects_incompatible_program_type() {
        let tp_event = dummy_perf_event(PerfEventClock::Tracepoint(pulse_bpf_schema::TracepointId::SchedSwitch));
        let cpu_event = dummy_perf_event(PerfEventClock::CpuClock);

        let prog_tp = dummy_prog(BpfProgType::Tracepoint);
        let prog_perf = dummy_prog(BpfProgType::PerfEvent);

        // 1. Tracepoint rejects PerfEvent program
        assert_eq!(
            BpfLink::new(prog_perf.clone(), tp_event.clone()).map(|_| ()),
            Err(LinuxError::EINVAL)
        );
        // 2. CpuClock rejects Tracepoint program
        assert_eq!(
            BpfLink::new(prog_tp.clone(), cpu_event.clone()).map(|_| ()),
            Err(LinuxError::EINVAL)
        );
        // 3. Tracepoint accepts Tracepoint program
        assert!(BpfLink::new(prog_tp.clone(), tp_event.clone()).is_ok());
        // 4. CpuClock accepts PerfEvent program
        assert!(BpfLink::new(prog_perf.clone(), cpu_event.clone()).is_ok());
    }

    #[test]
    fn bpf_concurrent_tracepoint_links_refcounting() {
        let tp_id = pulse_bpf_schema::TracepointId::SchedSwitch;
        let event1 = dummy_perf_event(PerfEventClock::Tracepoint(tp_id));
        let event2 = dummy_perf_event(PerfEventClock::Tracepoint(tp_id));

        let prog1 = dummy_prog(BpfProgType::Tracepoint);
        let prog2 = dummy_prog(BpfProgType::Tracepoint);

        let link1 = BpfLink::new(prog1.clone(), event1.clone()).unwrap();
        let link2 = BpfLink::new(prog2.clone(), event2.clone()).unwrap();

        assert!(event1.attached_prog().is_some());
        assert!(event2.attached_prog().is_some());

        // Detaching link1 does not affect event2
        assert!(link1.detach().is_ok());
        assert!(event1.attached_prog().is_none());
        assert!(event2.attached_prog().is_some());

        // Detaching link2 completes teardown
        assert!(link2.detach().is_ok());
        assert!(event2.attached_prog().is_none());
    }

    #[test]
    fn perf_event_sample_invocation_and_counters() {
        let sw_event = dummy_perf_event(PerfEventClock::CpuClock);
        let prog = dummy_prog(BpfProgType::PerfEvent);
        let _link = BpfLink::new(prog.clone(), sw_event.clone()).unwrap();

        let counters = sw_event.sample_counters();
        assert_eq!(counters.delivered_samples, 0);
        assert_eq!(counters.re_entry_drops, 0);
        assert_eq!(counters.helper_failures, 0);
        assert_eq!(counters.budget_failures, 0);

        // Disabled event does not sample
        assert_eq!(sw_event.sample_at(1000, 0, 1, 1, 1), Ok(false));
        assert_eq!(sw_event.sample_counters().delivered_samples, 0);

        // Enable event -> samples delivered
        sw_event.enable_at(1000);
        assert_eq!(sw_event.sample_at(2000, 0, 1, 1, 1), Ok(true));
        assert_eq!(sw_event.sample_counters().delivered_samples, 1);
    }

    #[test]
    fn perf_event_sample_context_fields_delivered_to_program() {
        use super::core_verifier::{VerifierConfig, VerifierLog, verify_program, MapResolver};

        // 1. Create an Array Map (key: u32, value: 48 bytes matching context fields)
        let map_req = core_map::BpfMapCreateRequest {
            map_type: core_map::BPF_MAP_TYPE_ARRAY,
            key_size: 4,
            value_size: 48,
            max_entries: 1,
            ..Default::default()
        };
        let map = Arc::new(core_map::BpfMap::create(core_map::BpfMapSpec::validate(&map_req).unwrap()).unwrap());

        struct TestMapResolver {
            map: Arc<core_map::BpfMap>,
        }
        impl MapResolver for TestMapResolver {
            fn resolve_map(&self, _fd: u32) -> Result<Arc<core_map::BpfMap>, LinuxError> {
                Ok(self.map.clone())
            }
        }
        let resolver = TestMapResolver { map: map.clone() };

        // 2. Verified BPF program that copies all context fields into the Array Map:
        //    offset 0: sample_period (u64)
        //    offset 8: addr (u64)
        //    offset 16: timestamp_ns (u64)
        //    offset 24: cpu_id (u32)
        //    offset 28: pid (u32)
        //    offset 32: tid (u32)
        //    offset 40: task_id (u64)
        let insns = [
            // Save ctx pointer in r6
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_1, 0, 0),
            // Look up map element: key = 0
            BpfInsn::new(BPF_ALU | BPF_MOV | BPF_K, BPF_REG_1, 0, 0, 0),
            BpfInsn::new(BPF_ST | BPF_MEM | BPF_W, BPF_REG_10, 0, -4, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
            // ld_imm64 map
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 0),
            BpfInsn::new(0, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_MAP_LOOKUP_ELEM),
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 16, 0), // jump to exit if NULL
            // r7 = map value pointer
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
            // Copy sample_period (offset 0, u64)
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_1, BPF_REG_6, 0, 0),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_7, BPF_REG_1, 0, 0),
            // Copy addr (offset 8, u64)
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_1, BPF_REG_6, 8, 0),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_7, BPF_REG_1, 8, 0),
            // Copy timestamp_ns (offset 16, u64)
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_1, BPF_REG_6, 16, 0),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_7, BPF_REG_1, 16, 0),
            // Copy cpu_id (offset 24, u32)
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_W, BPF_REG_1, BPF_REG_6, 24, 0),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_W, BPF_REG_7, BPF_REG_1, 24, 0),
            // Copy pid (offset 28, u32)
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_W, BPF_REG_1, BPF_REG_6, 28, 0),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_W, BPF_REG_7, BPF_REG_1, 28, 0),
            // Copy tid (offset 32, u32)
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_W, BPF_REG_1, BPF_REG_6, 32, 0),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_W, BPF_REG_7, BPF_REG_1, 32, 0),
            // Copy task_id (offset 40, u64)
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_1, BPF_REG_6, 40, 0),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_7, BPF_REG_1, 40, 0),
            // Exit 0
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let config = VerifierConfig::new(BpfProgType::PerfEvent, 1);
        let mut log = VerifierLog::new();
        let verified = verify_program(&config, &insns, Some(&resolver), &mut log).expect("Program must verify");

        let prog = Arc::new(BpfProgram::new(
            verified.prog_type,
            [0u8; 16],
            verified.insns,
            verified.referenced_maps,
        ));

        let spec = PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 5 },
            sample_period: 42000,
            disabled: false,
            cloexec: true,
        };
        let event = Arc::new(PerfEvent::new(spec, 1000));
        let _link = BpfLink::new(prog, event.clone()).unwrap();

        // 3. Deliver sample with distinct, verifiable field values
        let now_ns = 999_888_777u64;
        let cpu = 5usize;
        let pid = 1234u64;
        let tid = 5678u64;
        let task_id = 9999u64;

        let delivered = event.sample_at(now_ns, cpu, pid, tid, task_id).expect("Sample execution must succeed");
        assert!(delivered);
        assert_eq!(event.sample_counters().delivered_samples, 1);

        // 4. Read back the Array Map value and verify all scalar fields exactly match
        let mut val = [0u8; 48];
        map.lookup(&0u32.to_ne_bytes(), &mut val).expect("Map lookup must succeed");

        let recorded_period = u64::from_ne_bytes(val[0..8].try_into().unwrap());
        let recorded_addr = u64::from_ne_bytes(val[8..16].try_into().unwrap());
        let recorded_ts = u64::from_ne_bytes(val[16..24].try_into().unwrap());
        let recorded_cpu = u32::from_ne_bytes(val[24..28].try_into().unwrap());
        let recorded_pid = u32::from_ne_bytes(val[28..32].try_into().unwrap());
        let recorded_tid = u32::from_ne_bytes(val[32..36].try_into().unwrap());
        let recorded_task_id = u64::from_ne_bytes(val[40..48].try_into().unwrap());

        assert_eq!(recorded_period, 42000);
        assert_eq!(recorded_addr, 0);
        assert_eq!(recorded_ts, 999_888_777);
        assert_eq!(recorded_cpu, 5);
        assert_eq!(recorded_pid, 1234);
        assert_eq!(recorded_tid, 5678);
        assert_eq!(recorded_task_id, 9999);
    }

    #[test]
    fn perf_event_period_accumulation_and_threshold() {
        let spec = PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 2 },
            sample_period: 10_000,
            disabled: true,
            cloexec: true,
        };
        let event = Arc::new(PerfEvent::new(spec, 1000));
        let prog = dummy_prog(BpfProgType::PerfEvent);
        let _link = BpfLink::new(prog, event.clone()).unwrap();

        // When disabled, advance produces 0 samples
        assert_eq!(event.advance_and_maybe_sample(5000, 2, 1, 1, 1), Ok(0));

        // Enable at t=5000
        event.enable_at(5000);

        // Advance 4,000 ns (t=9000, delta=4000 < period 10000): 0 samples
        assert_eq!(event.advance_and_maybe_sample(9000, 2, 1, 1, 1), Ok(0));
        assert_eq!(event.sample_counters().delivered_samples, 0);

        // Advance 7,000 ns (t=16000, total accumulated = 11000 >= 10000): 1 sample
        assert_eq!(event.advance_and_maybe_sample(16000, 2, 1, 1, 1), Ok(1));
        assert_eq!(event.sample_counters().delivered_samples, 1);

        // Advance 25,000 ns (t=41000, accumulated = 1000 + 25000 = 26000 >= 2 * 10000): 2 samples
        assert_eq!(event.advance_and_maybe_sample(41000, 2, 1, 1, 1), Ok(2));
        assert_eq!(event.sample_counters().delivered_samples, 3);
    }

    #[test]
    fn perf_event_same_cpu_reentrancy_drop_accounting() {
        let event = dummy_perf_event(PerfEventClock::CpuClock);
        let prog = dummy_prog(BpfProgType::PerfEvent);
        let _link = BpfLink::new(prog, event.clone()).unwrap();
        event.enable_at(1000);

        let test_cpu = 15;
        let other_cpu = 14;

        assert!(!is_in_sampling(test_cpu));

        // Normal sample on test_cpu succeeds
        assert_eq!(event.sample_at(2000, test_cpu, 1, 1, 1), Ok(true));
        assert_eq!(event.sample_counters().delivered_samples, 1);
        assert_eq!(event.sample_counters().re_entry_drops, 0);

        // Simulate nested re-entrant invocation on test_cpu
        set_in_sampling_for_test(test_cpu, true);
        assert!(is_in_sampling(test_cpu));

        // Re-entrant sample on test_cpu must be dropped and counted, returning Ok(false)
        assert_eq!(event.sample_at(3000, test_cpu, 1, 1, 1), Ok(false));
        assert_eq!(event.sample_counters().delivered_samples, 1);
        assert_eq!(event.sample_counters().re_entry_drops, 1);

        // Meanwhile, a concurrent sample on other_cpu is NOT blocked by test_cpu's guard
        assert_eq!(event.sample_at(3000, other_cpu, 1, 1, 1), Ok(true));
        assert_eq!(event.sample_counters().delivered_samples, 2);
        assert_eq!(event.sample_counters().re_entry_drops, 1);

        // Clean up test simulation
        set_in_sampling_for_test(test_cpu, false);
        assert!(!is_in_sampling(test_cpu));

        // test_cpu can sample normally again
        assert_eq!(event.sample_at(4000, test_cpu, 1, 1, 1), Ok(true));
        assert_eq!(event.sample_counters().delivered_samples, 3);
        assert_eq!(event.sample_counters().re_entry_drops, 1);
    }

    #[test]
    fn perf_event_budget_failure_accounting() {
        // Construct a program with a backward jump that exceeds the step budget (BPF_MAX_STEPS = 65536)
        let insns = Arc::new([
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 1),
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, -1, 0), // jump back to self endlessly
        ]);
        let prog = Arc::new(BpfProgram::new(
            BpfProgType::PerfEvent,
            [0u8; 16],
            insns,
            alloc::vec::Vec::new(),
        ));

        let event = dummy_perf_event(PerfEventClock::CpuClock);
        let _link = BpfLink::new(prog, event.clone()).unwrap();
        event.enable_at(1000);

        // Executing the over-budget program fails cleanly without hanging on CPU 3
        assert_eq!(event.sample_at(2000, 3, 1, 1, 1), Ok(false));
        let counters = event.sample_counters();
        assert_eq!(counters.budget_failures, 1);
        assert_eq!(counters.delivered_samples, 0);
        assert_eq!(counters.re_entry_drops, 0);
    }

    #[test]
    fn perf_event_helper_failure_accounting() {
        // Construct a program calling an invalid helper ID
        let insns = Arc::new([
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 9999), // invalid helper
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ]);
        let prog = Arc::new(BpfProgram::new(
            BpfProgType::PerfEvent,
            [0u8; 16],
            insns,
            alloc::vec::Vec::new(),
        ));

        let event = dummy_perf_event(PerfEventClock::CpuClock);
        let _link = BpfLink::new(prog, event.clone()).unwrap();
        event.enable_at(1000);

        // Executing the helper-failure program fails cleanly on CPU 4
        assert_eq!(event.sample_at(2000, 4, 1, 1, 1), Ok(false));
        let counters = event.sample_counters();
        assert_eq!(counters.helper_failures, 1);
        assert_eq!(counters.delivered_samples, 0);
    }

    #[test]
    fn perf_event_attach_produces_no_invocation_until_sample() {
        let sw_event = dummy_perf_event(PerfEventClock::CpuClock);
        let prog = dummy_prog(BpfProgType::PerfEvent);
        let _link = BpfLink::new(prog.clone(), sw_event.clone()).unwrap();

        // Attach alone produces 0 sample invocations and 0 runs
        assert_eq!(sw_event.sample_counters().delivered_samples, 0);
        assert_eq!(prog.sample_counters().delivered_samples, 0);
        assert_eq!(prog.run_cnt(), 0);

        // Enabling event also produces no invocations until time advances or sample arrives
        sw_event.enable_at(1000);
        assert_eq!(sw_event.sample_counters().delivered_samples, 0);
        assert_eq!(prog.sample_counters().delivered_samples, 0);
        assert_eq!(prog.run_cnt(), 0);
    }

    #[test]
    fn perf_event_program_sample_counters_track_execution() {
        let event = dummy_perf_event(PerfEventClock::CpuClock);
        let prog = dummy_prog(BpfProgType::PerfEvent);
        let _link = BpfLink::new(prog.clone(), event.clone()).unwrap();
        event.enable_at(1000);

        let test_cpu = 6;
        assert_eq!(event.sample_at(2000, test_cpu, 1, 1, 1), Ok(true));

        assert_eq!(event.sample_counters().delivered_samples, 1);
        assert_eq!(prog.sample_counters().delivered_samples, 1);
        assert_eq!(prog.run_cnt(), 1);
    }

    #[test]
    fn perf_event_task_clock_and_task_scope_sampling() {
        let spec = PerfEventSpec {
            clock: PerfEventClock::TaskClock,
            scope: PerfEventScope::Task { pid: 42 },
            sample_period: 5_000,
            disabled: true,
            cloexec: true,
        };
        let event = Arc::new(PerfEvent::new(spec, 1000));
        let prog = dummy_prog(BpfProgType::PerfEvent);
        let _link = BpfLink::new(prog.clone(), event.clone()).unwrap();

        event.enable_at(1000);

        // Advance on CPU 7 for task 42
        assert_eq!(event.advance_and_maybe_sample(7000, 7, 42, 42, 10), Ok(1));
        assert_eq!(event.sample_counters().delivered_samples, 1);
        assert_eq!(prog.sample_counters().delivered_samples, 1);
    }

    #[test]
    fn perf_event_verifier_rejects_out_of_bounds_context_access() {
        use super::core_verifier::{verify_program, VerifierConfig, VerifierLog};

        // The read-only stack extension ends at byte 640.
        let insns = [
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_0, BPF_REG_1, 640, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let config = VerifierConfig::new(BpfProgType::PerfEvent, 1);
        let mut log = VerifierLog::new();
        let res = verify_program(&config, &insns, None, &mut log);

        assert!(res.is_err(), "Access past PerfStackSampleContext (640 bytes) must be rejected");
        assert!(log.as_str().contains("invalid context access"));
    }

    fn runtime_observation(timestamp_ns: u64, cpu: usize, tid: u64) -> RuntimeSample {
        RuntimeSample {
            timestamp_ns,
            cpu,
            pid: 123,
            tid,
            task_id: 789,
            ip: 0x402010,
            stack: pulse_bpf_schema::FrozenStack::unavailable(
                pulse_bpf_schema::StackRegisters { ip: 0x402010, sp: 0, fp: 0, ra: 0 },
                pulse_bpf_schema::StackStatus::Unavailable),
            user_mode: true,
            task_clock_ns: timestamp_ns,
            generation: observation_generation(),
        }
    }

    #[test]
    fn runtime_sample_emits_once_when_several_periods_elapsed() {
        let event = PerfEvent::new(PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 9 },
            sample_period: 10,
            disabled: false,
            cloexec: false,
        }, 0);
        let prog = dummy_prog(BpfProgType::PerfEvent);
        event.attach_program(prog.clone()).unwrap();
        assert_eq!(event.dispatch_sample(&runtime_observation(35, 9, 456)), Ok(true));
        assert_eq!(prog.run_cnt(), 1, "one observed PC cannot represent three historic samples");
        assert_eq!(event.runtime_counters().skipped_periods, 2);
        assert_eq!(event.dispatch_sample(&runtime_observation(39, 9, 456)), Ok(false));
        assert_eq!(event.dispatch_sample(&runtime_observation(40, 9, 456)), Ok(true));
        assert_eq!(prog.run_cnt(), 2);
    }


    #[test]
    fn runtime_task_clock_uses_thread_cpu_time_and_survives_migration() {
        let event = PerfEvent::new(PerfEventSpec {
            clock: PerfEventClock::TaskClock,
            scope: PerfEventScope::Task { pid: 42 },
            sample_period: 10,
            disabled: false,
            cloexec: false,
        }, 100);
        let prog = dummy_prog(BpfProgType::PerfEvent);
        event.attach_program(prog.clone()).unwrap();
        let mut sample = runtime_observation(1_000_000, 10, 99);
        sample.pid = 42; // A process with this PID is not the selected TID.
        sample.task_clock_ns = 105;
        assert_eq!(event.dispatch_sample(&sample), Ok(false));
        sample.tid = 42;
        sample.pid = 123;
        assert_eq!(event.dispatch_sample(&sample), Ok(false));
        sample.timestamp_ns = 9_000_000; // The task was sleeping.
        assert_eq!(event.dispatch_sample(&sample), Ok(false));
        sample.cpu = 11; // Migration does not reset the thread's CPU clock.
        sample.task_clock_ns = 110;
        sample.timestamp_ns += 5;
        assert_eq!(event.dispatch_sample(&sample), Ok(true));
        assert_eq!(prog.run_cnt(), 1);
        assert_eq!(event.runtime_counters().skipped_periods, 0);
    }

    #[test]
    fn runtime_cpu_scope_and_zero_period_do_not_execute() {
        let event = PerfEvent::new(PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 0 },
            sample_period: 10,
            disabled: false,
            cloexec: false,
        }, 0);
        let prog = dummy_prog(BpfProgType::PerfEvent);
        event.attach_program(prog.clone()).unwrap();
        assert_eq!(event.dispatch_sample(&runtime_observation(100, 12, 42)), Ok(false));
        assert_eq!(event.dispatch_sample(&runtime_observation(10, 0, 42)), Ok(true));
        event.set_period(0);
        assert_eq!(event.dispatch_sample(&runtime_observation(20, 0, 42)), Ok(false));
        assert_eq!(prog.run_cnt(), 1);
    }


    #[test]
    fn runtime_lifecycle_rejects_queued_observations_from_old_attachments() {
        let event = PerfEvent::new(PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 8 },
            sample_period: 10,
            disabled: true,
            cloexec: false,
        }, 0);
        let before_attach = runtime_observation(10, 8, 42);
        let old_prog = dummy_prog(BpfProgType::PerfEvent);
        event.attach_program(old_prog.clone()).unwrap();
        event.enable_at(0);
        assert_eq!(event.dispatch_sample(&before_attach), Ok(false));
        let queued = runtime_observation(10, 8, 42);
        event.disable_at(5);
        assert_eq!(event.dispatch_sample(&queued), Ok(false));
        event.enable_at(5);
        assert_eq!(event.dispatch_sample(&queued), Ok(false));
        let before_reattach = runtime_observation(20, 8, 42);
        event.detach_program(&old_prog).unwrap();
        let new_prog = dummy_prog(BpfProgType::PerfEvent);
        event.attach_program(new_prog.clone()).unwrap();
        assert_eq!(event.dispatch_sample(&before_reattach), Ok(false));
        let before_reset = runtime_observation(20, 8, 42);
        event.reset_at(5);
        assert_eq!(event.dispatch_sample(&before_reset), Ok(false));
        let before_period = runtime_observation(20, 8, 42);
        event.set_period(10);
        assert_eq!(event.dispatch_sample(&before_period), Ok(false));
        assert_eq!(event.dispatch_sample(&runtime_observation(20, 8, 42)), Ok(true));
        assert_eq!(old_prog.run_cnt(), 0);
        assert_eq!(new_prog.run_cnt(), 1);
        assert_eq!(event.runtime_counters().cancelled, 6);
    }


    #[test]
    fn runtime_context_and_helpers_use_the_observed_task_not_the_worker() {
        use super::core_verifier::{VerifierConfig, VerifierLog, verify_program, MapResolver};
        let request = core_map::BpfMapCreateRequest {
            map_type: core_map::BPF_MAP_TYPE_ARRAY,
            key_size: 4,
            value_size: 80,
            max_entries: 1,
            ..Default::default()
        };
        let map = Arc::new(core_map::BpfMap::create(core_map::BpfMapSpec::validate(&request).unwrap()).unwrap());
        struct Resolver(Arc<core_map::BpfMap>);
        impl MapResolver for Resolver {
            fn resolve_map(&self, _fd: u32) -> Result<Arc<core_map::BpfMap>, LinuxError> {
                Ok(self.0.clone())
            }
        }
        let mut insns = alloc::vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_1, 0, 0),
            BpfInsn::new(BPF_ST | BPF_MEM | BPF_W, BPF_REG_10, 0, -4, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 0),
            BpfInsn::new(0, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_MAP_LOOKUP_ELEM),
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
        ];
        for offset in (0..64).step_by(8) {
            insns.push(BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_1, BPF_REG_6, offset, 0));
            insns.push(BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_7, BPF_REG_1, offset, 0));
        }
        insns.push(BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_KTIME_GET_NS));
        insns.push(BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_7, BPF_REG_0, 64, 0));
        insns.push(BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_GET_SMP_PROCESSOR_ID));
        insns.push(BpfInsn::new(BPF_STX | BPF_MEM | BPF_W, BPF_REG_7, BPF_REG_0, 72, 0));
        insns[7].off = (insns.len() - 8) as i16;
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0));
        insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
        let verified = verify_program(&VerifierConfig::new(BpfProgType::PerfEvent, 1), &insns,
            Some(&Resolver(map.clone())), &mut VerifierLog::new()).unwrap();
        let prog = Arc::new(BpfProgram::new(verified.prog_type, [0; 16], verified.insns, verified.referenced_maps));
        let event = PerfEvent::new(PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 9 },
            sample_period: 10,
            disabled: false,
            cloexec: false,
        }, 0);
        event.attach_program(prog).unwrap();
        assert_eq!(event.dispatch_sample(&runtime_observation(123_456, 9, 456)), Ok(true));
        let mut value = [0; 80];
        map.lookup(&0u32.to_ne_bytes(), &mut value).unwrap();
        let qword = |off| u64::from_le_bytes(value[off..off+8].try_into().unwrap());
        let word = |off| u32::from_le_bytes(value[off..off+4].try_into().unwrap());
        assert_eq!(qword(0), 10);
        assert_eq!(qword(8), 0, "v1 addr is not repurposed as IP");
        assert_eq!(qword(16), 123_456);
        assert_eq!(word(24), 9);
        assert_eq!(word(28), 123);
        assert_eq!(word(32), 456);
        assert_eq!(qword(40), 789);
        assert_eq!(qword(48), 0x402010);
        assert_eq!(word(56), 2);
        assert_eq!(word(60), 2);
        assert_eq!(qword(64), 123_456, "ktime comes from the frozen observation");
        assert_eq!(word(72), 9, "helper CPU must not be the worker CPU");
    }


    #[test]
    fn runtime_stack_snapshot_is_frozen_and_same_cpu_sources_keep_distinct_ids() {
        use super::core_verifier::{VerifierConfig, VerifierLog, verify_program, MapResolver};
        let request = core_map::BpfMapCreateRequest {
            map_type: core_map::BPF_MAP_TYPE_ARRAY,
            key_size: 4,
            value_size: 640,
            max_entries: 1,
            ..Default::default()
        };
        let map = Arc::new(core_map::BpfMap::create(core_map::BpfMapSpec::validate(&request).unwrap()).unwrap());
        struct Resolver(Arc<core_map::BpfMap>);
        impl MapResolver for Resolver {
            fn resolve_map(&self, _fd: u32) -> Result<Arc<core_map::BpfMap>, LinuxError> {
                Ok(self.0.clone())
            }
        }
        let mut insns = alloc::vec![
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_1, 0, 0),
            BpfInsn::new(BPF_ST | BPF_MEM | BPF_W, BPF_REG_10, 0, -4, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 0),
            BpfInsn::new(0, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_MAP_LOOKUP_ELEM),
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
        ];
        for offset in (0..640).step_by(8) {
            insns.push(BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_1, BPF_REG_6, offset, 0));
            insns.push(BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_7, BPF_REG_1, offset, 0));
        }
        insns[7].off = (insns.len() - 8) as i16;
        insns.push(BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0));
        insns.push(BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
        let verified = verify_program(&VerifierConfig::new(BpfProgType::PerfEvent, 1), &insns,
            Some(&Resolver(map.clone())), &mut VerifierLog::new()).unwrap();
        let prog = Arc::new(BpfProgram::new(verified.prog_type, [0; 16], verified.insns, verified.referenced_maps));
        let make_event = |period| {
            let event = PerfEvent::new(PerfEventSpec {
                clock: PerfEventClock::CpuClock,
                scope: PerfEventScope::PerCpu { cpu: 9 },
                sample_period: period, disabled: false, cloexec: false,
            }, 0);
            event.attach_program(prog.clone()).unwrap();
            event
        };
        let first = make_event(10);
        let second = make_event(20);
        let mut sample = runtime_observation(40, 9, 456);
        sample.stack = pulse_bpf_schema::walk_frame_pointers(
            pulse_bpf_schema::StackRegisters { ip: sample.ip, sp: 0x8000, fp: 0x8010, ra: 0x404000 },
            pulse_bpf_schema::StackLimits::default(),
            |_| {
                let mut bytes = [0;16];
                bytes[8..].copy_from_slice(&0x404000u64.to_le_bytes());
                Ok(bytes)
            }, |_| true);
        let frozen = sample.stack;
        for (event, period) in [(&first, 10), (&second, 20)] {
            assert_eq!(event.dispatch_sample(&sample), Ok(true));
            let mut value = [0; 640];
            map.lookup(&0u32.to_ne_bytes(), &mut value).unwrap();
            let decoded = pulse_bpf_schema::PerfStackSampleContext::from_bytes(&value).unwrap();
            assert_eq!(decoded.source_id, event.diagnostics().id);
            assert_eq!(decoded.base.base.sample_period, period);
            assert_eq!(decoded.base.ip, sample.ip);
            assert_eq!(decoded.stack, frozen);
        }
        assert_ne!(first.diagnostics().id, second.diagnostics().id);
        assert_eq!(first.sample_counters().delivered_samples, 1);
        assert_eq!(second.sample_counters().delivered_samples, 1);
        assert_eq!(first.runtime_counters().skipped_periods, 3);
        assert_eq!(second.runtime_counters().skipped_periods, 1);
    }


    #[test]
    fn runtime_registry_registration_is_unique_and_survives_link_detach() {
        let event = Arc::new(PerfEvent::new(PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 12 },
            sample_period: 10,
            disabled: false,
            cloexec: false,
        }, 0));
        register_active_perf_event(&event); // The FD owns this registration.
        let old_prog = dummy_prog(BpfProgType::PerfEvent);
        let link = BpfLink::new(old_prog.clone(), event.clone()).unwrap();
        register_active_perf_event(&event); // Must not register a second instance.
        assert!(has_active_perf_events());
        assert_eq!(dispatch_runtime_sample(&runtime_observation(10, 12, 42)), 1);
        assert_eq!(old_prog.run_cnt(), 1);
        link.detach().unwrap();
        let new_prog = dummy_prog(BpfProgType::PerfEvent);
        event.attach_program(new_prog.clone()).unwrap(); // ioctl reattach path.
        assert_eq!(dispatch_runtime_sample(&runtime_observation(20, 12, 42)), 1);
        assert_eq!(new_prog.run_cnt(), 1);
        event.detach_program(&new_prog).unwrap();
        unregister_active_perf_event(&event);
        assert_eq!(dispatch_runtime_sample(&runtime_observation(30, 12, 42)), 0);
    }

    #[test]
    fn runtime_invalid_observation_does_not_move_period_baseline() {
        let event = PerfEvent::new(PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 13 },
            sample_period: 10,
            disabled: false,
            cloexec: false,
        }, 100);
        let prog = dummy_prog(BpfProgType::PerfEvent);
        event.attach_program(prog.clone()).unwrap();
        assert_eq!(event.dispatch_sample(&runtime_observation(99, 13, 42)), Ok(false));
        let mut bad_ip = runtime_observation(110, 13, 42);
        bad_ip.ip = 0;
        assert_eq!(event.dispatch_sample(&bad_ip), Ok(false));
        let mut bad_identity = runtime_observation(110, 13, 42);
        bad_identity.tid = u32::MAX as u64 + 1;
        assert_eq!(event.dispatch_sample(&bad_identity), Ok(false));
        assert_eq!(event.dispatch_sample(&runtime_observation(110, 13, 42)), Ok(true));
        assert_eq!(event.runtime_counters().invalid, 3);
        assert_eq!(prog.run_cnt(), 1);
    }


    fn switch_observation(cpu: u32, tid: u32, time: u64) -> [u8; 72] {
        let mut bytes = [0; 72];
        bytes[0..4].copy_from_slice(&2u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&time.to_le_bytes());
        bytes[16..20].copy_from_slice(&cpu.to_le_bytes());
        bytes[20..24].copy_from_slice(&123u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&tid.to_le_bytes());
        bytes[32..40].copy_from_slice(&5u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&5u64.to_le_bytes());
        bytes[48..56].copy_from_slice(&6u64.to_le_bytes());
        bytes
    }

    #[test]
    fn runtime_tracepoint_preserves_source_context_and_helper_environment() {
        use super::core_verifier::{VerifierConfig, VerifierLog, verify_program, MapResolver};
        let request = core_map::BpfMapCreateRequest {
            map_type: core_map::BPF_MAP_TYPE_ARRAY, key_size: 4,
            value_size: 40, max_entries: 1, ..Default::default()
        };
        let map = Arc::new(core_map::BpfMap::create(core_map::BpfMapSpec::validate(&request).unwrap()).unwrap());
        struct Resolver(Arc<core_map::BpfMap>);
        impl MapResolver for Resolver {
            fn resolve_map(&self, _fd: u32) -> Result<Arc<core_map::BpfMap>, LinuxError> { Ok(self.0.clone()) }
        }
        let insns = [
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_1, 0, 0),
            BpfInsn::new(BPF_ST | BPF_MEM | BPF_W, BPF_REG_10, 0, -4, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 0),
            BpfInsn::new(0, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_MAP_LOOKUP_ELEM),
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 11, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_1, BPF_REG_6, 8, 0),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_7, BPF_REG_1, 0, 0),
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_W, BPF_REG_1, BPF_REG_6, 16, 0),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_W, BPF_REG_7, BPF_REG_1, 8, 0),
            BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_1, BPF_REG_6, 48, 0),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_7, BPF_REG_1, 16, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_KTIME_GET_NS),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_7, BPF_REG_0, 24, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_GET_SMP_PROCESSOR_ID),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_W, BPF_REG_7, BPF_REG_0, 32, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        let verified = verify_program(&VerifierConfig::new(BpfProgType::Tracepoint, 1), &insns,
            Some(&Resolver(map.clone())), &mut VerifierLog::new()).unwrap();
        let prog = Arc::new(BpfProgram::new(verified.prog_type, [0; 16], verified.insns, verified.referenced_maps));
        let event = PerfEvent::new(PerfEventSpec {
            clock: PerfEventClock::Tracepoint(pulse_bpf_schema::TracepointId::SchedSwitch),
            scope: PerfEventScope::PerCpu { cpu: 9 }, sample_period: 0, disabled: false, cloexec: false,
        }, 0);
        event.attach_program(prog.clone()).unwrap();
        let bytes = switch_observation(9, 456, 987_654);
        assert_eq!(event.dispatch_sample(&runtime_observation(1_000_000, 9, 456)), Ok(false), "timer must not run a tracepoint program");
        assert_eq!(event.dispatch_tracepoint(pulse_bpf_schema::TracepointId::SchedSwitch,
            &bytes, observation_generation()), Ok(true));
        let mut value = [0; 40]; map.lookup(&0u32.to_ne_bytes(), &mut value).unwrap();
        assert_eq!(u64::from_le_bytes(value[0..8].try_into().unwrap()), 987_654);
        assert_eq!(u32::from_le_bytes(value[8..12].try_into().unwrap()), 9);
        assert_eq!(u64::from_le_bytes(value[16..24].try_into().unwrap()), 6);
        assert_eq!(u64::from_le_bytes(value[24..32].try_into().unwrap()), 987_654);
        assert_eq!(u32::from_le_bytes(value[32..36].try_into().unwrap()), 9);
        assert_eq!(prog.run_cnt(), 1);
    }


    #[test]
    fn runtime_tracepoint_dispatches_each_live_subscriber_and_cancels_old_epochs() {
        use pulse_bpf_schema::TracepointId;
        let make = || Arc::new(PerfEvent::new(PerfEventSpec {
            clock: PerfEventClock::Tracepoint(TracepointId::SchedSwitch),
            scope: PerfEventScope::PerCpu { cpu: 11 }, sample_period: 0, disabled: false, cloexec: false,
        }, 0));
        let a = make(); let b = make();
        let pa = dummy_prog(BpfProgType::Tracepoint); let pb = dummy_prog(BpfProgType::Tracepoint);
        let la = BpfLink::new(pa.clone(), a.clone()).unwrap();
        let lb = BpfLink::new(pb.clone(), b.clone()).unwrap();
        let bytes = switch_observation(11, 42, 50);
        let generation = observation_generation();
        assert_eq!(dispatch_tracepoint(TracepointId::SchedSwitch, &bytes, generation), 2);
        a.disable_at(60);
        // B's activation is unchanged. A's unrelated epoch must not cancel B.
        assert_eq!(dispatch_tracepoint(TracepointId::SchedSwitch, &bytes, generation), 1);
        lb.detach().unwrap();
        assert_eq!(dispatch_tracepoint(TracepointId::SchedSwitch, &bytes, generation), 0);
        a.enable_at(70);
        assert_eq!(dispatch_tracepoint(TracepointId::SchedSwitch, &bytes, generation), 0);
        assert_eq!(dispatch_tracepoint(TracepointId::SchedSwitch, &bytes, observation_generation()), 1);
        la.detach().unwrap();
        assert_eq!(dispatch_tracepoint(TracepointId::SchedSwitch, &bytes, observation_generation()), 0);
        assert_eq!(pa.run_cnt(), 2);
        assert_eq!(pb.run_cnt(), 2);
        unregister_active_perf_event(&a); unregister_active_perf_event(&b);
    }

    #[test]
    fn runtime_tracepoint_checks_context_shape_and_subject_tid_scope() {
        use pulse_bpf_schema::TracepointId;
        let event = PerfEvent::new(PerfEventSpec {
            clock: PerfEventClock::Tracepoint(TracepointId::SchedSwitch),
            scope: PerfEventScope::Task { pid: 42 }, sample_period: 0, disabled: false, cloexec: false,
        }, 0);
        let prog = dummy_prog(BpfProgType::Tracepoint);
        event.attach_program(prog.clone()).unwrap();
        let generation = observation_generation();
        assert_eq!(event.dispatch_tracepoint(TracepointId::TaskWake, &[], generation), Ok(false));
        assert_eq!(event.dispatch_tracepoint(TracepointId::SchedSwitch, &[], generation), Ok(false));
        assert_eq!(event.dispatch_tracepoint(TracepointId::SchedSwitch, &switch_observation(9, 0, 50), generation), Ok(false));
        assert_eq!(event.dispatch_tracepoint(TracepointId::SchedSwitch, &switch_observation(9, 43, 50), generation), Ok(false));
        let mut malformed = switch_observation(9, 42, 50);
        malformed[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(event.dispatch_tracepoint(TracepointId::SchedSwitch, &malformed, generation), Ok(false));
        assert_eq!(event.dispatch_tracepoint(TracepointId::SchedSwitch, &switch_observation(9, 42, 50), generation), Ok(true));
        assert_eq!(event.runtime_counters().invalid, 3);
        assert_eq!(prog.run_cnt(), 1);
    }

    #[test]
    fn runtime_ioctl_period_restarts_at_the_control_clock() {
        let event = PerfEvent::new(PerfEventSpec {
            clock: PerfEventClock::CpuClock,
            scope: PerfEventScope::PerCpu { cpu: 10 }, sample_period: 10, disabled: false, cloexec: false,
        }, 0);
        let prog = dummy_prog(BpfProgType::PerfEvent);
        event.attach_program(prog.clone()).unwrap();
        assert_eq!(event.dispatch_sample(&runtime_observation(10, 10, 42)), Ok(true));
        event.ioctl_at(PERF_EVENT_IOC_PERIOD, 20, 100).unwrap();
        assert_eq!(event.dispatch_sample(&runtime_observation(119, 10, 42)), Ok(false));
        assert_eq!(event.dispatch_sample(&runtime_observation(120, 10, 42)), Ok(true));
        assert_eq!(prog.run_cnt(), 2);
        assert_eq!(event.runtime_counters().skipped_periods, 0);
    }


    #[test]
    fn runtime_tracepoint_parallel_attachment_counts_preserve_live_subscribers() {
        use pulse_bpf_schema::TracepointId;
        use std::sync::Barrier;
        let id = TracepointId::PhaseMarker;
        let initial = tracepoint_subscriber_count_for_test(id);
        let ready = Barrier::new(5);
        let release = Barrier::new(5);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let ready = &ready; let release = &release;
                scope.spawn(move || {
                    let event = dummy_perf_event(PerfEventClock::Tracepoint(id));
                    let prog = dummy_prog(BpfProgType::Tracepoint);
                    for _ in 0..100 {
                        event.attach_program(prog.clone()).unwrap();
                        event.detach_program(&prog).unwrap();
                    }
                    event.attach_program(prog).unwrap();
                    ready.wait();
                    release.wait();
                    // Drop tears down the final attachment using the same path.
                });
            }
            ready.wait();
            assert_eq!(tracepoint_subscriber_count_for_test(id), initial + 4);
            release.wait();
        });
        assert_eq!(tracepoint_subscriber_count_for_test(id), initial);
    }


    #[test]
    fn runtime_task_identity_survives_exec_tid_rebinding_without_sampling_reused_tid() {
        let event = PerfEvent::new(PerfEventSpec {
            clock: PerfEventClock::TaskClock,
            scope: PerfEventScope::Task { pid: 42 }, sample_period: 10, disabled: false, cloexec: false,
        }, 100);
        let prog = dummy_prog(BpfProgType::PerfEvent);
        event.attach_program(prog.clone()).unwrap();
        let mut before_bind = runtime_observation(1_000, 10, 42);
        before_bind.task_id = 901;
        before_bind.task_clock_ns = 110;
        assert_eq!(event.bind_task_identity(0), Err(LinuxError::EINVAL));
        event.bind_task_identity(901).unwrap();
        assert_eq!(event.dispatch_sample(&before_bind), Ok(false), "binding invalidates old queued observations");
        let mut replacement = runtime_observation(1_000, 10, 42);
        replacement.task_id = 902; // A different thread now has the old numeric TID.
        replacement.task_clock_ns = 9_000;
        assert_eq!(event.dispatch_sample(&replacement), Ok(false));
        let mut same_thread = runtime_observation(1_010, 11, 100); // exec changed this thread's TID.
        same_thread.task_id = 901;
        same_thread.task_clock_ns = 110;
        assert_eq!(event.dispatch_sample(&same_thread), Ok(true));
        let generation = observation_generation();
        event.bind_task_identity(901).unwrap();
        assert_eq!(observation_generation(), generation, "same binding is idempotent");
        assert_eq!(event.bind_task_identity(902), Err(LinuxError::EBUSY));
        assert_eq!(prog.run_cnt(), 1);
        assert_eq!(event.runtime_counters().skipped_periods, 0);
    }

    #[test]
    fn runtime_trace_task_scope_uses_bound_subject_identity_after_exec() {
        use pulse_bpf_schema::TracepointId;
        let event = PerfEvent::new(PerfEventSpec {
            clock: PerfEventClock::Tracepoint(TracepointId::SchedSwitch),
            scope: PerfEventScope::Task { pid: 42 }, sample_period: 0, disabled: false, cloexec: false,
        }, 0);
        let prog = dummy_prog(BpfProgType::Tracepoint);
        event.attach_program(prog.clone()).unwrap();
        event.bind_task_identity(901).unwrap();
        let mut reused_tid = switch_observation(9, 42, 50);
        reused_tid[32..40].copy_from_slice(&902u64.to_le_bytes());
        assert_eq!(event.dispatch_tracepoint(TracepointId::SchedSwitch, &reused_tid, observation_generation()), Ok(false));
        let mut rebound_tid = switch_observation(9, 100, 60);
        rebound_tid[32..40].copy_from_slice(&901u64.to_le_bytes());
        assert_eq!(event.dispatch_tracepoint(TracepointId::SchedSwitch, &rebound_tid, observation_generation()), Ok(true));
        assert_eq!(prog.run_cnt(), 1);
    }


    fn runtime_failure_event(clock: PerfEventClock, cpu: usize, insns: &[BpfInsn]) -> (Arc<PerfEvent>, Arc<BpfProgram>) {
        let prog_type = if matches!(clock, PerfEventClock::Tracepoint(_)) {
            BpfProgType::Tracepoint
        } else {
            BpfProgType::PerfEvent
        };
        let prog = Arc::new(BpfProgram::new(prog_type, [0; 16], Arc::from(insns), alloc::vec![]));
        let event = Arc::new(PerfEvent::new(PerfEventSpec {
            clock, scope: PerfEventScope::PerCpu { cpu }, sample_period: 10, disabled: false, cloexec: false,
        }, 0));
        event.attach_program(prog.clone()).unwrap();
        (event, prog)
    }

    fn dispatch_failure_observation(event: &PerfEvent, time: u64, cpu: usize) -> Result<bool, LinuxError> {
        match event.spec().clock {
            PerfEventClock::Tracepoint(id) => event.dispatch_tracepoint(id,
                &switch_observation(cpu as u32, 42, time), observation_generation()),
            _ => event.dispatch_sample(&runtime_observation(time, cpu, 42)),
        }
    }

    #[test]
    fn runtime_sample_and_tracepoint_budget_failures_are_not_delivered() {
        for clock in [PerfEventClock::CpuClock, PerfEventClock::Tracepoint(pulse_bpf_schema::TracepointId::SchedSwitch)] {
            // Direct VM model fixture: the production verifier rejects this
            // loop, while runtime must still enforce its independent step cap.
            let (event, prog) = runtime_failure_event(clock, 13, &[
                BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
                BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, -1, 0),
            ]);
            assert_eq!(dispatch_failure_observation(&event, 10, 13), Ok(false));
            let expected = PerfEventSampleCounters {
                delivered_samples: 0, re_entry_drops: 0, helper_failures: 0, budget_failures: 1,
            };
            assert_eq!(event.sample_counters(), expected);
            assert_eq!(prog.sample_counters(), expected);
            assert_eq!(prog.run_cnt(), 1);
            assert_eq!(event.runtime_counters().observed, 1);
            assert_eq!(event.runtime_counters().invalid, 0);
            assert!(!is_in_sampling(13), "failed execution releases its sampling guard");
        }
    }

    #[test]
    fn runtime_sample_and_tracepoint_helper_failures_are_not_delivered() {
        for clock in [PerfEventClock::CpuClock, PerfEventClock::Tracepoint(pulse_bpf_schema::TracepointId::SchedSwitch)] {
            let (event, prog) = runtime_failure_event(clock, 13, &[
                BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, 9999),
                BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
            ]);
            assert_eq!(dispatch_failure_observation(&event, 10, 13), Ok(false));
            let expected = PerfEventSampleCounters {
                delivered_samples: 0, re_entry_drops: 0, helper_failures: 1, budget_failures: 0,
            };
            assert_eq!(event.sample_counters(), expected);
            assert_eq!(prog.sample_counters(), expected);
            assert_eq!(prog.run_cnt(), 1);
            assert_eq!(event.runtime_counters().invalid, 0);
            assert!(!is_in_sampling(13));
        }
    }

    #[test]
    fn runtime_sample_and_tracepoint_reentry_is_counted_without_running_program() {
        struct ResetSamplingCpu(usize);
        impl Drop for ResetSamplingCpu {
            fn drop(&mut self) { set_in_sampling_for_test(self.0, false); }
        }
        for clock in [PerfEventClock::CpuClock, PerfEventClock::Tracepoint(pulse_bpf_schema::TracepointId::SchedSwitch)] {
            let (event, prog) = runtime_failure_event(clock, 13, &[
                BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
                BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
            ]);
            assert!(!is_in_sampling(13));
            set_in_sampling_for_test(13, true);
            let reset = ResetSamplingCpu(13);
            assert_eq!(dispatch_failure_observation(&event, 10, 13), Ok(false));
            let expected = PerfEventSampleCounters {
                delivered_samples: 0, re_entry_drops: 1, helper_failures: 0, budget_failures: 0,
            };
            assert_eq!(event.sample_counters(), expected);
            assert_eq!(prog.sample_counters(), expected);
            assert_eq!(prog.run_cnt(), 0);
            drop(reset);
            assert_eq!(dispatch_failure_observation(&event, 20, 13), Ok(true));
            assert_eq!(event.sample_counters().delivered_samples, 1);
            assert_eq!(prog.run_cnt(), 1);
        }
    }

    #[test]
    fn runtime_detach_allows_only_the_already_accepted_program_to_finish() {
        use core_map::{BpfMap, BpfMapCreateRequest, BpfMapSpec, PerfEventOutputSink};
        use std::sync::{Mutex, mpsc::{channel, Sender, Receiver}};
        use std::time::Duration;

        // Pause through the public output-sink interface, not an internal
        // dispatcher hook: control changes happen while accepted BPF is running.
        struct PausingSink {
            entered: Sender<()>,
            resume: Mutex<Receiver<()>>,
        }
        impl PerfEventOutputSink for PausingSink {
            fn output_sample(&self, data: &[u8]) -> Result<(), LinuxError> {
                assert_eq!(data.len(), 4);
                self.entered.send(()).map_err(|_| LinuxError::EINVAL)?;
                self.resume.lock().unwrap().recv_timeout(Duration::from_secs(5))
                    .map_err(|_| LinuxError::EINVAL)?;
                Ok(())
            }
            fn as_any(&self) -> &dyn core::any::Any { self }
        }

        for clock in [PerfEventClock::CpuClock, PerfEventClock::Tracepoint(pulse_bpf_schema::TracepointId::SchedSwitch)] {
            let (entered_tx, entered_rx) = channel();
            let (resume_tx, resume_rx) = channel();
            let map = Arc::new(BpfMap::create(BpfMapSpec::validate(&BpfMapCreateRequest {
                map_type: core_map::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                key_size: 4, value_size: 4, max_entries: 16, ..Default::default()
            }).unwrap()).unwrap());
            map.set_slot(13, Some(1), Some(Arc::new(PausingSink {
                entered: entered_tx, resume: Mutex::new(resume_rx),
            }))).unwrap();
            let prog_type = if matches!(clock, PerfEventClock::Tracepoint(_)) {
                BpfProgType::Tracepoint
            } else { BpfProgType::PerfEvent };
            let old_prog = Arc::new(BpfProgram::new(prog_type, [0; 16], Arc::from([
                BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_1, 0, 0),
                BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_2, BPF_PSEUDO_MAP_FD, 0, 0),
                BpfInsn::new(0, 0, 0, 0, 0),
                BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_3, 0, 0, -1),
                BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_4, BPF_REG_6, 0, 0),
                BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_5, 0, 0, 4),
                BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_PERF_EVENT_OUTPUT),
                BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
            ]), alloc::vec![map]));
            let event = Arc::new(PerfEvent::new(PerfEventSpec {
                clock, scope: PerfEventScope::PerCpu { cpu: 13 }, sample_period: 10, disabled: false, cloexec: false,
            }, 0));
            event.attach_program(old_prog.clone()).unwrap();
            let new_prog = dummy_prog(prog_type);
            std::thread::scope(|scope| {
                let event_ref = &event;
                let in_flight = scope.spawn(move || dispatch_failure_observation(event_ref, 10, 13));
                entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                assert_eq!(event.diagnostics().inflight, 1);
                event.disable_at(10);
                let stopped = event.diagnostics();
                assert!(!stopped.enabled);
                assert_eq!(stopped.inflight, 1, "disable cannot hide an accepted invocation");
                event.detach_program(&old_prog).unwrap();
                event.attach_program(new_prog.clone()).unwrap();
                assert_eq!(new_prog.run_cnt(), 0);
                resume_tx.send(()).unwrap();
                assert_eq!(in_flight.join().unwrap(), Ok(true));
            });
            assert_eq!(old_prog.run_cnt(), 1);
            assert_eq!(old_prog.sample_counters().delivered_samples, 1);
            assert_eq!(new_prog.run_cnt(), 0, "reattach cannot steal an accepted invocation");
            assert_eq!(event.diagnostics().inflight, 0);
            event.enable_at(10);
            assert_eq!(dispatch_failure_observation(&event, 20, 13), Ok(true));
            assert_eq!(new_prog.run_cnt(), 1);
            assert_eq!(old_prog.run_cnt(), 1);
        }
    }

    #[test]
    fn runtime_stop_counts_old_queue_cancellation_but_not_new_disabled_observations() {
        let event = PerfEvent::new(PerfEventSpec {
            clock: PerfEventClock::CpuClock, scope: PerfEventScope::PerCpu { cpu: 10 },
            sample_period: 10, disabled: false, cloexec: false,
        }, 0);
        event.attach_program(dummy_prog(BpfProgType::PerfEvent)).unwrap();
        let queued = runtime_observation(10, 10, 1);
        event.disable_at(11);
        assert_eq!(event.dispatch_sample(&queued), Ok(false));
        assert_eq!(event.runtime_counters().cancelled, 1);
        for time in [20, 30, 40] {
            assert_eq!(event.dispatch_sample(&runtime_observation(time, 10, 1)), Ok(false));
        }
        assert_eq!(event.runtime_counters().cancelled, 1);
        let snapshot = event.diagnostics();
        assert!(!snapshot.enabled);
        assert_eq!(snapshot.inflight, 0);
        assert_eq!(snapshot.samples.delivered_samples, 0);
        assert_ne!(snapshot.id, 0);
    }

}
