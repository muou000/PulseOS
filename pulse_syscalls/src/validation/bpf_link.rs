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
}
