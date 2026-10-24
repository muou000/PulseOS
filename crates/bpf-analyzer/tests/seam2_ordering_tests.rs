use bpf_analyzer::CaptureAnalyzer;
use bpf_capture::framing::CaptureArch;
use bpf_capture::record::NormalizedRecord;
use bpf_capture::schema::SchemaRegistry;
use bpf_capture::session::{CaptureScope, SessionConfig};
use bpf_capture::writer::CaptureWriter;
use pulse_bpf_schema::{
    ContextCommon, PhaseBoundary, PhaseMarkerContext, SchedSwitchContext, TaskMetadataContext,
    TracepointId,
};

fn create_test_config() -> SessionConfig {
    SessionConfig {
        pulse_commit: String::from("11223344556677889900aabbccddeeff00112233"),
        target_arch: CaptureArch::Riscv64,
        kernel_elf_path: String::from("PulseOS_riscv64-qemu-virt.elf"),
        kernel_elf_hash: String::from("sha256:1111"),
        image_path: String::from("sdcard-rv.img"),
        image_hash: String::from("sha256:2222"),
        libbpf_fixture_version: String::from("v1.0"),
        prog_id: 1,
        map_id: 2,
        link_id: 3,
        perf_event_id: 4,
        output_path: String::from("test.bin"),
        scope: CaptureScope::AllCpus,
        sample_period: 100_000,
        buffer_pages: 4,
        clock_name: String::from("monotonic"),
        clock_res_ns: 1,
    }
}

#[test]
fn test_cross_cpu_out_of_order_records_merged_monotonically() {
    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(create_test_config(), registry);
    writer.start(1_000_000).unwrap();

    // Ingest out-of-order records simulating separate CPU Perf Buffers:
    // CPU 0 delivers at t=100 and t=300
    // CPU 1 delivers at t=200 and t=400
    // Raw arrival: [t=100 (cpu0), t=300 (cpu0), t=200 (cpu1), t=400 (cpu1)]
    let sched_c0_1 = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 100, 0, 10, 10, 1),
        prev_task_id: 1,
        next_task_id: 2,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    let rec1 = NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
        core::slice::from_raw_parts(&sched_c0_1 as *const _ as *const u8, core::mem::size_of_val(&sched_c0_1))
    })
    .unwrap();
    writer.write_record(rec1).unwrap();

    let sched_c0_2 = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 300, 0, 10, 10, 2),
        prev_task_id: 2,
        next_task_id: 1,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    let rec2 = NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
        core::slice::from_raw_parts(&sched_c0_2 as *const _ as *const u8, core::mem::size_of_val(&sched_c0_2))
    })
    .unwrap();
    writer.write_record(rec2).unwrap();

    let sched_c1_1 = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 200, 1, 20, 20, 3),
        prev_task_id: 3,
        next_task_id: 4,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    let rec3 = NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
        core::slice::from_raw_parts(&sched_c1_1 as *const _ as *const u8, core::mem::size_of_val(&sched_c1_1))
    })
    .unwrap();
    writer.write_record(rec3).unwrap();

    let sched_c1_2 = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 400, 1, 20, 20, 4),
        prev_task_id: 4,
        next_task_id: 3,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    let rec4 = NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
        core::slice::from_raw_parts(&sched_c1_2 as *const _ as *const u8, core::mem::size_of_val(&sched_c1_2))
    })
    .unwrap();
    writer.write_record(rec4).unwrap();

    let bytes = writer.finish(2_000_000).unwrap();
    let analyzer = CaptureAnalyzer::from_bytes(&bytes).unwrap();

    // Check that raw records are in insertion order
    assert_eq!(analyzer.records().len(), 4);
    assert_eq!(analyzer.records()[0].timestamp_ns, 100);
    assert_eq!(analyzer.records()[1].timestamp_ns, 300);
    assert_eq!(analyzer.records()[2].timestamp_ns, 200);
    assert_eq!(analyzer.records()[3].timestamp_ns, 400);

    // Anchor A2: Host aggregation must merge by record timestamp rather than raw arrival order
    let ordered = analyzer.ordered_events();
    assert_eq!(ordered.len(), 4);
    assert_eq!(ordered[0].timestamp_ns, 100);
    assert_eq!(ordered[0].cpu_id, 0);
    assert_eq!(ordered[1].timestamp_ns, 200);
    assert_eq!(ordered[1].cpu_id, 1);
    assert_eq!(ordered[2].timestamp_ns, 300);
    assert_eq!(ordered[2].cpu_id, 0);
    assert_eq!(ordered[3].timestamp_ns, 400);
    assert_eq!(ordered[3].cpu_id, 1);
}

#[test]
fn test_task_comm_mapping_from_metadata() {
    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(create_test_config(), registry);
    writer.start(1_000_000).unwrap();

    // 1. TaskMetadata registering comm "worker_thread" for task 42
    let mut comm = [0u8; 16];
    comm[..13].copy_from_slice(b"worker_thread");
    let meta = TaskMetadataContext {
        common: ContextCommon::new(TracepointId::TaskMetadata, 100, 0, 10, 10, 42),
        target_task_id: 42,
        target_pid: 10,
        target_tid: 10,
        comm,
    };
    let rec1 = NormalizedRecord::from_tracepoint_slice(TracepointId::TaskMetadata as u32, unsafe {
        core::slice::from_raw_parts(&meta as *const _ as *const u8, core::mem::size_of_val(&meta))
    })
    .unwrap();
    writer.write_record(rec1).unwrap();

    // 2. SchedSwitch referencing task 42 at t=200
    let sched = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 200, 0, 10, 10, 42),
        prev_task_id: 42,
        next_task_id: 99,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    let rec2 = NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
        core::slice::from_raw_parts(&sched as *const _ as *const u8, core::mem::size_of_val(&sched))
    })
    .unwrap();
    writer.write_record(rec2).unwrap();

    let bytes = writer.finish(2_000_000).unwrap();
    let analyzer = CaptureAnalyzer::from_bytes(&bytes).unwrap();

    let events = analyzer.ordered_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].comm.as_deref(), Some("worker_thread"));
}

#[test]
fn test_phase_marker_window_filtering() {
    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(create_test_config(), registry);
    writer.start(1_000_000).unwrap();

    // Event before phase at t=50
    let sched0 = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 50, 0, 1, 1, 1),
        prev_task_id: 1,
        next_task_id: 2,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    writer
        .write_record(
            NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
                core::slice::from_raw_parts(&sched0 as *const _ as *const u8, core::mem::size_of_val(&sched0))
            })
            .unwrap(),
        )
        .unwrap();

    // PhaseMarker Begin "BENCHMARK" at t=100
    let mut phase_name = [0u8; 16];
    phase_name[..9].copy_from_slice(b"BENCHMARK");
    let p_begin = PhaseMarkerContext {
        common: ContextCommon::new(TracepointId::PhaseMarker, 100, 0, 1, 1, 1),
        phase_boundary: PhaseBoundary::Begin as u32,
        phase_len: 9,
        phase_name,
    };
    writer
        .write_record(
            NormalizedRecord::from_tracepoint_slice(TracepointId::PhaseMarker as u32, unsafe {
                core::slice::from_raw_parts(&p_begin as *const _ as *const u8, core::mem::size_of_val(&p_begin))
            })
            .unwrap(),
        )
        .unwrap();

    // Event inside phase at t=150
    let sched1 = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 150, 0, 1, 1, 2),
        prev_task_id: 2,
        next_task_id: 1,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    writer
        .write_record(
            NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
                core::slice::from_raw_parts(&sched1 as *const _ as *const u8, core::mem::size_of_val(&sched1))
            })
            .unwrap(),
        )
        .unwrap();

    // PhaseMarker End "BENCHMARK" at t=200
    let p_end = PhaseMarkerContext {
        common: ContextCommon::new(TracepointId::PhaseMarker, 200, 0, 1, 1, 1),
        phase_boundary: PhaseBoundary::End as u32,
        phase_len: 9,
        phase_name,
    };
    writer
        .write_record(
            NormalizedRecord::from_tracepoint_slice(TracepointId::PhaseMarker as u32, unsafe {
                core::slice::from_raw_parts(&p_end as *const _ as *const u8, core::mem::size_of_val(&p_end))
            })
            .unwrap(),
        )
        .unwrap();

    // Event after phase at t=250
    let sched2 = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 250, 0, 1, 1, 1),
        prev_task_id: 1,
        next_task_id: 2,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    writer
        .write_record(
            NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
                core::slice::from_raw_parts(&sched2 as *const _ as *const u8, core::mem::size_of_val(&sched2))
            })
            .unwrap(),
        )
        .unwrap();

    let bytes = writer.finish(2_000_000).unwrap();
    let analyzer = CaptureAnalyzer::from_bytes(&bytes).unwrap();

    let all_events = analyzer.ordered_events();
    assert_eq!(all_events.len(), 5);

    let phase_events = analyzer.events_in_phase("BENCHMARK");
    // Should include the phase marker begin/end and events inside: t=100, t=150, t=200
    assert_eq!(phase_events.len(), 3);
    assert_eq!(phase_events[0].timestamp_ns, 100);
    assert_eq!(phase_events[1].timestamp_ns, 150);
    assert_eq!(phase_events[2].timestamp_ns, 200);
}
