use bpf_analyzer::CaptureAnalyzer;
use bpf_capture::framing::CaptureArch;
use bpf_capture::record::NormalizedRecord;
use bpf_capture::schema::SchemaRegistry;
use bpf_capture::session::{CaptureScope, SessionConfig};
use bpf_capture::writer::CaptureWriter;
use pulse_bpf_schema::{
    ContextCommon, SchedSwitchContext, TaskBlockContext, TaskMetadataContext, TaskWakeContext,
    TracepointId,
};

fn create_test_config() -> SessionConfig {
    SessionConfig {
        pulse_commit: String::from("abcdef0123456789abcdef0123456789abcdef01"),
        target_arch: CaptureArch::Riscv64,
        kernel_elf_path: String::from("PulseOS_riscv64-qemu-virt.elf"),
        kernel_elf_hash: String::from("sha256:3333"),
        image_path: String::from("sdcard-rv.img"),
        image_hash: String::from("sha256:4444"),
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
fn test_sched_switch_on_cpu_duration_tracking() {
    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(create_test_config(), registry);
    writer.start(1_000_000).unwrap();

    // Task 1 metadata: "task_one"
    let mut comm1 = [0u8; 16];
    comm1[..8].copy_from_slice(b"task_one");
    let meta1 = TaskMetadataContext {
        common: ContextCommon::new(TracepointId::TaskMetadata, 1_000, 0, 10, 10, 1),
        target_task_id: 1,
        target_pid: 10,
        target_tid: 10,
        comm: comm1,
    };
    writer
        .write_record(
            NormalizedRecord::from_tracepoint_slice(TracepointId::TaskMetadata as u32, unsafe {
                core::slice::from_raw_parts(&meta1 as *const _ as *const u8, core::mem::size_of_val(&meta1))
            })
            .unwrap(),
        )
        .unwrap();

    // At t=10_000, switch from Task 1 to Task 2 on CPU 0
    let sw1 = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 10_000, 0, 10, 10, 1),
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
                core::slice::from_raw_parts(&sw1 as *const _ as *const u8, core::mem::size_of_val(&sw1))
            })
            .unwrap(),
        )
        .unwrap();

    // At t=25_000, switch from Task 2 to Task 1 on CPU 0 (Task 2 ran for 15_000 ns)
    let sw2 = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 25_000, 0, 10, 10, 2),
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
                core::slice::from_raw_parts(&sw2 as *const _ as *const u8, core::mem::size_of_val(&sw2))
            })
            .unwrap(),
        )
        .unwrap();

    // At t=40_000, switch from Task 1 to Task 3 on CPU 0 (Task 1 ran for 15_000 ns)
    let sw3 = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 40_000, 0, 10, 10, 1),
        prev_task_id: 1,
        next_task_id: 3,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    writer
        .write_record(
            NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
                core::slice::from_raw_parts(&sw3 as *const _ as *const u8, core::mem::size_of_val(&sw3))
            })
            .unwrap(),
        )
        .unwrap();

    let bytes = writer.finish(2_000_000).unwrap();
    let analyzer = CaptureAnalyzer::from_bytes(&bytes).unwrap();

    let stats = analyzer.aggregate_statistics();
    let t1_stat = stats.task_stats.get(&1).expect("Task 1 stats must exist");
    assert_eq!(t1_stat.comm.as_deref(), Some("task_one"));
    assert_eq!(t1_stat.on_cpu_time_ns, 15_000);

    let t2_stat = stats.task_stats.get(&2).expect("Task 2 stats must exist");
    assert_eq!(t2_stat.on_cpu_time_ns, 15_000);

    let cpu0_stat = stats.cpu_stats.get(&0).expect("CPU 0 stats must exist");
    assert_eq!(cpu0_stat.context_switches, 3);
}

#[test]
fn test_task_block_and_wake_off_cpu_pairing() {
    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(create_test_config(), registry);
    writer.start(1_000_000).unwrap();

    // Task 50 blocks at t=100_000 with block_sequence = 1, wait_reason = 3
    let block = TaskBlockContext {
        common: ContextCommon::new(TracepointId::TaskBlock, 100_000, 0, 50, 50, 50),
        block_sequence: 1,
        wait_reason: 3,
        _pad: 0,
        resource_id: 1001,
        resource_detail: 2002,
    };
    writer
        .write_record(
            NormalizedRecord::from_tracepoint_slice(TracepointId::TaskBlock as u32, unsafe {
                core::slice::from_raw_parts(&block as *const _ as *const u8, core::mem::size_of_val(&block))
            })
            .unwrap(),
        )
        .unwrap();

    // Task 50 is switched out at t=101_000
    let sw = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 101_000, 0, 50, 50, 50),
        prev_task_id: 50,
        next_task_id: 0,
        prev_state: 1,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    writer
        .write_record(
            NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
                core::slice::from_raw_parts(&sw as *const _ as *const u8, core::mem::size_of_val(&sw))
            })
            .unwrap(),
        )
        .unwrap();

    // Task 50 is woken by Task 10 at t=150_000 with block_sequence = 1 (duration = 50_000 ns)
    let wake = TaskWakeContext {
        common: ContextCommon::new(TracepointId::TaskWake, 150_000, 1, 10, 10, 10),
        target_task_id: 50,
        block_sequence: 1,
        waker_task_id: 10,
        wake_source: 1,
        _pad: 0,
        source_id: 999,
    };
    writer
        .write_record(
            NormalizedRecord::from_tracepoint_slice(TracepointId::TaskWake as u32, unsafe {
                core::slice::from_raw_parts(&wake as *const _ as *const u8, core::mem::size_of_val(&wake))
            })
            .unwrap(),
        )
        .unwrap();

    let bytes = writer.finish(2_000_000).unwrap();
    let analyzer = CaptureAnalyzer::from_bytes(&bytes).unwrap();

    let stats = analyzer.aggregate_statistics();
    let t50_stat = stats.task_stats.get(&50).expect("Task 50 stats");
    assert_eq!(t50_stat.block_count, 1);
    assert_eq!(t50_stat.wake_count, 1);
    assert_eq!(t50_stat.off_cpu_wait_ns, 50_000);

    assert_eq!(stats.off_cpu_intervals.len(), 1);
    let interval = &stats.off_cpu_intervals[0];
    assert_eq!(interval.task_id, 50);
    assert_eq!(interval.wait_reason, 3);
    assert_eq!(interval.start_ns, 100_000);
    assert_eq!(interval.end_ns, 150_000);
    assert_eq!(interval.duration_ns, 50_000);
    assert_eq!(interval.waker_task_id, 10);
}

#[test]
fn test_unpaired_events_handled_gracefully() {
    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(create_test_config(), registry);
    writer.start(1_000_000).unwrap();

    // 1. Orphan wake without prior block (e.g. task blocked before sampling began)
    let wake = TaskWakeContext {
        common: ContextCommon::new(TracepointId::TaskWake, 200_000, 0, 1, 1, 1),
        target_task_id: 77,
        block_sequence: 999,
        waker_task_id: 1,
        wake_source: 2,
        _pad: 0,
        source_id: 0,
    };
    writer
        .write_record(
            NormalizedRecord::from_tracepoint_slice(TracepointId::TaskWake as u32, unsafe {
                core::slice::from_raw_parts(&wake as *const _ as *const u8, core::mem::size_of_val(&wake))
            })
            .unwrap(),
        )
        .unwrap();

    // 2. Orphan block without subsequent wake (e.g. task still waiting when session ends)
    let block = TaskBlockContext {
        common: ContextCommon::new(TracepointId::TaskBlock, 300_000, 0, 88, 88, 88),
        block_sequence: 42,
        wait_reason: 5,
        _pad: 0,
        resource_id: 123,
        resource_detail: 456,
    };
    writer
        .write_record(
            NormalizedRecord::from_tracepoint_slice(TracepointId::TaskBlock as u32, unsafe {
                core::slice::from_raw_parts(&block as *const _ as *const u8, core::mem::size_of_val(&block))
            })
            .unwrap(),
        )
        .unwrap();

    let bytes = writer.finish(2_000_000).unwrap();
    let analyzer = CaptureAnalyzer::from_bytes(&bytes).unwrap();

    // Aggregation should not panic and should record unpaired events
    let stats = analyzer.aggregate_statistics();
    assert_eq!(stats.unpaired_wakes, 1);
    assert_eq!(stats.unpaired_blocks, 1);
    // No completed paired off-cpu intervals for these orphaned events
    assert_eq!(stats.off_cpu_intervals.len(), 0);
}
