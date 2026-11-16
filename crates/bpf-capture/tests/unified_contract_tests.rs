use bpf_capture::{CaptureArch, CaptureReader, CaptureScope, CaptureWriter, RecorderKind,
    RecorderSource, SchemaRegistry, SessionConfig};
use bpf_capture::recorder::{SourceClock, SourceConfig, SourceFallback, SourceUnit};
use pulse_bpf_schema::{PerfEventContext, PerfSampleContext};

fn writer() -> CaptureWriter {
    CaptureWriter::new(SessionConfig {
        pulse_commit: "test".into(), target_arch: CaptureArch::Riscv64,
        kernel_elf_path: "unknown".into(), kernel_elf_hash: "unknown".into(),
        image_path: "unknown".into(), image_hash: "unknown".into(),
        libbpf_fixture_version: "test".into(), prog_id: 0, map_id: 0, link_id: 0,
        perf_event_id: 0, output_path: "test".into(), scope: CaptureScope::PerCpu(3),
        sample_period: 10, buffer_pages: 1, clock_name: "monotonic".into(), clock_res_ns: 1,
    }, SchemaRegistry::default_pulse_registry())
}
fn source(id: u32) -> RecorderSource {
    RecorderSource {
        id, kind: RecorderKind::SoftwareStackV3, event_id: 0x1002, schema_version: 3,
        scope: CaptureScope::PerCpu(3), bound_task_id: 0, sample_period: 10,
        kernel_event_id: 100 + id as u64, program_id: 2, link_id: 200 + id,
        enable_before_ns: 110, enable_after_ns: 120, disable_before_ns: 250, disable_after_ns: 260,
        clock: SourceClock::Monotonic, requested_config: SourceConfig::CpuClock,
        config: SourceConfig::CpuClock, requested_sample_period: 10,
        requested_frequency_hz: 0, effective_frequency_hz: 0,
        requested_buffer_pages: 1, effective_buffer_pages: 1,
        unit: SourceUnit::Nanoseconds, fallback: SourceFallback::None,
    }
}
fn stack(kernel_id: u64) -> bpf_capture::NormalizedRecord {
    let mut raw = [0u8; 640];
    raw[..64].copy_from_slice(&PerfSampleContext {
        base: PerfEventContext::new(10, 0, 200, 3, 40, 41, 99),
        ip: 0x400110, mode: 2, version: 2,
    }.to_bytes());
    for (offset, value) in [(64,kernel_id),(72,0x8000),(80,0x8020),(88,0x400220),(96,19)] {
        raw[offset..offset+8].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [(104,3u16),(106,32),(108,3),(110,4)] {
        raw[offset..offset+2].copy_from_slice(&value.to_le_bytes());
    }
    raw[112..116].copy_from_slice(&32u32.to_le_bytes());
    raw[116..120].copy_from_slice(&512u32.to_le_bytes());
    for (index, ip) in [0x400110u64,0x400220,0x400330].iter().enumerate() {
        raw[128+index*8..136+index*8].copy_from_slice(&ip.to_le_bytes());
    }
    bpf_capture::NormalizedRecord::from_software_stack_v3_slice(&raw).unwrap()
}
fn mappings() -> bpf_capture::mapping::MappingMetadata {
    bpf_capture::mapping::MappingMetadata {
        journal: "PULSE_BPF_MAPPINGS version=2 available=1 started_ns=0 snapshot_ns=500 dropped=0 records=0\nEND records=0 dropped=0 snapshot_ns=500\n".into(),
        artifacts: vec![], kernel: None,
    }
}
#[test]
fn source_stack_mapping_coexist_with_distinct_logical_and_kernel_ids() {
    let mut w = writer();
    w.set_mappings(mappings()).unwrap();
    w.configure_recorder(vec![source(7),source(8)], 4096).unwrap();
    w.start(100).unwrap();
    assert!(w.write_record_from(7, stack(107)).unwrap());
    assert!(w.write_record_from(8, stack(108)).unwrap());
    let capture = CaptureReader::from_bytes(&w.finish(300).unwrap()).unwrap();
    assert_eq!(capture.header.format_version, 6);
    assert_eq!(capture.recorder.as_ref().unwrap().record_sources, [7,8]);
    assert_eq!(capture.recorder.as_ref().unwrap().sources, [source(7),source(8)]);
    assert_eq!(capture.records[0].software_stack_v3().unwrap().source_id, 107);
    assert_eq!(capture.mappings, Some(mappings()));
    assert!(!capture.metadata.status.is_complete());
}

#[test]
fn missing_unknown_and_duplicate_bindings_are_rejected() {
    let mut unconfigured = writer();
    unconfigured.start(100).unwrap();
    assert!(unconfigured.write_record_from(7, stack(107)).is_err());
    assert!(unconfigured.finish(300).is_err());
    let mut duplicate = writer();
    assert!(duplicate.configure_recorder(vec![source(7), source(7)], 4096).is_err());
    let mut duplicate_kernel = source(8);
    duplicate_kernel.kernel_event_id = 107;
    assert!(writer().configure_recorder(vec![source(7), duplicate_kernel],4096).is_err());
    let mut w = writer();
    w.configure_recorder(vec![source(7)],4096).unwrap();
    w.start(100).unwrap();
    assert!(w.write_record_from(8,stack(107)).is_err());
    assert!(w.write_record_from(7,stack(108)).is_err());
    let capture = CaptureReader::from_bytes(&w.finish(300).unwrap()).unwrap();
    assert_eq!(capture.metadata.counters.consumer_corrupt_records,2);
    assert!(capture.records.is_empty());
}

#[test]
fn native_records_cannot_bypass_identity_checks_as_custom_records() {
    for id in [1,0x1000,0x1001,0x1002] {
        let mut declaration = source(7);
        declaration.event_id = id;
        declaration.kind = RecorderKind::Normalized;
        declaration.config = SourceConfig::Custom;
        declaration.requested_config = SourceConfig::Custom;
        declaration.unit = SourceUnit::Events;
        assert!(writer().configure_recorder(vec![declaration],4096).is_err());
    }
}

#[test]
fn declared_kind_schema_parameters_and_final_windows_are_validated() {
    let original = source(7);
    let mut wrong_kind = original.clone(); wrong_kind.kind = RecorderKind::SoftwareV2;
    let mut wrong_schema = original.clone(); wrong_schema.schema_version = 2;
    let mut wrong_unit = original.clone(); wrong_unit.unit = SourceUnit::Events;
    let mut wrong_request = original.clone(); wrong_request.requested_frequency_hz = 100;
    let mut wrong_fallback = original.clone(); wrong_fallback.fallback = SourceFallback::HardwareUnavailable;
    for bad in [wrong_kind,wrong_schema,wrong_unit,wrong_request,wrong_fallback] {
        assert!(writer().configure_recorder(vec![bad],4096).is_err());
    }
    let mut bad_window = original.clone(); bad_window.disable_after_ns=301;
    let mut w=writer(); w.configure_recorder(vec![bad_window],4096).unwrap(); w.start(100).unwrap();
    assert!(w.finish(300).is_err());
    assert!(w.is_running(), "invalid final window must not consume the session");
    w.update_recorder_source(original).unwrap();
    assert!(w.finish(300).is_ok());
}

#[test]
fn retention_budget_counts_bindings_and_loss_once() {
    let mut w=writer();
    // 48 normalized header + 608 stack payload + 4 logical source binding.
    w.configure_recorder(vec![source(7)],660).unwrap();
    w.start(100).unwrap();
    assert!(w.write_record_from(7,stack(107)).unwrap());
    assert!(!w.write_record_from(7,stack(107)).unwrap());
    w.ingest_perf_lost(3,2);
    let capture=CaptureReader::from_bytes(&w.finish(300).unwrap()).unwrap();
    assert_eq!(capture.records.len(),1);
    assert_eq!(capture.recorder.unwrap().record_sources,[7]);
    assert_eq!(capture.metadata.counters.discarded_records,1);
    assert_eq!(capture.metadata.counters.lost_records_total,2);
    assert_eq!(capture.metadata.counters.get_cpu_lost(3),2);
    assert_eq!(capture.metadata.counters.delivered,1);
    assert_eq!(capture.metadata.counters.attempted,3);
    assert!(!capture.metadata.status.is_complete());
}

fn capture_bytes() -> Vec<u8> {
    let mut w=writer(); w.configure_recorder(vec![source(7)],4096).unwrap(); w.start(100).unwrap();
    w.write_record_from(7,stack(107)).unwrap(); w.finish(300).unwrap()
}
fn repair_crc(bytes: &mut [u8]) {
    let trailer=u64::from_le_bytes(bytes[64..72].try_into().unwrap()) as usize;
    let crc=bpf_capture::framing::compute_checksum_ieee(&bytes[..trailer]);
    bytes[trailer+24..trailer+28].copy_from_slice(&crc.to_le_bytes());
}
#[test]
fn unsupported_containers_extensions_corruption_and_missing_trailers_fail_closed() {
    let good=capture_bytes();
    for version in [1u32,2,3,4,5,7] {
        let mut bad=good.clone();bad[8..12].copy_from_slice(&version.to_le_bytes());
        assert!(matches!(CaptureReader::from_bytes(&bad),Err(bpf_capture::CaptureError::UnsupportedFormatVersion(v)) if v==version));
    }
    let header=bpf_capture::CaptureHeader::from_bytes(&good).unwrap();
    for flags in [0u64,1,4,13,u64::MAX] {
        let mut bad=good.clone();let at=header.records_offset as usize-8;
        bad[at..at+8].copy_from_slice(&flags.to_le_bytes());repair_crc(&mut bad);
        assert!(CaptureReader::from_bytes(&bad).is_err());
    }
    assert!(CaptureReader::from_bytes(&good[..good.len()-40]).is_err());
    let mut bad=good.clone();bad[header.records_offset as usize+8]^=1;
    assert!(matches!(CaptureReader::from_bytes(&bad),Err(bpf_capture::CaptureError::ChecksumMismatch{..})));
}

#[test]
fn task_source_preserves_stable_identity_and_hardware_fallback() {
    let mut declaration=source(7);
    declaration.scope=CaptureScope::Task(41);declaration.bound_task_id=99;
    declaration.requested_config=SourceConfig::HardwareCycles;
    declaration.config=SourceConfig::TaskClock;
    declaration.fallback=SourceFallback::HardwareUnavailable;
    declaration.requested_sample_period=0;declaration.requested_frequency_hz=100;
    let mut w=writer();w.configure_recorder(vec![declaration.clone()],4096).unwrap();w.start(100).unwrap();
    let mut record=stack(107);record.tid=42;
    assert!(w.write_record_from(7,record.clone()).unwrap(),"numeric TID may change while stable task remains bound");
    record.task_id=100;assert!(w.write_record_from(7,record).is_err());
    let capture=CaptureReader::from_bytes(&w.finish(300).unwrap()).unwrap();
    assert_eq!(capture.recorder.unwrap().sources,[declaration]);
    assert!(capture.mappings.is_none());
}

#[test]
fn cpu_task_scheduler_fault_and_mixed_sessions_share_one_container_contract() {
    use pulse_bpf_schema::{ContextCommon, PageFaultContext, PageFaultOrigin, PageFaultOutcome, TracepointId};
    let cpu = source(7);
    let mut task=source(8);task.scope=CaptureScope::Task(41);task.bound_task_id=99;
    task.config=SourceConfig::TaskClock;task.requested_config=SourceConfig::TaskClock;
    let trace = |id,event| RecorderSource {
        kind: RecorderKind::Tracepoint,event_id:event,schema_version:1,sample_period:1,
        requested_sample_period:1,config:SourceConfig::Tracepoint,requested_config:SourceConfig::Tracepoint,
        unit:SourceUnit::Events,..source(id)
    };
    let sched=trace(9,TracepointId::SchedSwitch as u32);
    let fault=trace(10,TracepointId::PageFault as u32);
    let mut scheduler_payload=vec![0;32];
    scheduler_payload[..8].copy_from_slice(&99u64.to_le_bytes());
    scheduler_payload[8..16].copy_from_slice(&100u64.to_le_bytes());
    let sched_record=bpf_capture::NormalizedRecord::new(TracepointId::SchedSwitch as u32,1,200,3,40,41,99,scheduler_payload);
    let fault_raw=PageFaultContext::from_completion(
        ContextCommon::new(TracepointId::PageFault,200,3,40,41,99),0x400000,150,2,
        PageFaultOrigin::User,PageFaultOutcome::NotHandled).unwrap().to_bytes();
    let fault_record=bpf_capture::NormalizedRecord::from_tracepoint_slice(TracepointId::PageFault as u32,&fault_raw).unwrap();
    let declarations=[cpu,task,sched,fault];
    let records=[stack(107),stack(108),sched_record,fault_record];
    for selection in [vec![0],vec![1],vec![2],vec![3],vec![0,1,2,3]] {
        let mut w=writer();
        w.configure_recorder(selection.iter().map(|&i|declarations[i].clone()).collect(),4096).unwrap();
        w.set_mappings(mappings()).unwrap();w.start(100).unwrap();
        for &i in &selection { assert!(w.write_record_from(declarations[i].id,records[i].clone()).unwrap()); }
        let capture=CaptureReader::from_bytes(&w.finish(300).unwrap()).unwrap();
        assert_eq!(capture.header.format_version,6);
        assert_eq!(capture.records,selection.iter().map(|&i|records[i].clone()).collect::<Vec<_>>());
        assert_eq!(capture.recorder.unwrap().record_sources,selection.iter().map(|&i|declarations[i].id).collect::<Vec<_>>());
        assert_eq!(capture.mappings,Some(mappings()));
    }
}

#[test]
fn zero_sample_declarations_still_require_registered_matching_schema() {
    let mut configured=writer();configured.configure_recorder(vec![source(7)],4096).unwrap();configured.start(100).unwrap();
    let config=CaptureReader::from_bytes(&configured.finish(300).unwrap()).unwrap().metadata.config;
    let mut registry=SchemaRegistry::default_pulse_registry();
    let mut schema=registry.lookup(0x1002).unwrap().clone();schema.payload_size=1;registry.register(schema);
    let mut w=CaptureWriter::new(config,registry);
    assert!(w.configure_recorder(vec![source(7)],4096).is_err());
}

#[test]
fn software_clock_and_scope_coupling_is_checked_at_declaration_and_read_boundaries() {
    let mut cpu_clock_on_task = source(7);
    cpu_clock_on_task.scope = CaptureScope::Task(41);
    cpu_clock_on_task.bound_task_id = 99;
    let mut task_clock_on_cpu = source(7);
    task_clock_on_cpu.config = SourceConfig::TaskClock;
    task_clock_on_cpu.requested_config = SourceConfig::TaskClock;
    for invalid_source in [cpu_clock_on_task, task_clock_on_cpu] {
        assert!(writer().configure_recorder(vec![invalid_source], 4096).is_err());
    }

    let good = capture_bytes();
    let source_row = good.windows(8).position(|bytes| bytes == b"PBSRC003").unwrap() + 24;
    let mut cpu_clock_on_task = good.clone();
    cpu_clock_on_task[source_row + 16..source_row + 20].copy_from_slice(&2u32.to_le_bytes());
    cpu_clock_on_task[source_row + 24..source_row + 32].copy_from_slice(&41u64.to_le_bytes());
    cpu_clock_on_task[source_row + 88..source_row + 96].copy_from_slice(&99u64.to_le_bytes());
    let mut task_clock_on_cpu = good;
    task_clock_on_cpu[source_row + 100..source_row + 104].copy_from_slice(&2u32.to_le_bytes());
    task_clock_on_cpu[source_row + 104..source_row + 108].copy_from_slice(&2u32.to_le_bytes());
    for mut invalid_capture in [cpu_clock_on_task, task_clock_on_cpu] {
        repair_crc(&mut invalid_capture);
        assert!(CaptureReader::from_bytes(&invalid_capture).is_err());
    }
}
