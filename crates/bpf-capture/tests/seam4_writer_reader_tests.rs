mod support;
use bpf_capture::framing::{CaptureArch, CaptureError, SessionStatusCode};
use bpf_capture::reader::CaptureReader;
use bpf_capture::record::NormalizedRecord;
use bpf_capture::schema::SchemaRegistry;
use bpf_capture::session::{CaptureScope, SessionConfig};
use bpf_capture::writer::{CaptureWriter, NativeContextFormat, PERF_RECORD_LOST, PERF_RECORD_SAMPLE};
use pulse_bpf_schema::{ContextCommon, SchedSwitchContext, TaskMetadataContext, TracepointId};

fn test_config() -> SessionConfig {
    SessionConfig {
        pulse_commit: String::from("0123456789abcdef0123456789abcdef01234567"),
        target_arch: CaptureArch::Riscv64,
        kernel_elf_path: String::from("PulseOS_riscv64-qemu-virt.elf"),
        kernel_elf_hash: String::from("sha256:abcd1234"),
        image_path: String::from("sdcard-rv.img"),
        image_hash: String::from("sha256:5678ef01"),
        libbpf_fixture_version: String::from("v1.0.0-pulse-fixture"),
        prog_id: 1,
        map_id: 2,
        link_id: 3,
        perf_event_id: 4,
        output_path: String::from("bpf_capture.bin"),
        scope: CaptureScope::AllCpus,
        sample_period: 100_000,
        buffer_pages: 4,
        clock_name: String::from("monotonic"),
        clock_res_ns: 1,
    }
}

#[test]
fn test_capture_without_runtime_diagnostics_stays_partial() {
    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(test_config(), registry.clone());
    writer.configure_recorder(vec![support::trace(1, 2, 0, 1_000_000, 2_000_000), support::trace(2, 1, 1, 1_000_000, 2_000_000), support::trace(3, 2, 3, 1_000_000, 2_000_000)], 4096).unwrap();
    writer.start(1_000_000).expect("start should succeed");

    // Write a sched_switch record
    let sched_ctx = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 1_000_100, 0, 10, 10, 1),
        prev_task_id: 1,
        next_task_id: 2,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    let rec1 = NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
        core::slice::from_raw_parts(&sched_ctx as *const _ as *const u8, core::mem::size_of_val(&sched_ctx))
    })
    .unwrap();
    writer.write_record_from(1, rec1.clone()).unwrap();

    // Write a task_metadata record
    let meta_ctx = TaskMetadataContext {
        common: ContextCommon::new(TracepointId::TaskMetadata, 1_000_200, 1, 20, 20, 2),
        target_task_id: 2,
        target_pid: 20,
        target_tid: 20,
        comm: *b"worker\0\0\0\0\0\0\0\0\0\0",
    };
    let rec2 = NormalizedRecord::from_tracepoint_slice(TracepointId::TaskMetadata as u32, unsafe {
        core::slice::from_raw_parts(&meta_ctx as *const _ as *const u8, core::mem::size_of_val(&meta_ctx))
    })
    .unwrap();
    writer.write_record_from(2, rec2.clone()).unwrap();

    // Finish a session with no runtime diagnostics
    let file_bytes = writer.finish(2_000_000).expect("finish should succeed");
    assert!(!file_bytes.is_empty());

    // Read back and validate
    let capture = CaptureReader::from_bytes(&file_bytes).expect("reader should validate capture");
    assert_eq!(capture.header.format_version, 6);
    assert_eq!(capture.header.target_arch, CaptureArch::Riscv64);
    assert_eq!(capture.metadata.status, SessionStatusCode::IncompleteError);
    assert_eq!(capture.metadata.start_ns, 1_000_000);
    assert_eq!(capture.metadata.stop_ns, 2_000_000);
    assert_eq!(capture.metadata.counters.attempted, 2);
    assert_eq!(capture.metadata.counters.delivered, 2);
    assert_eq!(capture.records.len(), 2);
    assert_eq!(capture.records[0], rec1);
    assert_eq!(capture.records[1], rec2);
}

#[test]
fn test_capture_round_trip_with_perf_buffer_ingestion_and_loss() {
    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(test_config(), registry);
    writer.configure_recorder(vec![support::trace(1, 2, 1, 5_000_000, 6_000_000)], 4096).unwrap();
    writer.start(5_000_000).unwrap();

    // Simulate PerfRecord::Sample payload
    let sched_ctx = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 5_000_500, 1, 30, 30, 3),
        prev_task_id: 3,
        next_task_id: 4,
        prev_state: 1,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    let raw_sched_bytes = unsafe {
        core::slice::from_raw_parts(&sched_ctx as *const _ as *const u8, core::mem::size_of_val(&sched_ctx))
    };
    // Ingest sample
    writer.ingest_perf_sample_as(1, 1, raw_sched_bytes, NativeContextFormat::Tracepoint).unwrap();

    // Ingest lost counter on CPU 1 (5 lost events)
    writer.ingest_perf_lost(1, 5);

    // Finish session
    let file_bytes = writer.finish(6_000_000).unwrap();

    let capture = CaptureReader::from_bytes(&file_bytes).expect("reader should validate capture with loss");
    // Missing diagnostics stays partial; observed loss counts are preserved.
    assert_eq!(capture.metadata.status, SessionStatusCode::IncompleteError);
    assert_eq!(capture.trailer.status_code, SessionStatusCode::IncompleteError);
    assert_eq!(capture.metadata.counters.lost_records_total, 5);
    assert_eq!(capture.metadata.counters.get_cpu_lost(1), 5);
    assert_eq!(capture.metadata.counters.delivered, 1);
    assert_eq!(capture.metadata.counters.attempted, 6); // 1 delivered + 5 lost
    assert_eq!(capture.records.len(), 1);
}

#[test]
fn test_ingest_raw_perf_frame_sample_and_lost() {
    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(test_config(), registry);
    writer.configure_recorder(vec![support::trace(1, 2, 2, 10_000_000, 20_000_000), support::trace(2, 2, 0, 10_000_000, 20_000_000)], 4096).unwrap();
    writer.start(10_000_000).unwrap();

    // 1. Ingest raw PERF_RECORD_SAMPLE frame:
    // Header + 72-byte RAW payload + 4-byte padding: size=88, raw_len=72
    let sched_ctx = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 10_000_100, 2, 40, 40, 4),
        prev_task_id: 4,
        next_task_id: 5,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    let sched_bytes = unsafe {
        core::slice::from_raw_parts(&sched_ctx as *const _ as *const u8, core::mem::size_of_val(&sched_ctx))
    };

    let mut sample_frame = vec![0u8; (12 + sched_bytes.len() + 7) & !7];
    sample_frame[0..4].copy_from_slice(&PERF_RECORD_SAMPLE.to_ne_bytes());
    sample_frame[4..6].copy_from_slice(&0u16.to_ne_bytes());
    let frame_len = sample_frame.len() as u16;
    sample_frame[6..8].copy_from_slice(&frame_len.to_ne_bytes());
    sample_frame[8..12].copy_from_slice(&(sched_bytes.len() as u32).to_ne_bytes());
    sample_frame[12..12 + sched_bytes.len()].copy_from_slice(sched_bytes);

    writer.ingest_raw_perf_frame_as(1, 2, &sample_frame, NativeContextFormat::Tracepoint).expect("raw sample frame should ingest");

    // 2. Ingest raw PERF_RECORD_LOST frame:
    // Header (8 bytes: event_type=2, misc=0, size=24), id=2 (8 bytes), lost=8 (8 bytes)
    let mut lost_frame = vec![0u8; 24];
    lost_frame[0..4].copy_from_slice(&PERF_RECORD_LOST.to_ne_bytes());
    lost_frame[4..6].copy_from_slice(&0u16.to_ne_bytes());
    lost_frame[6..8].copy_from_slice(&24u16.to_ne_bytes());
    lost_frame[8..16].copy_from_slice(&2u64.to_ne_bytes()); // id = CPU 2
    lost_frame[16..24].copy_from_slice(&8u64.to_ne_bytes()); // lost = 8

    writer.ingest_raw_perf_frame_as(1, 2, &lost_frame, NativeContextFormat::Tracepoint).expect("raw lost frame should ingest");

    let file_bytes = writer.finish(20_000_000).unwrap();
    let capture = CaptureReader::from_bytes(&file_bytes).unwrap();

    assert_eq!(capture.records.len(), 1);
    assert_eq!(capture.records[0].cpu_id, 2);
    assert_eq!(capture.metadata.counters.delivered, 1);
    assert_eq!(capture.metadata.counters.lost_records_total, 8);
    assert_eq!(capture.metadata.counters.get_cpu_lost(2), 8);
    assert_eq!(capture.metadata.status, SessionStatusCode::IncompleteError);
}

#[test]
fn test_capture_corruption_detection() {
    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(test_config(), registry);
    writer.configure_recorder(vec![support::trace(1, 2, 0, 1_000, 2_000)], 4096).unwrap();
    writer.start(1_000).unwrap();
    let file_bytes = writer.finish(2_000).unwrap();

    // 1. Truncation at header
    let truncated_hdr = &file_bytes[..40];
    let err = CaptureReader::from_bytes(truncated_hdr).unwrap_err();
    assert_eq!(err, CaptureError::TruncatedHeader);

    // 2. Corrupted checksum
    let mut corrupted_bytes = file_bytes.clone();
    corrupted_bytes[30] ^= 0x55;
    let err = CaptureReader::from_bytes(&corrupted_bytes).unwrap_err();
    assert!(matches!(err, CaptureError::ChecksumMismatch { .. }));

    // 3. Truncated trailer
    let truncated_trl = &file_bytes[..file_bytes.len() - 10];
    let err = CaptureReader::from_bytes(truncated_trl).unwrap_err();
    assert!(matches!(err, CaptureError::TruncatedTrailer | CaptureError::InvalidTrailerOffset));
}

#[test]
fn test_capture_ringbuf_sample_and_loss_ingestion() {
    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(test_config(), registry);
    writer.configure_recorder(vec![support::trace(1, 2, 0, 1_000_000, 2_000_000), support::trace(2, 1, 1, 1_000_000, 2_000_000), support::trace(3, 2, 3, 1_000_000, 2_000_000)], 4096).unwrap();
    writer.start(1_000_000).unwrap();

    let sched_ctx = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 1_000_100, 3, 50, 50, 5),
        prev_task_id: 5,
        next_task_id: 6,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    let raw_sched_bytes = unsafe {
        core::slice::from_raw_parts(&sched_ctx as *const _ as *const u8, core::mem::size_of_val(&sched_ctx))
    };

    // Ingest ringbuf sample (same normalized format as perf sample)
    writer.ingest_ringbuf_sample(3, 3, raw_sched_bytes, NativeContextFormat::Tracepoint).unwrap();

    // Ingest ringbuf loss (e.g., 12 records dropped due to full ring buffer)
    writer.ingest_ringbuf_lost(12);

    let file_bytes = writer.finish(2_000_000).unwrap();
    let capture = CaptureReader::from_bytes(&file_bytes).expect("reader must parse ringbuf capture");

    assert_eq!(capture.metadata.status, SessionStatusCode::IncompleteError);
    assert_eq!(capture.trailer.status_code, SessionStatusCode::IncompleteError);
    assert_eq!(capture.metadata.counters.ringbuf_lost, 12);
    assert_eq!(capture.metadata.counters.delivered, 1);
    assert_eq!(capture.metadata.counters.attempted, 13);
    assert_eq!(capture.records.len(), 1);
    assert_eq!(capture.records[0].cpu_id, 3);
}

#[test]
fn test_ingest_raw_ringbuf_frame_sample_and_discard() {
    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(test_config(), registry);
    writer.configure_recorder(vec![support::trace(1, 2, 2, 10_000_000, 20_000_000), support::trace(2, 2, 0, 10_000_000, 20_000_000)], 4096).unwrap();
    writer.start(10_000_000).unwrap();

    let sched_ctx = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 10_000_500, 0, 10, 10, 1),
        prev_task_id: 1,
        next_task_id: 2,
        prev_state: 1,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    let raw_sched_bytes = unsafe {
        core::slice::from_raw_parts(&sched_ctx as *const _ as *const u8, core::mem::size_of_val(&sched_ctx))
    };

    // 1. Construct raw ringbuf frame: 8-byte header (len: u32, pg_off: u32) + payload
    let mut valid_frame = Vec::new();
    let payload_len = raw_sched_bytes.len() as u32;
    valid_frame.extend_from_slice(&payload_len.to_ne_bytes());
    valid_frame.extend_from_slice(&0u32.to_ne_bytes()); // pg_off
    valid_frame.extend_from_slice(raw_sched_bytes);
    writer.ingest_raw_ringbuf_frame(2, 0, &valid_frame, NativeContextFormat::Tracepoint).unwrap();

    // 2. Construct discarded ringbuf frame: DISCARD bit (bit 30) set
    let mut discard_frame = Vec::new();
    let discard_len = 16u32 | (1 << 30);
    discard_frame.extend_from_slice(&discard_len.to_ne_bytes());
    discard_frame.extend_from_slice(&0u32.to_ne_bytes());
    discard_frame.extend_from_slice(&[0u8; 16]);
    writer.ingest_raw_ringbuf_frame(2, 0, &discard_frame, NativeContextFormat::Tracepoint).unwrap();

    // 3. Busy frame: BUSY bit (bit 31) set -> should return Err(TruncatedRecord)
    let mut busy_frame = Vec::new();
    let busy_len = 16u32 | (1 << 31);
    busy_frame.extend_from_slice(&busy_len.to_ne_bytes());
    busy_frame.extend_from_slice(&0u32.to_ne_bytes());
    busy_frame.extend_from_slice(&[0u8; 16]);
    assert!(writer.ingest_raw_ringbuf_frame(2, 0, &busy_frame, NativeContextFormat::Tracepoint).is_err());

    let file_bytes = writer.finish(20_000_000).unwrap();
    let capture = CaptureReader::from_bytes(&file_bytes).expect("reader parse");

    assert_eq!(capture.records.len(), 1);
    assert_eq!(capture.metadata.counters.delivered, 1);
    assert_eq!(capture.metadata.counters.discarded_records, 1);
    assert_eq!(capture.metadata.status, SessionStatusCode::IncompleteError);
}
