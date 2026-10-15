use bpf_capture::fixture::generate_deterministic_fixture;
use bpf_capture::framing::{
    CaptureArch, CaptureError, SessionStatusCode, CAPTURE_HEADER_SIZE,
};
use bpf_capture::reader::CaptureReader;
use bpf_capture::record::NormalizedRecord;
use bpf_capture::schema::SchemaRegistry;
use bpf_capture::session::{CaptureScope, SessionConfig};
use bpf_capture::writer::CaptureWriter;
use pulse_bpf_schema::{ContextCommon, SchedSwitchContext, TaskBlockContext, TracepointId};

fn deterministic_session_config() -> SessionConfig {
    SessionConfig {
        pulse_commit: String::from("49ad1424deadbeef"),
        target_arch: CaptureArch::Riscv64,
        kernel_elf_path: String::from("PulseOS_riscv64-qemu-virt.elf"),
        kernel_elf_hash: String::from("sha256:1122334455667788"),
        image_path: String::from("sdcard-rv.img"),
        image_hash: String::from("sha256:9988776655443322"),
        libbpf_fixture_version: String::from("v1.0.0-pulse-fixture"),
        prog_id: 101,
        map_id: 202,
        link_id: 303,
        perf_event_id: 404,
        output_path: String::from("records/deterministic_capture.bin"),
        scope: CaptureScope::AllCpus,
        sample_period: 100_000,
        buffer_pages: 4,
        clock_name: String::from("monotonic"),
        clock_res_ns: 1,
    }
}

/// Acceptance Criterion 1:
/// Capture round trip validates header, schema, records, counts, checksum/hash and trailer.
#[test]
fn acceptance_test_deterministic_fixture_round_trip() {
    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(deterministic_session_config(), registry.clone());
    writer.start(1_000_000).expect("start session");

    // 1. SchedSwitch record
    let sched = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 1_000_100, 0, 100, 100, 10),
        prev_task_id: 10,
        next_task_id: 20,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    let rec1 = NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
        core::slice::from_raw_parts(&sched as *const _ as *const u8, core::mem::size_of_val(&sched))
    })
    .unwrap();
    writer.write_record(rec1.clone()).unwrap();

    // 2. TaskBlock record
    let block = TaskBlockContext {
        common: ContextCommon::new(TracepointId::TaskBlock, 1_000_200, 1, 200, 200, 20),
        block_sequence: 1,
        wait_reason: 2,
        _pad: 0,
        resource_id: 42,
        resource_detail: 84,
    };
    let rec2 = NormalizedRecord::from_tracepoint_slice(TracepointId::TaskBlock as u32, unsafe {
        core::slice::from_raw_parts(&block as *const _ as *const u8, core::mem::size_of_val(&block))
    })
    .unwrap();
    writer.write_record(rec2.clone()).unwrap();

    let bytes = writer.finish(2_000_000).expect("finish capture");

    // Validate capture reader
    let capture = CaptureReader::from_bytes(&bytes).expect("round trip validation must pass");
    assert_eq!(capture.header.records_count, 2);
    assert_eq!(capture.records.len(), 2);
    assert_eq!(capture.records[0], rec1);
    assert_eq!(capture.records[1], rec2);
    assert_eq!(capture.trailer.status_code, SessionStatusCode::Complete);
    assert_eq!(capture.metadata.status, SessionStatusCode::Complete);
    assert_eq!(capture.metadata.config.image_path, "sdcard-rv.img");
    assert_eq!(capture.metadata.counters.attempted, 2);
    assert_eq!(capture.metadata.counters.delivered, 2);
    assert_eq!(capture.metadata.counters.lost_records_total, 0);
}

/// Acceptance Criterion 2:
/// Truncated, mismatched or lossy input is explicitly incomplete/error.
#[test]
fn acceptance_test_truncated_mismatched_and_lossy_inputs() {
    let registry = SchemaRegistry::default_pulse_registry();

    // Case A: Lossy input preserves IncompleteLoss status rather than producing a complete-looking artifact
    {
        let mut writer = CaptureWriter::new(deterministic_session_config(), registry.clone());
        writer.start(1_000_000).unwrap();
        writer.ingest_perf_lost(0, 7);
        writer.ingest_perf_lost(1, 3);
        let bytes = writer.finish(2_000_000).unwrap();

        let capture = CaptureReader::from_bytes(&bytes).unwrap();
        assert_eq!(capture.metadata.status, SessionStatusCode::IncompleteLoss);
        assert_eq!(capture.trailer.status_code, SessionStatusCode::IncompleteLoss);
        assert_eq!(capture.metadata.counters.lost_records_total, 10);
        assert_eq!(capture.metadata.counters.get_cpu_lost(0), 7);
        assert_eq!(capture.metadata.counters.get_cpu_lost(1), 3);
    }

    // Case B: Truncated header
    {
        let mut writer = CaptureWriter::new(deterministic_session_config(), registry.clone());
        writer.start(1_000).unwrap();
        let bytes = writer.finish(2_000).unwrap();
        let err = CaptureReader::from_bytes(&bytes[..CAPTURE_HEADER_SIZE - 8]).unwrap_err();
        assert_eq!(err, CaptureError::TruncatedHeader);
    }

    // Case C: Checksum mismatch (corrupted byte in metadata stream)
    {
        let mut writer = CaptureWriter::new(deterministic_session_config(), registry.clone());
        writer.start(1_000).unwrap();
        let mut bytes = writer.finish(2_000).unwrap();
        bytes[CAPTURE_HEADER_SIZE + 10] ^= 0xAA;
        let err = CaptureReader::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, CaptureError::ChecksumMismatch { .. }));
    }

    // Case D: Record-count mismatch
    {
        let mut writer = CaptureWriter::new(deterministic_session_config(), registry.clone());
        writer.start(1_000).unwrap();
        let sched = SchedSwitchContext {
            common: ContextCommon::new(TracepointId::SchedSwitch, 1_100, 0, 10, 10, 1),
            prev_task_id: 1,
            next_task_id: 2,
            prev_state: 0,
            prev_prio: 120,
            next_prio: 120,
            _pad: 0,
        };
        let rec = NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
            core::slice::from_raw_parts(&sched as *const _ as *const u8, core::mem::size_of_val(&sched))
        })
        .unwrap();
        writer.write_record(rec).unwrap();
        let mut bytes = writer.finish(2_000).unwrap();

        // Tamper with records_count in header (bytes 48..56)
        bytes[48] = 99;
        let err = CaptureReader::from_bytes(&bytes).unwrap_err();
        assert_eq!(err, CaptureError::RecordCountMismatch { expected: 1, actual: 99 });
    }

    // Case E: Schema mismatch in capture file
    {
        let mut writer = CaptureWriter::new(deterministic_session_config(), registry.clone());
        writer.start(1_000).unwrap();
        let sched = SchedSwitchContext {
            common: ContextCommon::new(TracepointId::SchedSwitch, 1_100, 0, 10, 10, 1),
            prev_task_id: 1,
            next_task_id: 2,
            prev_state: 0,
            prev_prio: 120,
            next_prio: 120,
            _pad: 0,
        };
        let rec = NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
            core::slice::from_raw_parts(&sched as *const _ as *const u8, core::mem::size_of_val(&sched))
        })
        .unwrap();
        writer.write_record(rec.clone()).unwrap();

        // Deliberately tamper with record schema version in stream
        let file_bytes = writer.finish(2_000).unwrap();
        let hdr = bpf_capture::framing::CaptureHeader::from_bytes(&file_bytes).unwrap();
        let mut tampered = file_bytes.clone();
        let rec_start = hdr.records_offset as usize;
        // offset 4..8 in record is schema_version
        tampered[rec_start + 4] = 99; // mutate schema_version to 99

        // Recompute trailer checksum so it bypasses checksum validation and exercises schema validation
        let trailer_offset = hdr.trailer_offset as usize;
        let new_crc = bpf_capture::framing::compute_checksum(&tampered[..trailer_offset]);
        tampered[trailer_offset + 24..trailer_offset + 28].copy_from_slice(&new_crc.to_le_bytes());

        let err = CaptureReader::from_bytes(&tampered).unwrap_err();
        assert_eq!(err, CaptureError::SchemaMismatch { expected: 1, actual: 99 });
    }
}

/// Acceptance Criterion 3 & 4:
/// Deterministic fixture generation across RISC-V64 and LoongArch64, stable for T13 and T14.
#[test]
fn acceptance_test_deterministic_fixture_generator_dual_arch() {
    // 1. RISC-V64 Complete fixture
    let rv_complete = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete)
        .expect("RV64 fixture generation");
    let rv_cap = CaptureReader::from_bytes(&rv_complete).expect("RV64 capture read");
    assert_eq!(rv_cap.header.target_arch, CaptureArch::Riscv64);
    assert_eq!(rv_cap.metadata.status, SessionStatusCode::Complete);
    assert_eq!(rv_cap.records.len(), 2);
    assert_eq!(rv_cap.metadata.config.image_path, "sdcard-rv.img");

    // 2. LoongArch64 Complete fixture
    let la_complete = generate_deterministic_fixture(CaptureArch::LoongArch64, SessionStatusCode::Complete)
        .expect("LA64 fixture generation");
    let la_cap = CaptureReader::from_bytes(&la_complete).expect("LA64 capture read");
    assert_eq!(la_cap.header.target_arch, CaptureArch::LoongArch64);
    assert_eq!(la_cap.metadata.status, SessionStatusCode::Complete);
    assert_eq!(la_cap.records.len(), 2);
    assert_eq!(la_cap.metadata.config.image_path, "sdcard-la.img");

    // 3. Lossy fixture preserves IncompleteLoss
    let rv_lossy = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::IncompleteLoss)
        .expect("RV64 lossy fixture generation");
    let lossy_cap = CaptureReader::from_bytes(&rv_lossy).expect("RV64 lossy capture read");
    assert_eq!(lossy_cap.metadata.status, SessionStatusCode::IncompleteLoss);
    assert_eq!(lossy_cap.trailer.status_code, SessionStatusCode::IncompleteLoss);
    assert_eq!(lossy_cap.metadata.counters.lost_records_total, 7);
}
