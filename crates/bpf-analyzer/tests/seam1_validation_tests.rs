use bpf_analyzer::{AnalyzerError, CaptureAnalyzer};
use bpf_capture::fixture::generate_deterministic_fixture;
use bpf_capture::framing::{CaptureArch, CaptureError, SessionStatusCode, CAPTURE_HEADER_SIZE};

#[test]
fn test_valid_capture_ingestion_and_integrity_check() {
    let bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete)
        .expect("generate fixture");

    let analyzer = CaptureAnalyzer::from_bytes(&bytes).expect("analyzer should parse valid capture");
    assert!(analyzer.is_complete(), "clean capture must be marked complete");
    assert_eq!(analyzer.status_code(), SessionStatusCode::Complete);
    assert_eq!(analyzer.target_arch(), CaptureArch::Riscv64);
    assert_eq!(analyzer.header().records_count, 2);
    assert_eq!(analyzer.records().len(), 2);
    assert!(!analyzer.loss_counters().has_loss_or_error());
    assert_eq!(analyzer.loss_counters().lost_records_total, 0);
    assert!(analyzer.attribution_claim_allowed(), "clean capture allows attribution claim");
}

#[test]
fn test_malformed_trailer_magic_rejected() {
    let mut bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete)
        .expect("generate fixture");

    // Corrupt the trailer magic at the end
    let len = bytes.len();
    bytes[len - 40..len - 32].copy_from_slice(b"BADMAGIC");

    let err = CaptureAnalyzer::from_bytes(&bytes).expect_err("bad trailer magic must fail");
    assert_eq!(err, AnalyzerError::Capture(CaptureError::BadTrailerMagic));
}

#[test]
fn test_checksum_mismatch_rejected() {
    let mut bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete)
        .expect("generate fixture");

    // Corrupt a byte in the metadata region
    bytes[CAPTURE_HEADER_SIZE + 5] ^= 0xFF;

    let err = CaptureAnalyzer::from_bytes(&bytes).expect_err("corrupted byte must trigger checksum mismatch");
    assert!(matches!(err, AnalyzerError::Capture(CaptureError::ChecksumMismatch { .. })));
}

#[test]
fn test_schema_mismatch_rejected() {
    let bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete)
        .expect("generate fixture");
    let hdr = bpf_capture::framing::CaptureHeader::from_bytes(&bytes).unwrap();

    let mut tampered = bytes.clone();
    let rec_start = hdr.records_offset as usize;
    tampered[rec_start + 4] = 99; // mutate schema_version to 99

    let trailer_offset = hdr.trailer_offset as usize;
    let new_crc = bpf_capture::framing::compute_checksum(&tampered[..trailer_offset]);
    tampered[trailer_offset + 24..trailer_offset + 28].copy_from_slice(&new_crc.to_le_bytes());

    let err = CaptureAnalyzer::from_bytes(&tampered).expect_err("schema mismatch must be rejected");
    assert_eq!(
        err,
        AnalyzerError::Capture(CaptureError::SchemaMismatch {
            expected: 1,
            actual: 99
        })
    );
}

#[test]
fn test_truncated_input_rejected() {
    let bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete)
        .expect("generate fixture");

    let err = CaptureAnalyzer::from_bytes(&bytes[..CAPTURE_HEADER_SIZE - 10])
        .expect_err("truncated header must fail");
    assert_eq!(err, AnalyzerError::Capture(CaptureError::TruncatedHeader));
}

#[test]
fn test_nonzero_loss_capture_flagged_incomplete() {
    let bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::IncompleteLoss)
        .expect("generate lossy fixture");

    let analyzer = CaptureAnalyzer::from_bytes(&bytes)
        .expect("analyzer should parse lossy capture without panic");

    assert!(!analyzer.is_complete(), "lossy capture must NOT be marked complete");
    assert_eq!(analyzer.status_code(), SessionStatusCode::IncompleteLoss);
    assert!(analyzer.loss_counters().has_loss());
    assert_eq!(analyzer.loss_counters().lost_records_total, 7);
    assert_eq!(analyzer.loss_counters().get_cpu_lost(0), 5);
    assert_eq!(analyzer.loss_counters().get_cpu_lost(1), 2);
    // Anchor A3 / #88: incomplete or lossy captures cannot claim complete attribution
    assert!(!analyzer.attribution_claim_allowed(), "lossy capture cannot make complete attribution claim");
}

#[test]
fn test_incomplete_error_flagged_incomplete() {
    let bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::IncompleteError)
        .expect("generate error fixture");

    let analyzer = CaptureAnalyzer::from_bytes(&bytes)
        .expect("analyzer should parse error capture without panic");

    assert!(!analyzer.is_complete(), "error capture must NOT be marked complete");
    assert_eq!(analyzer.status_code(), SessionStatusCode::IncompleteError);
    assert!(analyzer.loss_counters().has_loss_or_error());
    assert!(!analyzer.attribution_claim_allowed());
}

#[test]
fn test_nonzero_ringbuf_loss_capture_flagged_incomplete() {
    use bpf_capture::schema::SchemaRegistry;
    use bpf_capture::session::{CaptureScope, SessionConfig};
    use bpf_capture::writer::CaptureWriter;
    use pulse_bpf_schema::{ContextCommon, SchedSwitchContext, TracepointId};

    let config = SessionConfig {
        pulse_commit: String::from("49ad1424deadbeef0123456789abcdef01234567"),
        target_arch: CaptureArch::Riscv64,
        kernel_elf_path: String::from("PulseOS_riscv64-qemu-virt.elf"),
        kernel_elf_hash: String::from("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        image_path: String::from("sdcard-rv.img"),
        image_hash: String::from("sha256:ca978112ca1bbdcafac231b39a23dc4da7860814965409b5416f65f356071a14"),
        libbpf_fixture_version: String::from("v1.0.0-pulse-fixture"),
        prog_id: 10,
        map_id: 27,
        link_id: 30,
        perf_event_id: 0,
        output_path: String::from("records/ringbuf_loss_capture.bin"),
        scope: CaptureScope::AllCpus,
        sample_period: 0,
        buffer_pages: 4,
        clock_name: String::from("monotonic"),
        clock_res_ns: 1,
    };

    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(config, registry);
    writer.start(1_000_000_000).unwrap();

    let sched = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 1_000_100_000, 0, 100, 100, 1),
        prev_task_id: 1,
        next_task_id: 2,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    let sched_bytes = unsafe {
        core::slice::from_raw_parts(&sched as *const _ as *const u8, core::mem::size_of_val(&sched))
    };
    writer.ingest_ringbuf_sample(0, sched_bytes).unwrap();
    writer.ingest_ringbuf_lost(5);

    let bytes = writer.finish(2_000_000_000).unwrap();
    let analyzer = CaptureAnalyzer::from_bytes(&bytes)
        .expect("analyzer should parse ringbuf lossy capture without panic");

    assert!(!analyzer.is_complete(), "ringbuf loss capture must NOT be marked complete");
    assert_eq!(analyzer.status_code(), SessionStatusCode::IncompleteLoss);
    assert!(analyzer.loss_counters().has_loss());
    assert_eq!(analyzer.loss_counters().ringbuf_lost, 5);
    assert_eq!(analyzer.loss_counters().delivered, 1);
    assert_eq!(analyzer.loss_counters().attempted, 6);
    assert!(!analyzer.attribution_claim_allowed(), "ringbuf loss capture cannot make complete attribution claim");

    // Events are still parsed and accessible with transport neutrality
    let events = analyzer.ordered_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].cpu_id, 0);
}
