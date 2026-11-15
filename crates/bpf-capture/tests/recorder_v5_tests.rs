use bpf_capture::{
    CaptureArch, CaptureReader, CaptureScope, CaptureWriter, RecorderKind, RecorderSource,
    SchemaRegistry, SessionConfig, SessionStatusCode,
};
use pulse_bpf_schema::{PerfEventContext, PerfSampleContext};

fn writer() -> CaptureWriter {
    CaptureWriter::new(SessionConfig {
        pulse_commit: "unknown".into(), target_arch: CaptureArch::Riscv64,
        kernel_elf_path: "unknown".into(), kernel_elf_hash: "unknown".into(),
        image_path: "unknown".into(), image_hash: "unknown".into(),
        libbpf_fixture_version: "bpf-record-v1".into(), prog_id: 0, map_id: 0,
        link_id: 0, perf_event_id: 0, output_path: "capture.bin".into(),
        scope: CaptureScope::PerCpu(3), sample_period: 100, buffer_pages: 1,
        clock_name: "monotonic".into(), clock_res_ns: 1,
    }, SchemaRegistry::default_pulse_registry())
}

fn source(id: u32, kind: RecorderKind) -> RecorderSource {
    RecorderSource {
        id, kind, event_id: if kind == RecorderKind::SoftwareV2 { 0x1001 } else { 6 },
        schema_version: if kind == RecorderKind::SoftwareV2 { 2 } else { 1 },
        scope: CaptureScope::PerCpu(3), sample_period: if kind == RecorderKind::SoftwareV2 { 100 } else { 1 },
        kernel_event_id: 1000 + id as u64, program_id: 2000 + id, link_id: 3000 + id,
        enable_before_ns: 110, enable_after_ns: 120, disable_before_ns: 250, disable_after_ns: 260,
    }
}

fn software() -> Vec<u8> {
    PerfSampleContext {
        base: PerfEventContext::new(100, 0, 200, 3, 40, 41, 99),
        ip: 0x400110, mode: 2, version: 2,
    }.to_bytes().to_vec()
}

fn enqueue() -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(&6u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    bytes[8..16].copy_from_slice(&200u64.to_le_bytes());
    bytes[16..20].copy_from_slice(&3u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&99u64.to_le_bytes());
    bytes[40..48].copy_from_slice(&99u64.to_le_bytes());
    bytes[60..64].copy_from_slice(&2u32.to_le_bytes());
    bytes
}

fn envelope(id: u32, kind: u16, context: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x31524250u32.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(&(context.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&id.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(context);
    bytes
}

#[test]
fn mixed_equal_length_contexts_and_identical_sources_keep_explicit_bindings() {
    let mut w = writer();
    w.configure_recorder(vec![source(1, RecorderKind::SoftwareV2), source(2, RecorderKind::SoftwareV2), source(3, RecorderKind::Tracepoint)], 4096).unwrap();
    w.start(100).unwrap();
    for (id, kind, raw) in [(1, 1, software()), (3, 2, enqueue()), (2, 1, software())] {
        assert!(w.ingest_recorder_sample(3, &envelope(id, kind, &raw)).unwrap());
    }
    let bytes = w.finish(300).unwrap();
    let capture = CaptureReader::from_bytes(&bytes).unwrap();
    assert_eq!(capture.header.format_version, 5);
    assert_eq!(capture.records.iter().map(|r| r.event_id).collect::<Vec<_>>(), [0x1001, 6, 0x1001]);
    assert_eq!(capture.recorder.as_ref().unwrap().record_sources, [1, 3, 2]);
    assert_eq!(capture.recorder.unwrap().sources.len(), 3);
    assert_eq!(capture.metadata.status, SessionStatusCode::IncompleteError);
}

#[test]
fn corrupt_or_undeclared_envelopes_cannot_be_decoded_by_payload_length() {
    let valid = envelope(1, 1, &software());
    let mut invalid = Vec::new();
    for (offset, bytes) in [
        (0, 0u32.to_le_bytes().to_vec()),
        (4, 2u16.to_le_bytes().to_vec()),
        (6, 2u16.to_le_bytes().to_vec()),
        (8, 63u32.to_le_bytes().to_vec()),
        (12, 99u32.to_le_bytes().to_vec()),
        (16, 1u64.to_le_bytes().to_vec()),
    ] {
        let mut bad = valid.clone();
        bad[offset..offset + bytes.len()].copy_from_slice(&bytes);
        invalid.push(bad);
    }
    invalid.push(valid[..23].to_vec());
    invalid.push(envelope(1, 1, &enqueue()));
    for bad in invalid {
        let mut w = writer();
        w.configure_recorder(vec![source(1, RecorderKind::SoftwareV2)], 4096).unwrap();
        w.start(100).unwrap();
        assert!(w.ingest_recorder_sample(3, &bad).is_err());
        let capture = CaptureReader::from_bytes(&w.finish(300).unwrap()).unwrap();
        assert!(capture.records.is_empty());
        assert_eq!(capture.metadata.counters.consumer_corrupt_records, 1);
        assert!(!capture.metadata.status.is_complete());
    }
}

#[test]
fn bounded_retention_accounts_for_dropped_samples_and_keeps_bindings_aligned() {
    let mut w = writer();
    w.configure_recorder(vec![source(1, RecorderKind::SoftwareV2)], 84).unwrap();
    w.start(100).unwrap();
    let raw = envelope(1, 1, &software());
    assert!(w.ingest_recorder_sample(3, &raw).unwrap());
    assert!(!w.ingest_recorder_sample(3, &raw).unwrap());
    let capture = CaptureReader::from_bytes(&w.finish(300).unwrap()).unwrap();
    assert_eq!(capture.records.len(), 1);
    assert_eq!(capture.recorder.unwrap().record_sources, [1]);
    assert_eq!(capture.metadata.counters.discarded_records, 1);
    assert!(!capture.metadata.status.is_complete());
}

#[test]
fn task_identity_period_and_transport_cpu_must_match_the_declared_source() {
    for (scope, period, cpu) in [
        (CaptureScope::Task(42), 100, 3),
        (CaptureScope::PerCpu(3), 101, 3),
        (CaptureScope::PerCpu(3), 100, 2),
    ] {
        let mut declaration = source(1, RecorderKind::SoftwareV2);
        declaration.scope = scope;
        declaration.sample_period = period;
        let mut w = writer();
        w.configure_recorder(vec![declaration], 4096).unwrap();
        w.start(100).unwrap();
        assert!(w.ingest_recorder_sample(cpu, &envelope(1, 1, &software())).is_err());
    }
}

#[test]
fn measured_windows_can_be_completed_but_source_identity_cannot_change() {
    let final_source = source(1, RecorderKind::SoftwareV2);
    let mut pending = final_source.clone();
    pending.enable_before_ns = 0;
    pending.enable_after_ns = 0;
    pending.disable_before_ns = 0;
    pending.disable_after_ns = 0;
    let mut w = writer();
    w.configure_recorder(vec![pending], 4096).unwrap();
    w.start(100).unwrap();
    w.ingest_recorder_sample(3, &envelope(1, 1, &software())).unwrap();
    assert!(w.finish(300).is_err());
    let mut changed = final_source.clone();
    changed.kernel_event_id += 1;
    assert!(w.update_recorder_source(changed).is_err());
    w.update_recorder_source(final_source).unwrap();
    CaptureReader::from_bytes(&w.finish(300).unwrap()).unwrap();
}

fn bound_capture() -> Vec<u8> {
    let mut w = writer();
    w.configure_recorder(vec![source(1, RecorderKind::SoftwareV2)], 4096).unwrap();
    w.start(100).unwrap();
    w.ingest_recorder_sample(3, &envelope(1, 1, &software())).unwrap();
    w.finish(300).unwrap()
}

fn repair_checksum(bytes: &mut [u8]) {
    let trailer = u64::from_le_bytes(bytes[64..72].try_into().unwrap()) as usize;
    let crc = bpf_capture::framing::compute_checksum_ieee(&bytes[..trailer]);
    bytes[trailer + 24..trailer + 28].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn independent_reader_rejects_rebound_records_bad_windows_and_missing_required_extension() {
    let original = bound_capture();
    let metadata = original.windows(8).position(|s| s == b"PBSRC001").unwrap();
    let records = u64::from_le_bytes(original[40..48].try_into().unwrap()) as usize;
    for (offset, bytes) in [
        (metadata + 16, 2u64.to_le_bytes().to_vec()),
        (metadata + 24 + 88, 99u32.to_le_bytes().to_vec()),
        (metadata + 24 + 72, 100u64.to_le_bytes().to_vec()),
        (metadata + 24 + 80, 160u64.to_le_bytes().to_vec()),
        (records - 8, 0u64.to_le_bytes().to_vec()),
    ] {
        let mut bad = original.clone();
        bad[offset..offset + bytes.len()].copy_from_slice(&bytes);
        repair_checksum(&mut bad);
        assert!(CaptureReader::from_bytes(&bad).is_err(), "accepted mutation at {offset}");
    }
    assert!(CaptureReader::from_bytes(&original[..original.len() - 40]).is_err());
}

#[test]
fn lost_frames_and_unknown_perf_records_remain_partial() {
    let mut w = writer();
    w.configure_recorder(vec![source(1, RecorderKind::SoftwareV2)], 4096).unwrap();
    w.start(100).unwrap();
    w.ingest_recorder_sample(3, &envelope(1, 1, &software())).unwrap();
    let mut frame = vec![0u8; 24];
    frame[..4].copy_from_slice(&2u32.to_le_bytes());
    frame[6..8].copy_from_slice(&24u16.to_le_bytes());
    frame[16..24].copy_from_slice(&7u64.to_le_bytes());
    assert!(w.ingest_recorder_frame(3, &frame).unwrap());
    frame[..4].copy_from_slice(&11u32.to_le_bytes());
    assert!(w.ingest_recorder_frame(3, &frame).is_err());
    let capture = CaptureReader::from_bytes(&w.finish(300).unwrap()).unwrap();
    assert_eq!(capture.records.len(), 1);
    assert_eq!(capture.metadata.counters.get_cpu_lost(3), 7);
    assert_eq!(capture.metadata.counters.consumer_corrupt_records, 1);
    assert!(!capture.metadata.status.is_complete());
}

#[test]
fn unrelated_known_counters_cannot_certify_recorder_loss_coverage() {
    let mut w = writer();
    w.configure_recorder(vec![source(1, RecorderKind::SoftwareV2)], 4096).unwrap();
    w.set_diagnostics(bpf_capture::RuntimeDiagnostics {
        counters: vec![bpf_capture::DiagnosticCounter { name: "activity".into(), scope: "test".into(), value: Some(1), kind: bpf_capture::CounterKind::Activity }],
        identities: vec![bpf_capture::DiagnosticIdentity { name: "test".into(), value: Some("fixture".into()) }],
        phases: vec![bpf_capture::PhaseMeasurement { name: "test".into(), start_ns: 100, stop_ns: 300, iterations: 1, mapped_bytes: Some(4096) }],
        evidence_json: None,
    }).unwrap();
    w.start(100).unwrap();
    w.ingest_recorder_sample(3, &envelope(1, 1, &software())).unwrap();
    let capture = CaptureReader::from_bytes(&w.finish(300).unwrap()).unwrap();
    assert!(!capture.metadata.status.is_complete());
}
