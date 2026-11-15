use bpf_capture::writer::NativeContextFormat;
use bpf_capture::{CaptureArch, CaptureReader, CaptureScope, CaptureWriter, SchemaRegistry, SessionConfig, SessionStatusCode};
use pulse_bpf_schema::{PerfEventContext, PerfSampleContext};

fn writer() -> CaptureWriter {
    let config = SessionConfig {
        pulse_commit: "fixture-only".into(), target_arch: CaptureArch::Riscv64,
        kernel_elf_path: "kernel.elf".into(), kernel_elf_hash: "unknown".into(),
        image_path: "image".into(), image_hash: "unknown".into(),
        libbpf_fixture_version: "test-native-v2".into(), prog_id: 1, map_id: 2,
        link_id: 3, perf_event_id: 4, output_path: "capture.bin".into(),
        scope: CaptureScope::PerCpu(3), sample_period: 10_000_000, buffer_pages: 16,
        clock_name: "monotonic".into(), clock_res_ns: 1,
    };
    let mut writer = CaptureWriter::new(config, SchemaRegistry::default_pulse_registry());
    writer.start(100).unwrap();
    writer
}
fn context() -> [u8; 64] {
    PerfSampleContext {
        base: PerfEventContext::new(10_000_000, 0xdead, 200, 3, 40, 41, 99),
        ip: 0x400110, mode: 2, version: 2,
    }.to_bytes()
}
fn frame(raw: &[u8]) -> Vec<u8> {
    let size = (12 + raw.len() + 7) & !7;
    let mut frame = vec![0; size];
    frame[..4].copy_from_slice(&9u32.to_le_bytes());
    frame[6..8].copy_from_slice(&(size as u16).to_le_bytes());
    frame[8..12].copy_from_slice(&(raw.len() as u32).to_le_bytes());
    frame[12..12+raw.len()].copy_from_slice(raw);
    frame
}

#[test]
fn runtime_context_preserves_distinct_data_address_and_instruction_pointer() {
    let mut w = writer();
    w.ingest_raw_perf_frame_as(3, &frame(&context()), NativeContextFormat::PerfEventV2).unwrap();
    let captured = CaptureReader::from_bytes(&w.finish(300).unwrap()).unwrap();
    let r = &captured.records[0];
    assert_eq!((r.event_id, r.schema_version), (0x1001, 2));
    assert_eq!((r.timestamp_ns, r.cpu_id, r.pid, r.tid, r.task_id), (200, 3, 40, 41, 99));
    assert_eq!(r.payload.len(), 32);
    assert_eq!(&r.payload[0..8], &10_000_000u64.to_le_bytes());
    assert_eq!(&r.payload[8..16], &0xdeadu64.to_le_bytes());
    assert_eq!(&r.payload[16..24], &0x400110u64.to_le_bytes());
    assert_eq!(&r.payload[24..28], &2u32.to_le_bytes());
    assert_eq!(&r.payload[28..32], &[0;4]);
}

#[test]
fn source_cpu_mismatch_is_corruption_not_a_relabelled_record() {
    let mut w = writer();
    assert!(w.ingest_raw_perf_frame_as(2, &frame(&context()), NativeContextFormat::PerfEventV2).is_err());
    let c = CaptureReader::from_bytes(&w.finish(300).unwrap()).unwrap();
    assert!(c.records.is_empty());
    assert_eq!(c.metadata.counters.consumer_corrupt_records, 1);
    assert_eq!(c.metadata.status, SessionStatusCode::IncompleteError);
}

#[test]
fn bad_context_version_mode_and_truncated_perf_header_are_rejected() {
    let mut bad_version = context(); bad_version[60..64].copy_from_slice(&3u32.to_le_bytes());
    let mut bad_mode = context(); bad_mode[56..60].copy_from_slice(&9u32.to_le_bytes());
    for input in [frame(&bad_version), frame(&bad_mode), vec![9,0,0,0,0,0,0,0]] {
        let mut w = writer();
        assert!(w.ingest_raw_perf_frame_as(3, &input, NativeContextFormat::PerfEventV2).is_err());
        let c = CaptureReader::from_bytes(&w.finish(300).unwrap()).unwrap();
        assert_eq!(c.metadata.status, SessionStatusCode::IncompleteError);
    }
}

#[test]
fn exact_frame_boundary_rejects_extra_bytes_and_oversized_payload() {
    let mut extra = frame(&context()); extra.push(0);
    let mut oversized = frame(&context()); oversized[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    for input in [extra, oversized] {
        let mut w = writer();
        assert!(w.ingest_raw_perf_frame_as(3, &input, NativeContextFormat::PerfEventV2).is_err());
    }
}

#[test]
fn same_size_task_enqueue_requires_explicit_context_format() {
    let mut raw = [0u8; 64];
    raw[..4].copy_from_slice(&6u32.to_le_bytes());
    raw[4..8].copy_from_slice(&1u32.to_le_bytes());
    raw[8..16].copy_from_slice(&200u64.to_le_bytes());
    raw[16..20].copy_from_slice(&3u32.to_le_bytes());
    raw[32..40].copy_from_slice(&99u64.to_le_bytes());
    raw[40..48].copy_from_slice(&99u64.to_le_bytes());
    raw[48..52].copy_from_slice(&3u32.to_le_bytes());
    raw[52..56].copy_from_slice(&2u32.to_le_bytes());
    raw[56..60].copy_from_slice(&8u32.to_le_bytes());
    raw[60..64].copy_from_slice(&2u32.to_le_bytes()); // enqueue reason, NOT a version
    let mut w = writer();
    w.ingest_raw_perf_frame_as(3, &frame(&raw), NativeContextFormat::Tracepoint).unwrap();
    let c = CaptureReader::from_bytes(&w.finish(300).unwrap()).unwrap();
    assert_eq!((c.records[0].event_id, c.records[0].schema_version), (6,1));
    assert_eq!(c.records[0].payload.len(), 24);
}

#[test]
fn capture_offsets_and_counts_cannot_panic_or_force_unbounded_allocation() {
    let mut w = writer();
    w.ingest_perf_sample_as(3, &context(), NativeContextFormat::PerfEventV2).unwrap();
    let bytes = w.finish(300).unwrap();
    let header = bpf_capture::CaptureHeader::from_bytes(&bytes).unwrap();
    let trailer = header.trailer_offset as usize;
    for offset in [24, 32, 40, 56, 64, 72] {
        let mut bad = bytes.clone();
        bad[offset..offset+8].copy_from_slice(&u64::MAX.to_le_bytes());
        let crc = bpf_capture::framing::compute_checksum_ieee(&bad[..trailer]);
        bad[trailer+24..trailer+28].copy_from_slice(&crc.to_le_bytes());
        let result = std::panic::catch_unwind(|| CaptureReader::from_bytes(&bad));
        assert!(result.is_ok(), "reader panicked for header offset {offset}");
        assert!(result.unwrap().is_err());
    }
    let mut bad = bytes;
    bad[48..56].copy_from_slice(&u64::MAX.to_le_bytes());
    bad[trailer+8..trailer+16].copy_from_slice(&u64::MAX.to_le_bytes());
    let crc = bpf_capture::framing::compute_checksum_ieee(&bad[..trailer]);
    bad[trailer+24..trailer+28].copy_from_slice(&crc.to_le_bytes());
    let result = std::panic::catch_unwind(|| CaptureReader::from_bytes(&bad));
    assert!(result.is_ok(), "untrusted count triggered an allocation panic");
    assert!(result.unwrap().is_err());
}
