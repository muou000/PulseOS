mod support;
use bpf_capture::{
    CaptureArch, CaptureReader, CaptureWriter, CounterKind, DiagnosticCounter, DiagnosticIdentity,
    PhaseMeasurement, RuntimeDiagnostics, SessionStatusCode,
};

fn diagnostics() -> RuntimeDiagnostics {
    RuntimeDiagnostics {
        counters: vec![
            DiagnosticCounter {
                name: "delivered".into(),
                scope: "source:1".into(),
                value: Some(1),
                kind: CounterKind::Activity,
            },
            DiagnosticCounter {
                name: "lost".into(),
                scope: "sink:2".into(),
                value: Some(0),
                kind: CounterKind::Loss,
            },
        ],
        identities: vec![DiagnosticIdentity {
            name: "kernel_sha256".into(),
            value: Some("a".repeat(64)),
        }],
        phases: vec![PhaseMeasurement {
            name: "attached".into(),
            start_ns: 100,
            stop_ns: 300,
            iterations: 128,
            mapped_bytes: Some(4096),
        }],
        evidence_json: Some("{\"fixture\":true}".into()),
    }
}
fn capture(diag: RuntimeDiagnostics, include_record: bool) -> Vec<u8> {
    let original = bpf_capture::generate_deterministic_fixture(
        CaptureArch::Riscv64,
        SessionStatusCode::Complete,
    )
    .unwrap();
    let data = CaptureReader::from_bytes(&original).unwrap();
    let mut writer = CaptureWriter::new(data.metadata.config, data.registry);
    writer.set_diagnostics(diag).unwrap();
    writer.configure_recorder(vec![support::trace(1, 2, 0, 100, 300)], 4096).unwrap();
    writer.start(100).unwrap();
    if include_record {
        let mut record = data.records[0].clone();
    record.timestamp_ns = 200;
    writer.write_record_from(1, record).unwrap();
    }
    writer.finish(300).unwrap()
}
#[test]
fn diagnostics_round_trip_uses_ieee_crc() {
    assert_eq!(
        bpf_capture::framing::compute_checksum_ieee(b"123456789"),
        0xcbf43926
    );
    let bytes = capture(diagnostics(), true);
    let data = CaptureReader::from_bytes(&bytes).unwrap();
    assert_eq!(data.header.format_version, 6);
    assert_eq!(data.diagnostics, Some(diagnostics()));
    assert_eq!(data.metadata.status, SessionStatusCode::IncompleteError);
    assert_eq!(
        data.trailer.checksum,
        bpf_capture::framing::compute_checksum_ieee(&bytes[..data.header.trailer_offset as usize])
    );
}

#[test]
fn retired_container_is_rejected_even_with_a_valid_current_checksum() {
    let mut bytes = capture(diagnostics(), true);
    let trailer = CaptureReader::from_bytes(&bytes).unwrap().header.trailer_offset as usize;
    bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
    let checksum = bpf_capture::framing::compute_checksum_ieee(&bytes[..trailer]);
    bytes[trailer + 24..trailer + 28].copy_from_slice(&checksum.to_le_bytes());
    assert_eq!(CaptureReader::from_bytes(&bytes).unwrap_err(), bpf_capture::CaptureError::UnsupportedFormatVersion(1));
}

#[test]
fn writer_without_runtime_evidence_emits_current_partial_capture() {
    let input = CaptureReader::from_bytes(&capture(diagnostics(), true)).unwrap();
    let mut writer = CaptureWriter::new(input.metadata.config, input.registry);
    writer.configure_recorder(vec![support::trace(1, 2, 0, 100, 300)], 4096).unwrap();
    writer.start(100).unwrap();
    let mut record = input.records[0].clone();
    record.timestamp_ns = 200;
    writer.write_record_from(1, record).unwrap();
    let data = CaptureReader::from_bytes(&writer.finish(300).unwrap()).unwrap();
    assert_eq!(data.header.format_version, 6);
    assert_eq!(data.diagnostics, Some(RuntimeDiagnostics::default()));
    assert_eq!(data.metadata.status, SessionStatusCode::IncompleteError);
}
#[test]
fn loss_unknown_and_empty_records_cannot_report_complete() {
    let mut loss = diagnostics();
    loss.counters[1].value = Some(7);
    let d = CaptureReader::from_bytes(&capture(loss, true)).unwrap();
    assert_eq!(d.metadata.status, SessionStatusCode::IncompleteLoss);
    assert_eq!(d.trailer.status_code, SessionStatusCode::IncompleteLoss);
    let mut unknown = diagnostics();
    unknown.identities[0].value = None;
    assert!(
        !CaptureReader::from_bytes(&capture(unknown, true))
            .unwrap()
            .metadata
            .status
            .is_complete()
    );
    assert!(
        !CaptureReader::from_bytes(&capture(diagnostics(), false))
            .unwrap()
            .metadata
            .status
            .is_complete()
    );
}
#[test]
fn corruption_and_every_trailer_truncation_fail_closed() {
    let bytes = capture(diagnostics(), true);
    for removed in 1..=40 {
        assert!(CaptureReader::from_bytes(&bytes[..bytes.len() - removed]).is_err());
    }
    let mut corrupt = bytes.clone();
    corrupt[100] ^= 1;
    assert!(CaptureReader::from_bytes(&corrupt).is_err());
}
#[test]
fn unknown_counter_round_trips_and_reduces_status() {
    let mut diag = diagnostics();
    diag.counters[1].value = None;
    let d = CaptureReader::from_bytes(&capture(diag.clone(), true)).unwrap();
    assert_eq!(d.diagnostics, Some(diag));
    assert!(!d.metadata.status.is_complete());
}
#[test]
fn diagnostics_reject_duplicate_keys_bad_phases_and_hostile_lengths() {
    let mut bad = diagnostics();
    bad.counters.push(bad.counters[0].clone());
    assert!(bad.to_bytes().is_err());
    let mut bad = diagnostics();
    bad.phases[0].stop_ns = 1;
    assert!(bad.to_bytes().is_err());
    let mut bytes = diagnostics().to_bytes().unwrap();
    bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    let parsed = std::panic::catch_unwind(|| RuntimeDiagnostics::from_bytes(&bytes));
    assert!(parsed.is_ok());
    assert!(parsed.unwrap().is_err());
}

#[test]
fn even_rechecksummed_complete_claim_cannot_override_loss_evidence() {
    let mut diag = diagnostics();
    diag.counters[1].value = Some(7);
    let mut bytes = capture(diag, true);
    let data = CaptureReader::from_bytes(&bytes).unwrap();
    let status = data.header.metadata_offset as usize
        + data.registry.to_bytes().len()
        + data.metadata.config.to_bytes().len()
        + 16;
    bytes[status..status + 4].copy_from_slice(&0u32.to_le_bytes());
    let trailer = data.header.trailer_offset as usize;
    bytes[trailer + 28..trailer + 32].copy_from_slice(&0u32.to_le_bytes());
    let checksum = bpf_capture::framing::compute_checksum_ieee(&bytes[..trailer]);
    bytes[trailer + 24..trailer + 28].copy_from_slice(&checksum.to_le_bytes());
    assert!(CaptureReader::from_bytes(&bytes).is_err());
}

#[test]
fn aggregate_diagnostic_size_is_bounded_before_encoding() {
    let mut diag = diagnostics();
    for i in 0..3 {
        diag.identities.push(DiagnosticIdentity {
            name: format!("large_{i}"),
            value: Some("a".repeat(400_000)),
        });
    }
    assert!(diag.validate().is_err());
    assert!(diag.to_bytes().is_err());
}
