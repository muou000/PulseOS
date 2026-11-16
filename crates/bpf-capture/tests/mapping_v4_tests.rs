mod support;
use bpf_capture::{
    CaptureArch, CaptureReader, CaptureWriter, SessionStatusCode,
    mapping::{Artifact, MappingJournal, MappingMetadata},
};
fn journal() -> String {
    "PULSE_BPF_MAPPINGS version=2 available=1 started_ns=0 snapshot_ns=500 dropped=0 \
     records=2\nSPACE seq=1 ts=10 begin_ns=1 space=4 revision=2 count=1\nMAP start=4096 len=4096 \
     pgoff=8192 perms=5 object=0\nENDSPACE\nTASK seq=2 ts=20 task=3 pid=4 tid=4 space=4 exec=1 \
     kind=bind parent=0 class=user begin_ns=20 comm_hex=78\nEND records=2 dropped=0 \
     snapshot_ns=500\n"
        .into()
}
fn metadata() -> MappingMetadata {
    MappingMetadata {
        journal: journal(),
        artifacts: vec![Artifact {
            sha256: "a".repeat(64),
            gnu_build_id: None,
            path: format!("artifacts/{}.elf", "a".repeat(64)),
            debug_sha256: None,
            debug_build_id: None,
        }],
        kernel: None,
    }
}
#[test]
fn current_capture_retains_verbatim_journal_and_explicit_absent_gnu_id() {
    let fixture = bpf_capture::generate_deterministic_fixture(
        CaptureArch::Riscv64,
        SessionStatusCode::Complete,
    )
    .unwrap();
    let old = CaptureReader::from_bytes(&fixture).unwrap();
    let mut writer = CaptureWriter::new(old.metadata.config, old.registry);
    writer.set_mappings(metadata()).unwrap();
    writer.configure_recorder(vec![support::trace(1, 2, 0, 100, 300)], 4096).unwrap();
    writer.start(100).unwrap();
    let mut record = old.records[0].clone();
    record.timestamp_ns = 200;
    writer.write_record_from(1, record).unwrap();
    let bytes = writer.finish(300).unwrap();
    let parsed = CaptureReader::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.header.format_version, 6);
    assert_eq!(parsed.mappings, Some(metadata()));
    assert_eq!(parsed.mappings.unwrap().artifacts[0].gnu_build_id, None);
}
#[test]
fn malformed_journal_is_not_promoted_into_valid_metadata() {
    for text in [
        journal().replace("seq=2", "seq=3"),
        journal().replace("seq=2 ts=20", "seq=2 ts=5"),
        journal().replace("len=4096", "len=18446744073709551615"),
        journal().replace("ENDSPACE\n", ""),
        journal().replace("snapshot_ns=500\n", "snapshot_ns=499\n"),
        journal().replace("begin_ns=20", "begin_ns=21"),
    ] {
        assert!(MappingJournal::parse(&text).is_err(), "{text}");
    }
}
#[test]
fn counted_loss_preserves_partial_journal_and_truncation_rejects() {
    let text = journal()
        .replace("dropped=0", "dropped=1")
        .replace("seq=2", "seq=3");
    assert_eq!(MappingJournal::parse(&text).unwrap().dropped, 1);
    let bytes = metadata().to_bytes().unwrap();
    for end in [0, 7, 8, 12, bytes.len() - 1] {
        assert!(MappingMetadata::from_bytes(&bytes[..end]).is_err());
    }
}
#[test]
fn bundle_paths_and_fake_build_ids_are_rejected() {
    let mut m = metadata();
    m.artifacts[0].path = "/tmp/same-name.elf".into();
    assert!(m.validate().is_err());
    let mut m = metadata();
    m.artifacts[0].gnu_build_id = Some("not-a-build-id".into());
    assert!(m.validate().is_err());
    let mut m = metadata();
    m.artifacts.push(m.artifacts[0].clone());
    assert!(m.validate().is_err());
}
#[test]
fn current_capture_unknown_required_feature_is_rejected() {
    let fixture = bpf_capture::generate_deterministic_fixture(
        CaptureArch::Riscv64,
        SessionStatusCode::Complete,
    )
    .unwrap();
    let old = CaptureReader::from_bytes(&fixture).unwrap();
    let mut writer = CaptureWriter::new(old.metadata.config, old.registry);
    writer.set_mappings(metadata()).unwrap();
    writer.configure_recorder(vec![support::trace(1, 2, 0, 100, 300)], 4096).unwrap();
    writer.start(100).unwrap();
    let mut record = old.records[0].clone();
    record.timestamp_ns = 200;
    writer.write_record_from(1, record).unwrap();
    let mut bytes = writer.finish(300).unwrap();
    let h = bpf_capture::CaptureHeader::from_bytes(&bytes).unwrap();
    let pos = h.records_offset as usize - 8;
    bytes[pos..pos + 8].copy_from_slice(&8u64.to_le_bytes());
    let crc = bpf_capture::framing::compute_checksum_ieee(&bytes[..h.trailer_offset as usize]);
    let off = h.trailer_offset as usize + 24;
    bytes[off..off + 4].copy_from_slice(&crc.to_le_bytes());
    assert!(CaptureReader::from_bytes(&bytes).is_err());
}

#[test]
fn mapping_journal_has_an_independent_bound_from_diagnostics() {
    let mut rows = String::new();
    for index in 1..=200 {
        rows.push_str(&format!(
            "OBJECT seq={index} ts={index} object={index} sha256=unknown path_hex={}\n",
            "61".repeat(4096)
        ));
    }
    let mut mappings = metadata();
    mappings.journal = format!(
        "PULSE_BPF_MAPPINGS version=2 available=1 started_ns=0 snapshot_ns=500 dropped=0 \
         records=200\n{rows}END records=200 dropped=0 snapshot_ns=500\n"
    );
    assert!(mappings.journal.len() > 1024 * 1024);
    let original = bpf_capture::generate_deterministic_fixture(
        CaptureArch::Riscv64,
        SessionStatusCode::Complete,
    )
    .unwrap();
    let data = CaptureReader::from_bytes(&original).unwrap();
    let mut writer = CaptureWriter::new(data.metadata.config, data.registry);
    writer.set_mappings(mappings.clone()).unwrap();
    writer.configure_recorder(vec![support::trace(1, 2, 0, 100, 300)], 4096).unwrap();
    writer.start(100).unwrap();
    let mut record = data.records[0].clone();
    record.timestamp_ns = 200;
    writer.write_record_from(1, record).unwrap();
    assert_eq!(
        CaptureReader::from_bytes(&writer.finish(300).unwrap())
            .unwrap()
            .mappings,
        Some(mappings)
    );
}

#[test]
fn retrospective_only_journal_cannot_claim_live_mutation_coverage() {
    assert!(MappingJournal::parse(&journal().replace("version=2", "version=1")).is_err());
    assert!(MappingJournal::parse(&journal().replace("version=2", "version=3")).is_err());
}
