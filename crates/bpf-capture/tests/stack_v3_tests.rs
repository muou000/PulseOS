mod support;
use bpf_capture::{CaptureArch, CaptureReader, CaptureWriter, NativeContextFormat, NormalizedRecord,
    SchemaRegistry, SessionStatusCode};
use bpf_capture::framing::{compute_checksum_ieee, CaptureError, CaptureHeader};
use pulse_bpf_schema::{PerfEventContext, PerfSampleContext};

fn context(source: u64) -> [u8; 640] {
    let mut raw = [0u8; 640];
    raw[..64].copy_from_slice(&PerfSampleContext {
        base: PerfEventContext::new(10, 0, 200, 3, 40, 41, 99),
        ip: 0x400110, mode: 2, version: 2,
    }.to_bytes());
    for (offset, value) in [(64,source),(72,0x8000),(80,0x8020),(88,0x400220),(96,19)] {
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
    raw
}
fn writer() -> CaptureWriter {
    let fixture = bpf_capture::generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete).unwrap();
    let config = CaptureReader::from_bytes(&fixture).unwrap().metadata.config;
    let mut writer = CaptureWriter::new(config, SchemaRegistry::default_pulse_registry());
    let sources = [(7, 123), (8, 124)].map(|(id, kernel_event_id)| bpf_capture::RecorderSource {
        kind: bpf_capture::RecorderKind::SoftwareStackV3, event_id: 0x1002,
        schema_version: 3, kernel_event_id, ..support::software(id, 3, 10, 100, 300)
    });
    writer.configure_recorder(sources.to_vec(), 4096).unwrap();
    writer.start(100).unwrap();
    writer
}
fn capture() -> Vec<u8> {
    let mut writer = writer();
    writer.ingest_perf_sample_as(7, 3, &context(123), NativeContextFormat::SoftwareStackV3).unwrap();
    writer.ingest_perf_sample_as(8, 3, &context(124), NativeContextFormat::SoftwareStackV3).unwrap();
    writer.finish(300).unwrap()
}
fn checksum(bytes: &mut [u8]) {
    let trailer = u64::from_le_bytes(bytes[64..72].try_into().unwrap()) as usize;
    let crc = compute_checksum_ieee(&bytes[..trailer]);
    bytes[trailer+24..trailer+28].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn stack_capture_preserves_frozen_prefix_and_same_cpu_source_instances() {
    let bytes = capture();
    let data = CaptureReader::from_bytes(&bytes).unwrap();
    assert_eq!(data.header.format_version, 6);
    assert_eq!(data.records.len(), 2);
    for (record, id) in data.records.iter().zip([123,124]) {
        assert_eq!((record.event_id,record.schema_version,record.payload.len()),(0x1002,3,608));
        let decoded = record.software_stack_v3().unwrap();
        assert_eq!(decoded.to_bytes(), context(id));
        assert_eq!(decoded.source_id,id);
        assert_eq!(decoded.stack.len,3);
        assert_eq!(decoded.stack.status.as_str(),"read_fault");
    }
    assert!(!data.metadata.status.is_complete(), "missing evidence must stay unknown");
}

#[test]
fn unknown_required_extensions_and_future_native_versions_fail_closed() {
    let bytes = capture();
    let header = CaptureHeader::from_bytes(&bytes).unwrap();
    let mask_offset = header.records_offset as usize - 8;
    for mask in [0u64, 2, 3, u64::MAX] {
        let mut bad=bytes.clone();
        bad[mask_offset..mask_offset+8].copy_from_slice(&mask.to_le_bytes());
        checksum(&mut bad);
        assert!(CaptureReader::from_bytes(&bad).is_err());
    }
    let mut future = bytes.clone();
    future[8..12].copy_from_slice(&7u32.to_le_bytes());
    assert_eq!(CaptureReader::from_bytes(&future).unwrap_err(),CaptureError::UnsupportedFormatVersion(7));
    for offset in [104,120] {
        let mut raw=context(123); raw[offset]=7;
        assert!(NormalizedRecord::from_software_stack_v3_slice(&raw).is_err());
    }
}

#[test]
fn malformed_chain_fields_and_wrong_declared_context_are_rejected() {
    for (offset,value) in [(64,0),(104,9),(106,65),(108,65),(110,255),(128,0),(152,1)] {
        let mut raw=context(123);
        raw[offset]=value;
        if offset==64 { raw[64..72].fill(0); }
        if offset==128 { raw[128..136].fill(0); }
        assert!(NormalizedRecord::from_software_stack_v3_slice(&raw).is_err(),"offset={offset}");
    }
    let mut writer=writer();
    assert!(writer.ingest_perf_sample_as(7, 3,&context(123),NativeContextFormat::PerfEventV2).is_err());
    assert!(writer.ingest_perf_sample_as(7, 2,&context(123),NativeContextFormat::SoftwareStackV3).is_err());
}

#[test]
fn stack_record_cannot_be_downgraded_into_legacy_container() {
    let mut bytes=capture();
    let h=CaptureHeader::from_bytes(&bytes).unwrap();
    let mask_at=h.records_offset as usize-8;
    bytes.drain(mask_at..mask_at+8);
    bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&(h.metadata_size-8).to_le_bytes());
    bytes[40..48].copy_from_slice(&(h.records_offset-8).to_le_bytes());
    bytes[64..72].copy_from_slice(&(h.trailer_offset-8).to_le_bytes());
    checksum(&mut bytes);
    assert!(matches!(CaptureReader::from_bytes(&bytes),Err(CaptureError::UnsupportedFormatVersion(2))));
}

#[test]
fn mapping_extension_coexists_with_required_software_stack() {
    let mut writer = writer();
    writer.set_mappings(bpf_capture::mapping::MappingMetadata {
        journal: "PULSE_BPF_MAPPINGS version=2 available=1 started_ns=0 snapshot_ns=500 dropped=0 records=0\nEND records=0 dropped=0 snapshot_ns=500\n".into(),
        artifacts: vec![], kernel: None,
    }).unwrap();
    writer.ingest_perf_sample_as(7, 3, &context(123), NativeContextFormat::SoftwareStackV3).unwrap();
    let bytes = writer.finish(300).unwrap();
    let data = CaptureReader::from_bytes(&bytes).unwrap();
    assert_eq!(data.header.format_version, 6);
    assert_eq!(data.records[0].software_stack_v3().unwrap().source_id, 123);
    assert!(data.mappings.is_some());
}
