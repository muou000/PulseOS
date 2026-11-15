use bpf_capture::{CaptureArch, CaptureReader, CaptureWriter, SchemaRegistry, SessionStatusCode};
use bpf_capture::writer::SampleFormat;
use pulse_bpf_schema::{ContextCommon, PageFaultContext, PageFaultOrigin, PageFaultOutcome, TracepointId};

fn writer() -> CaptureWriter {
    let fixture=bpf_capture::generate_deterministic_fixture(CaptureArch::Riscv64,SessionStatusCode::Complete).unwrap();
    let parsed=CaptureReader::from_bytes(&fixture).unwrap();
    let mut writer=CaptureWriter::new(parsed.metadata.config,SchemaRegistry::default_pulse_registry());
    writer.start(90).unwrap(); writer
}
fn context()->[u8;80] {
    PageFaultContext::from_completion(ContextCommon::new(TracepointId::PageFault,350,2,40,41,99),
        0,100,2,PageFaultOrigin::Kernel,PageFaultOutcome::NotHandled).unwrap().to_bytes()
}
#[test]
fn fault_completion_preserves_null_address_kernel_origin_and_unknown_classification() {
    let mut w=writer();w.ingest_perf_sample_as(2,&context(),SampleFormat::Tracepoint).unwrap();
    let data=CaptureReader::from_bytes(&w.finish(400).unwrap()).unwrap();let r=&data.records[0];
    assert_eq!((r.event_id,r.timestamp_ns,r.cpu_id,r.pid,r.tid,r.task_id),(8,350,2,40,41,99));
    assert_eq!(u64::from_le_bytes(r.payload[0..8].try_into().unwrap()),0);
    assert_eq!(u64::from_le_bytes(r.payload[16..24].try_into().unwrap()),250);
    assert_eq!(u32::from_le_bytes(r.payload[28..32].try_into().unwrap()),1);
    assert_eq!(u32::from_le_bytes(r.payload[32..36].try_into().unwrap()),2);
    assert_eq!(u32::from_le_bytes(r.payload[36..40].try_into().unwrap()),0);
}
#[test]
fn malformed_fault_timing_access_and_enum_values_are_rejected() {
    for (offset,value,width) in [(48,351u64,8),(56,249,8),(64,8,4),(68,0,4),(72,5,4),(76,3,4)] {
        let mut raw=context();raw[offset..offset+width].copy_from_slice(&value.to_le_bytes()[..width]);
        assert!(writer().ingest_perf_sample_as(2,&raw,SampleFormat::Tracepoint).is_err(),"accepted malformed offset {offset}");
    }
}

#[test]
fn architecture_unknown_access_is_preserved_without_guessing_an_operation() {
    let raw=PageFaultContext::from_completion(
        ContextCommon::new(TracepointId::PageFault,350,2,40,41,99),
        0xffff_8000_0000_0000,100,0,PageFaultOrigin::User,PageFaultOutcome::NotHandled).unwrap().to_bytes();
    let mut w=writer();
    w.ingest_perf_sample_as(2,&raw,SampleFormat::Tracepoint).unwrap();
    let data=CaptureReader::from_bytes(&w.finish(400).unwrap()).unwrap();
    assert_eq!(&data.records[0].payload[24..28],&[0;4]);
}

#[test]
fn classified_faults_round_trip_but_unsuccessful_minor_and_major_are_rejected() {
    let mut w = writer();
    for classification in [0u32, 1, 2] {
        let mut raw = context();
        raw[72..76].copy_from_slice(&1u32.to_le_bytes());
        raw[76..80].copy_from_slice(&classification.to_le_bytes());
        w.ingest_perf_sample_as(2, &raw, SampleFormat::Tracepoint).unwrap();
    }
    let data = CaptureReader::from_bytes(&w.finish(400).unwrap()).unwrap();
    let classes: Vec<_> = data.records.iter().map(|r| {
        u32::from_le_bytes(r.payload[36..40].try_into().unwrap())
    }).collect();
    assert_eq!(classes, vec![0, 1, 2]);

    for outcome in [2u32, 3, 4] {
        for classification in [1u32, 2] {
            let mut raw = context();
            raw[72..76].copy_from_slice(&outcome.to_le_bytes());
            raw[76..80].copy_from_slice(&classification.to_le_bytes());
            assert!(writer().ingest_perf_sample_as(2, &raw, SampleFormat::Tracepoint).is_err(),
                "accepted outcome={outcome} classification={classification}");
        }
    }
}
