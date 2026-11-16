use bpf_analyzer::{CaptureAnalyzer, query::{Query, SampleWeight}};
use bpf_capture::{CaptureArch, CaptureReader, CaptureWriter, NativeContextFormat, SchemaRegistry, SessionStatusCode};
use pulse_bpf_schema::{PerfEventContext, PerfSampleContext};

fn analyzer() -> CaptureAnalyzer {
    let fixture=bpf_capture::generate_deterministic_fixture(CaptureArch::Riscv64,SessionStatusCode::Complete).unwrap();
    let mut writer=CaptureWriter::new(CaptureReader::from_bytes(&fixture).unwrap().metadata.config,SchemaRegistry::default_pulse_registry());
    writer.configure_recorder(vec![
        support::source(7, bpf_capture::RecorderKind::SoftwareStackV3, 0x1002, 3, 3, 10, 123, 100, 300),
        support::source(9, bpf_capture::RecorderKind::SoftwareStackV3, 0x1002, 3, 3, 20, 124, 100, 300),
    ], 4096).unwrap();
    writer.start(100).unwrap();
    for (logical,source,period) in [(7,123u64,10u64),(9,124,20)] {
        let mut raw=[0u8;640];
        raw[..64].copy_from_slice(&PerfSampleContext {
            base:PerfEventContext::new(period,0,200,3,40,41,99),ip:0x400110,mode:2,version:2,
        }.to_bytes());
        for (offset,value) in [(64,source),(72,0x8000),(80,0x8020),(88,0x400220),(96,19)] {
            raw[offset..offset+8].copy_from_slice(&value.to_le_bytes());
        }
        for (offset,value) in [(104,3u16),(106,32),(108,3),(110,4)] {
            raw[offset..offset+2].copy_from_slice(&value.to_le_bytes());
        }
        raw[112..116].copy_from_slice(&32u32.to_le_bytes());
        raw[116..120].copy_from_slice(&512u32.to_le_bytes());
        for (index,ip) in [0x400110u64,0x400220,0x400330].iter().enumerate() {
            raw[128+index*8..136+index*8].copy_from_slice(&ip.to_le_bytes());
        }
        writer.ingest_perf_sample_as(logical,3,&raw,NativeContextFormat::SoftwareStackV3).unwrap();
    }
    CaptureAnalyzer::from_bytes(&writer.finish(300).unwrap()).unwrap()
}

#[test]
fn table_json_and_folded_preserve_real_chain_and_termination() {
    let a=analyzer();
    let table=a.render_event_table();
    assert!(table.contains("source_id=123") && table.contains("source_id=124"),"{table}");
    assert!(table.contains("termination=read_fault") && table.contains("stack=partial"),"{table}");
    let json=a.render_json();
    let report: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(report["stack_samples"][0]["logical_source"], 7);
    assert_eq!(report["stack_samples"][0]["sample"]["source_id"], 123);
    assert!(json.contains("\"source_id\":123") && json.contains("\"source_id\":124"),"{json}");
    assert!(json.contains("\"ips\":[4194576,4194848,4195120]"),"{json}");
    assert!(json.contains("\"termination\":\"read_fault\""),"{json}");
    let folded=a.render_on_cpu_folded();
    assert!(folded.text.contains("[partial:read_fault];pc:0x400330;pc:0x400220;pc:0x400110 2"),"{}",folded.text);
    assert!(!folded.is_complete);
    assert_eq!(a.aggregate_statistics().cpu_stats[&3].sample_count,2);
}

#[test]
fn period_weight_and_query_filter_apply_to_stack_samples() {
    let a=analyzer();
    let mut query=Query::default();
    query.weight=SampleWeight::Period;
    let result=a.query(&query).unwrap();
    let folded=bpf_analyzer::emission::render_on_cpu_folded_weighted(&a,&result.events,query.weight);
    assert!(folded.text.ends_with("pc:0x400110 30\n"),"{}",folded.text);
    query.cpu=Some(7);
    let result=a.query(&query).unwrap();
    assert!(result.events.is_empty());
    assert!(bpf_analyzer::emission::render_query_json(&a,&result).contains("\"stack_samples\": []"));
}

mod support;
