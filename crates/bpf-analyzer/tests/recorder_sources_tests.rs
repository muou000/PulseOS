use bpf_analyzer::CaptureAnalyzer;
use bpf_capture::{CaptureArch, CaptureReader, CaptureScope, CaptureWriter, RecorderKind, RecorderSource, SourceClock, SourceConfig, SourceUnit, SourceFallback, SchemaRegistry, SessionStatusCode};
use pulse_bpf_schema::{PerfEventContext, PerfSampleContext};

#[test]
fn recorder_json_preserves_each_identical_source_and_transport_order() {
    let fixture = bpf_capture::generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete).unwrap();
    let config = CaptureReader::from_bytes(&fixture).unwrap().metadata.config;
    let mut writer = CaptureWriter::new(config, SchemaRegistry::default_pulse_registry());
    let sources = [7, 9].map(|id| RecorderSource {
        id, kind: RecorderKind::SoftwareV2, event_id: 0x1001, schema_version: 2,
        scope: CaptureScope::PerCpu(3), bound_task_id: 0, sample_period: 100, kernel_event_id: id as u64,
        program_id: id, link_id: id, enable_before_ns: 110, enable_after_ns: 120,
        disable_before_ns: 250, disable_after_ns: 260,
        clock: SourceClock::Monotonic, requested_config: SourceConfig::CpuClock,
        config: SourceConfig::CpuClock, requested_sample_period: 100,
        requested_frequency_hz: 0, effective_frequency_hz: 0,
        requested_buffer_pages: 4, effective_buffer_pages: 4,
        unit: SourceUnit::Nanoseconds, fallback: SourceFallback::None,
    });
    writer.configure_recorder(sources.to_vec(), 4096).unwrap();
    writer.start(100).unwrap();
    for id in [9, 7, 9] {
        let context = PerfSampleContext {
            base: PerfEventContext::new(100, 0, 200, 3, 40, 41, 99),
            ip: 0x400110, mode: 2, version: 2,
        }.to_bytes();
        let mut envelope = vec![0; 24];
        envelope[..4].copy_from_slice(&0x31524250u32.to_le_bytes());
        envelope[4..6].copy_from_slice(&1u16.to_le_bytes());
        envelope[6..8].copy_from_slice(&1u16.to_le_bytes());
        envelope[8..12].copy_from_slice(&64u32.to_le_bytes());
        envelope[12..16].copy_from_slice(&u32::to_le_bytes(id));
        envelope.extend_from_slice(&context);
        writer.ingest_recorder_sample(3, &envelope).unwrap();
    }
    let bytes = writer.finish(300).unwrap();
    let analyzer = CaptureAnalyzer::from_bytes(&bytes).unwrap();
    let report: serde_json::Value = serde_json::from_str(&analyzer.render_json()).unwrap();
    assert_eq!(report["format_version"], 6);
    assert_eq!(report["recorder"]["record_sources"], serde_json::json!([9, 7, 9]));
    let rows = report["recorder"]["sources"].as_array().unwrap();
    assert_eq!((rows[0]["logical_source"].as_u64(), rows[0]["records_count"].as_u64()), (Some(7), Some(1)));
    assert_eq!((rows[1]["logical_source"].as_u64(), rows[1]["records_count"].as_u64()), (Some(9), Some(2)));
    assert_eq!(rows[1]["kind"], "software-v2");
    assert_eq!(rows[1]["cpu"], 3);
    assert!(rows[1]["tid"].is_null());
    assert!(rows[1]["bound_task_id"].is_null());
    assert_eq!(rows[1]["period"], 100);
    assert_eq!(rows[1]["clock"], "monotonic");
    assert_eq!(rows[1]["config"], "cpu-clock");
    assert_eq!(rows[1]["requested_config"], "cpu-clock");
    assert_eq!(rows[1]["requested_sample_period"], 100);
    assert_eq!(rows[1]["requested_buffer_pages"], 4);
    assert_eq!(rows[1]["effective_buffer_pages"], 4);
    assert_eq!(rows[1]["unit"], "nanoseconds");
    assert_eq!(rows[1]["fallback"], "none");
    assert_eq!(report["mapping_evidence"]["present"], false);
    assert!(report["mapping_evidence"]["dropped"].is_null());
    let all = analyzer.query(&Default::default()).unwrap();
    let timeline: serde_json::Value = serde_json::from_str(&bpf_analyzer::emission::render_timeline(&analyzer, &all)).unwrap();
    assert_eq!(timeline["events"][0]["logical_source"], 9);
    assert_eq!(timeline["events"][1]["logical_source"], 7);
    assert_eq!(timeline["events"][2]["logical_source"], 9);
    assert_eq!(timeline["recorder"]["record_sources"], serde_json::json!([9, 7, 9]));
    assert_eq!(report["is_complete"], false);
    assert_eq!(report["attribution_claim_allowed"], false);
    assert!(CaptureAnalyzer::from_bytes(&bytes[..bytes.len() - 40]).is_err());
    let query = analyzer.query(&bpf_analyzer::query::Query { from_ns: Some(250), ..Default::default() }).unwrap();
    let filtered: serde_json::Value = serde_json::from_str(
        &bpf_analyzer::emission::render_query_json(&analyzer, &query),
    ).unwrap();
    assert_eq!(filtered["records_count"], 0);
    assert_eq!(filtered["recorder"]["scope"], "capture");
    assert_eq!(filtered["recorder"]["order"], "transport");
    assert_eq!(filtered["recorder"]["records_count"], 3);
    assert_eq!(filtered["recorder"]["source_schema_version"], 3);
    assert_eq!(filtered["recorder"]["record_sources"], serde_json::json!([9, 7, 9]));
}
