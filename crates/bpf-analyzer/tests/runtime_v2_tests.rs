use bpf_analyzer::CaptureAnalyzer;
use bpf_capture::{CaptureArch, CaptureReader, CaptureWriter, SchemaRegistry, SessionStatusCode};
use bpf_capture::writer::NativeContextFormat;
use pulse_bpf_schema::{PerfEventContext, PerfSampleContext};

#[test]
fn v2_hotspot_uses_instruction_pointer_and_keeps_privilege_mode() {
    let fixture = bpf_capture::generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete).unwrap();
    let config = CaptureReader::from_bytes(&fixture).unwrap().metadata.config;
    let mut writer = CaptureWriter::new(config, SchemaRegistry::default_pulse_registry());
    writer.configure_recorder(vec![support::source(7, bpf_capture::RecorderKind::SoftwareV2,
        0x1001, 2, 3, 10_000_000, 123, 100, 300)], 4096).unwrap();
    writer.start(100).unwrap();
    let sample = PerfSampleContext {
        base: PerfEventContext::new(10_000_000, 0xdead, 200, 3, 40, 41, 99),
        ip: 0x400110, mode: 2, version: 2,
    };
    writer.ingest_perf_sample_as(7, 3, &sample.to_bytes(), NativeContextFormat::PerfEventV2).unwrap();
    let analyzer = CaptureAnalyzer::from_bytes(&writer.finish(300).unwrap()).unwrap();
    let table = analyzer.render_event_table();
    assert!(table.contains("pc=0x0000000000400110"), "{table}");
    assert!(table.contains("mode=user"), "{table}");
    assert!(table.contains("addr=0x000000000000dead"), "{table}");
    assert_eq!(analyzer.aggregate_statistics().task_stats[&99].sample_count, 1);
    let folded = analyzer.render_on_cpu_folded();
    assert!(folded.text.contains("pc:0x400110 1"), "{}", folded.text);
    assert!(!folded.text.contains("pc:0xdead"));
}

mod support;
