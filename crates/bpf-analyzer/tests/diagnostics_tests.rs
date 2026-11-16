use bpf_analyzer::CaptureAnalyzer;
use bpf_capture::{
    CaptureArch, CaptureReader, CounterKind, DiagnosticCounter, DiagnosticIdentity,
    PhaseMeasurement, RuntimeDiagnostics, SessionStatusCode,
};

fn analyzer(unknown: bool) -> CaptureAnalyzer {
    let original = bpf_capture::generate_deterministic_fixture(
        CaptureArch::Riscv64,
        SessionStatusCode::Complete,
    )
    .unwrap();
    let data = CaptureReader::from_bytes(&original).unwrap();
    let mut writer = CaptureWriter::new(data.metadata.config, data.registry);
    writer
        .set_diagnostics(RuntimeDiagnostics {
            counters: vec![DiagnosticCounter {
                name: "lost".into(),
                scope: "system".into(),
                value: if unknown { None } else { Some(0) },
                kind: CounterKind::Loss,
            }],
            identities: vec![DiagnosticIdentity {
                name: "path".into(),
                value: Some("a\\b\"c\nd".into()),
            }],
            phases: vec![PhaseMeasurement {
                name: "attached".into(),
                start_ns: 100,
                stop_ns: 300,
                iterations: 128,
                mapped_bytes: Some(4096),
            }],
            evidence_json: Some("{\"test\":true}".into()),
        })
        .unwrap();
    writer.start(1).unwrap();
    for record in data.records {
        writer.write_record(record).unwrap();
    }
    CaptureAnalyzer::from_bytes(&writer.finish(2_000_000_000).unwrap()).unwrap()
}
#[test]
fn unknown_is_preserved_and_unmeasured_counters_are_not_reported_as_zero() {
    let analyzer = analyzer(true);
    assert!(!analyzer.is_complete());
    let report = analyzer.render_loss_report();
    assert!(report.contains("system lost (Loss): unknown"), "{report}");
    assert!(!report.contains("Verifier Failures: 0"), "{report}");
    let json = analyzer.render_json();
    assert!(json.contains("\"loss_counters\": null"), "{json}");
    assert!(json.contains("\"value\":null"), "{json}");
    assert!(json.contains("a\\\\b\\\"c\\nd"), "{json}");
    assert!(
        json.contains("\"evidence_json\":\"{\\\"test\\\":true}\""),
        "{json}"
    );
}
#[test]
fn clean_transport_never_proves_complete_runtime_attribution() {
    let analyzer = analyzer(false);
    assert!(!analyzer.is_complete());
    assert!(!analyzer.attribution_claim_allowed());
    assert!(!analyzer.render_off_cpu_folded().is_complete);
    assert!(
        analyzer
            .render_loss_report()
            .contains("Complete CPU/off-CPU attribution: unavailable")
    );
    assert!(
        analyzer
            .render_json()
            .contains("\"attribution_claim_allowed\": false")
    );
}

use support::SemanticFixture as CaptureWriter;

mod support;
