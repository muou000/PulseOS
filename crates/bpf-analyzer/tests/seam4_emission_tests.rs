use bpf_analyzer::CaptureAnalyzer;
use bpf_capture::fixture::generate_deterministic_fixture;
use bpf_capture::framing::{CaptureArch, SessionStatusCode};

#[test]
fn test_render_event_table_contains_aligned_headers_and_rows() {
    let bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete)
        .expect("fixture");
    let analyzer = CaptureAnalyzer::from_bytes(&bytes).unwrap();

    let table = analyzer.render_event_table();
    assert!(table.contains("TIMESTAMP (ns)"), "table must have timestamp column");
    assert!(table.contains("CPU"), "table must have CPU column");
    assert!(table.contains("EVENT"), "table must have event column");
    assert!(table.contains("sched_switch"), "table must contain sched_switch event");
    assert!(table.contains("task_block"), "table must contain task_block event");
}

#[test]
fn test_render_loss_report_complete_vs_incomplete() {
    // 1. Complete capture
    let complete_bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete)
        .expect("complete fixture");
    let comp_analyzer = CaptureAnalyzer::from_bytes(&complete_bytes).unwrap();
    let comp_report = comp_analyzer.render_loss_report();
    assert!(comp_report.contains("Status: Complete"));
    assert!(comp_report.contains("Lost Records: 0"));
    assert!(comp_report.contains("Attribution Claim: Allowed"));

    // 2. Incomplete lossy capture
    let lossy_bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::IncompleteLoss)
        .expect("lossy fixture");
    let loss_analyzer = CaptureAnalyzer::from_bytes(&lossy_bytes).unwrap();
    let loss_report = loss_analyzer.render_loss_report();
    assert!(loss_report.contains("Status: IncompleteLoss"));
    assert!(loss_report.contains("Lost Records: 7"));
    assert!(loss_report.contains("CPU 0: 5 lost"));
    assert!(loss_report.contains("CPU 1: 2 lost"));
    assert!(loss_report.contains("WARNING: Capture is incomplete"));
    assert!(loss_report.contains("Attribution Claim: Disallowed"));
}

#[test]
fn test_render_json_valid_schema_and_completeness_flag() {
    let bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete)
        .expect("fixture");
    let analyzer = CaptureAnalyzer::from_bytes(&bytes).unwrap();

    let json_str = analyzer.render_json();
    assert!(json_str.starts_with('{') && json_str.ends_with('}'));
    assert!(json_str.contains("\"is_complete\": true"));
    assert!(json_str.contains("\"status\": \"Complete\""));
    assert!(json_str.contains("\"arch\": \"riscv64\""));
    assert!(json_str.contains("\"pulse_commit\": \"49ad1424deadbeef0123456789abcdef01234567\""));
    assert!(json_str.contains("\"kernel_elf_path\": \"PulseOS_riscv64-qemu-virt.elf\""));
    assert!(json_str.contains("\"loss_counters\""));
    assert!(json_str.contains("\"cpu_stats\""));
    assert!(json_str.contains("\"task_stats\""));

    // Verify lossy JSON flags incomplete
    let lossy_bytes = generate_deterministic_fixture(CaptureArch::LoongArch64, SessionStatusCode::IncompleteLoss)
        .expect("lossy fixture");
    let loss_analyzer = CaptureAnalyzer::from_bytes(&lossy_bytes).unwrap();
    let loss_json = loss_analyzer.render_json();
    assert!(loss_json.contains("\"is_complete\": false"));
    assert!(loss_json.contains("\"status\": \"IncompleteLoss\""));
    assert!(loss_json.contains("\"arch\": \"loongarch64\""));
    assert!(loss_json.contains("\"attribution_claim_allowed\": false"));
}

#[test]
fn test_render_folded_on_and_off_cpu_complete_vs_incomplete() {
    // 1. Complete capture folded output
    let comp_bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete)
        .expect("fixture");
    let comp_analyzer = CaptureAnalyzer::from_bytes(&comp_bytes).unwrap();
    let on_cpu = comp_analyzer.render_on_cpu_folded();
    assert!(on_cpu.is_complete);
    assert!(!on_cpu.text.contains("[INCOMPLETE_CAPTURE]"));

    let off_cpu = comp_analyzer.render_off_cpu_folded();
    assert!(off_cpu.is_complete);
    assert!(!off_cpu.text.contains("[INCOMPLETE_CAPTURE]"));

    // 2. Incomplete lossy capture folded output must be marked incomplete
    let loss_bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::IncompleteLoss)
        .expect("fixture");
    let loss_analyzer = CaptureAnalyzer::from_bytes(&loss_bytes).unwrap();
    let loss_on_cpu = loss_analyzer.render_on_cpu_folded();
    assert!(!loss_on_cpu.is_complete);
    assert!(loss_on_cpu.text.contains("[INCOMPLETE_CAPTURE]"));

    let loss_off_cpu = loss_analyzer.render_off_cpu_folded();
    assert!(!loss_off_cpu.is_complete);
    assert!(loss_off_cpu.text.contains("[INCOMPLETE_CAPTURE]"));
}
