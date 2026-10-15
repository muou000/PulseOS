use bpf_analyzer::CaptureAnalyzer;
use bpf_capture::fixture::generate_deterministic_fixture;
use bpf_capture::framing::{
    CaptureArch, CaptureError, SessionStatusCode, CAPTURE_HEADER_SIZE,
};

/// Acceptance Criterion 1:
/// Valid fixtures produce deterministic table/JSON/loss/folded outputs on both RISC-V64 and LoongArch64.
#[test]
fn acceptance_test_deterministic_valid_fixtures_dual_arch() {
    for arch in [CaptureArch::Riscv64, CaptureArch::LoongArch64] {
        let fixture_bytes = generate_deterministic_fixture(arch, SessionStatusCode::Complete)
            .expect("deterministic fixture generation");

        let analyzer1 = CaptureAnalyzer::from_bytes(&fixture_bytes).expect("parse analyzer");
        let analyzer2 = CaptureAnalyzer::from_bytes(&fixture_bytes).expect("parse analyzer second time");

        // Completeness and status verification
        assert!(analyzer1.is_complete());
        assert_eq!(analyzer1.status_code(), SessionStatusCode::Complete);
        assert_eq!(analyzer1.target_arch(), arch);
        assert!(analyzer1.attribution_claim_allowed());
        assert_eq!(analyzer1.records().len(), 2);

        // 1. Table output determinism
        let table1 = analyzer1.render_event_table();
        let table2 = analyzer2.render_event_table();
        assert_eq!(table1, table2, "table output must be deterministic");
        assert!(table1.contains("sched_switch"));
        assert!(table1.contains("task_block"));

        // 2. Loss report determinism
        let loss1 = analyzer1.render_loss_report();
        let loss2 = analyzer2.render_loss_report();
        assert_eq!(loss1, loss2, "loss report must be deterministic");
        assert!(loss1.contains("Status: Complete"));
        assert!(loss1.contains("Attribution Claim: Allowed"));
        assert!(loss1.contains(arch.as_str()));

        // 3. JSON output determinism
        let json1 = analyzer1.render_json();
        let json2 = analyzer2.render_json();
        assert_eq!(json1, json2, "json output must be deterministic");
        assert!(json1.contains("\"is_complete\": true"));
        assert!(json1.contains(&format!("\"arch\": \"{}\"", arch.as_str())));

        // 4. Folded outputs determinism
        let on_cpu1 = analyzer1.render_on_cpu_folded();
        let on_cpu2 = analyzer2.render_on_cpu_folded();
        assert_eq!(on_cpu1, on_cpu2, "on-cpu folded output must be deterministic");
        assert!(on_cpu1.is_complete);
        assert!(!on_cpu1.text.contains("[INCOMPLETE_CAPTURE]"));

        let off_cpu1 = analyzer1.render_off_cpu_folded();
        let off_cpu2 = analyzer2.render_off_cpu_folded();
        assert_eq!(off_cpu1, off_cpu2, "off-cpu folded output must be deterministic");
        assert!(off_cpu1.is_complete);
        assert!(!off_cpu1.text.contains("[INCOMPLETE_CAPTURE]"));
    }
}

/// Acceptance Criterion 2:
/// Bad hash/trailer/schema and incomplete/lossy captures are reported explicitly.
#[test]
fn acceptance_test_explicit_reporting_on_corrupted_and_incomplete_captures() {
    // Case 1: Bad trailer magic
    {
        let mut bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete).unwrap();
        let len = bytes.len();
        bytes[len - 40..len - 32].copy_from_slice(b"BAD_TRLR");
        let err = CaptureAnalyzer::from_bytes(&bytes).unwrap_err();
        assert_eq!(err, bpf_analyzer::AnalyzerError::Capture(CaptureError::BadTrailerMagic));
    }

    // Case 2: Checksum / hash mismatch
    {
        let mut bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete).unwrap();
        bytes[CAPTURE_HEADER_SIZE + 10] ^= 0x55;
        let err = CaptureAnalyzer::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, bpf_analyzer::AnalyzerError::Capture(CaptureError::ChecksumMismatch { .. })));
    }

    // Case 3: Schema version mismatch
    {
        let bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete).unwrap();
        let hdr = bpf_capture::framing::CaptureHeader::from_bytes(&bytes).unwrap();
        let mut tampered = bytes.clone();
        let rec_start = hdr.records_offset as usize;
        tampered[rec_start + 4] = 42; // tamper schema_version
        let trailer_offset = hdr.trailer_offset as usize;
        let new_crc = bpf_capture::framing::compute_checksum(&tampered[..trailer_offset]);
        tampered[trailer_offset + 24..trailer_offset + 28].copy_from_slice(&new_crc.to_le_bytes());

        let err = CaptureAnalyzer::from_bytes(&tampered).unwrap_err();
        assert_eq!(
            err,
            bpf_analyzer::AnalyzerError::Capture(CaptureError::SchemaMismatch {
                expected: 1,
                actual: 42
            })
        );
    }

    // Case 4: Nonzero loss capture explicitly reports incomplete status
    {
        let lossy_bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::IncompleteLoss).unwrap();
        let analyzer = CaptureAnalyzer::from_bytes(&lossy_bytes).expect("parse lossy capture");

        assert!(!analyzer.is_complete());
        assert_eq!(analyzer.status_code(), SessionStatusCode::IncompleteLoss);
        assert!(!analyzer.attribution_claim_allowed(), "No complete attribution claim allowed (Anchor A3 / #88)");

        let loss_rep = analyzer.render_loss_report();
        assert!(loss_rep.contains("WARNING: Capture is incomplete"));
        assert!(loss_rep.contains("Attribution Claim: Disallowed"));
        assert!(loss_rep.contains("Lost Records: 7"));

        let json = analyzer.render_json();
        assert!(json.contains("\"is_complete\": false"));
        assert!(json.contains("\"attribution_claim_allowed\": false"));

        let on_cpu = analyzer.render_on_cpu_folded();
        assert!(!on_cpu.is_complete);
        assert!(on_cpu.text.contains("[INCOMPLETE_CAPTURE]"));

        let off_cpu = analyzer.render_off_cpu_folded();
        assert!(!off_cpu.is_complete);
        assert!(off_cpu.text.contains("[INCOMPLETE_CAPTURE]"));
    }
}

/// Acceptance Criterion 3:
/// No qperf binary or qperf analyzer dependency is required.
#[test]
fn acceptance_test_no_qperf_dependency() {
    // Verify that the analyzer operates purely on standard in-memory / byte-level BPF capture
    // without requiring any qperf files, QEMU plugins, or qperf binaries.
    let bytes = generate_deterministic_fixture(CaptureArch::Riscv64, SessionStatusCode::Complete).unwrap();
    let analyzer = CaptureAnalyzer::from_bytes(&bytes).unwrap();
    assert!(analyzer.is_complete());

    // Verify all outputs are produced without external commands
    let table = analyzer.render_event_table();
    let json = analyzer.render_json();
    let loss = analyzer.render_loss_report();
    let on_cpu = analyzer.render_on_cpu_folded();
    let off_cpu = analyzer.render_off_cpu_folded();

    assert!(!table.is_empty());
    assert!(!json.is_empty());
    assert!(!loss.is_empty());
    assert!(!on_cpu.text.is_empty());
    assert!(!off_cpu.text.is_empty());
}
