//! Collection reads identities from the original validated capture.
use std::{fs, process::Command};

#[test]
fn absent_mapping_identity_stays_unknown_in_collection_manifest() {
    let bytes = bpf_capture::generate_deterministic_fixture(
        bpf_capture::CaptureArch::Riscv64,
        bpf_capture::SessionStatusCode::IncompleteError,
    )
    .unwrap();
    let file =
        std::env::temp_dir().join(format!("pulse-manifest-{}.pbcapture", std::process::id()));
    fs::write(&file, &bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bpf-analyzer"))
        .arg(&file)
        .arg("--artifact-manifest")
        .output()
        .unwrap();
    assert_eq!(fs::read(&file).unwrap(), bytes);
    fs::remove_file(file).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["mapping_metadata"], false);
    assert_eq!(report["kernel"], serde_json::Value::Null);
    assert_eq!(report["artifacts"], serde_json::json!([]));
    assert_eq!(
        report["capture_sha256"],
        bpf_analyzer::artifact::sha256(&bytes)
    );
}
