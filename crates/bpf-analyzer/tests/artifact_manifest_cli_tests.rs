//! Collection reads identities from the original validated capture.
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn elf_identity_cli_reads_exact_bytes_and_preserves_absent_build_id() {
    let mut bytes = vec![0; 120];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&243u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    let mut child = Command::new(env!("CARGO_BIN_EXE_bpf-analyzer"))
        .args(["--elf-identity", "riscv64"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["gnu_build_id"], serde_json::Value::Null);
    assert_eq!(report["sha256"], bpf_analyzer::artifact::sha256(&bytes));
}

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

#[cfg(unix)]
#[test]
fn collection_report_alias_cannot_overwrite_its_original_capture() {
    let bytes = bpf_capture::generate_deterministic_fixture(
        bpf_capture::CaptureArch::Riscv64,
        bpf_capture::SessionStatusCode::IncompleteError,
    )
    .unwrap();
    let root = std::env::temp_dir().join(format!("pulse-collection-alias-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let capture = root.join("sample.pbcapture");
    let collector =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/bpf-record/collect.py");
    for alias in ["hardlink", "symlink"] {
        fs::write(&capture, &bytes).unwrap();
        let bundle = root.join(alias);
        fs::create_dir_all(&bundle).unwrap();
        let report = bundle.join("sample-collection.json");
        if alias == "hardlink" {
            fs::hard_link(&capture, &report).unwrap();
        } else {
            std::os::unix::fs::symlink(&capture, &report).unwrap();
        }
        let output = Command::new("python3")
            .arg(&collector)
            .arg(&capture)
            .arg("--bundle")
            .arg(&bundle)
            .arg("--analyzer")
            .arg(env!("CARGO_BIN_EXE_bpf-analyzer"))
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "collector accepted {alias} report alias"
        );
        assert_eq!(
            fs::read(&capture).unwrap(),
            bytes,
            "{alias} changed capture"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("aliases"));
    }
    fs::remove_dir_all(root).unwrap();
}
