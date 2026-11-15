//! Exercise the executable boundary, including source/report alias protection.
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    dir: PathBuf,
    capture: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "pulse-perf-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let capture = dir.join("input.pbcapture");
        let bytes = bpf_capture::generate_deterministic_fixture(
            bpf_capture::CaptureArch::Riscv64,
            bpf_capture::SessionStatusCode::Complete,
        )
        .unwrap();
        fs::write(&capture, bytes).unwrap();
        Self { dir, capture }
    }
    fn cli(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_bpf-analyzer"))
            .arg(&self.capture)
            .args(args)
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.dir).unwrap();
    }
}

#[test]
fn perf_export_requires_explicit_artifact_bundle_before_creating_output() {
    let f = Fixture::new();
    let path = f.dir.join("perf.data");
    let result = f.cli(&["--perf-data", path.to_str().unwrap()]);
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("--perf-data requires --bundle"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!path.exists());
}

#[test]
fn empty_query_is_shared_by_json_folded_and_perf_export() {
    let f = Fixture::new();
    let path = f.dir.join("perf.data");
    let folded = f.dir.join("cpu.folded");
    let result = f.cli(&[
        "--from-ns",
        "18446744073709551614",
        "--json",
        "--oncpu",
        folded.to_str().unwrap(),
        "--weight",
        "period",
        "--perf-data",
        path.to_str().unwrap(),
        "--bundle",
        f.dir.to_str().unwrap(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read_to_string(folded).unwrap(), "");
    assert!(path.exists(), "perf output was not written");
    assert_eq!(&fs::read(&path).unwrap()[..8], b"PERFILE2");
    let json = f.dir.join("selected.json");
    fs::write(&json, result.stdout).unwrap();
    let check = Command::new("python3")
        .args([
            "-c",
            "import json,sys; q=json.load(open(sys.argv[1])); e=json.load(open(sys.argv[2])); \
             assert q['query']==e['query']; assert e['sample_count']==0; assert \
             e['total_period_ns']==0; assert e['weight_unit']=='period_ns'",
        ])
        .arg(json)
        .arg(f.dir.join("perf.data.json"))
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
}
