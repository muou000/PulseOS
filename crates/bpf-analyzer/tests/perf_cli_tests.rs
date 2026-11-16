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

mod support;

impl Fixture {
    /// Explicit current-contract sources; diagnostics carry no source identities.
    fn mixed() -> Self {
        use bpf_capture::{
            CaptureReader, CaptureScope, CaptureWriter, NativeContextFormat, RecorderKind,
            SchemaRegistry, SourceConfig,
            diagnostics::RuntimeDiagnostics,
            mapping::{Artifact, MappingMetadata},
            record::NormalizedRecord,
        };
        use pulse_bpf_schema::{PerfEventContext, PerfSampleContext, TracepointId};

        let f = Self::new();
        let initial = CaptureReader::from_bytes(&fs::read(&f.capture).unwrap()).unwrap();
        let elf = support::perf_test_image();
        let hash = bpf_analyzer::artifact::sha256(&elf);
        let artifact = Artifact {
            sha256: hash.clone(),
            path: format!("artifacts/{hash}.elf"),
            gnu_build_id: None,
            debug_sha256: None,
            debug_build_id: None,
        };
        fs::create_dir(f.dir.join("artifacts")).unwrap();
        fs::write(f.dir.join(&artifact.path), elf).unwrap();
        let mappings = MappingMetadata {
            journal: format!(
                "PULSE_BPF_MAPPINGS version=2 available=1 started_ns=0 snapshot_ns=1000 dropped=0 \
                 records=5\nOBJECT seq=1 ts=1 object=9 sha256={hash} path_hex=2f776f726b\nSPACE \
                 seq=2 ts=10 begin_ns=2 space=100 revision=1 count=1\nMAP start=4194304 len=4096 \
                 pgoff=4096 perms=5 object=9\nENDSPACE\nTASK seq=3 ts=20 task=99 pid=40 tid=777 \
                 space=100 exec=0 kind=bind parent=0 class=user comm_hex=776f726b\nSPACE seq=4 \
                 ts=140 begin_ns=130 space=200 revision=1 count=1\nMAP start=4194304 len=4096 \
                 pgoff=4096 perms=5 object=9\nENDSPACE\nTASK seq=5 ts=150 task=99 pid=40 tid=41 \
                 space=200 exec=1 kind=exec parent=0 class=user comm_hex=776f726b\nEND records=5 \
                 dropped=0 snapshot_ns=1000\n"
            ),
            artifacts: vec![artifact],
            kernel: None,
        };
        let mut writer = CaptureWriter::new(
            initial.metadata.config,
            SchemaRegistry::default_pulse_registry(),
        );
        writer
            .set_diagnostics(RuntimeDiagnostics::default())
            .unwrap();
        writer.set_mappings(mappings).unwrap();
        let mut task_source = support::source(
            11,
            RecorderKind::SoftwareV2,
            0x1001,
            2,
            3,
            30,
            9011,
            100,
            500,
        );
        task_source.scope = CaptureScope::Task(777);
        task_source.bound_task_id = 99;
        task_source.config = SourceConfig::TaskClock;
        task_source.requested_config = SourceConfig::TaskClock;
        writer
            .configure_recorder(
                vec![
                    support::source(
                        7,
                        RecorderKind::SoftwareV2,
                        0x1001,
                        2,
                        3,
                        10,
                        9007,
                        100,
                        500,
                    ),
                    support::source(
                        9,
                        RecorderKind::SoftwareV2,
                        0x1001,
                        2,
                        3,
                        10,
                        9009,
                        100,
                        500,
                    ),
                    task_source,
                    support::source(
                        13,
                        RecorderKind::Tracepoint,
                        TracepointId::SchedSwitch as u32,
                        1,
                        3,
                        1,
                        9013,
                        100,
                        500,
                    ),
                    support::source(
                        15,
                        RecorderKind::Tracepoint,
                        TracepointId::PageFault as u32,
                        1,
                        3,
                        1,
                        9015,
                        100,
                        500,
                    ),
                ],
                8192,
            )
            .unwrap();
        writer.start(100).unwrap();
        // Transport order differs from timestamp order. Two sources are otherwise
        // indistinguishable; the task source migrates after nonleader exec.
        for (logical, period, time, cpu, tid) in [
            (11, 30, 300, 4, 41),
            (7, 10, 200, 3, 41),
            (9, 10, 200, 3, 41),
            (11, 30, 120, 3, 777),
        ] {
            let context = PerfSampleContext {
                base: PerfEventContext::new(period, 0, time, cpu, 40, tid, 99),
                ip: 0x400110,
                mode: 2,
                version: 2,
            };
            writer
                .ingest_perf_sample_as(
                    logical,
                    cpu,
                    &context.to_bytes(),
                    NativeContextFormat::PerfEventV2,
                )
                .unwrap();
        }
        let mut sched = Vec::new();
        for id in [99u64, 100] {
            sched.extend(id.to_le_bytes());
        }
        for field in [0u32, 120, 120, 0] {
            sched.extend(field.to_le_bytes());
        }
        writer
            .write_record_from(
                13,
                NormalizedRecord {
                    event_id: TracepointId::SchedSwitch as u32,
                    schema_version: 1,
                    timestamp_ns: 250,
                    cpu_id: 3,
                    pid: 40,
                    tid: 41,
                    task_id: 99,
                    payload: sched,
                },
            )
            .unwrap();
        let mut fault = Vec::new();
        for value in [0x400110u64, 255, 5] {
            fault.extend(value.to_le_bytes());
        }
        for value in [1u32, 2, 1, 1] {
            fault.extend(value.to_le_bytes());
        }
        writer
            .write_record_from(
                15,
                NormalizedRecord {
                    event_id: TracepointId::PageFault as u32,
                    schema_version: 1,
                    timestamp_ns: 260,
                    cpu_id: 3,
                    pid: 40,
                    tid: 41,
                    task_id: 99,
                    payload: fault,
                },
            )
            .unwrap();
        fs::write(&f.capture, writer.finish(500).unwrap()).unwrap();
        f
    }

    fn export_selected(&self, weight: &str) -> serde_json::Value {
        let output = self.cli(&[
            "--from-ns",
            "150",
            "--json",
            "--weight",
            weight,
            "--oncpu",
            self.dir.join(format!("{weight}.folded")).to_str().unwrap(),
            "--perf-data",
            self.dir.join(format!("{weight}.data")).to_str().unwrap(),
            "--bundle",
            self.dir.to_str().unwrap(),
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

#[test]
fn mixed_recorder_query_keeps_source_identity_and_weights_at_cli_boundary() {
    let f = Fixture::mixed();
    let original = fs::read(&f.capture).unwrap();
    for (weight, unit, expected) in [("samples", "samples", 3), ("period", "period_ns", 50)] {
        let report = f.export_selected(weight);
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(f.dir.join(format!("{weight}.data.json"))).unwrap())
                .unwrap();
        assert_eq!(report["records_count"], 5);
        assert_eq!(report["software_samples_with_ip"], 3);
        assert_eq!(
            report["sample_weight"],
            serde_json::json!({"unit":unit,"total":expected,"samples":3})
        );
        assert_eq!(manifest["query"], report["query"]);
        assert_eq!(manifest["sample_count"], 3);
        assert_eq!(manifest["total_period_ns"], 50);
        assert_eq!(manifest["selected_weight"], expected);
        assert_eq!(manifest["weight_unit"], unit);
        let samples = manifest["samples"].as_array().unwrap();
        assert_eq!(
            samples
                .iter()
                .map(|s| s["sequence_index"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [1, 2, 0]
        );
        assert_eq!(
            samples
                .iter()
                .map(|s| s["source_id"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [7, 9, 11]
        );
        assert_eq!(samples[2]["cpu"], 4);
        assert_eq!(samples[2]["tid"], 41);
        assert_eq!(manifest["sources"][2]["target"], 777);
        assert_eq!(manifest["sources"][2]["task_id"], 99);
        assert_eq!(manifest["sources"][2]["kernel_event_id"], 9011);
        let folded = fs::read_to_string(f.dir.join(format!("{weight}.folded"))).unwrap();
        let total: u64 = folded
            .lines()
            .map(|line| line.rsplit_once(' ').unwrap().1.parse::<u64>().unwrap())
            .sum();
        assert_eq!(total, expected);
        let table = f.cli(&["--from-ns", "150", "--weight", weight]);
        assert!(table.status.success());
        assert!(
            String::from_utf8_lossy(&table.stdout)
                .contains(&format!("CPU samples: 3; weight: {expected} {unit}"))
        );
    }
    assert_eq!(fs::read(&f.capture).unwrap(), original);
    let alias = f.dir.join("capture-alias.data");
    fs::hard_link(&f.capture, &alias).unwrap();
    let second = f.cli(&[
        "--from-ns",
        "150",
        "--perf-data",
        alias.to_str().unwrap(),
        "--bundle",
        f.dir.to_str().unwrap(),
    ]);
    assert!(!second.status.success());
    assert!(!f.dir.join("capture-alias.data.json").exists());
    assert_eq!(fs::read(&f.capture).unwrap(), original);
}

#[test]
#[ignore = "requires native Linux perf and the pinned FlameGraph scripts"]
fn native_perf_and_flamegraph_preserve_mixed_query_for_both_weight_units() {
    let f = Fixture::mixed();
    let perf = std::env::var_os("PULSE_PERF")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|directory| directory.join("perf"))
                .find(|path| path.is_file())
                .expect("native perf in PATH")
        });
    let flamegraph = std::env::var("FLAMEGRAPH_DIR")
        .unwrap_or_else(|_| "/tmp/pulse-perf-research-181/flamegraph".into());
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (weight, expected) in [("samples", 3), ("period", 50)] {
        f.export_selected(weight);
        let output_dir = f.dir.join(format!("{weight}-report"));
        let output = Command::new("python3")
            .arg(repo.join("scripts/perf_pipeline.py"))
            .arg(f.dir.join(format!("{weight}.data")))
            .arg("--manifest")
            .arg(f.dir.join(format!("{weight}.data.json")))
            .arg("--bundle")
            .arg(&f.dir)
            .arg("--perf")
            .arg(&perf)
            .arg("--flamegraph")
            .arg(&flamegraph)
            .arg("--output")
            .arg(&output_dir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "native pipeline failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let script = fs::read_to_string(output_dir.join("script.stdout")).unwrap();
        assert_eq!(script.matches("cpu-clock:").count(), 2, "{script}");
        assert_eq!(script.matches("task-clock:").count(), 1, "{script}");
        let headers: Vec<Vec<&str>> = script
            .lines()
            .filter(|line| line.starts_with("work "))
            .map(|line| line.split_whitespace().skip(1).collect())
            .collect();
        assert_eq!(
            headers,
            vec![
                vec!["40/41", "[003]", "0.000000200:", "10", "cpu-clock:HG:"],
                vec!["40/41", "[003]", "0.000000200:", "10", "cpu-clock:HG:"],
                vec!["40/41", "[004]", "0.000000300:", "30", "task-clock:HG:"],
            ]
        );
        assert!(script.contains("leaf"), "{script}");
        let report = fs::read_to_string(output_dir.join("report.stdout")).unwrap();
        let rows: Vec<Vec<&str>> = report
            .lines()
            .filter(|line| {
                line.split_whitespace()
                    .next()
                    .is_some_and(|first| first.ends_with('%'))
                    && line.contains("leaf")
            })
            .map(|line| line.split_whitespace().collect())
            .collect();
        let report_samples: u64 = rows.iter().map(|row| row[1].parse::<u64>().unwrap()).sum();
        let report_period: u64 = rows.iter().map(|row| row[2].parse::<u64>().unwrap()).sum();
        assert_eq!((report_samples, report_period), (3, 50), "{report}");
        let ids = fs::read_to_string(output_dir.join("buildid-list.stdout")).unwrap();
        assert!(
            ids.trim().starts_with("/artifacts/"),
            "missing build-id must remain absent: {ids}"
        );
        let folded = fs::read_to_string(output_dir.join("flamegraph.folded")).unwrap();
        let total: u64 = folded
            .lines()
            .map(|line| line.rsplit_once(' ').unwrap().1.parse::<u64>().unwrap())
            .sum();
        assert_eq!(total, expected);
        let svg = fs::read_to_string(output_dir.join("flamegraph.svg")).unwrap();
        assert!(svg.contains(if weight == "samples" {
            "samples"
        } else {
            "nanoseconds"
        }));
        let result: serde_json::Value =
            serde_json::from_slice(&fs::read(output_dir.join("result.json")).unwrap()).unwrap();
        assert_eq!(result["selected_weight"], expected);
        assert_eq!(result["sample_count"], 3);
        assert_eq!(result["total_period_ns"], 50);
        // The existing independent oracle checks both perf's raw bytes and its
        // decoded summary, including logical IDs and user context markers.
        let oracle = Command::new("python3")
            .arg("-c")
            .arg(
                "import pathlib,sys; sys.path.insert(0,sys.argv[1]); import perf_evidence; \
                 actual=perf_evidence.native_samples(pathlib.Path(sys.argv[2]).read_text()); \
                 marker=(1<<64)-512; expected=[(7,0x400110,40,41,200,3,10,2,(marker,0x400110)), \
                 (9,0x400110,40,41,200,3,10,2,(marker,0x400110)), \
                 (11,0x400110,40,41,300,4,30,2,(marker,0x400110))]; assert \
                 actual==expected,(actual,expected)",
            )
            .arg(repo.join("tests/bpf_sampling"))
            .arg(output_dir.join("dump.stdout"))
            .output()
            .unwrap();
        assert!(
            oracle.status.success(),
            "{}",
            String::from_utf8_lossy(&oracle.stderr)
        );
    }
}
