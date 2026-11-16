use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use bpf_analyzer::{
    CaptureAnalyzer,
    artifact::sha256,
    query::{Query, SampleWeight},
};
use bpf_capture::{
    CaptureArch, CaptureReader, CaptureWriter, NativeContextFormat, SchemaRegistry,
    SessionStatusCode, RecorderKind,
    diagnostics::{DiagnosticIdentity, RuntimeDiagnostics},
    mapping::{Artifact, MappingMetadata},
};
use pulse_bpf_schema::{PerfEventContext, PerfSampleContext};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    bytes: Vec<u8>,
    artifact: Artifact,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn put16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn image() -> Vec<u8> {
    support::perf_test_image()
}

fn fixture(change: impl FnOnce(&mut MappingMetadata), loss: u64) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "pulse-perf-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(root.join("artifacts")).unwrap();
    let elf = image();
    let hash = sha256(&elf);
    let artifact = Artifact {
        sha256: hash.clone(),
        path: format!("artifacts/{hash}.elf"),
        gnu_build_id: None,
        debug_sha256: None,
        debug_build_id: None,
    };
    fs::write(root.join(&artifact.path), elf).unwrap();
    let mut mappings = MappingMetadata {
        journal: format!(
            "PULSE_BPF_MAPPINGS version=2 available=1 started_ns=0 snapshot_ns=1000 dropped=0 \
             records=3\nOBJECT seq=1 ts=1 object=9 sha256={hash} path_hex=2f73616d65\nSPACE seq=2 \
             ts=10 begin_ns=2 space=100 revision=1 count=1\nMAP start=4194304 len=4096 pgoff=4096 \
             perms=5 object=9\nENDSPACE\nTASK seq=3 ts=20 task=99 pid=40 tid=41 space=100 exec=0 \
             kind=bind parent=0 class=user comm_hex=776f726b\nEND records=3 dropped=0 \
             snapshot_ns=1000\n"
        ),
        artifacts: vec![artifact.clone()],
        kernel: None,
    };
    change(&mut mappings);
    let old = CaptureReader::from_bytes(
        &bpf_capture::generate_deterministic_fixture(
            CaptureArch::Riscv64,
            SessionStatusCode::Complete,
        )
        .unwrap(),
    )
    .unwrap();
    let mut writer = CaptureWriter::new(
        old.metadata.config,
        SchemaRegistry::default_pulse_registry(),
    );
    writer.set_diagnostics(RuntimeDiagnostics::default()).unwrap();
    writer.configure_recorder(vec![
        support::source(7, RecorderKind::SoftwareStackV3, 0x1002, 3, 3, 10, 123, 100, 500),
        support::source(9, RecorderKind::SoftwareStackV3, 0x1002, 3, 3, 30, 124, 100, 500),
    ], 4096).unwrap();
    writer.set_mappings(mappings).unwrap();
    writer.start(100).unwrap();
    for (logical, source, period, time) in [(7, 123u64, 10u64, 200u64), (9, 124, 30, 300)] {
        let mut raw = [0u8; 640];
        raw[..64].copy_from_slice(
            &PerfSampleContext {
                base: PerfEventContext::new(period, 0, time, 3, 40, 41, 99),
                ip: 0x400100,
                mode: 2,
                version: 2,
            }
            .to_bytes(),
        );
        for (offset, value) in [
            (64, source),
            (72, 0x8000),
            (80, 0x8020),
            (88, 0x400220),
            (96, 19),
        ] {
            put64(&mut raw, offset, value);
        }
        for (offset, value) in [(104, 3), (106, 32), (108, 3), (110, 4)] {
            put16(&mut raw, offset, value);
        }
        put32(&mut raw, 112, 32);
        put32(&mut raw, 116, 512);
        for (i, ip) in [0x400100, 0x400220, 0x400330].into_iter().enumerate() {
            put64(&mut raw, 128 + i * 8, ip);
        }
        writer
            .ingest_perf_sample_as(logical, 3, &raw, NativeContextFormat::SoftwareStackV3)
            .unwrap();
    }
    if loss > 0 {
        writer.ingest_perf_lost(3, loss);
    }
    Fixture {
        root,
        bytes: writer.finish(500).unwrap(),
        artifact,
    }
}
#[test]
fn exported_cpu_samples_preserve_source_and_period_after_query() {
    let f = fixture(|_| {}, 0);
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let selected = a
        .query(&Query {
            from_ns: Some(250),
            weight: SampleWeight::Samples,
            ..Default::default()
        })
        .unwrap();
    let exported = bpf_analyzer::perf::export(&a, &selected, &f.root, &f.bytes).unwrap();
    assert_eq!(&exported.data[..8], b"PERFILE2");
    assert!(
        exported.manifest.contains("\"sample_count\":1"),
        "{}",
        exported.manifest
    );
    assert!(exported.manifest.contains("\"total_period_ns\":30"));
    let manifest: serde_json::Value = serde_json::from_str(&exported.manifest).unwrap();
    assert_eq!(manifest["samples"][0]["source_id"], 9);
    assert_eq!(manifest["sources"][0]["kernel_event_id"], 124);
    assert!(exported.manifest.contains("\"selected_weight\":1"));
    assert!(exported.manifest.contains("\"partial_chain_count\":1"));
    assert!(exported.manifest.contains(&sha256(&f.bytes)));
}

#[test]
fn task_source_uses_stable_identity_after_numeric_tid_changes() {
    let mut f = fixture(|_| {}, 0);
    rewrite(&mut f, |data| {
        for source in &mut data.recorder.as_mut().unwrap().sources {
            source.scope = bpf_capture::CaptureScope::Task(777);
            source.bound_task_id = 99;
            source.config = bpf_capture::SourceConfig::TaskClock;
            source.requested_config = bpf_capture::SourceConfig::TaskClock;
        }
    });
    let analyzer = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let selected = analyzer.query(&Query::default()).unwrap();
    let exported = bpf_analyzer::perf::export(&analyzer, &selected, &f.root, &f.bytes).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&exported.manifest).unwrap();
    assert_eq!(manifest["sources"][0]["target"], 777);
    assert_eq!(manifest["sources"][0]["task_id"], 99);
    assert_eq!(manifest["sources"][0]["config"], 1);
    assert_eq!(manifest["samples"][0]["tid"], 41);
}

#[test]
fn missing_or_wrong_same_name_artifact_never_exports_symbols() {
    let f = fixture(|_| {}, 0);
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let selected = a.query(&Query::default()).unwrap();
    fs::remove_file(f.root.join(&f.artifact.path)).unwrap();
    assert!(
        bpf_analyzer::perf::export(&a, &selected, &f.root, &f.bytes)
            .unwrap_err()
            .contains("unavailable")
    );
    fs::write(f.root.join(&f.artifact.path), b"same name but wrong bytes").unwrap();
    assert!(
        bpf_analyzer::perf::export(&a, &selected, &f.root, &f.bytes)
            .unwrap_err()
            .contains("SHA256")
    );
}
#[test]
fn mapping_loss_and_pid_reuse_do_not_inherit_stale_mappings() {
    let f = fixture(
        |m| m.journal = m.journal.replace("dropped=0", "dropped=1"),
        0,
    );
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let selected = a.query(&Query::default()).unwrap();
    let report: serde_json::Value = serde_json::from_str(&a.render_json()).unwrap();
    assert_eq!(report["mapping_evidence"]["present"], true);
    assert_eq!(report["mapping_evidence"]["dropped"], 1);
    assert_eq!(report["mapping_evidence"]["artifacts_count"], 1);
    assert!(!a.is_complete());
    assert!(
        bpf_analyzer::perf::export(&a, &selected, &f.root, &f.bytes)
            .unwrap_err()
            .contains("journal loss")
    );
    let f = fixture(
        |m| {
            m.journal = m.journal.replace("records=3", "records=5").replace(
                "END records=5",
                "TASK seq=4 ts=250 task=99 pid=40 tid=41 space=100 exec=0 kind=exit parent=0 \
                 class=user comm_hex=776f726b\nTASK seq=5 ts=260 task=100 pid=40 tid=41 space=200 \
                 exec=0 kind=bind parent=0 class=user comm_hex=6e6577\nEND records=5",
            );
        },
        0,
    );
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let selected = a.query(&Query::default()).unwrap();
    assert!(
        bpf_analyzer::perf::export(&a, &selected, &f.root, &f.bytes)
            .unwrap_err()
            .contains("identity unavailable")
    );
}
#[test]
fn transport_loss_and_partial_chain_are_retained_without_inventing_timestamps() {
    let f = fixture(|_| {}, 7);
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let selected = a
        .query(&Query {
            weight: SampleWeight::Period,
            ..Default::default()
        })
        .unwrap();
    let exported = bpf_analyzer::perf::export(&a, &selected, &f.root, &f.bytes).unwrap();
    assert!(exported.manifest.contains("\"lost_records_total\":7"));
    assert!(exported.manifest.contains("\"capture_complete\":false"));
    assert!(exported.manifest.contains("\"attribution_complete\":false"));
    assert!(exported.manifest.contains("\"selected_weight\":40"));
    assert!(exported.manifest.contains("\"partial_chain_count\":2"));
    let manifest: serde_json::Value = serde_json::from_str(&exported.manifest).unwrap();
    let reasons = manifest["attribution_incomplete_reasons"].as_array().unwrap();
    assert!(reasons.contains(&serde_json::json!("capture_incomplete")));
    assert!(reasons.contains(&serde_json::json!("partial_callchain")));
    assert!(reasons.contains(&serde_json::json!("scheduler_and_irq_residency_unavailable")));
}

fn perf(f: &Fixture, arguments: &[&str]) -> String {
    let out = std::process::Command::new(std::env::var("PULSE_PERF").unwrap_or("perf".into()))
        .arg("--buildid-dir")
        .arg(f.root.join("buildid-cache"))
        .args(arguments)
        .arg("-i")
        .arg(f.root.join("perf.data"))
        .env("LC_ALL", "C")
        .env("DEBUGINFOD_URLS", "")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "native perf failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
#[test]
#[ignore = "requires an installed native Linux perf consumer"]
fn native_perf_resolves_pie_nonzero_pgoff_and_preserves_counts_and_periods() {
    let f = fixture(|_| {}, 0);
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let selected = a.query(&Query::default()).unwrap();
    let exported = bpf_analyzer::perf::export(&a, &selected, &f.root, &f.bytes).unwrap();
    fs::write(f.root.join("perf.data"), exported.data).unwrap();
    let script = perf(&f, &["script", "--ns", "--symfs", f.root.to_str().unwrap()]);
    assert!(
        script.contains("leaf") && script.contains("parent") && script.contains("outer"),
        "{script}"
    );
    assert_eq!(script.matches("cpu-clock:").count(), 2, "{script}");
    assert!(
        script.contains("10 cpu-clock:") && script.contains("30 cpu-clock:"),
        "{script}"
    );
    let dump = perf(&f, &["script", "-D", "--symfs", f.root.to_str().unwrap()]);
    assert!(dump.contains("PERF_RECORD_SAMPLE"), "{dump}");
    assert!(
        dump.contains("400100") && dump.contains("400220") && dump.contains("400330"),
        "{dump}"
    );
    let report = perf(
        &f,
        &[
            "report",
            "--stdio",
            "--no-children",
            "--show-nr-samples",
            "--show-total-period",
            "--percent-limit",
            "0",
            "--symfs",
            f.root.to_str().unwrap(),
        ],
    );
    assert!(report.contains("leaf"), "{report}");
    let ids = perf(&f, &["buildid-list"]);
    assert!(
        ids.trim() == format!("/{}", f.artifact.path),
        "absence of GNU build-id must remain absent: {ids}"
    );
}

#[test]
fn cli_output_cannot_overwrite_a_verified_artifact_through_hardlink() {
    let f = fixture(|_| {}, 0);
    let capture = f.root.join("capture.pbcapture");
    fs::write(&capture, &f.bytes).unwrap();
    let original = fs::read(f.root.join(&f.artifact.path)).unwrap();
    let alias = f.root.join("perf.data");
    fs::hard_link(f.root.join(&f.artifact.path), &alias).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bpf-analyzer"))
        .arg(&capture)
        .arg("--perf-data")
        .arg(&alias)
        .arg("--bundle")
        .arg(&f.root)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "CLI overwrote a verified artifact"
    );
    assert_eq!(fs::read(f.root.join(&f.artifact.path)).unwrap(), original);
}

fn rewrite(f: &mut Fixture, edit: impl FnOnce(&mut bpf_capture::reader::CaptureData)) {
    let mut data = CaptureReader::from_bytes(&f.bytes).unwrap();
    edit(&mut data);
    let mut writer = CaptureWriter::new(data.metadata.config, data.registry);
    if let Some(d) = data.diagnostics {
        writer.set_diagnostics(d).unwrap();
    }
    if let Some(m) = data.mappings {
        writer.set_mappings(m).unwrap();
    }
    let recorder = data.recorder.unwrap();
    writer.configure_recorder(recorder.sources, 4096).unwrap();
    writer.start(data.metadata.start_ns).unwrap();
    for (record, source) in data.records.into_iter().zip(recorder.record_sources) {
        assert!(writer.write_record_from(source, record).unwrap());
    }
    f.bytes = writer.finish(data.metadata.stop_ns).unwrap();
}
#[test]
fn mixed_domain_chain_and_wrong_pgoff_are_rejected_without_guessing() {
    let mut f = fixture(|_| {}, 0);
    rewrite(&mut f, |d| {
        put64(&mut d.records[0].payload, 96 + 8, 0xffff_ffff_8020_0100)
    });
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let selected = a.query(&Query::default()).unwrap();
    assert!(
        bpf_analyzer::perf::export(&a, &selected, &f.root, &f.bytes)
            .unwrap_err()
            .contains("unmapped")
    );
    let f = fixture(
        |m| m.journal = m.journal.replace("pgoff=4096", "pgoff=8192"),
        0,
    );
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let selected = a.query(&Query::default()).unwrap();
    assert!(
        bpf_analyzer::perf::export(&a, &selected, &f.root, &f.bytes)
            .unwrap_err()
            .contains("PT_LOAD")
    );
}
#[test]
fn duplicate_single_ip_sources_use_logical_bindings_without_diagnostics_inference() {
    let mut f = fixture(|_| {}, 0);
    rewrite(&mut f, |d| {
        for record in &mut d.records {
            record.event_id = bpf_capture::schema::PERF_EVENT_SOFTWARE_V2_ID;
            record.schema_version = 2;
            record.payload.truncate(32);
            put64(&mut record.payload, 0, 10);
        }
        for source in &mut d.recorder.as_mut().unwrap().sources {
            source.kind = RecorderKind::SoftwareV2;
            source.event_id = 0x1001;
            source.schema_version = 2;
            source.sample_period = 10;
            source.requested_sample_period = 10;
        }
        d.diagnostics.as_mut().unwrap().identities.clear();
    });
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let selected = a.query(&Query::default()).unwrap();
    let exported = bpf_analyzer::perf::export(&a, &selected, &f.root, &f.bytes).unwrap();
    let report: serde_json::Value = serde_json::from_str(&exported.manifest).unwrap();
    assert_eq!(report["ip_only_count"], 2);
    assert_eq!(report["total_period_ns"], 20);
    assert_eq!(report["samples"][0]["source_id"], 7);
    assert_eq!(report["samples"][1]["source_id"], 9);
    assert_eq!(report["sources"][0]["kernel_event_id"], 123);
    assert_eq!(report["sources"][1]["kernel_event_id"], 124);
}
#[test]
#[ignore = "requires an installed native Linux perf consumer"]
fn native_perf_does_not_reuse_symbols_after_pid_and_address_reuse() {
    let mut f = fixture(|_| {}, 0);
    let mut next = image();
    next[0x2901..0x2905].copy_from_slice(b"newl");
    let hash = sha256(&next);
    let artifact = Artifact {
        sha256: hash.clone(),
        path: format!("artifacts/{hash}.elf"),
        gnu_build_id: None,
        debug_sha256: None,
        debug_build_id: None,
    };
    fs::write(f.root.join(&artifact.path), next).unwrap();
    rewrite(&mut f, |d| {
        let m = d.mappings.as_mut().unwrap();
        m.artifacts.push(artifact);
        m.journal = m.journal.replace("records=3", "records=7").replace(
            "END records=7",
            &format!(
                "OBJECT seq=4 ts=210 object=10 sha256={hash} path_hex=2f73616d65\nSPACE seq=5 \
                 ts=230 begin_ns=220 space=200 revision=1 count=1\nMAP start=4194304 len=4096 \
                 pgoff=4096 perms=5 object=10\nENDSPACE\nTASK seq=6 ts=250 task=99 pid=40 tid=41 \
                 space=100 exec=0 kind=exit parent=0 class=user comm_hex=776f726b\nTASK seq=7 \
                 ts=260 task=100 pid=40 tid=41 space=200 exec=0 kind=bind parent=0 class=user \
                 comm_hex=6e6577\nEND records=7"
            ),
        );
        d.records[1].task_id = 100;
    });
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let selected = a.query(&Query::default()).unwrap();
    let exported = bpf_analyzer::perf::export(&a, &selected, &f.root, &f.bytes).unwrap();
    fs::write(f.root.join("perf.data"), exported.data).unwrap();
    let script = perf(&f, &["script", "--ns", "--symfs", f.root.to_str().unwrap()]);
    let samples: Vec<_> = script
        .split("\n\n")
        .filter(|part| part.contains("cpu-clock:"))
        .collect();
    assert_eq!(samples.len(), 2, "{script}");
    assert!(
        samples[0].contains("work")
            && samples[0].contains(" leaf+")
            && !samples[0].contains("newl"),
        "{script}"
    );
    assert!(
        samples[1].contains("new") && samples[1].contains("newl") && !samples[1].contains(" leaf+"),
        "{script}"
    );
}

#[test]
fn diagnostic_identity_strings_cannot_override_typed_source_config() {
    let mut f = fixture(|_| {}, 0);
    rewrite(&mut f, |d| {
        d.diagnostics.as_mut().unwrap().identities.push(DiagnosticIdentity {
            name: "event/123/config".into(), value: Some("1".into()),
        });
    });
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let selected = a.query(&Query::default()).unwrap();
    let exported = bpf_analyzer::perf::export(&a, &selected, &f.root, &f.bytes).unwrap();
    let report: serde_json::Value = serde_json::from_str(&exported.manifest).unwrap();
    assert_eq!(report["sources"][0]["config"], 0);
    assert_eq!(report["sources"][0]["effective_config"], "cpu-clock");
    assert_eq!(report["sources"][0]["id"], 7);
}

#[test]
fn modified_query_results_cannot_duplicate_omit_or_mislabel_samples() {
    let f = fixture(|_| {}, 0);
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    for case in 0..6 {
        let mut selected = a.query(&Query::default()).unwrap();
        match case {
            0 => selected.events.push(selected.events[0].clone()),
            1 => {
                selected.events.pop();
            }
            2 => selected.query.cpu = Some(7),
            3 => selected.from_ns = Some(299),
            4 => selected.to_ns = Some(301),
            _ => selected.phase_source = Some(bpf_analyzer::query::PhaseSource::StreamMarkers),
        }
        assert!(
            bpf_analyzer::perf::export(&a, &selected, &f.root, &f.bytes).is_err(),
            "accepted inconsistent query case {case}"
        );
    }
}

fn kernel_fixture() -> Fixture {
    let mut f = fixture(|_| {}, 0);
    let sha = f.artifact.sha256.clone();
    rewrite(&mut f, |d| {
        let m = d.mappings.as_mut().unwrap();
        m.kernel = Some(bpf_capture::mapping::KernelArtifact {
            sha256: sha,
            reference_symbol: "leaf".into(),
            reference_address: 0x2100,
            text_start: 0x2000,
            text_end: 0x3000,
        });
        m.journal = m.journal.replace("records=3", "records=4").replace(
            "END records=4",
            "KERNEL seq=4 ts=30 start=18446744071564165120 len=4096 \
             reference=18446744071564165376 symbol_hex=6c656166\nEND records=4",
        );
        for record in &mut d.records {
            let base = 0xffff_ffff_8020_0000u64;
            put64(&mut record.payload, 16, base + 0x100);
            put32(&mut record.payload, 24, 1);
            put64(&mut record.payload, 56, base + 0x220);
            for (i, offset) in [0x100, 0x220, 0x330].into_iter().enumerate() {
                put64(&mut record.payload, 96 + i * 8, base + offset);
            }
        }
    });
    f
}
#[test]
fn kernel_samples_validate_task_lifetime_mutations_and_timestamp_ties() {
    let f = kernel_fixture();
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    assert!(
        bpf_analyzer::perf::export(&a, &a.query(&Query::default()).unwrap(), &f.root, &f.bytes)
            .is_ok()
    );
    for case in 0..5 {
        let mut f = kernel_fixture();
        rewrite(&mut f, |d| {
            if case == 0 {
                d.records[1].task_id = 100;
                return;
            }
            if case == 1 {
                d.records[1].pid = 42;
                return;
            }
            let row = match case {
                2 => {
                    "TASK seq=5 ts=250 task=99 pid=40 tid=41 space=100 exec=0 kind=exit parent=0 \
                     class=user comm_hex=776f726b\n"
                }
                3 => "MUTATION seq=5 ts=250 target=task id=99 token=1 complete=0\n",
                _ => {
                    "TASK seq=5 ts=300 task=99 pid=40 tid=41 space=100 exec=0 kind=rename parent=0 \
                     class=user comm_hex=6e6577\n"
                }
            };
            let m = d.mappings.as_mut().unwrap();
            m.journal = m
                .journal
                .replace("records=4", "records=5")
                .replace("END records=5", &format!("{row}END records=5"));
        });
        let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
        assert!(
            bpf_analyzer::perf::export(&a, &a.query(&Query::default()).unwrap(), &f.root, &f.bytes)
                .is_err(),
            "kernel sample accepted uncertain task identity case {case}"
        );
    }
}

#[test]
fn kernel_idle_with_no_linux_identity_remains_explicitly_unknown() {
    let mut f = kernel_fixture();
    rewrite(&mut f, |d| {
        for r in &mut d.records {
            r.pid = 0;
            r.tid = 0;
            r.task_id = 100;
        }
    });
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let export =
        bpf_analyzer::perf::export(&a, &a.query(&Query::default()).unwrap(), &f.root, &f.bytes)
            .unwrap();
    assert_eq!(
        export
            .manifest
            .matches("\"task_identity_quality\":\"unknown_kernel_or_idle\"")
            .count(),
        2
    );
}
#[test]
#[ignore = "requires an installed native Linux perf consumer"]
fn native_perf_keeps_kernel_symbols_for_every_sample_in_the_stream() {
    let f = kernel_fixture();
    let a = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let export =
        bpf_analyzer::perf::export(&a, &a.query(&Query::default()).unwrap(), &f.root, &f.bytes)
            .unwrap();
    fs::write(f.root.join("perf.data"), export.data).unwrap();
    let kernel = f.root.join(&f.artifact.path);
    let script = perf(
        &f,
        &[
            "script",
            "--ns",
            "--symfs",
            f.root.to_str().unwrap(),
            "--vmlinux",
            kernel.to_str().unwrap(),
        ],
    );
    assert_eq!(script.matches("cpu-clock:").count(), 2, "{script}");
    assert_eq!(script.matches(" leaf+").count(), 2, "{script}");
    assert_eq!(script.matches(" parent+").count(), 2, "{script}");
    assert!(!script.contains("[unknown]"), "{script}");
}

#[test]
fn perf_attributes_preserve_monotonic_clock_and_effective_frequency() {
    let mut f = fixture(|_| {}, 0);
    rewrite(&mut f, |data| {
        let sources = &mut data.recorder.as_mut().unwrap().sources;
        sources[0].requested_sample_period = 0;
        sources[0].requested_frequency_hz = 100;
        sources[0].effective_frequency_hz = 100;
        sources[1].scope = bpf_capture::CaptureScope::Task(41);
        sources[1].bound_task_id = 99;
        sources[1].config = bpf_capture::SourceConfig::TaskClock;
        sources[1].requested_config = bpf_capture::SourceConfig::TaskClock;
    });
    let analyzer = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let exported = bpf_analyzer::perf::export(
        &analyzer, &analyzer.query(&Query::default()).unwrap(), &f.root, &f.bytes,
    ).unwrap();
    let u32_at = |at| u32::from_le_bytes(exported.data[at..at + 4].try_into().unwrap());
    let u64_at = |at| u64::from_le_bytes(exported.data[at..at + 8].try_into().unwrap());
    // Linux perf_event_attr VER3 includes clockid at offset 92. file_attr
    // appends a 16-byte ID section after the complete attr.
    assert_eq!(u64_at(16), 112);
    let first = u64_at(24) as usize;
    assert_eq!(u32_at(first + 4), 96);
    assert_eq!(u64_at(first + 8), 0); // PERF_COUNT_SW_CPU_CLOCK
    assert_eq!(u64_at(first + 16), 100); // effective sample_freq
    assert_ne!(u64_at(first + 40) & (1 << 10), 0); // freq
    assert_ne!(u64_at(first + 40) & (1 << 25), 0); // use_clockid
    assert_eq!(u32_at(first + 92), 1); // CLOCK_MONOTONIC
    let second = first + 112;
    assert_eq!(u64_at(second + 8), 1); // PERF_COUNT_SW_TASK_CLOCK
    assert_eq!(u64_at(second + 16), 30); // effective sample_period
    assert_eq!(u64_at(second + 40) & (1 << 10), 0);
    assert_ne!(u64_at(second + 40) & (1 << 25), 0);
    assert_eq!(u32_at(second + 92), 1);
}

fn source_binding_fixture() -> Fixture {
    let mut f = fixture(|_| {}, 0);
    rewrite(&mut f, |data| {
        let metadata = data.recorder.as_mut().unwrap();
        for source in &mut metadata.sources {
            source.sample_period = 10;
            source.requested_sample_period = 10;
        }
        let mut task = metadata.sources[0].clone();
        task.id = 11;
        task.kernel_event_id = 999;
        task.program_id = 11;
        task.link_id = 11;
        task.scope = bpf_capture::CaptureScope::Task(41);
        task.bound_task_id = 99;
        task.config = bpf_capture::SourceConfig::TaskClock;
        task.requested_config = bpf_capture::SourceConfig::TaskClock;
        metadata.sources.push(task);
        let template = data.records[0].clone();
        data.records = [(999, 300, 7, 40), (124, 200, 3, 41),
            (999, 200, 3, 41), (123, 200, 3, 41), (123, 300, 3, 40)]
            .into_iter().map(|(kernel, time, cpu, tid)| {
                let mut record = template.clone();
                record.timestamp_ns = time;
                record.cpu_id = cpu;
                record.tid = tid;
                put64(&mut record.payload, 32, kernel);
                record
            }).collect();
        metadata.record_sources = vec![11, 9, 11, 7, 7];
        // A nonleader exec retains task 99 while replacing TID 41 with 40,
        // publishes a new address space, and is followed by CPU migration.
        let m = data.mappings.as_mut().unwrap();
        m.journal = m.journal.replace("records=3", "records=5").replace(
            "END records=5",
            "SPACE seq=4 ts=240 begin_ns=230 space=200 revision=1 count=1\n\
             MAP start=4194304 len=4096 pgoff=4096 perms=5 object=9\nENDSPACE\n\
             TASK seq=5 ts=250 task=99 pid=40 tid=40 space=200 exec=1 kind=exec parent=0 \
             class=user comm_hex=65786563\nEND records=5",
        );
    });
    f
}

#[test]
fn duplicate_sources_survive_transport_sort_ties_exec_migration_and_query_filtering() {
    let f = source_binding_fixture();
    let analyzer = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    for (query, expected) in [
        (Query::default(), vec![(1, 9), (2, 11), (3, 7), (0, 11), (4, 7)]),
        (Query { from_ns: Some(250), ..Default::default() }, vec![(0, 11), (4, 7)]),
        (Query { cpu: Some(7), ..Default::default() }, vec![(0, 11)]),
        (Query { tid: Some(41), ..Default::default() }, vec![(1, 9), (2, 11), (3, 7)]),
    ] {
        let selected = analyzer.query(&query).unwrap();
        let export = bpf_analyzer::perf::export(&analyzer, &selected, &f.root, &f.bytes).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&export.manifest).unwrap();
        let actual: Vec<_> = manifest["samples"].as_array().unwrap().iter()
            .map(|s| (s["sequence_index"].as_u64().unwrap(), s["source_id"].as_u64().unwrap()))
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(manifest["source_identifier_domain"], "recorder_logical_source_id");
        assert_eq!(manifest["selected_weight"], expected.len());
        assert_eq!(manifest["total_period_ns"], expected.len() * 10);
    }
}

#[test]
#[ignore = "requires an installed native Linux perf consumer"]
fn native_perf_reports_typed_clocks_frequency_exec_and_migration() {
    let mut f = source_binding_fixture();
    rewrite(&mut f, |data| {
        let source = &mut data.recorder.as_mut().unwrap().sources[0];
        source.requested_sample_period = 0;
        source.requested_frequency_hz = 100;
        source.effective_frequency_hz = 100;
    });
    let analyzer = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let export = bpf_analyzer::perf::export(
        &analyzer, &analyzer.query(&Query::default()).unwrap(), &f.root, &f.bytes,
    ).unwrap();
    fs::write(f.root.join("perf.data"), export.data).unwrap();
    let attrs = perf(&f, &["evlist", "-v"]);
    assert!(attrs.contains("cpu-clock:") && attrs.contains("task-clock:"), "{attrs}");
    assert_eq!(attrs.matches("use_clockid: 1").count(), 3, "{attrs}");
    assert_eq!(attrs.matches("clockid: 1").count(), 6, "{attrs}");
    assert!(attrs.contains("{ sample_period, sample_freq }: 100") && attrs.contains("freq: 1"), "{attrs}");
    let script = perf(&f, &["script", "--ns", "--symfs", f.root.to_str().unwrap()]);
    assert_eq!(script.matches("cpu-clock:").count(), 3, "{script}");
    assert_eq!(script.matches("task-clock:").count(), 2, "{script}");
    assert_eq!(script.matches(" leaf+").count(), 5, "{script}");
    assert!(script.contains("[007]") && script.contains("exec"), "{script}");
    let dump = perf(&f, &["script", "-D"]);
    assert!(dump.contains("COMM exec: exec:40/40"), "{dump}");
}

fn unavailable_stack_fixture() -> Fixture {
    let mut f = fixture(|_| {}, 0);
    rewrite(&mut f, |data| {
        let payload = &mut data.records[0].payload;
        put16(payload, 76, 0); // saved stack length
        put16(payload, 78, 9); // InvalidInstructionPointer
        put32(payload, 80, 0); // bytes read
        payload[96..].fill(0);
    });
    f
}

#[test]
fn unavailable_saved_stack_preserves_sample_ip_without_fabricating_a_callchain() {
    let f = unavailable_stack_fixture();
    let analyzer = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let export = bpf_analyzer::perf::export(
        &analyzer, &analyzer.query(&Query::default()).unwrap(), &f.root, &f.bytes,
    ).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&export.manifest).unwrap();
    assert_eq!(manifest["sample_count"], 2);
    assert_eq!(manifest["total_period_ns"], 40);
    assert_eq!(manifest["unavailable_chain_count"], 1);
    assert_eq!(manifest["samples"][0]["saved_chain_len"], 0);
    assert_eq!(manifest["samples"][1]["saved_chain_len"], 3);
    assert_eq!(manifest["samples"][0]["chain_status"], "invalid_instruction_pointer");
    let mut offset = u64::from_le_bytes(export.data[40..48].try_into().unwrap()) as usize;
    while u32::from_le_bytes(export.data[offset..offset + 4].try_into().unwrap()) != 9 {
        offset += u16::from_le_bytes(export.data[offset + 6..offset + 8].try_into().unwrap()) as usize;
    }
    let sample = &export.data[offset..];
    assert_eq!(u64::from_le_bytes(sample[16..24].try_into().unwrap()), 0x400100);
    assert_eq!(u64::from_le_bytes(sample[56..64].try_into().unwrap()), 0); // CALLCHAIN nr
    assert_eq!(u16::from_le_bytes(sample[6..8].try_into().unwrap()), 64);
}

#[test]
#[ignore = "requires native Linux perf and the pinned FlameGraph scripts"]
fn native_perf_keeps_unavailable_callchain_as_a_real_ip_sample() {
    let f = unavailable_stack_fixture();
    let analyzer = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let export = bpf_analyzer::perf::export(
        &analyzer, &analyzer.query(&Query::default()).unwrap(), &f.root, &f.bytes,
    ).unwrap();
    fs::write(f.root.join("perf.data"), export.data).unwrap();
    let script = perf(&f, &["script", "--ns", "--symfs", f.root.to_str().unwrap()]);
    assert_eq!(script.matches("cpu-clock:").count(), 2, "{script}");
    assert_eq!(script.matches("leaf").count(), 1, "{script}");
    assert_eq!(script.matches("parent").count(), 1, "{script}");
    assert_eq!(script.matches("outer").count(), 1, "{script}");
    let ips = perf(&f, &["script", "-G", "--ns", "--symfs", f.root.to_str().unwrap()]);
    assert_eq!(ips.matches("leaf").count(), 2, "{ips}");
    assert_unavailable_pipeline(&f);
}

#[test]
#[ignore = "requires native Linux perf and the pinned FlameGraph scripts"]
fn native_flamegraph_keeps_unavailable_kernel_identity_and_weights() {
    let mut f = kernel_fixture();
    rewrite(&mut f, |data| {
        for record in &mut data.records {
            record.pid = 0;
            record.tid = 0;
            record.task_id = 100;
        }
        let payload = &mut data.records[0].payload;
        put16(payload, 76, 0);
        put16(payload, 78, 9);
        put32(payload, 80, 0);
        payload[96..].fill(0);
    });
    assert_unavailable_pipeline(&f);
}

fn assert_unavailable_pipeline(f: &Fixture) {
    let analyzer = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let perf_path = std::env::var_os("PULSE_PERF").map(PathBuf::from).unwrap_or_else(|| {
        std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|directory| directory.join("perf"))
            .find(|path| path.is_file()).expect("native perf in PATH")
    });
    let flamegraph = std::env::var("FLAMEGRAPH_DIR")
        .unwrap_or_else(|_| "/tmp/pulse-perf-research-181/flamegraph".into());
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (weight, expected, unit) in [
        (SampleWeight::Samples, 2, "samples"),
        (SampleWeight::Period, 40, "nanoseconds"),
    ] {
        let selected = analyzer.query(&Query { weight, ..Default::default() }).unwrap();
        let export = bpf_analyzer::perf::export(&analyzer, &selected, &f.root, &f.bytes).unwrap();
        fs::write(f.root.join("perf.data"), export.data).unwrap();
        fs::write(f.root.join("perf.data.json"), export.manifest).unwrap();
        let output_dir = f.root.join(format!("{unit}-report"));
        let output = std::process::Command::new("python3")
            .arg(repo.join("scripts/perf_pipeline.py"))
            .arg(f.root.join("perf.data"))
            .arg("--bundle").arg(&f.root)
            .arg("--perf").arg(&perf_path)
            .arg("--flamegraph").arg(&flamegraph)
            .arg("--output").arg(&output_dir)
            .output().unwrap();
        assert!(output.status.success(), "{}\nscript:\n{}\ncollapsed:\n{}",
            String::from_utf8_lossy(&output.stderr),
            fs::read_to_string(output_dir.join("script.stdout")).unwrap_or_default(),
            fs::read_to_string(output_dir.join("stackcollapse.stdout")).unwrap_or_default());
        let result: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(output_dir.join("result.json")).unwrap(),
        ).unwrap();
        assert_eq!(result["selected_weight"], expected);
        let folded = fs::read_to_string(output_dir.join("flamegraph.folded")).unwrap();
        assert!(folded.contains("[unavailable_callchain]"), "{folded}");
        let svg = fs::read_to_string(output_dir.join("flamegraph.svg")).unwrap();
        assert!(svg.contains("[unavailable_callchain]"), "{svg}");
        assert!(svg.contains(&format!("all ({expected} {unit}, 100%)")), "{svg}");
    }
}

#[test]
fn sample_inside_mapping_mutation_gap_is_rejected() {
    let f = fixture(|m| {
        m.journal = m.journal.replace("records=3", "records=5").replace(
            "END records=5",
            "MUTATION seq=4 ts=150 target=space id=100 token=1 complete=0\n\
             MUTATION seq=5 ts=250 target=space id=100 token=1 complete=1\nEND records=5",
        );
    }, 0);
    let analyzer = CaptureAnalyzer::from_bytes(&f.bytes).unwrap();
    let error = bpf_analyzer::perf::export(
        &analyzer, &analyzer.query(&Query::default()).unwrap(), &f.root, &f.bytes,
    ).unwrap_err();
    assert_eq!(error, "sample 0 frame 0: mutation interval in progress");
}

mod support;
