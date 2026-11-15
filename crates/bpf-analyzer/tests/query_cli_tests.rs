//! Public CLI behavior: fixture inputs are synthetic specifications, not runtime evidence.
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use bpf_capture::{
    CaptureArch, CaptureReader, CaptureWriter, NormalizedRecord, SchemaRegistry, SessionStatusCode,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    dir: PathBuf,
    capture: PathBuf,
}
impl Fixture {
    fn new(records: Vec<NormalizedRecord>) -> Self {
        Self::with_diagnostics(records, None)
    }
    fn with_diagnostics(
        records: Vec<NormalizedRecord>,
        diagnostics: Option<bpf_capture::RuntimeDiagnostics>,
    ) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "pulse-query-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let original = bpf_capture::generate_deterministic_fixture(
            CaptureArch::Riscv64,
            SessionStatusCode::Complete,
        )
        .unwrap();
        let config = CaptureReader::from_bytes(&original)
            .unwrap()
            .metadata
            .config;
        let mut writer = CaptureWriter::new(config, SchemaRegistry::default_pulse_registry());
        if let Some(diagnostics) = diagnostics {
            writer.set_diagnostics(diagnostics).unwrap();
        }
        writer.start(1).unwrap();
        for record in records {
            writer.write_record(record).unwrap();
        }
        let capture = dir.join("input.pbcapture");
        fs::write(&capture, writer.finish(1000).unwrap()).unwrap();
        Self { dir, capture }
    }
    fn cli(&self, args: &[&str]) -> Output {
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
fn record(
    id: u32,
    version: u32,
    time: u64,
    cpu: u32,
    task: u64,
    pid: u32,
    tid: u32,
    payload: Vec<u8>,
) -> NormalizedRecord {
    NormalizedRecord::new(id, version, time, cpu, pid, tid, task, payload)
}
fn sample(time: u64, task: u64, tid: u32, pc: u64, period: u64) -> NormalizedRecord {
    let mut p = vec![0; 32];
    p[..8].copy_from_slice(&period.to_le_bytes());
    p[16..24].copy_from_slice(&pc.to_le_bytes());
    p[24..28].copy_from_slice(&2u32.to_le_bytes());
    record(0x1001, 2, time, 0, task, 100, tid, p)
}
fn metadata(time: u64, task: u64, tid: u32, name: &str) -> NormalizedRecord {
    let mut p = vec![0; 32];
    p[..8].copy_from_slice(&task.to_le_bytes());
    p[8..12].copy_from_slice(&100u32.to_le_bytes());
    p[12..16].copy_from_slice(&tid.to_le_bytes());
    p[16..16 + name.len()].copy_from_slice(name.as_bytes());
    record(1, 1, time, 0, task, 100, tid, p)
}
fn phase(time: u64, end: bool) -> NormalizedRecord {
    let mut p = vec![0; 24];
    p[..4].copy_from_slice(&(if end { 2u32 } else { 1u32 }).to_le_bytes());
    p[4..8].copy_from_slice(&6u32.to_le_bytes());
    p[8..14].copy_from_slice(b"active");
    record(7, 1, time, 0, 7, 100, 101, p)
}
fn fixture() -> Fixture {
    Fixture::new(vec![
        metadata(5, 7, 101, "old"),
        sample(10, 7, 101, 0x1000, 10),
        phase(20, false),
        sample(30, 7, 101, 0x2000, 10),
        metadata(35, 7, 101, "new"),
        sample(40, 7, 101, 0x3000, 30),
        sample(40, 8, 102, 0x4000, 20),
        phase(50, true),
        sample(50, 7, 101, 0x5000, 10),
        sample(60, 7, 101, 0x6000, 10),
    ])
}
fn stdout(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}
fn number(json: &str, key: &str) -> u64 {
    let part = json
        .split(&format!("\"{key}\":"))
        .nth(1)
        .unwrap_or_else(|| panic!("missing {key}: {json}"));
    part.trim_start()
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn phase_reaches_json_and_folded_through_actual_cli() {
    let f = fixture();
    let path = f.dir.join("on.folded");
    let result = f.cli(&[
        "--phase",
        "active",
        "--json",
        "--oncpu",
        path.to_str().unwrap(),
    ]);
    let json = stdout(&result);
    assert_eq!(
        number(&json, "records_count"),
        5,
        "phase is a half-open selected window"
    );
    assert_eq!(number(&json, "perf_sample_v2"), 3);
    let folded = fs::read_to_string(path).unwrap();
    assert!(
        !folded.contains("pc:0x1000")
            && !folded.contains("pc:0x5000")
            && !folded.contains("pc:0x6000"),
        "{folded}"
    );
}

#[test]
fn historical_names_are_not_replaced_by_future_metadata() {
    let f = fixture();
    let text = stdout(&f.cli(&["--table"]));
    let early = text
        .lines()
        .find(|line| line.contains("pc=0x0000000000002000"))
        .unwrap();
    assert!(early.contains("old"), "{early}");
    let late = text
        .lines()
        .find(|line| line.contains("pc=0x0000000000003000"))
        .unwrap();
    assert!(late.contains("new"), "{late}");
}

#[test]
fn cross_cpu_equal_time_rename_is_not_a_proven_name() {
    let mut observed = sample(30, 7, 101, 0x7777, 10);
    observed.cpu_id = 1;
    let f = Fixture::new(vec![
        metadata(5, 7, 101, "old"),
        metadata(30, 7, 101, "new"),
        observed,
    ]);
    let text = stdout(&f.cli(&["--table"]));
    let row = text
        .lines()
        .find(|line| line.contains("pc=0x0000000000007777"))
        .unwrap();
    assert!(
        !row.contains("new") && !row.contains("old"),
        "unordered rename must stay unknown: {row}"
    );
}

#[test]
fn all_cli_renderers_share_phase_tid_time_and_weight() {
    let f = fixture();
    let on = f.dir.join("period.folded");
    let off = f.dir.join("blocked.folded");
    let filter = [
        "--phase",
        "active",
        "--pid",
        "100",
        "--tid",
        "101",
        "--from-ns",
        "25",
        "--to-ns",
        "45",
    ];
    let mut args = filter.to_vec();
    args.extend([
        "--json",
        "--weight",
        "period",
        "--oncpu",
        on.to_str().unwrap(),
        "--offcpu",
        off.to_str().unwrap(),
    ]);
    let result = f.cli(&args);
    let json = stdout(&result);
    assert!(
        json.trim_end().ends_with('}'),
        "progress messages must not corrupt JSON stdout: {json}"
    );
    assert_eq!(number(&json, "records_count"), 3);
    assert_eq!(number(&json, "capture_records_count"), 10);
    assert_eq!(number(&json, "context_records_count"), 7);
    assert_eq!(number(&json, "perf_sample_v2"), 2);
    let folded = fs::read_to_string(on).unwrap();
    assert_eq!(folded, "new;[user];pc:0x3000 30\nold;[user];pc:0x2000 10\n");
    assert_eq!(fs::read_to_string(off).unwrap(), "");
    let mut args = filter.to_vec();
    args.push("--table");
    let table = stdout(&f.cli(&args));
    assert!(table.contains("pc=0x0000000000002000") && table.contains("pc=0x0000000000003000"));
    assert!(!table.contains("pc=0x0000000000004000") && !table.contains("pc=0x0000000000005000"));
}

#[test]
fn missing_ambiguous_or_invalid_query_fails_before_writing_outputs() {
    let f = fixture();
    let output = f.dir.join("must-not-exist.folded");
    for filter in [
        vec!["--phase", "absent"],
        vec!["--from-ns", "40", "--to-ns", "30"],
        vec!["--tid", "-1"],
        vec!["--cpu", "4294967296"],
    ] {
        let mut args = filter;
        args.extend(["--oncpu", output.to_str().unwrap()]);
        assert!(!f.cli(&args).status.success());
        assert!(!output.exists());
    }
    let f = Fixture::new(vec![
        phase(20, false),
        phase(30, true),
        phase(40, false),
        phase(50, true),
    ]);
    assert!(!f.cli(&["--phase", "active", "--json"]).status.success());
}

fn block(time: u64) -> NormalizedRecord {
    let mut p = vec![0; 32];
    p[..8].copy_from_slice(&1u64.to_le_bytes());
    p[8..12].copy_from_slice(&1u32.to_le_bytes());
    p[16..24].copy_from_slice(&0x55u64.to_le_bytes());
    record(3, 1, time, 0, 7, 100, 101, p)
}
fn wake(time: u64, cpu: u32) -> NormalizedRecord {
    let mut p = vec![0; 40];
    p[..8].copy_from_slice(&7u64.to_le_bytes());
    p[8..16].copy_from_slice(&1u64.to_le_bytes());
    p[16..24].copy_from_slice(&99u64.to_le_bytes());
    p[24..28].copy_from_slice(&2u32.to_le_bytes());
    record(4, 1, time, cpu, 99, 200, 201, p)
}
fn switch(time: u64, cpu: u32, prev: u64, next: u64, state: u32) -> NormalizedRecord {
    let mut p = vec![0; 32];
    p[..8].copy_from_slice(&prev.to_le_bytes());
    p[8..16].copy_from_slice(&next.to_le_bytes());
    p[16..20].copy_from_slice(&state.to_le_bytes());
    record(2, 1, time, cpu, prev, 0, 0, p)
}

#[test]
fn no_samples_or_unpaired_block_never_become_folded_weights() {
    let f = Fixture::new(vec![switch(5, 0, 8, 7, 2), block(10)]);
    let on = f.dir.join("on.folded");
    let off = f.dir.join("off.folded");
    stdout(&f.cli(&[
        "--oncpu",
        on.to_str().unwrap(),
        "--offcpu",
        off.to_str().unwrap(),
    ]));
    assert!(fs::read(on).unwrap().is_empty());
    assert!(fs::read(off).unwrap().is_empty());
}

#[test]
fn scheduler_uses_remote_context_before_cpu_filter_and_reports_clipping() {
    let f = Fixture::new(vec![
        metadata(2, 7, 101, "worker"),
        block(10),
        switch(20, 0, 7, 8, 3),
        wake(30, 0),
        switch(50, 1, 9, 7, 2),
    ]);
    let json = stdout(&f.cli(&[
        "--sched-report",
        "--json",
        "--tid",
        "101",
        "--cpu",
        "1",
        "--from-ns",
        "25",
        "--to-ns",
        "60",
    ]));
    assert!(
        json.contains("\"wake_to_switch_ns\":20"),
        "remote wake was lost: {json}"
    );
    assert!(json.contains("\"run_cpu\":1") && json.contains("\"wake_cpu\":0"));
    assert_eq!(number(&json, "selected_records_count"), 1);
    assert_eq!(number(&json, "context_records_count"), 4);
    let clipped = stdout(&f.cli(&[
        "--sched-report",
        "--json",
        "--tid",
        "101",
        "--from-ns",
        "40",
        "--to-ns",
        "60",
    ]));
    assert!(!clipped.contains("\"wake_to_switch_ns\":20"));
    assert_eq!(number(&clipped, "query_clipped_intervals"), 1);
}

fn fault(time: u64, start: u64, address: u64) -> NormalizedRecord {
    let mut p = vec![0; 40];
    p[..8].copy_from_slice(&address.to_le_bytes());
    p[8..16].copy_from_slice(&start.to_le_bytes());
    p[16..24].copy_from_slice(&(time - start).to_le_bytes());
    p[24..28].copy_from_slice(&1u32.to_le_bytes());
    p[28..32].copy_from_slice(&2u32.to_le_bytes());
    p[32..36].copy_from_slice(&1u32.to_le_bytes());
    record(8, 1, time, 0, 7, 100, 101, p)
}
#[test]
fn address_query_selects_fault_address_not_cpu_instruction_pointer() {
    let f = Fixture::new(vec![
        sample(40, 7, 101, 0x8000, 10),
        fault(50, 30, 0x8000),
        fault(60, 55, 0x9000),
    ]);
    let args = [
        "--address-start",
        "0x8000",
        "--address-end",
        "0x9000",
        "--json",
    ];
    let json = stdout(&f.cli(&args));
    assert_eq!(number(&json, "records_count"), 1);
    assert_eq!(number(&json, "page_fault"), 1);
    let table = stdout(&f.cli(&[
        "--address-start",
        "0x8000",
        "--address-end",
        "0x9000",
        "--table",
    ]));
    assert!(table.contains("classification=unknown") && table.contains("resolver_wall_ns=20"));
    assert!(!table.contains("pc=0x0000000000008000") && !table.contains("address=0x9000"));
}

#[test]
fn fault_report_uses_completion_selection_but_censors_cross_window_duration() {
    let f = Fixture::new(vec![
        fault(50, 10, 0x8000),
        fault(70, 60, 0x8000),
        fault(80, 75, 0x9000),
    ]);
    let json = stdout(&f.cli(&[
        "--fault-report",
        "--json",
        "--from-ns",
        "40",
        "--to-ns",
        "80",
        "--address-start",
        "0x8000",
        "--address-end",
        "0x9000",
    ]));
    assert_eq!(number(&json, "selected_records_count"), 2);
    assert_eq!(number(&json, "query_censored"), 1);
    assert_eq!(number(&json, "captured_events"), 2);
    assert_eq!(number(&json, "sum_ns"), 10);
    assert!(json.contains("\"is_complete\":false") || json.contains("\"is_complete\": false"));
    assert!(json.contains("unknown"));
}

#[test]
fn completed_blocked_interval_has_duration_without_count_fallback() {
    let f = Fixture::new(vec![metadata(5, 7, 101, "worker"), block(10), wake(30, 1)]);
    let path = f.dir.join("wait.folded");
    stdout(&f.cli(&["--tid", "101", "--offcpu", path.to_str().unwrap()]));
    assert_eq!(
        fs::read_to_string(path).unwrap(),
        "worker;wait_reason_1;res_85 20\n"
    );
}

#[test]
#[allow(deprecated)]
fn compatibility_phase_helpers_use_half_open_window_and_preserve_prior_pairing() {
    let f = Fixture::new(vec![
        metadata(5, 7, 101, "worker"),
        block(10),
        switch(15, 0, 7, 9, 3),
        phase(20, false),
        wake(30, 0),
        switch(40, 1, 9, 7, 2),
        phase(50, true),
    ]);
    let analyzer = bpf_analyzer::CaptureAnalyzer::from_file(&f.capture).unwrap();
    let rows = analyzer.events_in_phase("active");
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|r| r.timestamp_ns < 50));
    let stats = analyzer.aggregate_statistics_in_phase("active");
    assert_eq!(
        stats.unpaired_wakes, 0,
        "an observed block before the window remains context"
    );
    assert!(
        stats.off_cpu_intervals.is_empty(),
        "clipped blocked duration is not a full selected interval"
    );
}

#[test]
fn invalid_phase_boundary_is_not_silently_treated_as_begin() {
    let mut bad = phase(20, false);
    bad.payload[..4].copy_from_slice(&0u32.to_le_bytes());
    let f = Fixture::new(vec![bad, phase(50, true), sample(30, 7, 101, 0x100, 10)]);
    assert!(!f.cli(&["--phase", "active", "--json"]).status.success());
}

#[test]
fn task_names_cannot_inject_extra_folded_stacks_or_weights() {
    let f = Fixture::new(vec![
        metadata(5, 7, 101, "bad;x\nfake 9"),
        sample(10, 7, 101, 0x1000, 10),
    ]);
    let path = f.dir.join("on.folded");
    stdout(&f.cli(&["--oncpu", path.to_str().unwrap()]));
    let folded = fs::read_to_string(path).unwrap();
    assert_eq!(folded, "bad%3Bx%0Afake 9;[user];pc:0x1000 1\n");
}

#[test]
fn pending_wake_remains_query_censored_after_its_last_visible_event() {
    let f = Fixture::new(vec![
        metadata(2, 7, 101, "worker"),
        block(10),
        switch(20, 0, 7, 8, 3),
        wake(30, 1),
    ]);
    let analyzer = bpf_analyzer::CaptureAnalyzer::from_file(&f.capture).unwrap();
    let selected = analyzer
        .query(&bpf_analyzer::query::Query {
            task_id: Some(7),
            from_ns: Some(40),
            to_ns: Some(60),
            ..Default::default()
        })
        .unwrap();
    assert!(
        selected.events.is_empty(),
        "there is no new event in this window"
    );
    assert_eq!(
        selected.scheduler.unfinished.len(),
        1,
        "the observed pending episode still spans this query"
    );
    assert_eq!(
        selected.scheduler.unfinished[0].reason,
        bpf_analyzer::UnfinishedReason::RightCensored
    );
    assert_eq!(selected.clipped_intervals, 1);
    assert_eq!(
        selected.scheduler.summary.count, 0,
        "no actual switch means no fabricated latency"
    );
    let json = stdout(&f.cli(&[
        "--sched-report",
        "--json",
        "--task",
        "7",
        "--from-ns",
        "40",
        "--to-ns",
        "60",
    ]));
    assert!(json.contains("\"reason\":\"right_censored\""), "{json}");
    assert_eq!(number(&json, "query_clipped_intervals"), 1);
    let outside = analyzer
        .query(&bpf_analyzer::query::Query {
            task_id: Some(7),
            from_ns: Some(1200),
            to_ns: Some(1300),
            ..Default::default()
        })
        .unwrap();
    assert!(
        outside.scheduler.unfinished.is_empty(),
        "do not extend observations past capture stop"
    );
}

#[test]
fn unfinished_identity_uses_actual_wake_cpu_and_sequence() {
    let f = Fixture::new(vec![
        metadata(2, 7, 101, "old"),
        block(10),
        switch(20, 0, 7, 8, 3),
        metadata(30, 7, 202, "new"),
        wake(30, 1),
    ]);
    let analyzer = bpf_analyzer::CaptureAnalyzer::from_file(&f.capture).unwrap();
    let by_new_tid = analyzer
        .query(&bpf_analyzer::query::Query {
            tid: Some(202),
            from_ns: Some(29),
            to_ns: Some(40),
            ..Default::default()
        })
        .unwrap();
    assert!(
        by_new_tid.scheduler.unfinished.is_empty(),
        "metadata on the block CPU is unordered with this remote wake"
    );
    let by_task = analyzer
        .query(&bpf_analyzer::query::Query {
            task_id: Some(7),
            from_ns: Some(29),
            to_ns: Some(40),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        by_task.scheduler.unfinished.len(),
        1,
        "unknown display identity must not erase stable task evidence"
    );
}

#[test]
fn on_cpu_start_identity_uses_actual_switch_in_sequence() {
    let f = Fixture::new(vec![
        metadata(5, 7, 101, "old"),
        switch(10, 0, 8, 7, 2),
        metadata(10, 7, 202, "new"),
        switch(20, 0, 7, 8, 2),
    ]);
    let analyzer = bpf_analyzer::CaptureAnalyzer::from_file(&f.capture).unwrap();
    let before = analyzer
        .query(&bpf_analyzer::query::Query {
            tid: Some(101),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        before.stats.on_cpu_intervals.len(),
        1,
        "a later same-time metadata record cannot replace switch-in identity"
    );
    assert_eq!(
        before.stats.on_cpu_intervals[0].comm.as_deref(),
        Some("old")
    );
    assert_eq!(before.stats.on_cpu_intervals[0].duration_ns, 10);
    let after = analyzer
        .query(&bpf_analyzer::query::Query {
            tid: Some(202),
            ..Default::default()
        })
        .unwrap();
    assert!(after.stats.on_cpu_intervals.is_empty());
}

#[test]
fn unfinished_identity_remains_unknown_after_conflicting_equal_time_metadata() {
    let mut second = metadata(25, 7, 303, "other");
    second.cpu_id = 1;
    let f = Fixture::new(vec![
        metadata(2, 7, 101, "old"),
        block(10),
        switch(20, 0, 7, 8, 3),
        metadata(25, 7, 202, "new"),
        second,
        wake(30, 2),
    ]);
    let analyzer = bpf_analyzer::CaptureAnalyzer::from_file(&f.capture).unwrap();
    for tid in [202, 303] {
        let selected = analyzer
            .query(&bpf_analyzer::query::Query {
                tid: Some(tid),
                from_ns: Some(29),
                to_ns: Some(40),
                ..Default::default()
            })
            .unwrap();
        assert!(
            selected.scheduler.unfinished.is_empty(),
            "no proven latest TID after a cross-CPU timestamp tie: {tid}"
        );
    }
    let known_pid = analyzer
        .query(&bpf_analyzer::query::Query {
            pid: Some(100),
            from_ns: Some(29),
            to_ns: Some(40),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        known_pid.scheduler.unfinished.len(),
        1,
        "the agreeing PID remains known"
    );
}

#[test]
fn blocked_episode_without_wake_is_also_censored_in_a_later_window() {
    let f = Fixture::new(vec![
        metadata(2, 7, 101, "worker"),
        block(10),
        switch(20, 0, 7, 8, 3),
    ]);
    let analyzer = bpf_analyzer::CaptureAnalyzer::from_file(&f.capture).unwrap();
    let selected = analyzer
        .query(&bpf_analyzer::query::Query {
            tid: Some(101),
            from_ns: Some(40),
            to_ns: Some(60),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(selected.scheduler.unfinished.len(), 1);
    assert_eq!(selected.clipped_intervals, 1);
    assert!(selected.scheduler.blocked_waits.is_empty());
    assert!(selected.scheduler.wake_latencies.is_empty());
}

#[test]
fn on_cpu_start_uses_last_actual_switch_in_when_timestamps_repeat() {
    let f = Fixture::new(vec![
        metadata(5, 7, 101, "old"),
        switch(10, 0, 8, 7, 2),
        metadata(10, 7, 202, "middle"),
        switch(10, 0, 7, 9, 2),
        switch(10, 0, 9, 7, 2),
        metadata(10, 7, 303, "last"),
        switch(20, 0, 7, 8, 2),
    ]);
    let analyzer = bpf_analyzer::CaptureAnalyzer::from_file(&f.capture).unwrap();
    let selected = analyzer
        .query(&bpf_analyzer::query::Query {
            tid: Some(202),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(selected.stats.on_cpu_intervals.len(), 1);
    assert_eq!(
        selected.stats.on_cpu_intervals[0].comm.as_deref(),
        Some("middle")
    );
    assert_eq!(selected.stats.on_cpu_intervals[0].duration_ns, 10);
}

fn legacy_sample(time: u64) -> NormalizedRecord {
    let mut p = vec![0; 16];
    p[..8].copy_from_slice(&10u64.to_le_bytes());
    p[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    record(0x1000, 1, time, 0, 7, 100, 101, p)
}
#[test]
fn privilege_query_selects_explicit_sample_mode_and_fault_origin() {
    let mut kernel = sample(11, 7, 101, 0x1000, 30);
    kernel.payload[24..28].copy_from_slice(&1u32.to_le_bytes());
    let mut kernel_fault = fault(30, 15, 0x8000);
    kernel_fault.payload[28..32].copy_from_slice(&1u32.to_le_bytes());
    let f = Fixture::new(vec![
        metadata(2, 7, 101, "worker"),
        sample(10, 7, 101, 0x1000, 10),
        kernel,
        fault(20, 12, 0x8000),
        kernel_fault,
        legacy_sample(35),
        block(40),
    ]);
    for (mode, weight) in [("user", 10), ("kernel", 30)] {
        let file = f.dir.join(format!("{mode}.folded"));
        let json = stdout(&f.cli(&[
            "--mode",
            mode,
            "--json",
            "--weight",
            "period",
            "--oncpu",
            file.to_str().unwrap(),
        ]));
        assert_eq!(number(&json, "records_count"), 2);
        assert_eq!(number(&json, "perf_sample_v2"), 1);
        assert_eq!(number(&json, "page_fault"), 1);
        assert!(!json.contains("\"task_block\""));
        assert_eq!(
            fs::read_to_string(file).unwrap(),
            format!("worker;[{mode}];pc:0x1000 {weight}\n")
        );
    }
    let unknown = Fixture::new(vec![legacy_sample(10), block(20)]);
    let out = unknown.dir.join("empty.folded");
    let json =
        stdout(&unknown.cli(&["--mode", "user", "--json", "--oncpu", out.to_str().unwrap()]));
    assert_eq!(number(&json, "records_count"), 0);
    assert!(fs::read(out).unwrap().is_empty());
    assert!(!f.cli(&["--mode", "unknown", "--json"]).status.success());
    let rejected = f.cli(&["--mode", "user", "--sched-report", "--json"]);
    assert!(!rejected.status.success());
}

fn check_json_file(path: &std::path::Path, script: &str) {
    // Python's standard JSON reader is an independent serialization oracle;
    // python3 is already required by this repository's build/capture scripts.
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn timeline_preserves_raw_context_and_clipped_original_endpoints() {
    let f = Fixture::new(vec![
        metadata(2, 7, 101, "worker"),
        block(10),
        switch(20, 0, 7, 8, 3),
        wake(30, 0),
        switch(50, 1, 9, 7, 2),
    ]);
    let timeline = f.dir.join("timeline.json");
    let json = stdout(&f.cli(&[
        "--tid",
        "101",
        "--from-ns",
        "40",
        "--to-ns",
        "60",
        "--timeline",
        timeline.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(number(&json, "records_count"), 1);
    check_json_file(
        &timeline,
        r#"
import json,sys
x=json.load(open(sys.argv[1]));assert x['timeline_version']==1
assert [e['timestamp_ns'] for e in x['events']]==[50]
assert x['query']['from_ns']==40 and x['query']['to_ns']==60
assert {e['timestamp_ns'] for e in x['context_events']}=={2,10,20,30}
a=next(i for i in x['intervals'] if i['kind']=='wake_to_switch')
assert (a['start_ns'],a['end_ns'])==(30,50)
assert (a['visible_start_ns'],a['visible_end_ns'])==(40,50) and a['query_clipped']
assert a['start_cpu']==0 and a['end_cpu']==1
assert x['scheduler']['summary']['count']==0
wake=next(e for e in x['context_events'] if e['event_name']=='task_wake')
assert wake['task_id']==99 and wake['subjects']==[7]
assert int.from_bytes(bytes.fromhex(wake['payload_hex'])[:8],'little')==7
assert wake['semantic']['target_task_id']==7
assert next(s for s in x['schemas'] if s['event_id']==4)['payload_size']==40
assert all(e['timestamp_ns']!=40 for e in x['events']+x['context_events'])
"#,
    );
}

#[test]
fn timeline_pending_has_no_fabricated_end_or_boundary_event() {
    let f = Fixture::new(vec![
        metadata(2, 7, 101, "worker"),
        block(10),
        switch(20, 0, 7, 8, 3),
        wake(30, 1),
    ]);
    let path = f.dir.join("pending.json");
    stdout(&f.cli(&[
        "--task",
        "7",
        "--from-ns",
        "40",
        "--to-ns",
        "60",
        "--timeline",
        path.to_str().unwrap(),
    ]));
    check_json_file(
        &path,
        r#"
import json,sys
x=json.load(open(sys.argv[1]));assert x['events']==[] and x['intervals']==[]
assert len(x['unfinished'])==1
p=x['unfinished'][0];assert p['reason']=='right_censored' and p['start_ns']==30
assert p['end_ns'] is None and p['visible_end_ns'] is None
assert p['visible_start_ns']==40 and p['observation_limit_ns']==60
assert not p['observation_limit_is_endpoint'] and p['query_clipped']
assert {e['timestamp_ns'] for e in x['context_events']}=={2,10,20,30}
assert x['scheduler']['summary']['count']==0
"#,
    );
}

#[test]
fn timeline_mode_empty_and_unknown_records_are_explicit() {
    let f = Fixture::new(vec![legacy_sample(10), block(20)]);
    let empty = f.dir.join("empty.json");
    stdout(&f.cli(&["--mode", "user", "--timeline", empty.to_str().unwrap()]));
    check_json_file(
        &empty,
        r#"
import json,sys
x=json.load(open(sys.argv[1]));assert x['query']['mode']=='user'
assert x['events']==[] and x['intervals']==[] and x['unfinished']==[] and x['context_events']==[]
"#,
    );
    let all = f.dir.join("all.json");
    stdout(&f.cli(&["--timeline", all.to_str().unwrap()]));
    check_json_file(
        &all,
        r#"
import json,sys
x=json.load(open(sys.argv[1]));assert all(e['privilege'] is None for e in x['events'])
assert x['events'][0]['semantic']['mode'] is None
"#,
    );
    let before = fs::read(&f.capture).unwrap();
    assert!(
        !f.cli(&["--timeline", f.capture.to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(fs::read(&f.capture).unwrap(), before);
}

#[test]
fn timeline_fault_interval_clips_display_but_retains_original_observation() {
    let mut other = fault(90, 20, 0x8000);
    other.payload[28..32].copy_from_slice(&1u32.to_le_bytes());
    let f = Fixture::new(vec![fault(100, 10, 0x8000), other]);
    let path = f.dir.join("faults.json");
    stdout(&f.cli(&[
        "--mode",
        "user",
        "--from-ns",
        "40",
        "--to-ns",
        "60",
        "--timeline",
        path.to_str().unwrap(),
    ]));
    check_json_file(
        &path,
        r#"
import json,sys
x=json.load(open(sys.argv[1]));assert x['events']==[]
assert len(x['intervals'])==1 and len(x['context_events'])==1
p=x['intervals'][0];assert p['kind']=='page_fault_resolve'
assert (p['start_ns'],p['end_ns'],p['visible_start_ns'],p['visible_end_ns'])==(10,100,40,60)
assert p['query_clipped'] and p['start_cpu'] is None and p['end_cpu']==0
assert x['context_events'][0]['timestamp_ns']==100 and x['context_events'][0]['privilege']=='user'
"#,
    );
}

#[test]
fn disjoint_phase_intersection_has_no_inverted_timeline_interval() {
    let f = Fixture::new(vec![
        phase(20, false),
        phase(50, true),
        fault(100, 10, 0x8000),
    ]);
    let path = f.dir.join("empty-window.json");
    stdout(&f.cli(&[
        "--phase",
        "active",
        "--from-ns",
        "70",
        "--to-ns",
        "80",
        "--timeline",
        path.to_str().unwrap(),
    ]));
    check_json_file(
        &path,
        r#"
import json,sys
x=json.load(open(sys.argv[1]));assert x['events']==[] and x['intervals']==[] and x['unfinished']==[]
assert x['query']['empty_window']
"#,
    );
}

#[cfg(unix)]
#[test]
fn every_file_output_rejects_open_input_aliases_before_truncation() {
    let f = fixture();
    let before = fs::read(&f.capture).unwrap();
    for flag in ["--timeline", "--oncpu", "--offcpu"] {
        let alias = f
            .dir
            .join(format!("alias-{}", flag.trim_start_matches('-')));
        fs::hard_link(&f.capture, &alias).unwrap();
        let result = f.cli(&[flag, alias.to_str().unwrap()]);
        assert!(
            !result.status.success(),
            "{flag} accepted a source hardlink"
        );
        assert_eq!(
            fs::read(&f.capture).unwrap(),
            before,
            "{flag} truncated the source capture"
        );
    }
}
#[cfg(unix)]
#[test]
fn conflicting_outputs_fail_before_altering_existing_reports() {
    let f = fixture();
    let first = f.dir.join("first.out");
    let alias = f.dir.join("second.out");
    fs::write(&first, b"existing report").unwrap();
    fs::hard_link(&first, &alias).unwrap();
    let result = f.cli(&[
        "--oncpu",
        first.to_str().unwrap(),
        "--timeline",
        alias.to_str().unwrap(),
    ]);
    assert!(!result.status.success());
    assert_eq!(fs::read(&first).unwrap(), b"existing report");
    assert_eq!(fs::read(&alias).unwrap(), b"existing report");
    let result = f.cli(&[
        "--oncpu",
        first.to_str().unwrap(),
        "--offcpu",
        first.to_str().unwrap(),
    ]);
    assert!(!result.status.success());
    assert_eq!(fs::read(&first).unwrap(), b"existing report");
    stdout(&f.cli(&["--timeline", first.to_str().unwrap()]));
    check_json_file(
        &first,
        "import json,sys; assert json.load(open(sys.argv[1]))['timeline_version']==1",
    );
}

#[test]
fn scheduling_time_does_not_guess_idle_or_busy_from_task_id_pid_or_name() {
    let mut kernel_named_idle = metadata(2, 7, 0, "idle");
    kernel_named_idle.pid = 0;
    kernel_named_idle.tid = 0;
    kernel_named_idle.payload[8..12].copy_from_slice(&0u32.to_le_bytes());
    let f = Fixture::new(vec![
        kernel_named_idle,
        metadata(3, 8, 102, "idle"),
        switch(5, 0, 9, 7, 2),
        switch(15, 0, 7, 8, 2),
        switch(25, 0, 8, 7, 2),
        metadata(35, 8, 102, "idle"),
    ]);
    let analyzer = bpf_analyzer::CaptureAnalyzer::from_file(&f.capture).unwrap();
    for stats in [
        analyzer.aggregate_statistics(),
        analyzer.query(&Default::default()).unwrap().stats,
    ] {
        let cpu = &stats.cpu_stats[&0];
        assert_eq!(cpu.scheduled_time_ns, 20);
        assert_eq!(cpu.busy_time_ns, None);
        assert_eq!(cpu.idle_time_ns, None);
    }
    for json in [stdout(&f.cli(&["--json"])), analyzer.render_json()] {
        assert!(
            json.contains("\"busy_time_ns\": null"),
            "task IDs and names provide no busy-time evidence: {json}"
        );
        assert!(
            json.contains("\"idle_time_ns\": null"),
            "nonzero idle task IDs cannot be guessed from names: {json}"
        );
        assert_eq!(
            number(&json, "scheduled_time_ns"),
            20,
            "only the two actually closed switch intervals count"
        );
        assert!(json.contains("unsupported"));
    }
}

#[test]
fn regressing_scheduler_clock_does_not_create_a_sorted_on_cpu_interval() {
    let f = Fixture::new(vec![switch(20, 0, 1, 2, 2), switch(10, 0, 2, 1, 2)]);
    let analyzer = bpf_analyzer::CaptureAnalyzer::from_file(&f.capture).unwrap();
    let selected = analyzer.query(&Default::default()).unwrap();
    assert_eq!(selected.scheduler.diagnostics.clock_regressions, 1);
    assert_eq!(
        selected.events.len(),
        2,
        "retain both original observations"
    );
    assert_eq!(selected.stats.cpu_stats[&0].scheduled_time_ns, 0);
    assert!(selected.stats.on_cpu_intervals.is_empty());
    assert!(
        selected
            .timeline
            .intervals
            .iter()
            .all(|i| i.kind != "on_cpu")
    );
    assert_eq!(
        analyzer.aggregate_statistics().cpu_stats[&0].scheduled_time_ns,
        0
    );
    assert_eq!(number(&analyzer.render_json(), "scheduled_time_ns"), 0);

    let timeline = f.dir.join("regression.json");
    let json = stdout(&f.cli(&["--json", "--timeline", timeline.to_str().unwrap()]));
    assert_eq!(number(&json, "scheduled_time_ns"), 0);
    check_json_file(
        &timeline,
        r#"
import json,sys
x=json.load(open(sys.argv[1]))
assert x['scheduler']['diagnostics']['clock_regressions']==1
assert [e['timestamp_ns'] for e in x['events']]==[10,20]
assert not any(i['kind']=='on_cpu' for i in x['intervals'])
"#,
    );
}

#[test]
fn independent_sample_queue_and_other_cpu_regression_preserve_valid_scheduling_time() {
    let mut independent_sample = sample(100, 7, 101, 0x7000, 10);
    independent_sample.cpu_id = 1;
    let f = Fixture::new(vec![
        independent_sample,
        switch(20, 0, 1, 2, 2),
        switch(10, 0, 2, 1, 2),
        switch(10, 1, 8, 7, 2),
        switch(30, 1, 7, 8, 2),
    ]);
    let analyzer = bpf_analyzer::CaptureAnalyzer::from_file(&f.capture).unwrap();
    let selected = analyzer.query(&Default::default()).unwrap();
    assert_eq!(selected.scheduler.diagnostics.clock_regressions, 1);
    assert_eq!(selected.stats.cpu_stats[&0].scheduled_time_ns, 0);
    assert_eq!(selected.stats.cpu_stats[&1].scheduled_time_ns, 20);
    assert_eq!(selected.stats.on_cpu_intervals.len(), 1);
    let interval = &selected.stats.on_cpu_intervals[0];
    assert_eq!(
        (
            interval.cpu_id,
            interval.task_id,
            interval.start_ns,
            interval.end_ns
        ),
        (1, 7, 10, 30)
    );
    let timeline = f.dir.join("independent.json");
    let json = stdout(&f.cli(&[
        "--cpu",
        "1",
        "--json",
        "--timeline",
        timeline.to_str().unwrap(),
    ]));
    assert_eq!(number(&json, "scheduled_time_ns"), 20);
    check_json_file(
        &timeline,
        r#"
import json,sys
x=json.load(open(sys.argv[1]))
assert x['scheduler']['diagnostics']['clock_regressions']==1
bars=[i for i in x['intervals'] if i['kind']=='on_cpu']
assert len(bars)==1
assert (bars[0]['start_ns'],bars[0]['end_ns'],bars[0]['start_cpu'])==(10,30,1)
assert bars[0]['evidence_records']==[3,4]
"#,
    );
}

fn phase_metadata(start: u64, stop: u64) -> bpf_capture::RuntimeDiagnostics {
    bpf_capture::RuntimeDiagnostics {
        phases: vec![
            bpf_capture::PhaseMeasurement {
                name: "active".into(),
                start_ns: start,
                stop_ns: stop,
                iterations: 128,
                mapped_bytes: Some(4096),
            },
            bpf_capture::PhaseMeasurement {
                name: "baseline".into(),
                start_ns: 1,
                stop_ns: 8,
                iterations: 128,
                mapped_bytes: Some(0),
            },
        ],
        ..Default::default()
    }
}
#[test]
fn typed_phase_metadata_selects_real_window_without_stream_markers() {
    let f = Fixture::with_diagnostics(
        vec![
            sample(10, 7, 101, 0x1000, 10),
            sample(30, 7, 101, 0x2000, 10),
            sample(50, 7, 101, 0x3000, 10),
        ],
        Some(phase_metadata(20, 50)),
    );
    let path = f.dir.join("typed-phase.folded");
    let json = stdout(&f.cli(&[
        "--phase",
        "active",
        "--json",
        "--oncpu",
        path.to_str().unwrap(),
    ]));
    assert_eq!(number(&json, "records_count"), 1);
    assert!(json.contains("\"phase_source\":\"runtime_diagnostics\""));
    let folded = fs::read_to_string(path).unwrap();
    assert!(folded.contains("pc:0x2000"));
    assert!(!folded.contains("pc:0x1000") && !folded.contains("pc:0x3000"));
    let baseline = stdout(&f.cli(&["--phase", "baseline", "--json"]));
    assert_eq!(number(&baseline, "records_count"), 0);
    assert!(!f.cli(&["--phase", "missing", "--json"]).status.success());
}

#[test]
fn typed_phase_and_stream_markers_must_agree_without_ambiguous_precedence() {
    let same = Fixture::with_diagnostics(
        vec![
            phase(20, false),
            sample(30, 7, 101, 0x2000, 10),
            phase(50, true),
        ],
        Some(phase_metadata(20, 50)),
    );
    let json = stdout(&same.cli(&["--phase", "active", "--json"]));
    assert_eq!(number(&json, "records_count"), 2);
    assert!(json.contains("\"phase_source\":\"both\""));
    let disagree = Fixture::with_diagnostics(
        vec![phase(20, false), phase(50, true)],
        Some(phase_metadata(21, 50)),
    );
    let result = disagree.cli(&["--phase", "active", "--json"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("disagree"));
    let ambiguous = Fixture::with_diagnostics(
        vec![
            phase(20, false),
            phase(50, true),
            phase(60, false),
            phase(80, true),
        ],
        Some(phase_metadata(20, 50)),
    );
    assert!(
        !ambiguous
            .cli(&["--phase", "active", "--json"])
            .status
            .success()
    );
    let partial = Fixture::with_diagnostics(vec![phase(20, false)], Some(phase_metadata(20, 50)));
    assert!(
        !partial
            .cli(&["--phase", "active", "--json"])
            .status
            .success(),
        "typed metadata does not silently override an incomplete stream definition"
    );
}

#[test]
fn published_runtime_capture_phase_is_usable_without_injected_markers() {
    let f = Fixture::new(Vec::new());
    let evidence =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/bpf_sampling/evidence/191");
    let output=Command::new("python3").args(["-c",r#"
import tarfile,json,sys,hashlib,struct,pathlib
base=pathlib.Path(sys.argv[1]);case=next(v for v in json.load(open(base/'index.json')) if v['label']=='rv-task')
with tarfile.open(base/case['bundle']) as archive:
 raw=archive.extractfile(case['run']+'/capture.pbcapture').read()
 facts=json.load(archive.extractfile(case['run']+'/archive.json'))
assert hashlib.sha256(raw).hexdigest()==case['members_sha256']['capture.pbcapture']
offset,count=struct.unpack_from('<QQ',raw,40);time=[];ids=[]
for _ in range(count):
 ids.append(struct.unpack_from('<I',raw,offset)[0]);time.append(struct.unpack_from('<Q',raw,offset+8)[0]);offset+=48+struct.unpack_from('<I',raw,offset+40)[0]
assert 7 not in ids
phase=facts['measurements']['attached_capture'];assert sum(phase['start_ns']<=t<phase['stop_ns'] for t in time)==82
pathlib.Path(sys.argv[2]).write_bytes(raw)
"#]).arg(evidence).arg(&f.capture).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = stdout(&f.cli(&["--phase", "attached_capture", "--json"]));
    assert_eq!(number(&json, "records_count"), 82);
    assert!(json.contains("\"phase_source\":\"runtime_diagnostics\""));
    let baseline = stdout(&f.cli(&["--phase", "baseline", "--json"]));
    assert_eq!(number(&baseline, "records_count"), 0);
}

#[test]
fn legacy_data_address_remains_readable_but_never_becomes_an_ip_frame() {
    let mut actual = sample(20, 7, 101, 0x9000, 10);
    actual.payload[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    let f = Fixture::new(vec![legacy_sample(10), actual]);
    let output = f.dir.join("ip.folded");
    let json = stdout(&f.cli(&["--json", "--oncpu", output.to_str().unwrap()]));
    let folded = fs::read_to_string(output).unwrap();
    assert!(
        !folded.contains("pc:0x1000"),
        "legacy addr was reinterpreted as an instruction pointer: {folded}"
    );
    assert!(folded.contains("pc:0x9000 1"));
    assert_eq!(number(&json, "records_count"), 2);
    assert_eq!(number(&json, "software_samples_with_ip"), 1);
    assert_eq!(number(&json, "software_samples_without_ip"), 1);
    let table = stdout(&f.cli(&["--table"]));
    assert!(table.contains("addr=0x0000000000001000 ip=unavailable mode=unavailable"));
    let timeline = f.dir.join("legacy.json");
    stdout(&f.cli(&["--timeline", timeline.to_str().unwrap()]));
    check_json_file(
        &timeline,
        r#"
import json,sys
x=json.load(open(sys.argv[1]));legacy=x['events'][0]
assert legacy['semantic']['addr']==4096 and legacy['semantic']['ip'] is None and legacy['privilege'] is None
assert int.from_bytes(bytes.fromhex(legacy['payload_hex'])[8:16],'little')==4096
assert x['events'][1]['semantic']['ip']==36864
"#,
    );
}
