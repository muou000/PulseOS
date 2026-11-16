//! Synthetic event streams exercise the public capture-analysis interface;
//! these are semantic oracles, not guest performance evidence.
use bpf_analyzer::CaptureAnalyzer;
use bpf_capture::{
    CaptureArch, CaptureReader, NormalizedRecord, SchemaRegistry, SessionStatusCode,
};

fn record(id: u32, timestamp: u64, cpu: u32, task: u64, payload: Vec<u8>) -> NormalizedRecord {
    NormalizedRecord::new(id, 1, timestamp, cpu, 40, 41, task, payload)
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn block(time: u64, cpu: u32, task: u64, sequence: u64) -> NormalizedRecord {
    let mut p = vec![0; 32];
    put64(&mut p, 0, sequence);
    put32(&mut p, 8, 1);
    record(3, time, cpu, task, p)
}
fn wake(time: u64, cpu: u32, task: u64, sequence: u64) -> NormalizedRecord {
    let mut p = vec![0; 40];
    put64(&mut p, 0, task);
    put64(&mut p, 8, sequence);
    put64(&mut p, 16, 9);
    put32(&mut p, 24, 2);
    record(4, time, cpu, 9, p)
}
fn switch(time: u64, cpu: u32, prev: u64, next: u64, prev_state: u32) -> NormalizedRecord {
    let mut p = vec![0; 32];
    put64(&mut p, 0, prev);
    put64(&mut p, 8, next);
    put32(&mut p, 16, prev_state);
    record(2, time, cpu, prev, p)
}
fn analyze(records: Vec<NormalizedRecord>) -> CaptureAnalyzer {
    let fixture = bpf_capture::generate_deterministic_fixture(
        CaptureArch::Riscv64,
        SessionStatusCode::Complete,
    )
    .unwrap();
    let mut config = CaptureReader::from_bytes(&fixture).unwrap().metadata.config;
    config.pulse_commit = "synthetic scheduler test".into();
    let mut writer = CaptureWriter::new(config, SchemaRegistry::default_pulse_registry());
    writer.start(1).unwrap();
    for record in records {
        writer.write_record(record).unwrap();
    }
    CaptureAnalyzer::from_bytes(&writer.finish(1000).unwrap()).unwrap()
}
#[test]
fn blocked_wait_and_wake_to_switch_are_separate_observed_intervals() {
    let report = analyze(vec![
        block(10, 0, 1, 1),
        switch(20, 0, 1, 2, 3),
        wake(30, 0, 1, 1),
        switch(50, 0, 2, 1, 2),
    ])
    .scheduler_report();
    assert_eq!(report.blocked_waits.len(), 1);
    assert_eq!(report.blocked_waits[0].duration_ns, 20);
    assert_eq!(report.wake_latencies.len(), 1);
    assert_eq!(report.wake_latencies[0].wake_to_switch_ns, 20);
    assert_eq!(report.summary.count, 1);
    assert_eq!(report.summary.min_ns, Some(20));
    assert!(!report.complete_attribution);
}

#[test]
fn zero_block_sequence_is_invalid_not_a_left_censored_episode() {
    let report = analyze(vec![wake(30, 1, 1, 0), switch(50, 0, 2, 1, 2)]).scheduler_report();
    assert_eq!(report.diagnostics.invalid_sequences, 1);
    assert_eq!(report.diagnostics.left_censored, 0);
    assert!(report.wake_latencies.is_empty());
}

fn enqueue(time: u64, cpu: u32, task: u64, reason: u32) -> NormalizedRecord {
    let mut p = vec![0; 24];
    put64(&mut p, 0, task);
    put32(&mut p, 8, cpu);
    put32(&mut p, 12, 1);
    put32(&mut p, 20, reason);
    record(6, time, cpu, task, p)
}
fn exit(time: u64, task: u64) -> NormalizedRecord {
    let mut p = vec![0; 16];
    put64(&mut p, 0, task);
    record(5, time, 0, task, p)
}
fn metadata(time: u64, task: u64, name: &str) -> NormalizedRecord {
    let mut p = vec![0; 32];
    put64(&mut p, 0, task);
    put32(&mut p, 8, 40);
    put32(&mut p, 12, 41);
    p[16..16 + name.len()].copy_from_slice(name.as_bytes());
    record(1, time, 0, task, p)
}
#[test]
fn deferred_wake_and_migration_keep_original_cross_cpu_wake_time() {
    let r = analyze(vec![
        block(10, 0, 1, 1),
        switch(20, 0, 1, 2, 3),
        wake(30, 2, 1, 1),
        enqueue(35, 2, 1, 6),
        enqueue(38, 1, 1, 5),
        switch(50, 1, 3, 1, 2),
    ])
    .scheduler_report();
    assert_eq!(r.wake_latencies.len(), 1);
    let sample = &r.wake_latencies[0];
    assert_eq!(
        (sample.wake_to_switch_ns, sample.wake_cpu, sample.run_cpu),
        (20, 2, 1)
    );
    assert_eq!((sample.enqueue_count, sample.migration_count), (2, 1));
}
#[test]
fn duplicate_records_do_not_reset_the_first_block_or_wake() {
    let r = analyze(vec![
        block(10, 0, 1, 1),
        block(12, 0, 1, 1),
        switch(20, 0, 1, 2, 3),
        wake(30, 1, 1, 1),
        wake(35, 1, 1, 1),
        switch(50, 0, 2, 1, 2),
        wake(70, 1, 1, 1),
    ])
    .scheduler_report();
    assert_eq!(r.wake_latencies.len(), 1);
    assert_eq!(
        (
            r.wake_latencies[0].blocked_wait_ns,
            r.wake_latencies[0].wake_to_switch_ns
        ),
        (20, 20)
    );
    assert_eq!(
        (
            r.diagnostics.duplicate_blocks,
            r.diagnostics.duplicate_wakes
        ),
        (1, 2)
    );
}
#[test]
fn wake_before_actual_switch_out_never_pairs_with_a_later_unrelated_run() {
    let r = analyze(vec![
        block(10, 0, 1, 1),
        wake(15, 1, 1, 1),
        switch(20, 0, 1, 2, 2),
        switch(100, 0, 2, 1, 2),
    ])
    .scheduler_report();
    assert!(r.wake_latencies.is_empty());
    assert_eq!(r.blocked_waits[0].duration_ns, 5);
    assert_eq!(r.diagnostics.ambiguous_wakes, 1);
    assert_eq!(
        r.unfinished[0].reason,
        bpf_analyzer::UnfinishedReason::UnprovenBlockedSwitchOut
    );
}
#[test]
fn preemption_and_yield_are_not_successful_wake_events() {
    let r = analyze(vec![
        enqueue(10, 0, 1, 3),
        switch(20, 0, 1, 2, 2),
        switch(30, 0, 2, 1, 2),
        enqueue(40, 0, 1, 4),
        switch(50, 0, 1, 2, 2),
        switch(60, 0, 2, 1, 2),
    ])
    .scheduler_report();
    assert_eq!(r.summary.count, 0);
    assert_eq!(r.diagnostics.wake_events, 0);
}
#[test]
fn exiting_task_does_not_transfer_pending_wake_to_reused_pid() {
    let r = analyze(vec![
        metadata(2, 1, "first"),
        block(10, 0, 1, 1),
        switch(20, 0, 1, 9, 3),
        wake(30, 1, 1, 1),
        exit(40, 1),
        metadata(60, 2, "second"),
        block(70, 0, 2, 1),
        switch(80, 0, 2, 9, 3),
        wake(90, 1, 2, 1),
        switch(100, 0, 9, 2, 2),
    ])
    .scheduler_report();
    assert_eq!(r.diagnostics.exited, 1);
    assert_eq!(r.summary.count, 1);
    assert_eq!(
        (
            r.wake_latencies[0].task_id,
            r.wake_latencies[0].wake_to_switch_ns
        ),
        (2, 10)
    );
    assert_eq!(r.wake_latencies[0].identity.comm.as_deref(), Some("second"));
}
#[test]
fn missing_left_history_and_pending_right_edge_do_not_invent_latency() {
    let r = analyze(vec![
        wake(5, 1, 3, 7),
        switch(8, 0, 9, 3, 2),
        block(10, 0, 1, 1),
        switch(20, 0, 1, 2, 3),
        wake(30, 1, 1, 1),
    ])
    .scheduler_report();
    assert!(r.wake_latencies.is_empty());
    assert_eq!(
        (r.diagnostics.left_censored, r.diagnostics.right_censored),
        (1, 1)
    );
    assert_eq!(r.unfinished[1].wake_ns, Some(30));
    assert_eq!(r.summary.mean_ns, None);
}
#[test]
fn same_timestamp_wake_and_switch_are_ambiguous_in_either_transport_order() {
    for tail in [
        vec![wake(30, 1, 1, 1), switch(30, 0, 2, 1, 2)],
        vec![switch(30, 0, 2, 1, 2), wake(30, 1, 1, 1)],
    ] {
        let mut stream = vec![block(10, 0, 1, 1), switch(20, 0, 1, 2, 3)];
        stream.extend(tail);
        let r = analyze(stream).scheduler_report();
        assert!(r.wake_latencies.is_empty());
        assert_eq!(r.diagnostics.timestamp_ties, 1);
        assert_eq!(
            r.unfinished[0].reason,
            bpf_analyzer::UnfinishedReason::AmbiguousOrder
        );
    }
}
#[test]
fn task_name_is_the_name_observed_at_wake_not_a_later_rename() {
    let r = analyze(vec![
        metadata(2, 1, "before"),
        block(10, 0, 1, 1),
        switch(20, 0, 1, 2, 3),
        wake(30, 1, 1, 1),
        metadata(40, 1, "after"),
        switch(50, 0, 2, 1, 2),
    ])
    .scheduler_report();
    assert_eq!(r.wake_latencies[0].identity.comm.as_deref(), Some("before"));
}
#[test]
fn a_clock_regression_is_not_hidden_by_timestamp_sorting_or_saturating_sub() {
    let r = analyze(vec![
        block(10, 0, 1, 1),
        switch(20, 0, 1, 2, 3),
        wake(30, 0, 1, 1),
        switch(25, 0, 2, 1, 2),
    ])
    .scheduler_report();
    assert!(r.wake_latencies.is_empty());
    assert_eq!(r.diagnostics.clock_regressions, 1);
    assert!(r.diagnostics.invalid_time_order > 0);
}
#[test]
fn sample_statistics_have_explicit_units_and_exact_nearest_rank_percentiles() {
    let r = analyze(vec![
        block(2, 0, 1, 1),
        switch(5, 0, 1, 2, 3),
        wake(10, 1, 1, 1),
        switch(11, 0, 2, 1, 2),
        block(20, 0, 1, 2),
        switch(25, 0, 1, 2, 3),
        wake(30, 1, 1, 2),
        switch(32, 0, 2, 1, 2),
        block(40, 0, 1, 3),
        switch(45, 0, 1, 2, 3),
        wake(50, 1, 1, 3),
        switch(149, 0, 2, 1, 2),
    ])
    .scheduler_report();
    assert_eq!(
        (r.summary.count, r.summary.sum_ns, r.summary.mean_ns),
        (3, 102, Some(34.0))
    );
    assert_eq!(
        (r.summary.p50_ns, r.summary.p95_ns, r.summary.p99_ns),
        (Some(2), Some(99), Some(99))
    );
    assert_eq!(r.summary.histogram[0].count, 3);
    assert_eq!(r.by_task[&1], r.summary);
}

#[test]
fn reports_keep_unknown_censored_values_and_escape_names() {
    let r = analyze(vec![
        metadata(2, 1, "a\"\nb\\c"),
        block(10, 0, 1, 1),
        switch(20, 0, 1, 2, 3),
        wake(30, 1, 1, 1),
        switch(50, 0, 2, 1, 2),
        wake(60, 1, 3, 1),
    ])
    .scheduler_report();
    let json = r.render_json();
    assert!(json.contains("\"comm\":\"a\\\"\\u000ab\\\\c\""), "{json}");
    assert!(json.contains("\"sum_ns\":\"20\""));
    assert!(json.contains("\"block_ns\":null,\"wake_ns\":60,\"reason\":\"left_censored\""));
    assert!(json.contains("\"complete_attribution\":false"));
    let text = r.render_text();
    assert!(text.contains("WAKE_TO_SWITCH_NS BLOCKED_WAIT_NS"));
    assert!(text.contains("reason=left_censored"));
    assert!(!text.contains("a\"\nb\\c"));
}
#[test]
fn loss_marks_report_partial_without_discarding_observed_intervals() {
    let a = analyze(vec![
        block(10, 0, 1, 1),
        switch(20, 0, 1, 2, 3),
        wake(30, 1, 1, 1),
        switch(50, 0, 2, 1, 2),
    ]);
    let r = bpf_analyzer::SchedulerReport::compute(&a.ordered_events(), true);
    assert!(r.capture_incomplete);
    assert_eq!(r.summary.count, 1);
    assert!(!r.complete_attribution);
    assert!(r.render_json().contains("\"capture_incomplete\":true"));
}
#[test]
fn filtering_rebuilds_summaries_without_erasing_capture_diagnostics() {
    let mut r = analyze(vec![
        block(10, 0, 1, 1),
        switch(20, 0, 1, 2, 3),
        wake(30, 1, 1, 1),
        switch(50, 0, 2, 1, 2),
        wake(60, 1, 3, 1),
    ])
    .scheduler_report();
    r.wake_latencies.clear();
    r.rebuild_summaries();
    assert_eq!(r.summary.count, 0);
    assert!(r.by_task.is_empty());
    assert_eq!(r.diagnostics.left_censored, 1);
    assert!(!r.complete_attribution);
}

#[test]
fn observed_newer_block_generation_prevents_pairing_a_stale_older_wake() {
    let r = analyze(vec![
        block(10, 0, 1, 1),
        switch(20, 0, 1, 2, 3),
        wake(30, 1, 1, 2),
        wake(40, 1, 1, 1),
        switch(50, 0, 2, 1, 2),
    ])
    .scheduler_report();
    assert!(r.wake_latencies.is_empty());
    assert_eq!(r.diagnostics.superseded, 1);
    assert_eq!(r.diagnostics.invalid_sequences, 1);
}
#[test]
fn resumed_block_with_missing_wake_is_not_an_unfinished_sleep_at_stop() {
    let r = analyze(vec![
        block(10, 0, 1, 1),
        switch(20, 0, 1, 2, 3),
        switch(50, 0, 2, 1, 2),
    ])
    .scheduler_report();
    assert!(r.wake_latencies.is_empty());
    assert_eq!(r.diagnostics.missing_wakes, 1);
    assert_eq!(r.diagnostics.right_censored, 0);
}

#[test]
fn independent_software_sample_queue_does_not_invalidate_scheduler_clock_order() {
    // Perf samples and scheduler contexts can be drained from independent source
    // queues, so their merged transport order is not a scheduler clock oracle.
    let mut payload = vec![0; 32];
    put64(&mut payload, 0, 10);
    put64(&mut payload, 16, 0x400100);
    put32(&mut payload, 24, 2);
    let sample = NormalizedRecord::new(0x1001, 2, 80, 0, 40, 41, 1, payload);
    let r = analyze(vec![
        sample,
        block(10, 0, 1, 1),
        switch(20, 0, 1, 2, 3),
        wake(30, 1, 1, 1),
        switch(50, 0, 2, 1, 2),
    ])
    .scheduler_report();
    assert_eq!(r.diagnostics.clock_regressions, 0);
    assert_eq!(r.wake_latencies.len(), 1);
}

fn renamed(time: u64, cpu: u32, pid: u32, name: &str) -> NormalizedRecord {
    let mut event = metadata(time, 1, name);
    event.cpu_id = cpu;
    put32(&mut event.payload, 8, pid);
    event
}

#[test]
fn simultaneous_cross_cpu_target_rename_keeps_conflicting_identity_unknown() {
    for suffix in [
        vec![renamed(30, 0, 99, "new"), wake(30, 1, 1, 1)],
        vec![wake(30, 1, 1, 1), renamed(30, 0, 99, "new")],
    ] {
        let mut events = vec![
            metadata(2, 1, "old"),
            block(10, 0, 1, 1),
            switch(20, 0, 1, 2, 3),
        ];
        events.extend(suffix);
        events.push(switch(50, 2, 2, 1, 2));
        let report = analyze(events).scheduler_report();
        assert_eq!(report.wake_latencies.len(), 1);
        let sample = &report.wake_latencies[0];
        assert_eq!(
            sample.wake_to_switch_ns, 20,
            "identity uncertainty does not alter timing"
        );
        assert_eq!(sample.identity.pid, None);
        assert_eq!(
            sample.identity.tid,
            Some(41),
            "agreeing identity fields remain known"
        );
        assert_eq!(sample.identity.comm, None);
    }
}

#[test]
fn same_cpu_rename_uses_the_proven_sequence_relative_to_wake() {
    for (suffix, expected_pid, expected_name) in [
        (
            vec![renamed(30, 1, 99, "new"), wake(30, 1, 1, 1)],
            99,
            "new",
        ),
        (
            vec![wake(30, 1, 1, 1), renamed(30, 1, 99, "new")],
            40,
            "old",
        ),
    ] {
        let mut events = vec![
            metadata(2, 1, "old"),
            block(10, 0, 1, 1),
            switch(20, 0, 1, 2, 3),
        ];
        events.extend(suffix);
        events.push(switch(50, 2, 2, 1, 2));
        let report = analyze(events).scheduler_report();
        assert_eq!(report.wake_latencies[0].identity.pid, Some(expected_pid));
        assert_eq!(
            report.wake_latencies[0].identity.comm.as_deref(),
            Some(expected_name)
        );
    }
}

#[test]
fn conflicting_same_time_metadata_remains_unknown_for_a_later_wake() {
    let report = analyze(vec![
        metadata(2, 1, "old"),
        block(10, 0, 1, 1),
        switch(20, 0, 1, 2, 3),
        renamed(25, 0, 98, "left"),
        renamed(25, 1, 99, "right"),
        wake(30, 2, 1, 1),
        switch(50, 0, 2, 1, 2),
    ])
    .scheduler_report();
    assert_eq!(report.wake_latencies.len(), 1);
    assert_eq!(report.wake_latencies[0].identity.pid, None);
    assert_eq!(report.wake_latencies[0].identity.tid, Some(41));
    assert_eq!(report.wake_latencies[0].identity.comm, None);
}

use support::SemanticFixture as CaptureWriter;

mod support;
