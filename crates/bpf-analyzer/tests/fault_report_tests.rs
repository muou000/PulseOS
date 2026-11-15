use bpf_analyzer::{EventPayload, NormalizedEvent, fault::FaultReport};

fn fault(
    task: u64,
    address: u64,
    start: u64,
    end: u64,
    elapsed: u64,
    classification: u32,
) -> NormalizedEvent {
    NormalizedEvent {
        sequence_index: 0,
        event_id: 8,
        schema_version: 1,
        timestamp_ns: end,
        cpu_id: 2,
        pid: 40,
        tid: 41,
        task_id: task,
        comm: None,
        payload: EventPayload::PageFault {
            address,
            start_ns: start,
            elapsed_ns: elapsed,
            access: 1,
            origin: 2,
            outcome: 1,
            classification,
        },
    }
}
#[test]
fn unknown_classification_has_real_counts_and_measured_duration_distribution() {
    let report = FaultReport::compute(
        &[
            fault(99, 0x401010, 100, 200, 100, 0),
            fault(99, 0x401ff0, 200, 500, 300, 0),
        ],
        true,
    );
    assert_eq!(
        (
            report.captured_events,
            report.valid_events,
            report.unknown_classification
        ),
        (2, 2, 2)
    );
    assert!(!report.is_complete);
    assert_eq!(report.groups.len(), 1);
    assert_eq!(report.groups[0].key.page_address, 0x401000);
    assert_eq!(
        (
            report.duration.count,
            report.duration.sum_ns,
            report.duration.min_ns,
            report.duration.max_ns
        ),
        (2, 400, Some(100), Some(300))
    );
    assert_eq!(
        report.duration.histogram_ns.into_iter().collect::<Vec<_>>(),
        vec![(128, 1), (512, 1)]
    );
}

#[test]
fn invalid_timings_are_not_zero_samples_and_query_clipping_does_not_shorten_latency() {
    let invalid = FaultReport::compute(
        &[fault(99, 0, 200, 199, 0, 0), fault(99, 0, 100, 300, 199, 0)],
        true,
    );
    assert_eq!(
        (
            invalid.invalid_events,
            invalid.valid_events,
            invalid.duration.count
        ),
        (2, 0, 0)
    );
    assert_eq!(invalid.duration.min_ns, None);
    assert!(!invalid.is_complete);
    let selected = vec![
        fault(99, 0, 100, 300, 200, 0),
        fault(99, 0, 210, 350, 140, 0),
        fault(99, 0, 250, 400, 150, 0),
    ];
    let query = FaultReport::compute_in_window(&selected, true, Some(200), Some(400));
    assert_eq!(
        (
            query.valid_events,
            query.query_censored,
            query.duration.count
        ),
        (3, 2, 1)
    );
    assert_eq!(
        (
            query.duration.sum_ns,
            query.duration.min_ns,
            query.duration.max_ns
        ),
        (140, Some(140), Some(140))
    );
    assert_eq!(
        query.groups[0].key.page_address, 0,
        "NULL fault VA is a real address, not missing metadata"
    );
    assert_eq!(
        (query.groups[0].record_count, query.groups[0].query_censored),
        (3, 2)
    );
    assert!(!query.is_complete);
}

#[test]
fn grouping_keeps_task_lifetimes_access_origin_outcome_and_unknown_identity_separate() {
    let a = fault(99, 0x401010, 100, 200, 100, 0);
    let mut b = a.clone();
    b.task_id = 100; // same numeric PID/TID does not merge a new task identity
    let mut c = a.clone();
    if let EventPayload::PageFault {
        access,
        origin,
        outcome,
        ..
    } = &mut c.payload
    {
        *access = 2;
        *origin = 1;
        *outcome = 3;
    }
    let mut d = fault(99, 0x402010, 100, 200, 100, 0);
    d.pid = 0;
    d.tid = 0;
    let report = FaultReport::compute(&[a, b, c, d], false);
    assert_eq!(report.groups.len(), 4);
    assert_eq!((report.valid_events, report.unknown_identity), (4, 1));
    let json = report.render_json();
    assert!(json.contains("\"classification\":\"unknown\""), "{json}");
    assert!(json.contains("\"pid\":null"), "{json}");
    assert!(json.contains("\"outcome\":\"no_memory\""), "{json}");
    assert!(json.contains("\"capture_complete\":false"), "{json}");
    assert!(json.contains("\"is_complete\":false"), "{json}");
    let text = report.render_text();
    assert!(text.contains("resolver_wall_ns"), "{text}");
    assert!(text.contains("unknown_classification=4"), "{text}");
}

#[test]
fn no_measurements_remain_null_and_wide_wall_sums_do_not_wrap() {
    let empty = FaultReport::compute(&[], true);
    assert!(!empty.is_complete);
    let json = empty.render_json();
    assert!(json.contains("\"min_ns\":null"), "{json}");
    assert!(json.contains("\"mean_ns\":null"), "{json}");
    let big = fault(99, 0, 0, u64::MAX, u64::MAX, 1);
    let report = FaultReport::compute(&[big.clone(), big], false);
    assert_eq!(report.duration.sum_ns, 36_893_488_147_419_103_230);
    assert_eq!(
        report.duration.histogram_ns.into_iter().collect::<Vec<_>>(),
        vec![(u64::MAX, 2)]
    );
}

#[test]
fn unsupported_fields_and_invalid_windows_cannot_claim_complete() {
    let valid = fault(99, 0, 100, 200, 100, 1);
    let mut unsupported = valid.clone();
    unsupported.schema_version = 2;
    let mut bad_access = valid.clone();
    if let EventPayload::PageFault { access, .. } = &mut bad_access.payload {
        *access = 8;
    }
    let mut bad_outcome = valid.clone();
    if let EventPayload::PageFault { outcome, .. } = &mut bad_outcome.payload {
        *outcome = 0;
    }
    let report = FaultReport::compute(&[unsupported, bad_access, bad_outcome], true);
    assert_eq!(
        (
            report.captured_events,
            report.invalid_events,
            report.duration.count
        ),
        (3, 3, 0)
    );
    assert!(!report.is_complete);
    let report = FaultReport::compute_in_window(&[valid], true, Some(300), Some(200));
    assert!(report.invalid_window);
    assert_eq!(
        (
            report.valid_events,
            report.query_censored,
            report.duration.count
        ),
        (1, 1, 0)
    );
    assert!(!report.is_complete);
}
