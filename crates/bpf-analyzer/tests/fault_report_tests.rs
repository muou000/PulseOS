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

#[test]
fn successful_classes_and_unsuccessful_resolvers_have_disjoint_counts() {
    let mut events = vec![
        fault(99, 0x400000, 100, 101, 1, 2),
        fault(99, 0x401000, 100, 900, 800, 1),
        fault(99, 0x402000, 100, 200, 100, 0),
    ];
    for outcome_tag in [2, 3, 4] {
        let mut event = fault(99, 0x403000, 100, 200, 100, 0);
        if let EventPayload::PageFault { outcome, .. } = &mut event.payload {
            *outcome = outcome_tag;
        }
        events.push(event);
    }
    let report = FaultReport::compute(&events, true);
    assert_eq!((report.resolved_minor, report.resolved_major, report.resolved_unknown,
        report.unsuccessful), (1, 1, 1, 3));
    assert_eq!(report.valid_events, 6);
    assert_eq!(report.unknown_classification, 4);
    assert!(!report.is_complete);
    let json: serde_json::Value = serde_json::from_str(&report.render_json()).unwrap();
    assert_eq!(json["resolved_minor"], 1);
    assert_eq!(json["resolved_major"], 1);
    assert_eq!(json["resolved_unknown"], 1);
    assert_eq!(json["unsuccessful"], 3);
    let not_applicable: Vec<_> = json["groups"].as_array().unwrap().iter()
        .filter(|g| g["classification_applicability"] == "not_applicable").collect();
    assert_eq!(not_applicable.len(), 3);
    assert!(not_applicable.iter().all(|g| g["classification_id"] == 0));
    assert!(report.render_text().contains("resolved_minor=1 resolved_major=1 resolved_unknown=1 unsuccessful=3"));

    events.remove(2);
    assert!(FaultReport::compute(&events, true).is_complete,
        "fully observed failed outcomes are separate from unknown successful classification");
}

#[test]
fn contradictory_failed_minor_or_major_records_never_enter_success_counts() {
    let mut events = Vec::new();
    for outcome_tag in [2, 3, 4] {
        for class in [1, 2] {
            let mut event = fault(99, 0x400000, 100, 200, 100, class);
            if let EventPayload::PageFault { outcome, .. } = &mut event.payload {
                *outcome = outcome_tag;
            }
            events.push(event);
        }
    }
    let report = FaultReport::compute(&events, true);
    assert_eq!((report.captured_events, report.invalid_events, report.valid_events), (6, 6, 0));
    assert_eq!((report.resolved_minor, report.resolved_major, report.resolved_unknown,
        report.unsuccessful), (0, 0, 0, 0));
    assert_eq!(report.duration.count, 0);
}

#[test]
fn raw_classification_reaches_capture_report_table_and_timeline_without_inference() {
    use bpf_analyzer::CaptureAnalyzer;
    use bpf_capture::{CaptureArch, CaptureReader, CaptureWriter, SchemaRegistry, SessionStatusCode};
    use bpf_capture::writer::NativeContextFormat;
    use pulse_bpf_schema::{ContextCommon, PageFaultClassification as Class, PageFaultContext,
        PageFaultOrigin, PageFaultOutcome as Outcome, TracepointId};

    let fixture = bpf_capture::generate_deterministic_fixture(CaptureArch::Riscv64,
        SessionStatusCode::Complete).unwrap();
    let config = CaptureReader::from_bytes(&fixture).unwrap().metadata.config;
    let mut writer = CaptureWriter::new(config, SchemaRegistry::default_pulse_registry());
    writer.start(90).unwrap();
    for (outcome, classification, address, end) in [
        (Outcome::Resolved, Class::Major, 0x400000, 101),
        (Outcome::Resolved, Class::Minor, 0x401000, 900),
        (Outcome::Resolved, Class::Unknown, 0x402000, 200),
        (Outcome::ResolverError, Class::Unknown, 0x403000, 300),
    ] {
        let raw = PageFaultContext::from_classified_completion(
            ContextCommon::new(TracepointId::PageFault, end, 2, 40, 41, 99),
            address, 100, 1, PageFaultOrigin::User, outcome, classification).unwrap().to_bytes();
        writer.ingest_perf_sample_as(2, &raw, NativeContextFormat::Tracepoint).unwrap();
    }
    let analyzer = CaptureAnalyzer::from_bytes(&writer.finish(1000).unwrap()).unwrap();
    let report = analyzer.fault_report();
    assert_eq!((report.resolved_minor, report.resolved_major, report.resolved_unknown,
        report.unsuccessful), (1, 1, 1, 1));
    let table = analyzer.render_event_table();
    assert!(table.contains("resolver_wall_ns=1 access=0x1 origin=user outcome=resolved classification=major"));
    assert!(table.contains("resolver_wall_ns=800 access=0x1 origin=user outcome=resolved classification=minor"));
    assert!(table.contains("classification=unknown classification_applicability=not_applicable"));
    let query = analyzer.query(&Default::default()).unwrap();
    let qualities: Vec<_> = query.timeline.intervals.iter().map(|i| (i.end_ns, i.quality)).collect();
    assert!(qualities.contains(&(101, "observed_closed")));
    assert!(qualities.contains(&(200, "observed_closed_unknown_classification")));
    assert!(qualities.contains(&(300, "observed_closed_not_applicable")));
}
