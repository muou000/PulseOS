use pulse_bpf_schema::{
    ContextCommon, PageFaultAccess, PageFaultClassification, PageFaultContext, PageFaultOrigin,
    PageFaultOutcome, TracepointId, lookup_by_id, lookup_by_name,
};

#[test]
fn page_fault_completion_has_an_append_only_discoverable_wire_contract() {
    let metadata = lookup_by_id(8).unwrap();
    assert_eq!(metadata, lookup_by_name("mm", "page_fault").unwrap());
    assert_eq!(metadata.id, TracepointId::PageFault);
    assert_eq!(metadata.version, 1);
    assert_eq!(metadata.context_size, 80);
    for (name, offset, size) in [
        ("fault_address", 40, 8),
        ("start_ns", 48, 8),
        ("elapsed_ns", 56, 8),
        ("access", 64, 4),
        ("origin", 68, 4),
        ("outcome", 72, 4),
        ("classification", 76, 4),
    ] {
        let field = metadata
            .fields
            .iter()
            .find(|field| field.name == name)
            .unwrap();
        assert_eq!((field.offset, field.size), (offset, size));
    }
    assert_eq!(lookup_by_id(7).unwrap().name, "phase_marker");
    assert!(lookup_by_id(100).is_err());
}

#[test]
fn resolver_duration_and_origin_remain_separate_from_fault_address_and_cpu() {
    let record = PageFaultContext {
        common: ContextCommon::new(TracepointId::PageFault, 350, 6, 41, 42, 900),
        fault_address: 0x1234_5678_9abc,
        start_ns: 100,
        elapsed_ns: 250,
        access: PageFaultAccess::READ | PageFaultAccess::WRITE,
        origin: PageFaultOrigin::Kernel as u32,
        outcome: PageFaultOutcome::NoMemory as u32,
        classification: PageFaultClassification::Unknown as u32,
    };
    let bytes = record.to_bytes();
    assert_eq!(bytes.len(), 80);
    assert_eq!(&bytes[0..8], &[8, 0, 0, 0, 1, 0, 0, 0]);
    assert_eq!(&bytes[8..16], &350u64.to_le_bytes());
    assert_eq!(
        &bytes[16..32],
        &[6, 0, 0, 0, 41, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(&bytes[32..40], &900u64.to_le_bytes());
    assert_eq!(&bytes[40..48], &0x1234_5678_9abcu64.to_le_bytes());
    assert_eq!(&bytes[48..56], &100u64.to_le_bytes());
    assert_eq!(&bytes[56..64], &250u64.to_le_bytes());
    assert_eq!(
        &bytes[64..80],
        &[3, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn completion_uses_measured_wall_time_and_rejects_clock_regression() {
    let make = |end| {
        PageFaultContext::from_completion(
            ContextCommon::new(TracepointId::PageFault, end, 7, 40, 41, 99),
            0x400000,
            100,
            PageFaultAccess::EXECUTE,
            PageFaultOrigin::User,
            PageFaultOutcome::Resolved,
        )
    };
    let completed = make(350).unwrap();
    assert_eq!(completed.elapsed_ns, 250);
    assert_eq!(completed.common.cpu_id, 7);
    assert_eq!(completed.common.task_id, 99);
    assert_eq!(
        completed.classification,
        PageFaultClassification::Unknown as u32
    );
    assert_eq!(make(100).unwrap().elapsed_ns, 0); // same clock tick is observable
    assert!(make(99).is_none()); // never fabricate a zero duration for regression
}
