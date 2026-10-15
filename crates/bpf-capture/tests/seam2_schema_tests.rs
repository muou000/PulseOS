use bpf_capture::framing::CaptureError;
use bpf_capture::record::NormalizedRecord;
use bpf_capture::schema::SchemaRegistry;
use pulse_bpf_schema::{
    ContextCommon, SchedSwitchContext, TaskMetadataContext, TracepointId,
};

#[test]
fn test_normalized_record_round_trip() {
    let rec = NormalizedRecord {
        event_id: TracepointId::SchedSwitch as u32,
        schema_version: 1,
        timestamp_ns: 1_234_567_890,
        cpu_id: 2,
        pid: 100,
        tid: 101,
        task_id: 1000,
        payload: vec![1, 2, 3, 4, 5, 6, 7, 8],
    };

    let bytes = rec.to_bytes();
    let (parsed, consumed) = NormalizedRecord::from_bytes(&bytes).expect("record parse should succeed");
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed, rec);
}

#[test]
fn test_normalized_record_rejects_truncated() {
    let rec = NormalizedRecord {
        event_id: 1,
        schema_version: 1,
        timestamp_ns: 10,
        cpu_id: 0,
        pid: 1,
        tid: 1,
        task_id: 1,
        payload: vec![0xAA; 16],
    };
    let bytes = rec.to_bytes();
    let truncated = &bytes[..bytes.len() - 1];

    let err = NormalizedRecord::from_bytes(truncated).expect_err("should reject truncated record");
    assert_eq!(err, CaptureError::TruncatedRecord);
}

#[test]
fn test_convert_from_tracepoint_contexts() {
    // 1. SchedSwitchContext
    let sched = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 5000, 1, 10, 11, 100),
        prev_task_id: 100,
        next_task_id: 200,
        prev_state: 1,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    let rec = NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
        core::slice::from_raw_parts(&sched as *const _ as *const u8, core::mem::size_of_val(&sched))
    })
    .expect("sched switch should convert");

    assert_eq!(rec.event_id, TracepointId::SchedSwitch as u32);
    assert_eq!(rec.timestamp_ns, 5000);
    assert_eq!(rec.cpu_id, 1);
    assert_eq!(rec.pid, 10);
    assert_eq!(rec.tid, 11);
    assert_eq!(rec.task_id, 100);
    // Payload should contain the remaining fields (prev_task_id ... _pad = 32 bytes)
    assert_eq!(rec.payload.len(), 32);

    // 2. TaskMetadataContext
    let meta = TaskMetadataContext {
        common: ContextCommon::new(TracepointId::TaskMetadata, 6000, 0, 1, 1, 1),
        target_task_id: 1,
        target_pid: 1,
        target_tid: 1,
        comm: *b"init\0\0\0\0\0\0\0\0\0\0\0\0",
    };
    let rec_meta = NormalizedRecord::from_tracepoint_slice(TracepointId::TaskMetadata as u32, unsafe {
        core::slice::from_raw_parts(&meta as *const _ as *const u8, core::mem::size_of_val(&meta))
    })
    .expect("task metadata should convert");
    assert_eq!(rec_meta.payload.len(), 32);
}

#[test]
fn test_schema_registry_default_tracepoints() {
    let registry = SchemaRegistry::default_pulse_registry();
    // Registry must contain all 7 tracepoints + software perf event
    assert!(registry.lookup(TracepointId::TaskMetadata as u32).is_some());
    assert!(registry.lookup(TracepointId::SchedSwitch as u32).is_some());
    assert!(registry.lookup(TracepointId::TaskBlock as u32).is_some());
    assert!(registry.lookup(TracepointId::TaskWake as u32).is_some());
    assert!(registry.lookup(TracepointId::TaskExit as u32).is_some());
    assert!(registry.lookup(TracepointId::TaskEnqueue as u32).is_some());
    assert!(registry.lookup(TracepointId::PhaseMarker as u32).is_some());
    assert!(registry.lookup_by_name("sched", "sched_switch").is_some());
    assert!(registry.lookup_by_name("pulse", "perf_event").is_some());
}

#[test]
fn test_schema_registry_serialization_round_trip() {
    let registry = SchemaRegistry::default_pulse_registry();
    let bytes = registry.to_bytes();
    let (restored, consumed) = SchemaRegistry::from_bytes(&bytes).expect("registry parse should succeed");
    assert_eq!(consumed, bytes.len());
    assert_eq!(restored.schemas().len(), registry.schemas().len());

    for s in registry.schemas() {
        let found = restored.lookup(s.event_id).expect("schema must exist in restored registry");
        assert_eq!(found.name, s.name);
        assert_eq!(found.category, s.category);
        assert_eq!(found.version, s.version);
        assert_eq!(found.fields.len(), s.fields.len());
    }
}

#[test]
fn test_schema_validation_against_record() {
    let registry = SchemaRegistry::default_pulse_registry();

    let valid_rec = NormalizedRecord {
        event_id: TracepointId::SchedSwitch as u32,
        schema_version: 1,
        timestamp_ns: 100,
        cpu_id: 0,
        pid: 1,
        tid: 1,
        task_id: 1,
        payload: vec![0u8; 32],
    };
    assert!(registry.validate_record(&valid_rec).is_ok());

    // Schema mismatch (version != registered version)
    let bad_ver_rec = NormalizedRecord {
        schema_version: 2,
        ..valid_rec.clone()
    };
    let err = registry.validate_record(&bad_ver_rec).unwrap_err();
    assert_eq!(err, CaptureError::SchemaMismatch { expected: 1, actual: 2 });

    // Payload size mismatch
    let bad_size_rec = NormalizedRecord {
        payload: vec![0u8; 31],
        ..valid_rec
    };
    assert!(registry.validate_record(&bad_size_rec).is_err());
}
