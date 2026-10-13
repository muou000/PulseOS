use pulse_bpf_schema::{
    Endianness, FieldType, TracepointError, TracepointId, all_tracepoints, lookup_by_id,
    lookup_by_name,
};

#[test]
fn test_all_tracepoints_enumerated() {
    let tracepoints = all_tracepoints();
    assert_eq!(tracepoints.len(), 7, "Registry must enumerate all 7 supported tracepoints");
}

#[test]
fn test_event_names_and_ids() {
    let expected = [
        (TracepointId::TaskMetadata, 1, "task", "task_metadata"),
        (TracepointId::SchedSwitch, 2, "sched", "sched_switch"),
        (TracepointId::TaskBlock, 3, "sched", "task_block"),
        (TracepointId::TaskWake, 4, "sched", "task_wake"),
        (TracepointId::TaskExit, 5, "task", "task_exit"),
        (TracepointId::TaskEnqueue, 6, "sched", "task_enqueue"),
        (TracepointId::PhaseMarker, 7, "pulse", "phase_marker"),
    ];

    for (id, raw_id, category, name) in expected {
        let meta_by_id = lookup_by_id(raw_id).expect("Should find metadata by ID");
        assert_eq!(meta_by_id.id, id);
        assert_eq!(meta_by_id.category, category);
        assert_eq!(meta_by_id.name, name);

        let meta_by_name = lookup_by_name(category, name).expect("Should find metadata by name");
        assert_eq!(meta_by_name.id, id);
        assert_eq!(meta_by_name.id as u32, raw_id);
    }
}

#[test]
fn test_event_version_is_v1() {
    for tp in all_tracepoints() {
        assert_eq!(tp.version, 1, "Tracepoint {} must be version 1", tp.name);
    }
}

#[test]
fn test_endianness_is_little_endian() {
    for tp in all_tracepoints() {
        assert_eq!(
            tp.endianness,
            Endianness::Little,
            "Tracepoint {} must declare little-endian encoding",
            tp.name
        );
    }
}

#[test]
fn test_fixed_byte_fields() {
    // TaskMetadata comm field is fixed 16 bytes
    let meta_metadata = lookup_by_id(TracepointId::TaskMetadata as u32).unwrap();
    let comm_field = meta_metadata
        .fields
        .iter()
        .find(|f| f.name == "comm")
        .expect("task_metadata must have comm field");
    assert_eq!(comm_field.size, 16);
    assert_eq!(comm_field.field_type, FieldType::ByteArray(16));

    // PhaseMarker phase_name field is fixed 16 bytes
    let meta_phase = lookup_by_id(TracepointId::PhaseMarker as u32).unwrap();
    let phase_field = meta_phase
        .fields
        .iter()
        .find(|f| f.name == "phase_name")
        .expect("phase_marker must have phase_name field");
    assert_eq!(phase_field.size, 16);
    assert_eq!(phase_field.field_type, FieldType::ByteArray(16));
}

#[test]
fn test_unknown_event_handling() {
    // ID 0 is invalid
    assert_eq!(lookup_by_id(0), Err(TracepointError::UnknownId(0)));

    // ID 9999 is unknown
    assert_eq!(lookup_by_id(9999), Err(TracepointError::UnknownId(9999)));

    // Unknown category / name
    assert_eq!(lookup_by_name("sched", "unknown_event"), Err(TracepointError::UnknownName));
    assert_eq!(lookup_by_name("unknown_cat", "sched_switch"), Err(TracepointError::UnknownName));
}

#[test]
fn test_deferred_event_handling() {
    // IDs 100..=105 are reserved for deferred events (such as hardware PMU counters)
    for deferred_id in 100..=105 {
        assert_eq!(
            lookup_by_id(deferred_id),
            Err(TracepointError::DeferredId(deferred_id)),
            "Deferred ID {} must return DeferredId error",
            deferred_id
        );
    }
}

#[test]
fn test_context_layout_and_offsets() {
    use core::mem::{align_of, offset_of, size_of};
    use pulse_bpf_schema::*;

    assert_eq!(align_of::<ContextCommon>(), 8);
    assert_eq!(size_of::<ContextCommon>(), 40);
    assert_eq!(offset_of!(ContextCommon, event_id), 0);
    assert_eq!(offset_of!(ContextCommon, version), 4);
    assert_eq!(offset_of!(ContextCommon, timestamp_ns), 8);
    assert_eq!(offset_of!(ContextCommon, cpu_id), 16);
    assert_eq!(offset_of!(ContextCommon, pid), 20);
    assert_eq!(offset_of!(ContextCommon, tid), 24);
    assert_eq!(offset_of!(ContextCommon, _reserved), 28);
    assert_eq!(offset_of!(ContextCommon, task_id), 32);

    assert_eq!(align_of::<TaskMetadataContext>(), 8);
    assert_eq!(size_of::<TaskMetadataContext>(), 72);
    assert_eq!(offset_of!(TaskMetadataContext, target_task_id), 40);
    assert_eq!(offset_of!(TaskMetadataContext, target_pid), 48);
    assert_eq!(offset_of!(TaskMetadataContext, target_tid), 52);
    assert_eq!(offset_of!(TaskMetadataContext, comm), 56);

    assert_eq!(align_of::<SchedSwitchContext>(), 8);
    assert_eq!(size_of::<SchedSwitchContext>(), 72);
    assert_eq!(offset_of!(SchedSwitchContext, prev_task_id), 40);
    assert_eq!(offset_of!(SchedSwitchContext, next_task_id), 48);
    assert_eq!(offset_of!(SchedSwitchContext, prev_state), 56);
    assert_eq!(offset_of!(SchedSwitchContext, prev_prio), 60);
    assert_eq!(offset_of!(SchedSwitchContext, next_prio), 64);
    assert_eq!(offset_of!(SchedSwitchContext, _pad), 68);

    assert_eq!(align_of::<TaskBlockContext>(), 8);
    assert_eq!(size_of::<TaskBlockContext>(), 72);
    assert_eq!(offset_of!(TaskBlockContext, block_sequence), 40);
    assert_eq!(offset_of!(TaskBlockContext, wait_reason), 48);
    assert_eq!(offset_of!(TaskBlockContext, _pad), 52);
    assert_eq!(offset_of!(TaskBlockContext, resource_id), 56);
    assert_eq!(offset_of!(TaskBlockContext, resource_detail), 64);

    assert_eq!(align_of::<TaskWakeContext>(), 8);
    assert_eq!(size_of::<TaskWakeContext>(), 80);
    assert_eq!(offset_of!(TaskWakeContext, target_task_id), 40);
    assert_eq!(offset_of!(TaskWakeContext, block_sequence), 48);
    assert_eq!(offset_of!(TaskWakeContext, waker_task_id), 56);
    assert_eq!(offset_of!(TaskWakeContext, wake_source), 64);
    assert_eq!(offset_of!(TaskWakeContext, _pad), 68);
    assert_eq!(offset_of!(TaskWakeContext, source_id), 72);

    assert_eq!(align_of::<TaskExitContext>(), 8);
    assert_eq!(size_of::<TaskExitContext>(), 56);
    assert_eq!(offset_of!(TaskExitContext, exit_task_id), 40);
    assert_eq!(offset_of!(TaskExitContext, exit_code), 48);
    assert_eq!(offset_of!(TaskExitContext, _pad), 52);

    assert_eq!(align_of::<TaskEnqueueContext>(), 8);
    assert_eq!(size_of::<TaskEnqueueContext>(), 64);
    assert_eq!(offset_of!(TaskEnqueueContext, enqueue_task_id), 40);
    assert_eq!(offset_of!(TaskEnqueueContext, enqueue_cpu), 48);
    assert_eq!(offset_of!(TaskEnqueueContext, target_cpu), 52);
    assert_eq!(offset_of!(TaskEnqueueContext, queue_depth), 56);
    assert_eq!(offset_of!(TaskEnqueueContext, enqueue_reason), 60);

    assert_eq!(align_of::<PhaseMarkerContext>(), 8);
    assert_eq!(size_of::<PhaseMarkerContext>(), 64);
    assert_eq!(offset_of!(PhaseMarkerContext, phase_boundary), 40);
    assert_eq!(offset_of!(PhaseMarkerContext, phase_len), 44);
    assert_eq!(offset_of!(PhaseMarkerContext, phase_name), 48);
}

#[test]
fn test_event_record_layout_and_bounds() {
    use core::mem::{align_of, size_of};
    use pulse_bpf_schema::*;

    assert_eq!(align_of::<EventRecord>(), 8);
    assert_eq!(size_of::<EventRecord>(), 88);

    // Verify all 7 context types strictly fit in MAX_CONTEXT_SIZE (80 bytes)
    assert!(size_of::<TaskMetadataContext>() <= MAX_CONTEXT_SIZE);
    assert!(size_of::<SchedSwitchContext>() <= MAX_CONTEXT_SIZE);
    assert!(size_of::<TaskBlockContext>() <= MAX_CONTEXT_SIZE);
    assert!(size_of::<TaskWakeContext>() <= MAX_CONTEXT_SIZE);
    assert!(size_of::<TaskExitContext>() <= MAX_CONTEXT_SIZE);
    assert!(size_of::<TaskEnqueueContext>() <= MAX_CONTEXT_SIZE);
    assert!(size_of::<PhaseMarkerContext>() <= MAX_CONTEXT_SIZE);

    let dummy_data = [42u8; 16];
    let rec = EventRecord::new(TracepointId::SchedSwitch, &dummy_data);
    assert_eq!(rec.id, TracepointId::SchedSwitch);
    assert_eq!(rec.len, 16);
    assert_eq!(rec.as_bytes(), &dummy_data);
}

#[test]
fn test_bounded_queue_fifo_and_drain() {
    use pulse_bpf_schema::*;

    let queue = BoundedTraceQueue::<16>::new();
    assert_eq!(queue.drop_stats(), DropStats::default());

    for i in 0..10u8 {
        let payload = [i, i * 2, i * 3];
        assert_eq!(queue.enqueue_bytes(TracepointId::TaskBlock, &payload), Ok(()));
    }

    let stats = queue.drop_stats();
    assert_eq!(stats.total_enqueued, 10);
    assert_eq!(stats.dropped_full, 0);
    assert_eq!(stats.dropped_recursive, 0);

    let mut received = Vec::new();
    let count = queue.drain(100, |id, data| {
        assert_eq!(id, TracepointId::TaskBlock);
        received.push(data.to_vec());
    });

    assert_eq!(count, 10);
    assert_eq!(received.len(), 10);
    for (i, item) in received.iter().enumerate() {
        let expected = vec![i as u8, (i as u8) * 2, (i as u8) * 3];
        assert_eq!(item, &expected);
    }

    // Queue is now empty
    let count2 = queue.drain(10, |_, _| panic!("queue must be empty"));
    assert_eq!(count2, 0);
}

#[test]
fn test_bounded_queue_overflow_drop_accounting() {
    use pulse_bpf_schema::*;

    // Capacity 8
    let queue = BoundedTraceQueue::<8>::new();

    // Fill to capacity
    for i in 0..8u8 {
        assert_eq!(queue.enqueue_bytes(TracepointId::SchedSwitch, &[i]), Ok(()));
    }
    assert_eq!(queue.drop_stats().total_enqueued, 8);
    assert_eq!(queue.drop_stats().dropped_full, 0);

    // Enqueue 5 more: all must drop with QueueDropReason::Full
    for _ in 0..5 {
        assert_eq!(
            queue.enqueue_bytes(TracepointId::SchedSwitch, &[99]),
            Err(QueueDropReason::Full)
        );
    }

    let stats = queue.drop_stats();
    assert_eq!(stats.total_enqueued, 8);
    assert_eq!(stats.dropped_full, 5);
    assert_eq!(stats.dropped_recursive, 0);

    // Drain the 8 existing events
    let mut drained_count = 0;
    queue.drain(10, |id, data| {
        assert_eq!(id, TracepointId::SchedSwitch);
        assert_eq!(data[0], drained_count as u8);
        drained_count += 1;
    });
    assert_eq!(drained_count, 8);

    // After draining, new events can be enqueued again
    assert_eq!(queue.enqueue_bytes(TracepointId::SchedSwitch, &[100]), Ok(()));
    assert_eq!(queue.drop_stats().total_enqueued, 9);
    assert_eq!(queue.drop_stats().dropped_full, 5);
}

#[test]
fn test_bounded_queue_reentrancy_rejection() {
    use pulse_bpf_schema::*;

    let queue = BoundedTraceQueue::<8>::new();
    assert!(!queue.is_in_trace());

    // Simulate being inside critical section by setting in_trace
    queue.set_in_trace_for_test(true);
    assert!(queue.is_in_trace());

    // Reentrant call must fail with Recursive drop reason
    let res = queue.enqueue_bytes(TracepointId::TaskWake, &[1, 2, 3]);
    assert_eq!(res, Err(QueueDropReason::Recursive));

    let stats = queue.drop_stats();
    assert_eq!(stats.dropped_recursive, 1);
    assert_eq!(stats.total_enqueued, 0);
    assert_eq!(stats.dropped_full, 0);

    // Unset in_trace
    queue.set_in_trace_for_test(false);
    assert_eq!(queue.enqueue_bytes(TracepointId::TaskWake, &[1, 2, 3]), Ok(()));
    assert_eq!(queue.drop_stats().total_enqueued, 1);

    // Test stats reset
    queue.reset_drop_stats();
    assert_eq!(queue.drop_stats(), DropStats::default());
}
