//! Validation tests for BPF v1 semantic tracepoint registry and event schema.

pub use pulse_bpf_schema::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracepoint_registry_enumerates_supported_ids() {
        let tps = all_tracepoints();
        assert_eq!(tps.len(), 7);
        for id in [1, 2, 3, 4, 5, 6, 7] {
            assert!(is_supported_id(id));
            let meta = lookup_by_id(id).expect("supported id must resolve");
            assert_eq!(meta.version, 1);
            assert_eq!(meta.endianness, Endianness::Little);
            assert!(meta.context_size > 0);
            assert!(!meta.fields.is_empty());
        }
    }

    #[test]
    fn tracepoint_registry_rejects_unknown_and_deferred_ids() {
        assert_eq!(lookup_by_id(0), Err(TracepointError::UnknownId(0)));
        assert_eq!(lookup_by_id(8), Err(TracepointError::UnknownId(8)));
        assert_eq!(lookup_by_id(999), Err(TracepointError::UnknownId(999)));

        for deferred in 100..=105 {
            assert!(is_deferred_id(deferred));
            assert_eq!(lookup_by_id(deferred), Err(TracepointError::DeferredId(deferred)));
        }
    }

    #[test]
    fn tracepoint_registry_name_discovery() {
        let switch = lookup_by_name("sched", "sched_switch").expect("must find sched_switch");
        assert_eq!(switch.id, TracepointId::SchedSwitch);
        assert_eq!(switch.id.as_u32(), 2);

        assert_eq!(
            lookup_by_name("sched", "non_existent"),
            Err(TracepointError::UnknownName)
        );
        assert_eq!(
            lookup_by_name("unknown_cat", "sched_switch"),
            Err(TracepointError::UnknownName)
        );
    }

    #[test]
    fn tracepoint_fixed_byte_fields_and_endianness() {
        let meta = lookup_by_id(TracepointId::TaskMetadata as u32).unwrap();
        let comm_field = meta.fields.iter().find(|f| f.name == "comm").unwrap();
        assert_eq!(comm_field.size, 16);
        assert_eq!(comm_field.field_type, FieldType::ByteArray(16));

        let meta = lookup_by_id(TracepointId::PhaseMarker as u32).unwrap();
        let phase_field = meta.fields.iter().find(|f| f.name == "phase_name").unwrap();
        assert_eq!(phase_field.size, 16);
        assert_eq!(phase_field.field_type, FieldType::ByteArray(16));
    }

    #[test]
    fn tracepoint_static_size_and_alignment_guarantees() {
        use core::mem::{align_of, size_of};

        assert_eq!(align_of::<ContextCommon>(), 8);
        assert_eq!(size_of::<ContextCommon>(), 40);

        assert_eq!(align_of::<EventRecord>(), 8);
        assert_eq!(size_of::<EventRecord>(), 88);

        // Every supported context type must fit within MAX_CONTEXT_SIZE (80 bytes)
        assert!(size_of::<TaskMetadataContext>() <= MAX_CONTEXT_SIZE);
        assert!(size_of::<SchedSwitchContext>() <= MAX_CONTEXT_SIZE);
        assert!(size_of::<TaskBlockContext>() <= MAX_CONTEXT_SIZE);
        assert!(size_of::<TaskWakeContext>() <= MAX_CONTEXT_SIZE);
        assert!(size_of::<TaskExitContext>() <= MAX_CONTEXT_SIZE);
        assert!(size_of::<TaskEnqueueContext>() <= MAX_CONTEXT_SIZE);
        assert!(size_of::<PhaseMarkerContext>() <= MAX_CONTEXT_SIZE);
    }

    #[test]
    fn tracepoint_event_record_roundtrip() {
        let ctx = SchedSwitchContext {
            common: ContextCommon::new(TracepointId::SchedSwitch, 123456789, 2, 100, 101, 10),
            prev_task_id: 10,
            next_task_id: 20,
            prev_state: 1,
            prev_prio: 120,
            next_prio: 120,
            _pad: 0,
        };

        let raw_bytes = unsafe {
            core::slice::from_raw_parts(
                &ctx as *const SchedSwitchContext as *const u8,
                core::mem::size_of::<SchedSwitchContext>(),
            )
        };

        let rec = EventRecord::new(TracepointId::SchedSwitch, raw_bytes);
        assert_eq!(rec.id, TracepointId::SchedSwitch);
        assert_eq!(rec.len as usize, core::mem::size_of::<SchedSwitchContext>());
        assert_eq!(rec.as_bytes(), raw_bytes);
    }
}

