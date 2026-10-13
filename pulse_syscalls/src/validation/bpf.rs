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
}

