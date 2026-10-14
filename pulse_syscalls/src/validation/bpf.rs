//! Validation tests for BPF v1 semantic tracepoint registry and event schema.

#[cfg(test)]
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

    use axerrno::LinuxError;
    use crate::impls::bpf::abi::*;

    #[test]
    fn bpf_command_decoding_and_unknown_rejection() {
        assert_eq!(BpfCmd::from_raw(0), Ok(BpfCmd::MapCreate));
        assert_eq!(BpfCmd::from_raw(1), Ok(BpfCmd::MapLookupElem));
        assert_eq!(BpfCmd::from_raw(2), Ok(BpfCmd::MapUpdateElem));
        assert_eq!(BpfCmd::from_raw(3), Ok(BpfCmd::MapDeleteElem));
        assert_eq!(BpfCmd::from_raw(4), Ok(BpfCmd::MapGetNextKey));
        assert_eq!(BpfCmd::from_raw(5), Ok(BpfCmd::ProgLoad));
        assert_eq!(BpfCmd::from_raw(6), Ok(BpfCmd::ObjPin));
        assert_eq!(BpfCmd::from_raw(7), Ok(BpfCmd::ObjGet));
        assert_eq!(BpfCmd::from_raw(8), Ok(BpfCmd::ProgAttach));
        assert_eq!(BpfCmd::from_raw(9), Ok(BpfCmd::ProgDetach));
        assert_eq!(BpfCmd::from_raw(10), Ok(BpfCmd::ProgTestRun));
        assert_eq!(BpfCmd::from_raw(15), Ok(BpfCmd::ObjGetInfoByFd));
        assert_eq!(BpfCmd::from_raw(17), Ok(BpfCmd::RawTracepointOpen));
        assert_eq!(BpfCmd::from_raw(18), Ok(BpfCmd::BtfLoad));
        assert_eq!(BpfCmd::from_raw(28), Ok(BpfCmd::LinkCreate));
        assert_eq!(BpfCmd::from_raw(29), Ok(BpfCmd::LinkUpdate));
        assert_eq!(BpfCmd::from_raw(34), Ok(BpfCmd::LinkDetach));

        // Unknown commands must return EINVAL
        assert_eq!(BpfCmd::from_raw(36), Err(LinuxError::EINVAL));
        assert_eq!(BpfCmd::from_raw(37), Err(LinuxError::EINVAL));
        assert_eq!(BpfCmd::from_raw(100), Err(LinuxError::EINVAL));
        assert_eq!(BpfCmd::from_raw(u32::MAX), Err(LinuxError::EINVAL));
    }

    #[test]
    fn bpf_attribute_size_and_alignment_guarantees() {
        use core::mem::{align_of, size_of};

        assert_eq!(align_of::<BpfAttr>(), 8);
        assert_eq!(size_of::<BpfAttr>(), 144);

        assert_eq!(align_of::<BpfMapCreateAttr>(), 8);
        assert_eq!(size_of::<BpfMapCreateAttr>(), 72);

        assert_eq!(align_of::<BpfMapElemAttr>(), 8);
        assert_eq!(size_of::<BpfMapElemAttr>(), 32);

        assert_eq!(align_of::<BpfProgLoadAttr>(), 8);
        assert_eq!(size_of::<BpfProgLoadAttr>(), 144);

        assert_eq!(align_of::<BpfObjPinGetAttr>(), 8);
        assert_eq!(size_of::<BpfObjPinGetAttr>(), 24);

        assert_eq!(align_of::<BpfProgAttachDetachAttr>(), 8);
        assert_eq!(size_of::<BpfProgAttachDetachAttr>(), 32);

        assert_eq!(align_of::<BpfObjGetInfoAttr>(), 8);
        assert_eq!(size_of::<BpfObjGetInfoAttr>(), 16);

        assert_eq!(align_of::<BpfLinkCreateAttr>(), 8);
        assert_eq!(size_of::<BpfLinkCreateAttr>(), 64);

        assert_eq!(align_of::<BpfLinkUpdateAttr>(), 8);
        assert_eq!(size_of::<BpfLinkUpdateAttr>(), 16);

        assert_eq!(align_of::<BpfLinkDetachAttr>(), 4);
        assert_eq!(size_of::<BpfLinkDetachAttr>(), 4);
    }

    #[test]
    fn bpf_attribute_minimum_sizes() {
        assert_eq!(BpfCmd::MapCreate.min_attr_size(), 20);
        assert_eq!(BpfCmd::MapLookupElem.min_attr_size(), 24);
        assert_eq!(BpfCmd::MapUpdateElem.min_attr_size(), 32);
        assert_eq!(BpfCmd::MapDeleteElem.min_attr_size(), 16);
        assert_eq!(BpfCmd::MapGetNextKey.min_attr_size(), 24);
        assert_eq!(BpfCmd::ProgLoad.min_attr_size(), 48);
        assert_eq!(BpfCmd::ObjPin.min_attr_size(), 16);
        assert_eq!(BpfCmd::ObjGet.min_attr_size(), 16);
        assert_eq!(BpfCmd::ProgAttach.min_attr_size(), 16);
        assert_eq!(BpfCmd::ProgDetach.min_attr_size(), 16);
        assert_eq!(BpfCmd::ObjGetInfoByFd.min_attr_size(), 16);
        assert_eq!(BpfCmd::LinkCreate.min_attr_size(), 16);
        assert_eq!(BpfCmd::LinkDetach.min_attr_size(), 4);

        // Validating size against minimum
        assert_eq!(validate_bpf_attr_size(0, 20), Err(LinuxError::EINVAL));
        assert_eq!(validate_bpf_attr_size(19, 20), Err(LinuxError::EINVAL));
        assert_eq!(validate_bpf_attr_size(20, 20), Ok(20));
        assert_eq!(validate_bpf_attr_size(72, 20), Ok(72));
        assert_eq!(validate_bpf_attr_size(144, 20), Ok(144));
    }

    #[test]
    fn bpf_attribute_oversized_and_overflow_validation() {
        // Size > PAGE_SIZE (4096) returns E2BIG
        assert_eq!(validate_bpf_attr_size(4097, 20), Err(LinuxError::E2BIG));
        assert_eq!(validate_bpf_attr_size(usize::MAX, 20), Err(LinuxError::E2BIG));

        // Trailing bytes beyond 144 up to 4096 must be zero
        let zero_tail = [0u8; 32];
        assert_eq!(check_trailing_zero(&zero_tail), Ok(()));

        let mut nonzero_tail = [0u8; 32];
        nonzero_tail[10] = 1;
        assert_eq!(check_trailing_zero(&nonzero_tail), Err(LinuxError::E2BIG));

        // User pointer validation
        assert_eq!(validate_user_attr_range(0, 72), Err(LinuxError::EFAULT));
        assert_eq!(validate_user_attr_range(usize::MAX - 10, 72), Err(LinuxError::EFAULT));
    }

    #[test]
    fn bpf_permission_and_error_precedence() {
        let root = BpfPermissions::new(true, false, false);
        let unpriv = BpfPermissions::new(false, false, false);
        assert_eq!(check_bpf_permission(true, false, false), Ok(()));
        assert_eq!(check_bpf_permission(false, false, false), Err(LinuxError::EPERM));

        // 1. Permission check precedence:
        // Unprivileged caller gets EPERM even with invalid cmd, null pointer, 0 size, or oversized buffer.
        let mut read_noop = |_addr: usize, _buf: &mut [u8]| Ok(());
        assert_eq!(
            validate_bpf_syscall(unpriv, -1, 0, 0, &mut read_noop).err(),
            Some(LinuxError::EPERM)
        );
        assert_eq!(
            validate_bpf_syscall(unpriv, 9999, 0, 10000, &mut read_noop).err(),
            Some(LinuxError::EPERM)
        );
        assert_eq!(
            validate_bpf_syscall(unpriv, BpfCmd::MapCreate as i32, 0x1000, 72, &mut read_noop).err(),
            Some(LinuxError::EPERM)
        );

        // 2. Unknown command precedence:
        // Unknown command returns EINVAL even with null pointer or invalid size.
        assert_eq!(
            validate_bpf_syscall(root, -1, 0, 0, &mut read_noop).err(),
            Some(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_bpf_syscall(root, 9999, 0, 0, &mut read_noop).err(),
            Some(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_bpf_syscall(root, 9999, 0, 72, &mut read_noop).err(),
            Some(LinuxError::EINVAL)
        );

        // 3. Oversized buffer precedence:
        // Size > 4096 returns E2BIG even if pointer is null or invalid.
        assert_eq!(
            validate_bpf_syscall(root, BpfCmd::MapCreate as i32, 0, 5000, &mut read_noop).err(),
            Some(LinuxError::E2BIG)
        );

        // 4. Undersized buffer precedence:
        // Size < min_attr_size returns EINVAL even if pointer is null.
        assert_eq!(
            validate_bpf_syscall(root, BpfCmd::MapCreate as i32, 0, 0, &mut read_noop).err(),
            Some(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_bpf_syscall(root, BpfCmd::MapCreate as i32, 0, 10, &mut read_noop).err(),
            Some(LinuxError::EINVAL)
        );

        // 5. Pointer range check precedence:
        // Valid command and size but null pointer returns EFAULT.
        assert_eq!(
            validate_bpf_syscall(root, BpfCmd::MapCreate as i32, 0, 72, &mut read_noop).err(),
            Some(LinuxError::EFAULT)
        );
        // Address arithmetic overflow returns EFAULT.
        assert_eq!(
            validate_bpf_syscall(root, BpfCmd::MapCreate as i32, usize::MAX - 10, 72, &mut read_noop).err(),
            Some(LinuxError::EFAULT)
        );

        // 6. Base pointer read failure returns EFAULT before trailing byte check.
        let mut read_fault_base = |addr: usize, _buf: &mut [u8]| {
            if addr == 0x2000 {
                Err(LinuxError::EFAULT)
            } else {
                Ok(())
            }
        };
        assert_eq!(
            validate_bpf_syscall(root, BpfCmd::MapCreate as i32, 0x2000, 200, &mut read_fault_base).err(),
            Some(LinuxError::EFAULT)
        );

        // 7. Non-zero trailing bytes return E2BIG.
        let mut read_nonzero_tail = |addr: usize, buf: &mut [u8]| {
            if addr >= 0x2000 + 144 {
                buf[0] = 1;
            }
            Ok(())
        };
        assert_eq!(
            validate_bpf_syscall(root, BpfCmd::MapCreate as i32, 0x2000, 200, &mut read_nonzero_tail).err(),
            Some(LinuxError::E2BIG)
        );

        // 8. Valid call returns Ok((cmd, attr)) with deferred command status.
        let res = validate_bpf_syscall(root, BpfCmd::MapCreate as i32, 0x2000, 72, &mut read_noop);
        assert!(res.is_ok());
        let (cmd, _) = res.unwrap();
        assert_eq!(cmd, BpfCmd::MapCreate);
        assert!(cmd.is_deferred());

        // All recognized commands in this ticket are deferred
        for &cmd in &BpfCmd::ALL {
            assert!(cmd.is_deferred());
        }
    }
}


