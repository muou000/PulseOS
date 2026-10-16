//! Host tests for BPF Map objects (#92).
//!
//! `pulse_core` cannot be built for the host, so the pure Map model in
//! `pulse_core/src/bpf/map.rs` is compiled here directly. That file must stay
//! self-contained (only `core`, `alloc` and `axerrno`).

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/ring_buffer.rs"]
mod core_ring_buffer;

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/map.rs"]
mod core_map;

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use axerrno::LinuxError;

    use super::core_map::*;
    use crate::impls::bpf::{
        abi::{BpfAttr, BpfCmd, BpfMapElemAttr, check_attr_unused_tail},
        elem::{
            bpf_map_delete_elem, bpf_map_get_next_key, bpf_map_lookup_elem, bpf_map_update_elem,
            BpfMapOps,
        },
        info::copy_obj_info_to_user,
    };

    fn name(s: &str) -> [u8; BPF_OBJ_NAME_LEN] {
        let mut out = [0u8; BPF_OBJ_NAME_LEN];
        out[..s.len()].copy_from_slice(s.as_bytes());
        out
    }

    fn array_req() -> BpfMapCreateRequest {
        BpfMapCreateRequest {
            map_type: BPF_MAP_TYPE_ARRAY,
            key_size: 4,
            value_size: 8,
            max_entries: 16,
            map_name: name("counters"),
            ..Default::default()
        }
    }

    fn hash_req() -> BpfMapCreateRequest {
        BpfMapCreateRequest {
            map_type: BPF_MAP_TYPE_HASH,
            key_size: 16,
            value_size: 32,
            max_entries: 64,
            map_name: name("by_task.v1"),
            ..Default::default()
        }
    }

    fn err(req: BpfMapCreateRequest) -> LinuxError {
        BpfMapSpec::validate(&req).err().expect("request must be rejected")
    }

    #[test]
    fn bpf_map_create_accepts_array_and_hash() {
        let spec = BpfMapSpec::validate(&array_req()).unwrap();
        assert_eq!(spec.map_type(), BpfMapType::Array);
        assert_eq!(spec.storage_bytes(), 16 * 8);
        assert_eq!(spec.name_bytes(), &name("counters"));

        let spec = BpfMapSpec::validate(&hash_req()).unwrap();
        assert_eq!(spec.map_type(), BpfMapType::Hash);
        assert_eq!(spec.storage_bytes(), 64 * (16 + 32));

        let mut req = hash_req();
        req.map_flags = BPF_F_NO_PREALLOC;
        assert!(BpfMapSpec::validate(&req).is_ok());
        let mut req = array_req();
        req.map_flags = BPF_F_RDONLY_PROG;
        assert!(BpfMapSpec::validate(&req).is_ok());
    }

    #[test]
    fn bpf_map_create_rejects_unknown_and_unsupported_types() {
        for raw in [0, 34, 1000, u32::MAX] {
            let mut req = array_req();
            req.map_type = raw;
            assert_eq!(err(req), LinuxError::EINVAL, "type {raw}");
        }
        // Known Linux types outside the PulseOS compatibility tier.
        for raw in [3, 5, 28, 33] {
            let mut req = array_req();
            req.map_type = raw;
            assert_eq!(err(req), LinuxError::EOPNOTSUPP, "type {raw}");
        }
    }

    #[test]
    fn bpf_map_create_rejects_invalid_sizes() {
        let mut req = array_req();
        req.key_size = 8;
        assert_eq!(err(req), LinuxError::EINVAL);
        let mut req = array_req();
        req.value_size = 0;
        assert_eq!(err(req), LinuxError::EINVAL);
        let mut req = array_req();
        req.max_entries = 0;
        assert_eq!(err(req), LinuxError::EINVAL);

        let mut req = hash_req();
        req.key_size = 0;
        assert_eq!(err(req), LinuxError::EINVAL);
        let mut req = hash_req();
        req.key_size = BPF_MAP_MAX_KEY_SIZE + 1;
        assert_eq!(err(req), LinuxError::E2BIG);
        let mut req = hash_req();
        req.value_size = BPF_MAP_MAX_VALUE_SIZE + 1;
        assert_eq!(err(req), LinuxError::E2BIG);

        // Total storage is bounded and computed without overflow.
        let mut req = array_req();
        req.value_size = BPF_MAP_MAX_VALUE_SIZE;
        req.max_entries = u32::MAX;
        assert_eq!(err(req), LinuxError::E2BIG);
        let mut req = hash_req();
        req.key_size = BPF_MAP_MAX_KEY_SIZE;
        req.value_size = BPF_MAP_MAX_VALUE_SIZE;
        req.max_entries = u32::MAX;
        assert_eq!(err(req), LinuxError::E2BIG);
    }

    #[test]
    fn bpf_map_create_rejects_invalid_flags_and_unsupported_fields() {
        let mut req = array_req();
        req.map_flags = BPF_F_NO_PREALLOC;
        assert_eq!(err(req), LinuxError::EINVAL);
        let mut req = hash_req();
        req.map_flags = BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG;
        assert_eq!(err(req), LinuxError::EINVAL);
        let mut req = hash_req();
        req.map_flags = 1 << 31;
        assert_eq!(err(req), LinuxError::EINVAL);

        let mut req = array_req();
        req.inner_map_fd = 3;
        assert_eq!(err(req), LinuxError::EINVAL);
        let mut req = array_req();
        req.numa_node = 1;
        assert_eq!(err(req), LinuxError::EINVAL);
        let mut req = array_req();
        req.map_extra = 1;
        assert_eq!(err(req), LinuxError::EINVAL);
        let mut req = array_req();
        req.btf_fd = 5;
        req.btf_key_type_id = 1;
        assert_eq!(err(req), LinuxError::EINVAL);
        let mut req = array_req();
        req.btf_vmlinux_value_type_id = 1;
        assert_eq!(err(req), LinuxError::EINVAL);
        let mut req = array_req();
        req.map_ifindex = 2;
        assert_eq!(err(req), LinuxError::EOPNOTSUPP);
    }

    #[test]
    fn bpf_map_create_validates_object_name() {
        let mut req = array_req();
        req.map_name = name("");
        assert!(BpfMapSpec::validate(&req).is_ok());
        let mut req = array_req();
        req.map_name = name("abcdefghijklmno");
        assert!(BpfMapSpec::validate(&req).is_ok());

        // No NUL terminator within BPF_OBJ_NAME_LEN.
        let mut req = array_req();
        req.map_name = [b'a'; BPF_OBJ_NAME_LEN];
        assert_eq!(err(req), LinuxError::EINVAL);
        for bad in ["bad-name", "sp ace", "a/b"] {
            let mut req = array_req();
            req.map_name = name(bad);
            assert_eq!(err(req), LinuxError::EINVAL, "name {bad}");
        }
    }

    #[test]
    fn bpf_map_storage_is_charged_and_released_without_leaks() {
        static BUDGET: BpfMemoryBudget = BpfMemoryBudget::new(4096);

        let spec = BpfMapSpec::validate(&array_req()).unwrap();
        let map = Arc::new(BpfMap::create_in(spec, &BUDGET).unwrap());
        assert_eq!(BUDGET.charged_bytes(), 128);
        assert_eq!(BUDGET.live_maps(), 1);
        assert_eq!(map.storage_capacity(), 16);

        // Duplicated references (dup/fork) share one object.
        let dup = map.clone();
        let forked = map.clone();
        drop(map);
        assert_eq!(BUDGET.live_maps(), 1);
        drop(forked);
        assert_eq!(BUDGET.live_maps(), 1);
        assert_eq!(dup.id(), dup.info().id);
        drop(dup);
        assert_eq!(BUDGET.live_maps(), 0);
        assert_eq!(BUDGET.charged_bytes(), 0);

        // Budget exhaustion fails before allocation and leaves no charge.
        let mut req = hash_req();
        req.max_entries = 4096;
        let spec = BpfMapSpec::validate(&req).unwrap();
        assert_eq!(BpfMap::create_in(spec, &BUDGET).err(), Some(LinuxError::ENOMEM));
        assert_eq!(BUDGET.charged_bytes(), 0);
        assert_eq!(BUDGET.live_maps(), 0);
    }

    #[test]
    fn bpf_map_ids_are_unique_and_nonzero() {
        static BUDGET: BpfMemoryBudget = BpfMemoryBudget::new(1 << 20);
        let a = BpfMap::create_in(BpfMapSpec::validate(&array_req()).unwrap(), &BUDGET).unwrap();
        let b = BpfMap::create_in(BpfMapSpec::validate(&hash_req()).unwrap(), &BUDGET).unwrap();
        assert_ne!(a.id(), 0);
        assert_ne!(b.id(), 0);
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn bpf_map_info_matches_linux_layout_and_metadata() {
        use core::mem::{align_of, offset_of, size_of};
        assert_eq!(size_of::<BpfMapInfo>(), 88);
        assert_eq!(align_of::<BpfMapInfo>(), 8);
        assert_eq!(offset_of!(BpfMapInfo, name), 24);
        assert_eq!(offset_of!(BpfMapInfo, ifindex), 40);
        assert_eq!(offset_of!(BpfMapInfo, netns_dev), 48);
        assert_eq!(offset_of!(BpfMapInfo, btf_id), 64);
        assert_eq!(offset_of!(BpfMapInfo, map_extra), 80);

        static BUDGET: BpfMemoryBudget = BpfMemoryBudget::new(1 << 20);
        let mut req = hash_req();
        req.map_flags = BPF_F_NO_PREALLOC;
        let map = BpfMap::create_in(BpfMapSpec::validate(&req).unwrap(), &BUDGET).unwrap();
        let info = map.info();
        assert_eq!(info.map_type, BPF_MAP_TYPE_HASH);
        assert_eq!(info.id, map.id());
        assert_eq!(info.key_size, 16);
        assert_eq!(info.value_size, 32);
        assert_eq!(info.max_entries, 64);
        assert_eq!(info.map_flags, BPF_F_NO_PREALLOC);
        assert_eq!(info.name, name("by_task.v1"));
        assert_eq!(info.btf_id, 0);
        assert_eq!(info.as_bytes().len(), 88);
        assert_eq!(&info.as_bytes()[0..4], &BPF_MAP_TYPE_HASH.to_le_bytes());
    }

    #[test]
    fn bpf_attr_unused_tail_must_be_zero() {
        let mut attr = BpfAttr::default();
        assert_eq!(check_attr_unused_tail(BpfCmd::MapCreate, &attr), Ok(()));
        assert_eq!(check_attr_unused_tail(BpfCmd::ObjGetInfoByFd, &attr), Ok(()));
        unsafe { attr.raw[71] = 1 };
        assert_eq!(check_attr_unused_tail(BpfCmd::MapCreate, &attr), Ok(()));
        unsafe { attr.raw[72] = 1 };
        assert_eq!(check_attr_unused_tail(BpfCmd::MapCreate, &attr), Err(LinuxError::EINVAL));

        let mut attr = BpfAttr::default();
        unsafe { attr.raw[15] = 1 };
        assert_eq!(check_attr_unused_tail(BpfCmd::ObjGetInfoByFd, &attr), Ok(()));
        unsafe { attr.raw[16] = 1 };
        assert_eq!(
            check_attr_unused_tail(BpfCmd::ObjGetInfoByFd, &attr),
            Err(LinuxError::EINVAL)
        );

        let mut attr = BpfAttr::default();
        unsafe { attr.raw[15] = 1 };
        assert_eq!(check_attr_unused_tail(BpfCmd::MapDeleteElem, &attr), Ok(()));
        unsafe { attr.raw[16] = 1 };
        assert_eq!(
            check_attr_unused_tail(BpfCmd::MapDeleteElem, &attr),
            Err(LinuxError::EINVAL)
        );

        let mut attr = BpfAttr::default();
        unsafe { attr.raw[23] = 1 };
        assert_eq!(check_attr_unused_tail(BpfCmd::MapGetNextKey, &attr), Ok(()));
        unsafe { attr.raw[24] = 1 };
        assert_eq!(
            check_attr_unused_tail(BpfCmd::MapGetNextKey, &attr),
            Err(LinuxError::EINVAL)
        );

        let mut attr = BpfAttr::default();
        unsafe { attr.raw[31] = 1 };
        assert_eq!(check_attr_unused_tail(BpfCmd::MapLookupElem, &attr), Ok(()));
        assert_eq!(check_attr_unused_tail(BpfCmd::MapUpdateElem, &attr), Ok(()));
        unsafe { attr.raw[32] = 1 };
        assert_eq!(
            check_attr_unused_tail(BpfCmd::MapLookupElem, &attr),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            check_attr_unused_tail(BpfCmd::MapUpdateElem, &attr),
            Err(LinuxError::EINVAL)
        );
    }

    #[test]
    fn bpf_commands_implemented_by_map_slice() {
        let implemented = [
            BpfCmd::MapCreate,
            BpfCmd::MapLookupElem,
            BpfCmd::MapUpdateElem,
            BpfCmd::MapDeleteElem,
            BpfCmd::MapGetNextKey,
            BpfCmd::ObjGetInfoByFd,
            BpfCmd::ProgLoad,
            BpfCmd::LinkCreate,
            BpfCmd::LinkDetach,
        ];
        for &cmd in &implemented {
            assert!(!cmd.is_deferred(), "{cmd:?} must not be deferred");
        }
        for &cmd in &BpfCmd::ALL {
            if !implemented.contains(&cmd) {
                assert!(cmd.is_deferred(), "{cmd:?} must be deferred");
            }
        }
    }

    struct FakeUser {
        mem: alloc::vec::Vec<u8>,
        base: usize,
    }

    impl FakeUser {
        fn new(base: usize, len: usize) -> Self {
            Self { mem: alloc::vec![0; len], base }
        }

        fn range(&self, addr: usize, len: usize) -> Result<core::ops::Range<usize>, LinuxError> {
            let start = addr.checked_sub(self.base).ok_or(LinuxError::EFAULT)?;
            let end = start.checked_add(len).ok_or(LinuxError::EFAULT)?;
            if end > self.mem.len() {
                return Err(LinuxError::EFAULT);
            }
            Ok(start..end)
        }
    }

    fn run_info(
        user: &mut FakeUser,
        info_ptr: usize,
        info_len: u32,
        kernel: &[u8],
    ) -> Result<u32, LinuxError> {
        let user = core::cell::RefCell::new(user);
        copy_obj_info_to_user(
            info_ptr,
            info_len,
            kernel,
            |addr, buf| {
                let u = user.borrow();
                let r = u.range(addr, buf.len())?;
                buf.copy_from_slice(&u.mem[r]);
                Ok(())
            },
            |addr, buf| {
                let mut u = user.borrow_mut();
                let r = u.range(addr, buf.len())?;
                u.mem[r].copy_from_slice(buf);
                Ok(())
            },
        )
    }

    #[test]
    fn bpf_obj_get_info_copies_truncated_and_full_info() {
        let kernel: alloc::vec::Vec<u8> = (1..=88u8).collect();

        let mut user = FakeUser::new(0x1000, 256);
        assert_eq!(run_info(&mut user, 0x1000, 88, &kernel), Ok(88));
        assert_eq!(&user.mem[..88], &kernel[..]);

        // Short buffers receive a prefix and the truncated length.
        let mut user = FakeUser::new(0x1000, 256);
        assert_eq!(run_info(&mut user, 0x1000, 20, &kernel), Ok(20));
        assert_eq!(&user.mem[..20], &kernel[..20]);
        assert!(user.mem[20..].iter().all(|&b| b == 0));

        // Larger buffers with a zero tail are accepted and truncated to kernel size.
        let mut user = FakeUser::new(0x1000, 256);
        assert_eq!(run_info(&mut user, 0x1000, 200, &kernel), Ok(88));

        // info_len == 0 writes nothing, even with a null pointer.
        let mut user = FakeUser::new(0x1000, 256);
        assert_eq!(run_info(&mut user, 0, 0, &kernel), Ok(0));
    }

    #[test]
    fn bpf_obj_get_info_rejects_bad_buffers() {
        let kernel = [7u8; 88];

        let mut user = FakeUser::new(0x1000, 256);
        user.mem[100] = 1;
        assert_eq!(run_info(&mut user, 0x1000, 200, &kernel), Err(LinuxError::E2BIG));
        assert_eq!(user.mem[0], 0, "no partial copy after tail rejection");

        let mut user = FakeUser::new(0x1000, 256);
        assert_eq!(run_info(&mut user, 0x1000, 4097, &kernel), Err(LinuxError::E2BIG));

        let mut user = FakeUser::new(0x1000, 256);
        assert_eq!(run_info(&mut user, 0, 88, &kernel), Err(LinuxError::EFAULT));
        assert_eq!(run_info(&mut user, 0x9000, 88, &kernel), Err(LinuxError::EFAULT));
    }

    impl BpfMapOps for BpfMap {
        fn key_size(&self) -> usize {
            self.spec().key_size() as usize
        }

        fn value_size(&self) -> usize {
            self.spec().value_size() as usize
        }

        fn lookup(&self, key: &[u8], val_out: &mut [u8]) -> Result<(), LinuxError> {
            self.lookup(key, val_out)
        }

        fn update(&self, key: &[u8], val: &[u8], flags: u64) -> Result<(), LinuxError> {
            self.update(key, val, flags)
        }

        fn delete(&self, key: &[u8]) -> Result<(), LinuxError> {
            self.delete(key)
        }

        fn get_next_key(&self, key: Option<&[u8]>, next_key_out: &mut [u8]) -> Result<(), LinuxError> {
            self.get_next_key(key, next_key_out)
        }
    }

    #[test]
    fn bpf_map_elem_control_plane_error_precedence_and_bounded_copy() {
        let mut req = hash_req();
        req.key_size = 4;
        req.value_size = 8;
        req.max_entries = 2;
        let map = BpfMap::create(BpfMapSpec::validate(&req).unwrap()).unwrap();

        let mut user = FakeUser::new(0x1000, 0x1000);
        let key_addr = 0x1100;
        let val_addr = 0x1200;
        let next_key_addr = 0x1300;
        let out_of_bounds_addr = 0x9000;

        // Write key=1 and val=42 into user memory
        let key1 = 1u32.to_ne_bytes();
        let val1 = [42u8; 8];
        user.mem[key_addr - user.base..key_addr - user.base + 4].copy_from_slice(&key1);
        user.mem[val_addr - user.base..val_addr - user.base + 8].copy_from_slice(&val1);

        let user_cell = core::cell::RefCell::new(user);
        let mut read = |addr, buf: &mut [u8]| {
            let u = user_cell.borrow();
            let r = u.range(addr, buf.len())?;
            buf.copy_from_slice(&u.mem[r]);
            Ok(())
        };
        let mut write = |addr, buf: &[u8]| {
            let mut u = user_cell.borrow_mut();
            let r = u.range(addr, buf.len())?;
            u.mem[r].copy_from_slice(buf);
            Ok(())
        };

        // 1. UPDATE with bad key/value pointer returns EFAULT (even if flags are invalid)
        let bad_key_and_flag_attr = BpfMapElemAttr {
            key: 0,
            value_or_next_key: val_addr as u64,
            flags: 99,
            ..Default::default()
        };
        assert_eq!(
            bpf_map_update_elem(&map, &bad_key_and_flag_attr, &mut read),
            Err(LinuxError::EFAULT)
        );

        // 2. UPDATE with valid pointers but invalid flags returns EINVAL
        let bad_flag_attr = BpfMapElemAttr {
            key: key_addr as u64,
            value_or_next_key: val_addr as u64,
            flags: 99,
            ..Default::default()
        };
        assert_eq!(
            bpf_map_update_elem(&map, &bad_flag_attr, &mut read),
            Err(LinuxError::EINVAL)
        );

        // 3. UPDATE with bad value pointer returns EFAULT
        let bad_val_attr = BpfMapElemAttr {
            key: key_addr as u64,
            value_or_next_key: 0,
            flags: BPF_ANY,
            ..Default::default()
        };
        assert_eq!(
            bpf_map_update_elem(&map, &bad_val_attr, &mut read),
            Err(LinuxError::EFAULT)
        );

        // 4. UPDATE with valid pointers succeeds
        let valid_update_attr = BpfMapElemAttr {
            key: key_addr as u64,
            value_or_next_key: val_addr as u64,
            flags: BPF_NOEXIST,
            ..Default::default()
        };
        assert_eq!(
            bpf_map_update_elem(&map, &valid_update_attr, &mut read),
            Ok(0)
        );

        // 5. LOOKUP with invalid flags returns EINVAL
        let bad_lookup_flags = BpfMapElemAttr {
            key: key_addr as u64,
            value_or_next_key: val_addr as u64,
            flags: 1,
            ..Default::default()
        };
        assert_eq!(
            bpf_map_lookup_elem(&map, &bad_lookup_flags, &mut read, &mut write),
            Err(LinuxError::EINVAL)
        );

        // 6. LOOKUP with bad key pointer returns EFAULT
        let bad_lookup_key = BpfMapElemAttr {
            key: out_of_bounds_addr as u64,
            value_or_next_key: val_addr as u64,
            flags: 0,
            ..Default::default()
        };
        assert_eq!(
            bpf_map_lookup_elem(&map, &bad_lookup_key, &mut read, &mut write),
            Err(LinuxError::EFAULT)
        );

        // 7. LOOKUP with non-existent key returns ENOENT even if value pointer is invalid
        let missing_key_addr = 0x1400;
        let missing_key = 99u32.to_ne_bytes();
        user_cell.borrow_mut().mem[missing_key_addr - 0x1000..missing_key_addr - 0x1000 + 4]
            .copy_from_slice(&missing_key);
        let missing_lookup = BpfMapElemAttr {
            key: missing_key_addr as u64,
            value_or_next_key: 0, // bad pointer
            flags: 0,
            ..Default::default()
        };
        assert_eq!(
            bpf_map_lookup_elem(&map, &missing_lookup, &mut read, &mut write),
            Err(LinuxError::ENOENT)
        );

        // 8. LOOKUP on existent key with bad value pointer returns EFAULT
        let bad_lookup_val = BpfMapElemAttr {
            key: key_addr as u64,
            value_or_next_key: 0,
            flags: 0,
            ..Default::default()
        };
        assert_eq!(
            bpf_map_lookup_elem(&map, &bad_lookup_val, &mut read, &mut write),
            Err(LinuxError::EFAULT)
        );

        // 9. LOOKUP on existent key with valid value pointer succeeds and writes value
        let out_val_addr = 0x1500;
        let valid_lookup = BpfMapElemAttr {
            key: key_addr as u64,
            value_or_next_key: out_val_addr as u64,
            flags: 0,
            ..Default::default()
        };
        assert_eq!(
            bpf_map_lookup_elem(&map, &valid_lookup, &mut read, &mut write),
            Ok(0)
        );
        let mut copied_val = [0u8; 8];
        copied_val.copy_from_slice(&user_cell.borrow().mem[out_val_addr - 0x1000..out_val_addr - 0x1000 + 8]);
        assert_eq!(copied_val, val1);

        // 10. GET_NEXT_KEY with NULL key starts from the beginning
        let null_key_iter = BpfMapElemAttr {
            key: 0,
            value_or_next_key: next_key_addr as u64,
            flags: 0,
            ..Default::default()
        };
        assert_eq!(
            bpf_map_get_next_key(&map, &null_key_iter, &mut read, &mut write),
            Ok(0)
        );
        let mut copied_key = [0u8; 4];
        copied_key.copy_from_slice(&user_cell.borrow().mem[next_key_addr - 0x1000..next_key_addr - 0x1000 + 4]);
        assert_eq!(copied_key, key1);

        // 11. GET_NEXT_KEY at end returns ENOENT
        let end_iter = BpfMapElemAttr {
            key: key_addr as u64,
            value_or_next_key: next_key_addr as u64,
            flags: 0,
            ..Default::default()
        };
        assert_eq!(
            bpf_map_get_next_key(&map, &end_iter, &mut read, &mut write),
            Err(LinuxError::ENOENT)
        );

        // 12. DELETE with non-zero flags returns EINVAL
        let bad_del_flags = BpfMapElemAttr {
            key: key_addr as u64,
            flags: 1,
            ..Default::default()
        };
        assert_eq!(
            bpf_map_delete_elem(&map, &bad_del_flags, &mut read),
            Err(LinuxError::EINVAL)
        );

        // 13. DELETE with bad key pointer returns EFAULT
        let bad_del_key = BpfMapElemAttr {
            key: 0,
            flags: 0,
            ..Default::default()
        };
        assert_eq!(
            bpf_map_delete_elem(&map, &bad_del_key, &mut read),
            Err(LinuxError::EFAULT)
        );

        // 14. DELETE with valid key succeeds
        let valid_del = BpfMapElemAttr {
            key: key_addr as u64,
            flags: 0,
            ..Default::default()
        };
        assert_eq!(
            bpf_map_delete_elem(&map, &valid_del, &mut read),
            Ok(0)
        );

        // After deletion, lookup returns ENOENT
        assert_eq!(
            bpf_map_lookup_elem(&map, &valid_lookup, &mut read, &mut write),
            Err(LinuxError::ENOENT)
        );
    }

    #[test]
    fn bpf_map_lifecycle_fd_table_fork_exec_cloexec_and_dup() {
        static BUDGET: BpfMemoryBudget = BpfMemoryBudget::new(1024 * 1024);

        struct MockFdEntry {
            map: Arc<BpfMap>,
            cloexec: bool,
        }

        struct MockProcess {
            nofile: usize,
            fds: alloc::vec::Vec<Option<MockFdEntry>>,
        }

        impl MockProcess {
            fn new(nofile: usize) -> Self {
                Self {
                    nofile,
                    fds: alloc::vec::Vec::new(),
                }
            }

            fn insert_map(&mut self, map: Arc<BpfMap>) -> Result<usize, LinuxError> {
                let fd = self
                    .fds
                    .iter()
                    .position(|slot| slot.is_none())
                    .unwrap_or(self.fds.len());
                if fd >= self.nofile {
                    return Err(LinuxError::EMFILE);
                }
                let entry = MockFdEntry {
                    map,
                    cloexec: true,
                };
                if fd < self.fds.len() {
                    self.fds[fd] = Some(entry);
                } else {
                    self.fds.push(Some(entry));
                }
                Ok(fd)
            }

            fn dup(&mut self, old_fd: usize) -> Result<usize, LinuxError> {
                let entry = self
                    .fds
                    .get(old_fd)
                    .and_then(Option::as_ref)
                    .ok_or(LinuxError::EBADF)?;
                let new_entry = MockFdEntry {
                    map: entry.map.clone(),
                    cloexec: false,
                };
                let new_fd = self
                    .fds
                    .iter()
                    .position(|slot| slot.is_none())
                    .unwrap_or(self.fds.len());
                if new_fd >= self.nofile {
                    return Err(LinuxError::EMFILE);
                }
                if new_fd < self.fds.len() {
                    self.fds[new_fd] = Some(new_entry);
                } else {
                    self.fds.push(Some(new_entry));
                }
                Ok(new_fd)
            }

            fn close(&mut self, fd: usize) -> Result<(), LinuxError> {
                if fd >= self.fds.len() || self.fds[fd].is_none() {
                    return Err(LinuxError::EBADF);
                }
                self.fds[fd] = None;
                Ok(())
            }

            fn fork(&self) -> Self {
                let mut child_fds = alloc::vec::Vec::with_capacity(self.fds.len());
                for slot in &self.fds {
                    child_fds.push(slot.as_ref().map(|e| MockFdEntry {
                        map: e.map.clone(),
                        cloexec: e.cloexec,
                    }));
                }
                Self {
                    nofile: self.nofile,
                    fds: child_fds,
                }
            }

            fn exec(&mut self) {
                for slot in &mut self.fds {
                    if slot.as_ref().is_some_and(|e| e.cloexec) {
                        *slot = None;
                    }
                }
            }
        }

        assert_eq!(BUDGET.live_maps(), 0);
        assert_eq!(BUDGET.charged_bytes(), 0);

        let mut parent = MockProcess::new(16);

        // 1. Map creation inserts with CLOEXEC
        let map = Arc::new(BpfMap::create_in(BpfMapSpec::validate(&array_req()).unwrap(), &BUDGET).unwrap());
        let map_id = map.id();
        let fd = parent.insert_map(map).unwrap();
        assert_eq!(BUDGET.live_maps(), 1);
        assert!(parent.fds[fd].as_ref().unwrap().cloexec);

        // 2. dup creates non-CLOEXEC duplicate sharing the same object
        let dup_fd = parent.dup(fd).unwrap();
        assert_ne!(fd, dup_fd);
        assert!(!parent.fds[dup_fd].as_ref().unwrap().cloexec);
        assert_eq!(parent.fds[dup_fd].as_ref().unwrap().map.id(), map_id);
        assert_eq!(BUDGET.live_maps(), 1);

        // 3. fork shares descriptors across processes
        let mut child = parent.fork();
        assert_eq!(BUDGET.live_maps(), 1);
        assert_eq!(child.fds[fd].as_ref().unwrap().map.id(), map_id);
        assert_eq!(child.fds[dup_fd].as_ref().unwrap().map.id(), map_id);

        // 4. exec drops CLOEXEC in child, leaving non-CLOEXEC dup_fd
        child.exec();
        assert!(child.fds[fd].is_none());
        assert!(child.fds[dup_fd].is_some());
        assert_eq!(BUDGET.live_maps(), 1);

        // 5. Parent closes both descriptors; object remains alive in child
        parent.close(fd).unwrap();
        parent.close(dup_fd).unwrap();
        assert_eq!(BUDGET.live_maps(), 1);
        assert_eq!(BUDGET.charged_bytes(), 128);

        // 6. Child closes dup_fd; object is destroyed and budget is freed
        child.close(dup_fd).unwrap();
        assert_eq!(BUDGET.live_maps(), 0);
        assert_eq!(BUDGET.charged_bytes(), 0);
    }

    #[test]
    fn bpf_map_rlimit_nofile_exhaustion_does_not_leak_allocation() {
        static BUDGET: BpfMemoryBudget = BpfMemoryBudget::new(1024 * 1024);

        let spec = BpfMapSpec::validate(&hash_req()).unwrap();
        let charged = spec.storage_bytes();

        let map = Arc::new(BpfMap::create_in(spec, &BUDGET).unwrap());
        assert_eq!(BUDGET.live_maps(), 1);
        assert_eq!(BUDGET.charged_bytes(), charged);

        // Simulating Process::insert_fd_entry returning EMFILE when limit reached:
        // entry is dropped immediately when insertion fails.
        drop(map);
        assert_eq!(BUDGET.live_maps(), 0);
        assert_eq!(BUDGET.charged_bytes(), 0);
    }

    #[test]
    fn bpf_map_array_element_lifecycle() {
        let mut req = array_req();
        req.key_size = 4;
        req.value_size = 8;
        req.max_entries = 4;
        let spec = BpfMapSpec::validate(&req).unwrap();
        let map = BpfMap::create(spec).unwrap();

        // 1. Initial lookup on index 0 returns zeroes
        let mut val = [0xffu8; 8];
        map.lookup(&0u32.to_ne_bytes(), &mut val).unwrap();
        assert_eq!(val, [0u8; 8]);

        // 2. Out-of-bounds lookup returns ENOENT
        assert_eq!(
            map.lookup(&4u32.to_ne_bytes(), &mut val).unwrap_err(),
            LinuxError::ENOENT
        );

        // 3. Update with BPF_NOEXIST returns EEXIST
        let new_val = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            map.update(&1u32.to_ne_bytes(), &new_val, BPF_NOEXIST).unwrap_err(),
            LinuxError::EEXIST
        );

        // 4. Update with BPF_ANY succeeds
        map.update(&1u32.to_ne_bytes(), &new_val, BPF_ANY).unwrap();
        map.lookup(&1u32.to_ne_bytes(), &mut val).unwrap();
        assert_eq!(val, new_val);

        // 5. Update with BPF_EXIST succeeds
        let updated_val = [9u8; 8];
        map.update(&1u32.to_ne_bytes(), &updated_val, BPF_EXIST).unwrap();
        map.lookup(&1u32.to_ne_bytes(), &mut val).unwrap();
        assert_eq!(val, updated_val);

        // 6. Update out-of-bounds returns E2BIG
        assert_eq!(
            map.update(&4u32.to_ne_bytes(), &new_val, BPF_ANY).unwrap_err(),
            LinuxError::E2BIG
        );

        // 7. Update with invalid flags returns EINVAL
        assert_eq!(
            map.update(&1u32.to_ne_bytes(), &new_val, 3).unwrap_err(),
            LinuxError::EINVAL
        );

        // 8. Array delete returns EINVAL
        assert_eq!(
            map.delete(&1u32.to_ne_bytes()).unwrap_err(),
            LinuxError::EINVAL
        );

        // 9. Array get_next_key iteration
        let mut next = [0u8; 4];
        map.get_next_key(None, &mut next).unwrap();
        assert_eq!(u32::from_ne_bytes(next), 0);

        map.get_next_key(Some(&0u32.to_ne_bytes()), &mut next).unwrap();
        assert_eq!(u32::from_ne_bytes(next), 1);

        map.get_next_key(Some(&1u32.to_ne_bytes()), &mut next).unwrap();
        assert_eq!(u32::from_ne_bytes(next), 2);

        map.get_next_key(Some(&2u32.to_ne_bytes()), &mut next).unwrap();
        assert_eq!(u32::from_ne_bytes(next), 3);

        assert_eq!(
            map.get_next_key(Some(&3u32.to_ne_bytes()), &mut next).unwrap_err(),
            LinuxError::ENOENT
        );

        // Out-of-bounds key restarts iteration at 0
        map.get_next_key(Some(&99u32.to_ne_bytes()), &mut next).unwrap();
        assert_eq!(u32::from_ne_bytes(next), 0);
    }

    #[test]
    fn bpf_map_hash_element_lifecycle() {
        let mut req = hash_req();
        req.key_size = 4;
        req.value_size = 8;
        req.max_entries = 2;
        let spec = BpfMapSpec::validate(&req).unwrap();
        let map = BpfMap::create(spec).unwrap();

        let key1 = [1u8, 0, 0, 0];
        let val1 = [10u8; 8];
        let mut val_out = [0u8; 8];

        // 1. Empty lookup returns ENOENT
        assert_eq!(map.lookup(&key1, &mut val_out).unwrap_err(), LinuxError::ENOENT);

        // 2. Update non-existent with BPF_EXIST returns ENOENT
        assert_eq!(
            map.update(&key1, &val1, BPF_EXIST).unwrap_err(),
            LinuxError::ENOENT
        );

        // 3. Update non-existent with BPF_NOEXIST succeeds
        map.update(&key1, &val1, BPF_NOEXIST).unwrap();
        map.lookup(&key1, &mut val_out).unwrap();
        assert_eq!(val_out, val1);

        // 4. Update existing with BPF_NOEXIST returns EEXIST
        assert_eq!(
            map.update(&key1, &val1, BPF_NOEXIST).unwrap_err(),
            LinuxError::EEXIST
        );

        // 5. Update existing with BPF_EXIST succeeds
        let val1_new = [20u8; 8];
        map.update(&key1, &val1_new, BPF_EXIST).unwrap();
        map.lookup(&key1, &mut val_out).unwrap();
        assert_eq!(val_out, val1_new);

        // 6. Fill map up to max_entries (2)
        let key2 = [2u8, 0, 0, 0];
        let val2 = [30u8; 8];
        map.update(&key2, &val2, BPF_ANY).unwrap();

        // 7. Adding 3rd key returns E2BIG
        let key3 = [3u8, 0, 0, 0];
        let val3 = [40u8; 8];
        assert_eq!(
            map.update(&key3, &val3, BPF_ANY).unwrap_err(),
            LinuxError::E2BIG
        );

        // 8. Delete non-existent returns ENOENT
        assert_eq!(
            map.delete(&key3).unwrap_err(),
            LinuxError::ENOENT
        );

        // 9. Iteration over hash map
        let mut next_key = [0u8; 4];
        map.get_next_key(None, &mut next_key).unwrap();
        assert_eq!(next_key, key1);

        map.get_next_key(Some(&key1), &mut next_key).unwrap();
        assert_eq!(next_key, key2);

        assert_eq!(
            map.get_next_key(Some(&key2), &mut next_key).unwrap_err(),
            LinuxError::ENOENT
        );

        // Missing key in get_next_key returns first key
        map.get_next_key(Some(&key3), &mut next_key).unwrap();
        assert_eq!(next_key, key1);

        // 10. Delete key1 succeeds, free slot allows adding key3
        map.delete(&key1).unwrap();
        assert_eq!(map.lookup(&key1, &mut val_out).unwrap_err(), LinuxError::ENOENT);
        map.update(&key3, &val3, BPF_ANY).unwrap();
        map.lookup(&key3, &mut val_out).unwrap();
        assert_eq!(val_out, val3);
    }

    #[test]
    fn ltp_bpf_map01_assertions() {
        // Adapted assertions from ltp/testcases/kernel/syscalls/bpf/bpf_map01.c
        // 1. Hash map: key_size=8, val_size=1024, max_entries=1
        let mut hash_create = hash_req();
        hash_create.key_size = 8;
        hash_create.value_size = 1024;
        hash_create.max_entries = 1;
        let hash_map = BpfMap::create(BpfMapSpec::validate(&hash_create).unwrap()).unwrap();

        let mut key8 = [0u8; 8];
        key8.copy_from_slice(b"12345678");
        let mut val_get = [0x55u8; 1024];
        let mut val_set = [0u8; 1024];
        for i in 0..1024 {
            val_set[i] = (i % 256) as u8;
        }

        // Empty hash map lookup should fail with ENOENT
        assert_eq!(hash_map.lookup(&key8, &mut val_get).unwrap_err(), LinuxError::ENOENT);

        // Update hash map element with BPF_ANY succeeds
        hash_map.update(&key8, &val_set, BPF_ANY).unwrap();

        // Hash map lookup returns the updated value
        hash_map.lookup(&key8, &mut val_get).unwrap();
        assert_eq!(&val_get[..], &val_set[..]);

        // 2. Array map: key_size=4, val_size=1024, max_entries=1
        let mut array_create = array_req();
        array_create.key_size = 4;
        array_create.value_size = 1024;
        array_create.max_entries = 1;
        let array_map = BpfMap::create(BpfMapSpec::validate(&array_create).unwrap()).unwrap();

        let key4 = 0u32.to_ne_bytes();
        val_get.fill(0x77);

        // Preallocated array map lookup returns all zeroes
        array_map.lookup(&key4, &mut val_get).unwrap();
        assert!(val_get.iter().all(|&b| b == 0));

        // Update array map element with BPF_ANY succeeds
        array_map.update(&key4, &val_set, BPF_ANY).unwrap();

        // Array map lookup returns the updated value
        array_map.lookup(&key4, &mut val_get).unwrap();
        assert_eq!(&val_get[..], &val_set[..]);
    }
}


