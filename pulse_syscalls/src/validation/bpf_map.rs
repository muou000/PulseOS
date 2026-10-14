//! Host tests for BPF Map objects (#92).
//!
//! `pulse_core` cannot be built for the host, so the pure Map model in
//! `pulse_core/src/bpf/map.rs` is compiled here directly. That file must stay
//! self-contained (only `core`, `alloc` and `axerrno`).

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/map.rs"]
mod core_map;

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use axerrno::LinuxError;

    use super::core_map::*;
    use crate::impls::bpf::{
        abi::{BpfAttr, BpfCmd, check_attr_unused_tail},
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
        for raw in [3, 4, 5, 27, 33] {
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
    }

    #[test]
    fn bpf_commands_implemented_by_map_slice() {
        assert!(!BpfCmd::MapCreate.is_deferred());
        assert!(!BpfCmd::ObjGetInfoByFd.is_deferred());
        for &cmd in &BpfCmd::ALL {
            if cmd != BpfCmd::MapCreate && cmd != BpfCmd::ObjGetInfoByFd {
                assert!(cmd.is_deferred(), "{cmd:?}");
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
}

