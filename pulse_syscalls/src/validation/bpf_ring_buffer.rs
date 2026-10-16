//! Host validation tests for BPF Ring Buffer producer, mmap, epoll, and loss accounting (#107).

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use axerrno::LinuxError;

    use crate::validation::bpf_link::{
        core_insn::*, core_map::*, core_program::*, core_verifier::*,
    };

    pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;
    pub const BPF_FUNC_RINGBUF_OUTPUT: i32 = 130;
    pub const BPF_FUNC_RINGBUF_RESERVE: i32 = 131;
    pub const BPF_FUNC_RINGBUF_SUBMIT: i32 = 132;
    pub const BPF_FUNC_RINGBUF_DISCARD: i32 = 133;

    fn name(s: &str) -> [u8; BPF_OBJ_NAME_LEN] {
        let mut out = [0u8; BPF_OBJ_NAME_LEN];
        out[..s.len()].copy_from_slice(s.as_bytes());
        out
    }

    fn ringbuf_req(max_entries: u32) -> BpfMapCreateRequest {
        BpfMapCreateRequest {
            map_type: BPF_MAP_TYPE_RINGBUF,
            key_size: 0,
            value_size: 0,
            max_entries,
            map_name: name("ringbuf_test"),
            ..Default::default()
        }
    }

    #[test]
    fn seam1_ringbuf_metadata_validation_and_unsupported_helpers() {
        // Valid creation: key_size == 0, value_size == 0, max_entries power of two & multiple of 4096
        let req = ringbuf_req(4096);
        let spec = BpfMapSpec::validate(&req).expect("valid RINGBUF map creation should succeed");
        assert_eq!(spec.map_type(), BpfMapType::RingBuf);
        assert_eq!(spec.key_size(), 0);
        assert_eq!(spec.value_size(), 0);
        assert_eq!(spec.max_entries(), 4096);
        assert_eq!(spec.storage_bytes(), 4096);

        // Invalid key_size != 0
        let mut bad_key = req;
        bad_key.key_size = 4;
        assert_eq!(BpfMapSpec::validate(&bad_key).err(), Some(LinuxError::EINVAL));

        // Invalid value_size != 0
        let mut bad_val = req;
        bad_val.value_size = 4;
        assert_eq!(BpfMapSpec::validate(&bad_val).err(), Some(LinuxError::EINVAL));

        // Invalid max_entries == 0
        let mut zero_entries = req;
        zero_entries.max_entries = 0;
        assert_eq!(BpfMapSpec::validate(&zero_entries).err(), Some(LinuxError::EINVAL));

        // Invalid max_entries not multiple of 4096
        let mut non_page = req;
        non_page.max_entries = 3000;
        assert_eq!(BpfMapSpec::validate(&non_page).err(), Some(LinuxError::EINVAL));

        // Invalid max_entries not power of two (3 * 4096 = 12288)
        let mut non_pot = req;
        non_pot.max_entries = 12288;
        assert_eq!(BpfMapSpec::validate(&non_pot).err(), Some(LinuxError::EINVAL));

        // Invalid flags
        let mut bad_flags = req;
        bad_flags.map_flags = BPF_F_NO_PREALLOC;
        assert_eq!(BpfMapSpec::validate(&bad_flags).err(), Some(LinuxError::EINVAL));

        // Map creation
        let map = Arc::new(BpfMap::create(spec).expect("map creation within memory budget"));

        // RingBuf map does not support element lookup / update / delete
        let mut buf = [0u8; 4];
        assert_eq!(map.lookup(&[], &mut buf).err(), Some(LinuxError::EINVAL));
        assert_eq!(map.update(&[], &buf, BPF_ANY).err(), Some(LinuxError::EINVAL));
        assert_eq!(map.delete(&[]).err(), Some(LinuxError::EINVAL));

        // Verifier check: helper 130 (bpf_ringbuf_output) is accepted with RingBuf map
        struct Resolver(Arc<BpfMap>);
        impl MapResolver for Resolver {
            fn resolve_map(&self, _fd: u32) -> Result<Arc<BpfMap>, LinuxError> {
                Ok(self.0.clone())
            }
        }
        let resolver = Resolver(map);

        let valid_ringbuf_insns = [
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_1, 0, 0, 0x1234),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_W, BPF_REG_10, BPF_REG_1, -4, 0),
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 1),
            BpfInsn::new(0, 0, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_3, 0, 0, 4),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_4, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_RINGBUF_OUTPUT),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let config = VerifierConfig::new(BpfProgType::Tracepoint, 1);
        let mut log = VerifierLog::new();
        let verified = verify_program(&config, &valid_ringbuf_insns, Some(&resolver), &mut log);
        assert!(verified.is_ok(), "verifier should accept valid bpf_ringbuf_output");

        // Verifier check: reserve/submit/discard (131/132/133) rejected with EOPNOTSUPP
        for unsupp_helper in [BPF_FUNC_RINGBUF_RESERVE, BPF_FUNC_RINGBUF_SUBMIT, BPF_FUNC_RINGBUF_DISCARD] {
            let unsupp_insns = [
                BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 1),
                BpfInsn::new(0, 0, 0, 0, 0),
                BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_2, 0, 0, 8),
                BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, unsupp_helper),
                BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
            ];
            let mut unsupp_log = VerifierLog::new();
            let err = verify_program(&config, &unsupp_insns, Some(&resolver), &mut unsupp_log).err().unwrap();
            assert_eq!(err, LinuxError::EOPNOTSUPP, "helper {} should return EOPNOTSUPP", unsupp_helper);
        }
    }

    #[test]
    fn seam2_ringbuf_output_copy_mpsc_ordering_and_loss_accounting() {
        let req = ringbuf_req(4096);
        let spec = BpfMapSpec::validate(&req).unwrap();
        let map = Arc::new(BpfMap::create(spec).unwrap());
        let rb = map.ringbuf().expect("map should have ringbuf instance");

        struct Resolver(Arc<BpfMap>);
        impl MapResolver for Resolver {
            fn resolve_map(&self, _fd: u32) -> Result<Arc<BpfMap>, LinuxError> {
                Ok(self.0.clone())
            }
        }
        let resolver = Resolver(map);

        // eBPF program:
        // writes data (0x11223344) to stack, calls bpf_ringbuf_output
        let insns = [
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_1, 0, 0, 0x11223344),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_W, BPF_REG_10, BPF_REG_1, -4, 0),
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 1),
            BpfInsn::new(0, 0, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_3, 0, 0, 4),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_4, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_RINGBUF_OUTPUT),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let config = VerifierConfig::new(BpfProgType::Tracepoint, 1);
        let mut log = VerifierLog::new();
        let verified = verify_program(&config, &insns, Some(&resolver), &mut log).unwrap();
        let prog = Arc::new(BpfProgram::new(
            verified.prog_type,
            [0u8; 16],
            verified.insns,
            verified.referenced_maps,
        ));

        // 1. Single execution
        let dummy_ctx = [0u8; 80];
        let ret = prog.run(&dummy_ctx).expect("prog should run");
        assert_eq!(ret, 0);

        // Header: 8 bytes, payload: 4 bytes, aligned to 8: total = 16 bytes
        assert_eq!(rb.producer_pos(), 16);
        assert_eq!(rb.consumer_pos(), 0);
        assert!(rb.is_readable());

        let (recs, counters) = rb.parse_records().expect("parse should succeed");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].data, 0x11223344u32.to_ne_bytes());
        assert_eq!(counters.corrupt_records, 0);
        assert_eq!(counters.discarded_records, 0);
        assert_eq!(rb.consumer_pos(), 16);
        assert!(!rb.is_readable());

        // 2. MPSC concurrency & preservation of reservation order
        use std::thread;
        let mut handles = alloc::vec::Vec::new();
        for t in 0..4 {
            let prog_clone = prog.clone();
            handles.push(thread::spawn(move || {
                for i in 0..50 {
                    let mut ctx = [0u8; 80];
                    ctx[0..4].copy_from_slice(&(t as u32).to_ne_bytes());
                    ctx[4..8].copy_from_slice(&(i as u32).to_ne_bytes());
                    let res = prog_clone.run(&ctx).unwrap();
                    assert_eq!(res, 0);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // Total 4 threads * 50 = 200 records produced
        let (concurrent_recs, _) = rb.parse_records().expect("concurrent records parse");
        assert_eq!(concurrent_recs.len(), 200);
        for rec in &concurrent_recs {
            assert_eq!(rec.data.len(), 4);
            assert_eq!(rec.data, 0x11223344u32.to_ne_bytes());
        }

        // 3. Loss accounting when buffer is full
        // rb capacity is 4096. Each record is 16 bytes. 4096 / 16 = 256 records max.
        // Let's produce until full:
        let mut filled = 0;
        loop {
            let res = prog.run(&dummy_ctx).unwrap();
            if res as i64 == -(LinuxError::EAGAIN.code() as i64) {
                break;
            }
            assert_eq!(res, 0);
            filled += 1;
            if filled > 300 {
                panic!("should have filled the buffer");
            }
        }

        // Now buffer is full. Subsequent writes should fail with EAGAIN and increment ringbuf_lost!
        assert_eq!(rb.ringbuf_lost(), 1);
        let res2 = prog.run(&dummy_ctx).unwrap();
        assert_eq!(res2 as i64, -(LinuxError::EAGAIN.code() as i64));
        assert_eq!(rb.ringbuf_lost(), 2);

        // After consumer drains, writes succeed again
        let (drained, _) = rb.parse_records().unwrap();
        assert_eq!(drained.len(), filled);
        let res3 = prog.run(&dummy_ctx).unwrap();
        assert_eq!(res3, 0);
    }

    #[test]
    fn seam3_ringbuf_readiness_sequence_mmap_and_lifecycle() {
        let req = ringbuf_req(4096);
        let spec = BpfMapSpec::validate(&req).unwrap();
        let map = Arc::new(BpfMap::create(spec).unwrap());
        let rb = map.ringbuf().expect("must have ringbuf backend");

        // 1. Initial readiness state
        assert!(!rb.is_readable(), "empty ringbuf must not be readable");
        assert_eq!(rb.poll_event_sequence(), 0);
        assert_eq!(rb.consumer_pos(), 0);
        assert_eq!(rb.producer_pos(), 0);

        // 2. Memory layout for mmap:
        // Total size = 2 control pages (8192 bytes) + 4096 data bytes = 12288 bytes
        assert_eq!(rb.total_size(), 12288);
        assert_eq!(rb.data_size(), 4096);

        // Check raw base offsets:
        // Page 0 (offset 0): consumer pos atomic
        // Page 1 (offset 4096): producer pos atomic
        unsafe {
            let cons_ptr = rb.raw_base() as *const u64;
            let prod_ptr = (rb.raw_base() + 4096) as *const u64;
            assert_eq!(*cons_ptr, 0);
            assert_eq!(*prod_ptr, 0);
        }

        // 3. Write record #1 (empty -> non-empty default wakeup):
        // Default wakeup triggers notify_readable when buffer was empty (old_prod == consumer_pos)
        let sample1 = [0xAA; 16];
        rb.output(&sample1, 0).expect("output sample1");
        assert!(rb.is_readable());
        assert_eq!(rb.poll_event_sequence(), 1);

        // 4. Edge-triggered (EPOLLET) readiness scan helper
        let mut reported_in = false;
        let mut reported_in_seq: Option<u64> = None;
        let mut scan_epollet = |reported_in: &mut bool, reported_in_seq: &mut Option<u64>| -> u32 {
            let seq = rb.poll_event_sequence();
            let ready = rb.is_readable();
            let mut revents = 0u32;
            if ready {
                let seq_changed = *reported_in_seq != Some(seq);
                if !*reported_in || seq_changed {
                    revents |= 0x1; // EPOLLIN
                    *reported_in = true;
                    *reported_in_seq = Some(seq);
                }
            }
            revents
        };

        let revents1 = scan_epollet(&mut reported_in, &mut reported_in_seq);
        assert_eq!(revents1, 0x1, "first scan must report EPOLLIN");
        assert_eq!(reported_in_seq, Some(1));

        // Write record #2 with BPF_RB_NO_WAKEUP (when buffer already non-empty)
        let sample2 = [0xBB; 16];
        rb.output(&sample2, BPF_RB_NO_WAKEUP).expect("output sample2");
        // Sequence should remain unchanged because NO_WAKEUP was requested and old_prod != consumer_pos
        assert_eq!(rb.poll_event_sequence(), 1);

        // Second EPOLLET scan: still readable, but sequence did not change -> no event reported
        let revents2 = scan_epollet(&mut reported_in, &mut reported_in_seq);
        assert_eq!(revents2, 0, "EPOLLET must suppress reporting when sequence did not advance");

        // Write record #3 with BPF_RB_FORCE_WAKEUP: must unconditionally advance sequence
        let sample3 = [0xCC; 16];
        rb.output(&sample3, BPF_RB_FORCE_WAKEUP).expect("output sample3");
        assert_eq!(rb.poll_event_sequence(), 2);

        // Third EPOLLET scan: sequence advanced -> reports EPOLLIN
        let revents3 = scan_epollet(&mut reported_in, &mut reported_in_seq);
        assert_eq!(revents3, 0x1, "EPOLLET must fire on sequence change from FORCE_WAKEUP");
        assert_eq!(reported_in_seq, Some(2));

        // 5. Consumer drains records
        let (records, _) = rb.parse_records().unwrap();
        assert_eq!(records.len(), 3);
        assert!(!rb.is_readable());
        assert_eq!(rb.consumer_pos(), rb.producer_pos());

        // 6. Object FD sharing & reference count drop
        let map_ref1 = map.clone();
        let map_ref2 = map.clone();
        assert_eq!(Arc::strong_count(&map), 3);
        drop(map_ref1);
        assert_eq!(Arc::strong_count(&map), 2);
        drop(map_ref2);
        assert_eq!(Arc::strong_count(&map), 1);
        drop(map);
        // Only rb Arc remains in this test scope
        assert_eq!(Arc::strong_count(&rb), 1);
    }
}
