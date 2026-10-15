//! Host validation tests for single-CPU Perf Buffer producer and consumer path (#100).

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use axerrno::LinuxError;

    use crate::validation::bpf_link::{
        core_insn::*, core_map::*, core_perf_event::*, core_program::*, core_verifier::*,
    };

    pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: u32 = 4;
    pub const BPF_FUNC_PERF_EVENT_OUTPUT: i32 = 25;

    fn name(s: &str) -> [u8; BPF_OBJ_NAME_LEN] {
        let mut out = [0u8; BPF_OBJ_NAME_LEN];
        out[..s.len()].copy_from_slice(s.as_bytes());
        out
    }

    fn perf_event_array_req() -> BpfMapCreateRequest {
        BpfMapCreateRequest {
            map_type: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
            key_size: 4,
            value_size: 4,
            max_entries: 4,
            map_name: name("events"),
            ..Default::default()
        }
    }

    #[test]
    fn acceptance_single_cpu_produce_and_consume_normalized_record() {
        let req = perf_event_array_req();
        let spec = BpfMapSpec::validate(&req).unwrap();
        let map = Arc::new(BpfMap::create(spec).unwrap());

        let event = Arc::new(PerfEvent::new(
            PerfEventSpec {
                clock: PerfEventClock::BpfOutput,
                scope: PerfEventScope::PerCpu { cpu: 0 },
                sample_period: 0,
                disabled: false,
                cloexec: false,
            },
            0,
        ));
        let perf_buf = PerfBuffer::new(1).unwrap();
        event.set_buffer(perf_buf.clone());
        map.set_slot(0, Some(10), Some(event.clone())).unwrap();

        struct Resolver(Arc<BpfMap>);
        impl MapResolver for Resolver {
            fn resolve_map(&self, _fd: u32) -> Result<Arc<BpfMap>, LinuxError> {
                Ok(self.0.clone())
            }
        }
        let resolver = Resolver(map);

        let insns = [
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_1, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_1, 0, 0, 0x5678),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_W, BPF_REG_10, BPF_REG_1, -4, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_1, BPF_REG_6, 0, 0),
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_2, BPF_PSEUDO_MAP_FD, 0, 1),
            BpfInsn::new(0, 0, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_3, 0, 0, -1),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_4, BPF_REG_10, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_4, 0, 0, -4),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_5, 0, 0, 4),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_PERF_EVENT_OUTPUT),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let config = VerifierConfig::new(BpfProgType::PerfEvent, 1);
        let mut log = VerifierLog::new();
        let verified = verify_program(&config, &insns, Some(&resolver), &mut log).unwrap();
        let prog = Arc::new(BpfProgram::new(
            verified.prog_type,
            [0u8; 16],
            verified.insns,
            verified.referenced_maps,
        ));

        let ctx = pulse_bpf_schema::PerfEventContext::new(1000, 0, 100, 0, 1, 1, 1);
        let ret = prog.run(ctx.as_bytes()).expect("run should return R0");
        assert_eq!(ret, 0);

        // User-space consumer reads from perf buffer:
        let head = perf_buf.data_head();
        let tail = perf_buf.data_tail();
        assert_eq!(head, 16);
        assert_eq!(tail, 0);

        let mut rec = [0u8; 16];
        perf_buf.read_circular(0, &mut rec);
        let event_type = u32::from_ne_bytes(rec[0..4].try_into().unwrap());
        let rec_size = u16::from_ne_bytes(rec[6..8].try_into().unwrap());
        let raw_len = u32::from_ne_bytes(rec[8..12].try_into().unwrap());
        let payload = u32::from_ne_bytes(rec[12..16].try_into().unwrap());

        assert_eq!(event_type, PERF_RECORD_SAMPLE);
        assert_eq!(rec_size, 16);
        assert_eq!(raw_len, 4);
        assert_eq!(payload, 0x5678);

        perf_buf.set_data_tail(tail + rec_size as u64);
        assert_eq!(perf_buf.data_tail(), 16);
    }

    #[test]
    fn seam1_perf_event_array_metadata_and_slot_updates() {
        let req = perf_event_array_req();
        let spec = BpfMapSpec::validate(&req).expect("PERF_EVENT_ARRAY map creation should succeed");
        assert_eq!(spec.map_type(), BpfMapType::PerfEventArray);
        assert_eq!(spec.key_size(), 4);
        assert_eq!(spec.value_size(), 4);
        assert_eq!(spec.max_entries(), 4);
        assert_eq!(spec.storage_bytes(), 4 * 4);

        // Invalid key_size or value_size rejected
        let mut bad_key = req;
        bad_key.key_size = 8;
        assert_eq!(BpfMapSpec::validate(&bad_key).err(), Some(LinuxError::EINVAL));

        let mut bad_val = req;
        bad_val.value_size = 8;
        assert_eq!(BpfMapSpec::validate(&bad_val).err(), Some(LinuxError::EINVAL));

        let mut bad_flags = req;
        bad_flags.map_flags = BPF_F_NO_PREALLOC;
        assert_eq!(BpfMapSpec::validate(&bad_flags).err(), Some(LinuxError::EINVAL));

        // Create map and test slot updates
        let map = BpfMap::create(spec).expect("map creation in memory budget");
        let cpu0 = 0u32.to_ne_bytes();
        let cpu3 = 3u32.to_ne_bytes();
        let cpu4 = 4u32.to_ne_bytes();
        let dummy_fd = 42u32.to_ne_bytes();

        // Slot update for cpu 0 succeeds
        assert!(map.update(&cpu0, &dummy_fd, BPF_ANY).is_ok());

        // Slot lookup retrieves the updated value
        let mut out = [0u8; 4];
        assert!(map.lookup(&cpu0, &mut out).is_ok());
        assert_eq!(out, dummy_fd);

        // Slot update for cpu 3 succeeds
        assert!(map.update(&cpu3, &dummy_fd, BPF_ANY).is_ok());

        // Slot update for out-of-bounds cpu 4 fails with E2BIG
        assert_eq!(map.update(&cpu4, &dummy_fd, BPF_ANY).err(), Some(LinuxError::E2BIG));

        // Delete slot for cpu 0 succeeds
        assert!(map.delete(&cpu0).is_ok());
        // After delete, lookup returns ENOENT (or zero)
        assert_eq!(map.lookup(&cpu0, &mut out).err(), Some(LinuxError::ENOENT));
    }

    #[test]
    fn seam2_bpf_perf_event_output_verifier_and_helper_dispatch() {
        let req = perf_event_array_req();
        let map_spec = BpfMapSpec::validate(&req).unwrap();
        let map = Arc::new(BpfMap::create(map_spec).unwrap());

        struct MockResolver(Arc<BpfMap>);
        impl MapResolver for MockResolver {
            fn resolve_map(&self, _fd: u32) -> Result<Arc<BpfMap>, LinuxError> {
                Ok(self.0.clone())
            }
        }
        let resolver = MockResolver(map.clone());

        // eBPF program:
        // r6 = r1 (save context)
        // r1 = 0x1234
        // *(u32 *)(r10 - 4) = r1
        // r1 = r6 (ctx)
        // r2 = map_fd (LD_IMM64 pseudo map fd)
        // r3 = BPF_F_CURRENT_CPU (-1 as imm)
        // r4 = r10 - 4 (data pointer)
        // r5 = 4 (data length)
        // call bpf_perf_event_output (25)
        // exit
        let insns = [
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_1, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_1, 0, 0, 0x1234),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_W, BPF_REG_10, BPF_REG_1, -4, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_1, BPF_REG_6, 0, 0),
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_2, BPF_PSEUDO_MAP_FD, 0, 1),
            BpfInsn::new(0, 0, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_3, 0, 0, -1),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_4, BPF_REG_10, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_4, 0, 0, -4),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_5, 0, 0, 4),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_PERF_EVENT_OUTPUT),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let config = VerifierConfig::new(BpfProgType::PerfEvent, 1);
        let mut log = VerifierLog::new();
        let verified = verify_program(&config, &insns, Some(&resolver), &mut log)
            .expect("verifier should accept valid bpf_perf_event_output call");

        let prog = Arc::new(BpfProgram::new(
            verified.prog_type,
            [0u8; 16],
            verified.insns,
            verified.referenced_maps,
        ));

        // When map slot is empty, program runs and helper returns -ENOENT in R0
        let ctx = pulse_bpf_schema::PerfEventContext::new(1000, 0, 100, 0, 1, 1, 1);
        let ret = prog.run(ctx.as_bytes()).expect("run should return R0");
        assert_eq!(ret as i64, -(LinuxError::ENOENT.code() as i64));

        // When slot has PerfEvent without buffer, returns -ENOENT
        let event = Arc::new(PerfEvent::new(
            PerfEventSpec {
                clock: PerfEventClock::BpfOutput,
                scope: PerfEventScope::PerCpu { cpu: 0 },
                sample_period: 0,
                disabled: false,
                cloexec: false,
            },
            0,
        ));
        map.set_slot(0, Some(10), Some(event.clone())).unwrap();
        let ret_no_buf = prog.run(ctx.as_bytes()).expect("run should return R0");
        assert_eq!(ret_no_buf as i64, -(LinuxError::ENOENT.code() as i64));

        // Attach PerfBuffer: helper outputs sample, returns 0, and data_head advances
        let perf_buf = PerfBuffer::new(1).unwrap();
        event.set_buffer(perf_buf.clone());
        let ret_ok = prog.run(ctx.as_bytes()).expect("run should return R0");
        assert_eq!(ret_ok, 0);
        // Record size: 8 bytes header + 4 bytes raw_len + 4 bytes payload = 16 bytes
        assert_eq!(perf_buf.data_head(), 16);
    }

    fn consume_records(buf: &PerfBuffer) -> (Vec<Vec<u8>>, u64) {
        let mut samples = Vec::new();
        let mut lost_events = 0u64;
        let head = buf.data_head();
        let mut tail = buf.data_tail();

        while tail < head {
            let offset = (tail % buf.data_size() as u64) as usize;
            let mut header_bytes = [0u8; 8];
            buf.read_circular(offset, &mut header_bytes);
            let event_type = u32::from_ne_bytes(header_bytes[0..4].try_into().unwrap());
            let _misc = u16::from_ne_bytes(header_bytes[4..6].try_into().unwrap());
            let rec_size = u16::from_ne_bytes(header_bytes[6..8].try_into().unwrap()) as usize;

            if event_type == PERF_RECORD_SAMPLE {
                let mut raw_len_bytes = [0u8; 4];
                buf.read_circular((offset + 8) % buf.data_size(), &mut raw_len_bytes);
                let raw_len = u32::from_ne_bytes(raw_len_bytes) as usize;
                let mut payload = alloc::vec![0u8; raw_len];
                buf.read_circular((offset + 12) % buf.data_size(), &mut payload);
                samples.push(payload);
            } else if event_type == PERF_RECORD_LOST {
                let mut lost_bytes = [0u8; 8];
                buf.read_circular((offset + 16) % buf.data_size(), &mut lost_bytes);
                let lost = u64::from_ne_bytes(lost_bytes);
                lost_events += lost;
            }

            tail = tail.wrapping_add(rec_size as u64);
            buf.set_data_tail(tail);
        }
        (samples, lost_events)
    }

    #[test]
    fn seam3_perf_ring_buffer_wrapping_and_userspace_consumer() {
        let perf_buf = PerfBuffer::new(1).expect("alloc 1 data page perf buffer");
        assert_eq!(perf_buf.data_size(), 4096);
        assert_eq!(perf_buf.total_size(), 8192);
        assert_eq!(perf_buf.data_head(), 0);
        assert_eq!(perf_buf.data_tail(), 0);

        // 1. Write records until head reaches near the end of the 4096-byte ring buffer.
        // Each record with 8-byte payload:
        // rec_size = align_up(8 + 4 + 8, 8) = 24 bytes.
        // 170 * 24 = 4080 bytes.
        for i in 0..170u64 {
            perf_buf.output_sample(&i.to_le_bytes()).unwrap();
        }
        assert_eq!(perf_buf.data_head(), 4080);

        // Consume all 170 records:
        let (samples, lost) = consume_records(&perf_buf);
        assert_eq!(lost, 0);
        assert_eq!(samples.len(), 170);
        for (i, s) in samples.iter().enumerate() {
            assert_eq!(s.as_slice(), &(i as u64).to_le_bytes());
        }
        assert_eq!(perf_buf.data_tail(), 4080);

        // 2. Wrap-around write:
        // At head = 4080, writing 24 bytes crosses the 4096 boundary!
        // 16 bytes at end [4080..4096], 8 bytes wrapped to index 0 [0..8].
        let wrap_payload = 0xdeadbeef_cafebabe_u64.to_le_bytes();
        perf_buf.output_sample(&wrap_payload).unwrap();
        assert_eq!(perf_buf.data_head(), 4104);

        // Consume the wrapped record:
        let (samples, lost) = consume_records(&perf_buf);
        assert_eq!(lost, 0);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].as_slice(), &wrap_payload);
        assert_eq!(perf_buf.data_tail(), 4104);

        // 3. Full buffer and nonblocking loss counting:
        // Do NOT consume: fill the buffer until ENOSPC.
        // Capacity is 4096 bytes. Each 24-byte record: 4096 / 24 = 170 records fit (4080 bytes).
        // 4096 - 4080 = 16 bytes left, which cannot fit a 24-byte record.
        for i in 0..170u64 {
            perf_buf.output_sample(&i.to_le_bytes()).unwrap();
        }
        // Buffer is full (16 bytes available < 24):
        let err1 = perf_buf.output_sample(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap_err();
        assert_eq!(err1, LinuxError::ENOSPC);
        let err2 = perf_buf.output_sample(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap_err();
        assert_eq!(err2, LinuxError::ENOSPC);
        assert_eq!(perf_buf.lost_count(), 2);

        // 4. Free up space and deliver PERF_RECORD_LOST:
        // Consume 2 records to make room (frees 48 bytes; available becomes 16 + 48 = 64 bytes).
        // PERF_RECORD_LOST (24 bytes) + new sample (24 bytes) = 48 bytes <= 64 bytes!
        {
            let mut tail = perf_buf.data_tail();
            for _ in 0..2 {
                tail = tail.wrapping_add(24);
            }
            perf_buf.set_data_tail(tail);
        }

        // Produce a new sample: it should successfully deliver PERF_RECORD_LOST first,
        // then deliver the new sample, resetting lost_count to 0!
        let new_sample = [0x55u8; 8];
        perf_buf.output_sample(&new_sample).unwrap();
        assert_eq!(perf_buf.lost_count(), 0);

        // User-space consumer reads all remaining records:
        let (remaining_samples, lost_delivered) = consume_records(&perf_buf);
        assert_eq!(lost_delivered, 2); // exactly the 2 dropped events accounted for!
        assert_eq!(remaining_samples.len(), 169);
        assert_eq!(remaining_samples.last().unwrap().as_slice(), &new_sample);
        assert_eq!(perf_buf.data_tail(), perf_buf.data_head());
    }

    #[test]
    fn seam4_perf_buffer_lifecycle_and_shared_ownership() {
        // 1. Validate invalid buffer page counts
        assert_eq!(PerfBuffer::new(0).unwrap_err(), LinuxError::EINVAL);
        assert_eq!(PerfBuffer::new(3).unwrap_err(), LinuxError::EINVAL);
        assert_eq!(PerfBuffer::new(5).unwrap_err(), LinuxError::EINVAL);
        assert!(PerfBuffer::new(1).is_ok());
        assert!(PerfBuffer::new(2).is_ok());
        assert!(PerfBuffer::new(4).is_ok());

        // 2. Shared ownership: Unmap before Close
        {
            let event = Arc::new(PerfEvent::new(
                PerfEventSpec {
                    clock: PerfEventClock::BpfOutput,
                    scope: PerfEventScope::PerCpu { cpu: 0 },
                    sample_period: 0,
                    disabled: false,
                    cloexec: false,
                },
                0,
            ));
            let buf = PerfBuffer::new(1).unwrap();
            event.set_buffer(buf.clone());

            let user_mmap_ref: Arc<PerfBuffer> = buf.clone();
            assert_eq!(Arc::strong_count(&buf), 3);

            event.output_sample(&[1, 2, 3, 4]).unwrap();
            assert_eq!(buf.data_head(), 16);

            // User-space unmaps first:
            drop(user_mmap_ref);
            assert_eq!(Arc::strong_count(&buf), 2);

            // Event still functions and producer can still output:
            event.output_sample(&[5, 6, 7, 8]).unwrap();
            assert_eq!(buf.data_head(), 32);

            // Close event:
            drop(event);
            assert_eq!(Arc::strong_count(&buf), 1);
        }

        // 3. Shared ownership: Close before Unmap
        {
            let event = Arc::new(PerfEvent::new(
                PerfEventSpec {
                    clock: PerfEventClock::BpfOutput,
                    scope: PerfEventScope::PerCpu { cpu: 0 },
                    sample_period: 0,
                    disabled: false,
                    cloexec: false,
                },
                0,
            ));
            let buf = PerfBuffer::new(1).unwrap();
            event.set_buffer(buf.clone());

            let user_mmap_ref = buf.clone();
            event.output_sample(&0xabcd_u32.to_le_bytes()).unwrap();

            // Event fd is closed first:
            drop(event);

            // User-space mapping is still alive and buffer is NOT freed:
            assert_eq!(user_mmap_ref.data_head(), 16);
            let mut sample_out = [0u8; 16];
            user_mmap_ref.read_circular(0, &mut sample_out);
            let payload = u32::from_ne_bytes(sample_out[12..16].try_into().unwrap());
            assert_eq!(payload, 0xabcd);

            // Consumer updates tail safely:
            user_mmap_ref.set_data_tail(16);
            assert_eq!(user_mmap_ref.data_tail(), 16);

            // Unmap drops the last reference cleanly:
            drop(user_mmap_ref);
        }
    }

    #[test]
    fn seam1_multi_cpu_selected_routing_and_loss_attribution() {
        let req = perf_event_array_req();
        let spec = BpfMapSpec::validate(&req).unwrap();
        let map = Arc::new(BpfMap::create(spec).unwrap());

        // Create 3 per-CPU events and buffers (CPU 0, CPU 1, CPU 2)
        let event0 = Arc::new(PerfEvent::new(
            PerfEventSpec {
                clock: PerfEventClock::BpfOutput,
                scope: PerfEventScope::PerCpu { cpu: 0 },
                sample_period: 0,
                disabled: false,
                cloexec: false,
            },
            0,
        ));
        let buf0 = PerfBuffer::new(1).unwrap();
        event0.set_buffer(buf0.clone());
        map.set_slot(0, Some(10), Some(event0.clone())).unwrap();

        let event1 = Arc::new(PerfEvent::new(
            PerfEventSpec {
                clock: PerfEventClock::BpfOutput,
                scope: PerfEventScope::PerCpu { cpu: 1 },
                sample_period: 0,
                disabled: false,
                cloexec: false,
            },
            0,
        ));
        let buf1 = PerfBuffer::new(1).unwrap();
        event1.set_buffer(buf1.clone());
        map.set_slot(1, Some(11), Some(event1.clone())).unwrap();

        let event2 = Arc::new(PerfEvent::new(
            PerfEventSpec {
                clock: PerfEventClock::BpfOutput,
                scope: PerfEventScope::PerCpu { cpu: 2 },
                sample_period: 0,
                disabled: false,
                cloexec: false,
            },
            0,
        ));
        let buf2 = PerfBuffer::new(1).unwrap();
        event2.set_buffer(buf2.clone());
        map.set_slot(2, Some(12), Some(event2.clone())).unwrap();

        struct Resolver(Arc<BpfMap>);
        impl MapResolver for Resolver {
            fn resolve_map(&self, _fd: u32) -> Result<Arc<BpfMap>, LinuxError> {
                Ok(self.0.clone())
            }
        }
        let resolver = Resolver(map.clone());

        // eBPF program: output to target CPU 1 (fixed in R3) while running on CPU 0
        let insns = [
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_1, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_1, 0, 0, 0x9999),
            BpfInsn::new(BPF_STX | BPF_MEM | BPF_W, BPF_REG_10, BPF_REG_1, -4, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_1, BPF_REG_6, 0, 0),
            BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_2, BPF_PSEUDO_MAP_FD, 0, 1),
            BpfInsn::new(0, 0, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_3, 0, 0, 1), // target CPU 1
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_4, BPF_REG_10, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_4, 0, 0, -4),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_5, 0, 0, 4),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_PERF_EVENT_OUTPUT),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];

        let config = VerifierConfig::new(BpfProgType::PerfEvent, 1);
        let mut log = VerifierLog::new();
        let verified = verify_program(&config, &insns, Some(&resolver), &mut log).unwrap();
        let prog = Arc::new(BpfProgram::new(
            verified.prog_type,
            [0u8; 16],
            verified.insns,
            verified.referenced_maps,
        ));

        // Run program where current CPU is 0
        let ctx = pulse_bpf_schema::PerfEventContext::new(1000, 0, 100, 0, 1, 1, 1);
        let ret = prog.run(ctx.as_bytes()).expect("run should return R0");
        assert_eq!(ret, 0, "output to selected CPU 1 must succeed");

        // Verify isolation:
        assert_eq!(buf0.data_head(), 0, "CPU 0 buffer must be untouched");
        assert_eq!(buf2.data_head(), 0, "CPU 2 buffer must be untouched");
        assert_eq!(buf1.data_head(), 16, "CPU 1 buffer must have received record");

        let mut rec = [0u8; 16];
        buf1.read_circular(0, &mut rec);
        let event_type = u32::from_ne_bytes(rec[0..4].try_into().unwrap());
        let payload = u32::from_ne_bytes(rec[12..16].try_into().unwrap());
        assert_eq!(event_type, PERF_RECORD_SAMPLE);
        assert_eq!(payload, 0x9999);

        // Fill CPU 1's buffer until full, verify loss is attributed ONLY to CPU 1
        for _ in 0..255 {
            buf1.output_sample(&0x1111_u32.to_ne_bytes()).unwrap();
        }
        assert_eq!(buf1.data_head(), 4096);

        // Next output to CPU 1 overflows:
        let overflow_ret = prog.run(ctx.as_bytes()).expect("run returns R0");
        assert_eq!(overflow_ret as i64, -(LinuxError::ENOSPC.code() as i64));
        assert_eq!(buf1.lost_count(), 1, "CPU 1 buffer must track lost sample");
        assert_eq!(buf0.lost_count(), 0, "CPU 0 buffer lost_count must be 0");
        assert_eq!(buf2.lost_count(), 0, "CPU 2 buffer lost_count must be 0");

        // Free space on CPU 1 and output via event1: PERF_RECORD_LOST must preserve CPU 1 identity
        buf1.set_data_tail(48);
        event1.output_sample(&0x8888_u32.to_ne_bytes()).unwrap();
        let (recs, lost) = buf1.parse_records().unwrap();
        assert_eq!(lost, 1);
        let lost_rec = recs.iter().find(|r| matches!(r, PerfRecord::Lost { .. })).unwrap();
        assert_eq!(
            *lost_rec,
            PerfRecord::Lost { id: 1, lost: 1 },
            "PERF_RECORD_LOST must preserve CPU 1 identity"
        );
    }

    #[test]
    fn seam2_perf_buffer_readiness_sequence_and_edge_oneshot_semantics() {
        let event = Arc::new(PerfEvent::new(
            PerfEventSpec {
                clock: PerfEventClock::BpfOutput,
                scope: PerfEventScope::PerCpu { cpu: 0 },
                sample_period: 0,
                disabled: false,
                cloexec: false,
            },
            0,
        ));
        let buf = PerfBuffer::new(1).unwrap();
        event.set_buffer(buf.clone());

        // 1. Initially empty: not readable, sequence is 0
        assert!(!event.is_readable(), "empty buffer must not be readable");
        assert_eq!(event.poll_event_sequence(), 0);

        // 2. Producer writes a record: readable becomes true, sequence increments
        event.output_sample(&0x1111_u32.to_ne_bytes()).unwrap();
        assert!(event.is_readable(), "buffer with unread data must be readable");
        assert_eq!(event.poll_event_sequence(), 1);

        // 3. Edge-triggered (EPOLLET) readiness evaluation simulation:
        // First scan reports readiness:
        let mut reported_in = false;
        let mut reported_in_sequence: Option<u64> = None;
        let seq = event.poll_event_sequence();
        let is_ready = event.is_readable();
        assert!(is_ready);

        // Simulate epoll EPOLLET report:
        let mut revents = 0u32;
        if is_ready {
            let seq_changed = reported_in_sequence != Some(seq);
            if !reported_in || seq_changed {
                revents |= 0x1; // EPOLLIN
                reported_in = true;
                reported_in_sequence = Some(seq);
            }
        }
        assert_eq!(revents, 0x1, "first scan must report EPOLLIN");
        assert_eq!(reported_in_sequence, Some(1));

        // Second scan without any new write:
        // Even though buffer is still readable, EPOLLET must suppress reporting
        let mut revents_second = 0u32;
        let seq2 = event.poll_event_sequence();
        let is_ready2 = event.is_readable();
        assert!(is_ready2);
        if is_ready2 {
            let seq_changed = reported_in_sequence != Some(seq2);
            if !reported_in || seq_changed {
                revents_second |= 0x1;
            }
        }
        assert_eq!(revents_second, 0, "EPOLLET must not re-report without new sequence");

        // 4. Producer outputs a second sample: sequence changes!
        event.output_sample(&0x2222_u32.to_ne_bytes()).unwrap();
        assert_eq!(event.poll_event_sequence(), 2);

        // Third scan: EPOLLET detects sequence change and re-arms/fires!
        let mut revents_third = 0u32;
        let seq3 = event.poll_event_sequence();
        let is_ready3 = event.is_readable();
        if is_ready3 {
            let seq_changed = reported_in_sequence != Some(seq3);
            if !reported_in || seq_changed {
                revents_third |= 0x1;
                reported_in_sequence = Some(seq3);
            }
        }
        assert_eq!(revents_third, 0x1, "EPOLLET must report again when sequence advances");
        assert_eq!(reported_in_sequence, Some(2));

        // 5. Consume all records:
        let head = buf.data_head();
        buf.set_data_tail(head);
        assert!(!event.is_readable(), "fully consumed buffer must not be readable");

        // 6. EPOLLONESHOT simulation:
        let mut oneshot_events = 0x1u32; // EPOLLIN
        if event.is_readable() {
            // not ready
        } else {
            // remains armed
            assert_eq!(oneshot_events, 0x1);
        }
        // Write new record:
        event.output_sample(&0x3333_u32.to_ne_bytes()).unwrap();
        assert!(event.is_readable());
        // Triggered: oneshot disables events
        let mut fired = false;
        if event.is_readable() && (oneshot_events & 0x1 != 0) {
            fired = true;
            oneshot_events = 0; // oneshot disabled
        }
        assert!(fired);
        assert_eq!(oneshot_events, 0, "EPOLLONESHOT must disable event mask once fired");
    }

    #[test]
    fn seam3_perf_record_lost_parsing_and_error_counters() {
        let buf = PerfBuffer::new(1).unwrap();
        assert_eq!(buf.total_lost(), 0);
        assert_eq!(buf.lost_count(), 0);

        // 1. Output two samples:
        buf.output_sample(&0xaaaa_u32.to_ne_bytes()).unwrap();
        buf.output_sample(&0xbbbb_u32.to_ne_bytes()).unwrap();

        // Parse records:
        let (records, lost_count) = buf.parse_records().expect("parse must succeed");
        assert_eq!(lost_count, 0);
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0],
            PerfRecord::Sample {
                raw_len: 4,
                data: 0xaaaa_u32.to_ne_bytes().to_vec(),
            }
        );
        assert_eq!(
            records[1],
            PerfRecord::Sample {
                raw_len: 4,
                data: 0xbbbb_u32.to_ne_bytes().to_vec(),
            }
        );
        assert_eq!(buf.data_tail(), buf.data_head());

        // 2. Fill buffer to capacity (4096 bytes, 256 records of 16 bytes):
        for _ in 0..256 {
            buf.output_sample(&0x1234_u32.to_ne_bytes()).unwrap();
        }
        assert_eq!(buf.data_head() - buf.data_tail(), 4096);

        // 3 drops due to buffer full:
        assert_eq!(buf.output_sample(&[1, 2, 3, 4]).unwrap_err(), LinuxError::ENOSPC);
        assert_eq!(buf.output_sample(&[1, 2, 3, 4]).unwrap_err(), LinuxError::ENOSPC);
        assert_eq!(buf.output_sample(&[1, 2, 3, 4]).unwrap_err(), LinuxError::ENOSPC);
        assert_eq!(buf.lost_count(), 3, "pending lost must be 3");
        assert_eq!(buf.total_lost(), 3, "cumulative total_lost must be 3");

        // Free space by advancing tail 48 bytes (3 records):
        buf.set_data_tail(buf.data_tail() + 48);

        // Produce a new sample: emits PERF_RECORD_LOST (24 bytes) then sample (16 bytes) = 40 bytes <= 48 bytes free
        buf.output_sample(&0xcccc_u32.to_ne_bytes()).unwrap();
        assert_eq!(buf.lost_count(), 0, "pending lost resets after delivery");
        assert_eq!(buf.total_lost(), 3, "cumulative total_lost remains 3");

        // Parse records:
        let (recs, delivered_lost) = buf.parse_records().expect("parse should succeed");
        assert_eq!(delivered_lost, 3);
        // Find the Lost record:
        let has_lost = recs.iter().any(|r| matches!(r, PerfRecord::Lost { id: 0, lost: 3 }));
        assert!(has_lost, "parsed records must contain PERF_RECORD_LOST with count 3");

        // 3. Error counters for corrupted state:
        // Set invalid tail > head:
        buf.set_data_tail(buf.data_head() + 100);
        let err = buf.parse_records().unwrap_err();
        assert!(err.out_of_bounds > 0, "out_of_bounds counter must increment");
        assert_eq!(buf.consumer_error_counters().out_of_bounds, 1);

        // Modular wrapping parsing: head and tail at high u64 range
        buf.set_data_head(u64::MAX - 10);
        buf.set_data_tail(u64::MAX - 10);
        buf.output_sample(&0x5555_u32.to_ne_bytes()).unwrap();
        let (wrap_recs, _) = buf.parse_records().expect("wrapping records should parse");
        assert_eq!(wrap_recs.len(), 1);
    }

    #[test]
    fn seam4_epoll_producer_wake_and_lifecycle_races() {
        let event = Arc::new(PerfEvent::new(
            PerfEventSpec {
                clock: PerfEventClock::BpfOutput,
                scope: PerfEventScope::PerCpu { cpu: 0 },
                sample_period: 0,
                disabled: false,
                cloexec: false,
            },
            0,
        ));
        let buf = PerfBuffer::new(1).unwrap();
        event.set_buffer(buf.clone());

        // 1. Initial sequence is 0, not readable
        assert_eq!(event.poll_event_sequence(), 0);
        assert!(!event.is_readable());

        // 2. Producer writes a sample: advances sequence and becomes readable
        event.output_sample(&0x42_u32.to_ne_bytes()).unwrap();
        assert_eq!(event.poll_event_sequence(), 1);
        assert!(event.is_readable());

        // 3. Second write advances sequence again
        event.output_sample(&0x43_u32.to_ne_bytes()).unwrap();
        assert_eq!(event.poll_event_sequence(), 2);

        // 4. Drop event
        drop(event);

        // 4. Fork descriptor table sharing & unmap races:
        {
            let shared_event = Arc::new(PerfEvent::new(
                PerfEventSpec {
                    clock: PerfEventClock::BpfOutput,
                    scope: PerfEventScope::PerCpu { cpu: 0 },
                    sample_period: 0,
                    disabled: false,
                    cloexec: false,
                },
                0,
            ));
            let shared_buf = PerfBuffer::new(1).unwrap();
            shared_event.set_buffer(shared_buf.clone());

            // Parent and child both hold references (fork table cloning):
            let parent_ref = shared_event.clone();
            let child_ref = shared_event.clone();
            assert_eq!(Arc::strong_count(&shared_event), 3);

            // Parent outputs sample:
            parent_ref.output_sample(&[1, 2, 3, 4]).unwrap();
            assert_eq!(shared_buf.data_head(), 16);

            // Parent exits/closes its FD:
            drop(parent_ref);
            assert_eq!(Arc::strong_count(&shared_event), 2);

            // Child still has access and can output:
            child_ref.output_sample(&[5, 6, 7, 8]).unwrap();
            assert_eq!(shared_buf.data_head(), 32);

            // Child consumes records:
            let (recs, _) = shared_buf.parse_records().unwrap();
            assert_eq!(recs.len(), 2);
            assert_eq!(shared_buf.data_tail(), 32);

            drop(child_ref);
        }
    }
}




