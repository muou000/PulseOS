//! Public verifier/dispatch/Perf Buffer validation for returned page-fault observations.
#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use axerrno::LinuxError;
    use pulse_bpf_schema::*;

    use super::super::bpf_link::{
        core_insn::*, core_map::*, core_perf_event::*, core_program::*, core_verifier::*,
    };

    #[test]
    fn page_fault_completion_reaches_real_perf_output_and_old_entry_epoch_is_cancelled() {
        let request = BpfMapCreateRequest {
            map_type: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
            key_size: 4,
            value_size: 4,
            max_entries: 1,
            ..Default::default()
        };
        let outputs = Arc::new(BpfMap::create(BpfMapSpec::validate(&request).unwrap()).unwrap());
        struct Resolver(Arc<BpfMap>);
        impl MapResolver for Resolver {
            fn resolve_map(&self, _fd: u32) -> Result<Arc<BpfMap>, LinuxError> {
                Ok(self.0.clone())
            }
        }
        let mut instructions = alloc::vec![BpfInsn::new(
            BPF_ALU64 | BPF_MOV | BPF_X,
            BPF_REG_6,
            BPF_REG_1,
            0,
            0
        )];
        for offset in (0..80i16).step_by(8) {
            instructions.push(BpfInsn::new(
                BPF_LDX | BPF_MEM | BPF_DW,
                BPF_REG_7,
                BPF_REG_6,
                offset,
                0,
            ));
            instructions.push(BpfInsn::new(
                BPF_STX | BPF_MEM | BPF_DW,
                BPF_REG_10,
                BPF_REG_7,
                offset - 80,
                0,
            ));
        }
        instructions.extend_from_slice(&[
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_1, BPF_REG_6, 0, 0),
            BpfInsn::new(
                BPF_LD | BPF_IMM | BPF_DW,
                BPF_REG_2,
                BPF_PSEUDO_MAP_FD,
                0,
                1,
            ),
            BpfInsn::new(0, 0, 0, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_3, 0, 0, -1),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_4, BPF_REG_10, 0, 0),
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_4, 0, 0, -80),
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_5, 0, 0, 80),
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_PERF_EVENT_OUTPUT),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ]);
        let verified = verify_program(
            &VerifierConfig::new(BpfProgType::Tracepoint, 1),
            &instructions,
            Some(&Resolver(outputs.clone())),
            &mut VerifierLog::new(),
        )
        .unwrap();
        let program = Arc::new(BpfProgram::new(
            verified.prog_type,
            [0; 16],
            verified.insns,
            verified.referenced_maps,
        ));
        let source = PerfEvent::new(
            PerfEventSpec {
                clock: PerfEventClock::Tracepoint(TracepointId::PageFault),
                scope: PerfEventScope::PerCpu { cpu: 0 },
                sample_period: 0,
                disabled: false,
                cloexec: false,
            },
            0,
        );
        let sink = Arc::new(PerfEvent::new(
            PerfEventSpec {
                clock: PerfEventClock::BpfOutput,
                scope: PerfEventScope::PerCpu { cpu: 0 },
                sample_period: 0,
                disabled: false,
                cloexec: false,
            },
            0,
        ));
        let buffer = PerfBuffer::new(1).unwrap();
        sink.set_buffer(buffer.clone());
        outputs.set_slot(0, Some(10), Some(sink)).unwrap();
        source.attach_program(program.clone()).unwrap();
        let entry_generation = observation_generation();
        let context = PageFaultContext::from_completion(
            ContextCommon::new(TracepointId::PageFault, 350, 0, 40, 41, 99),
            0x400001,
            100,
            PageFaultAccess::WRITE,
            PageFaultOrigin::User,
            PageFaultOutcome::NoMemory,
        )
        .unwrap();
        let queue = BoundedTraceQueue::<2>::new();
        queue
            .enqueue_with_generation(
                TracepointId::PageFault,
                &context.to_bytes(),
                entry_generation,
            )
            .unwrap();
        source.disable_at(200);
        source.enable_at(250);
        queue.drain_with_generation(1, |id, bytes, generation| {
            assert_eq!(source.dispatch_tracepoint(id, bytes, generation), Ok(false));
        });
        assert_eq!(program.run_cnt(), 0);
        assert_eq!(buffer.data_head(), 0);
        assert_eq!(source.runtime_counters().cancelled, 1);
        let current_generation = observation_generation();
        assert_eq!(
            source.dispatch_tracepoint(
                TracepointId::PageFault,
                &context.to_bytes()[..79],
                current_generation
            ),
            Ok(false)
        );
        assert_eq!(
            source.dispatch_tracepoint(
                TracepointId::PageFault,
                &context.to_bytes(),
                current_generation
            ),
            Ok(true)
        );
        let (records, lost) = buffer.parse_records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(lost, 0);
        assert_eq!(
            records[0],
            PerfRecord::Sample {
                raw_len: 80,
                data: context.to_bytes().to_vec()
            }
        );
        assert_eq!(program.run_cnt(), 1);
        assert_eq!(source.runtime_counters().invalid, 1);
    }
}
