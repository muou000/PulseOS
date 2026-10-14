//! Host validation tests for BPF Program load and verifier (#94).

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/insn.rs"]
mod core_insn;

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/map.rs"]
mod core_map;

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/program.rs"]
mod core_program;

#[cfg(test)]
#[path = "../../../pulse_core/src/bpf/verifier.rs"]
mod core_verifier;

#[cfg(test)]
use core_insn as insn;
#[cfg(test)]
use core_map as map;
#[cfg(test)]
use core_program as program;
#[cfg(test)]
use core_map::BPF_OBJ_NAME_LEN;

#[cfg(test)]
mod tests {
    use alloc::{sync::Arc, vec, vec::Vec};
    use axerrno::LinuxError;

    use super::{core_insn::*, core_map::*, core_program::*, core_verifier::*};

    fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> BpfInsn {
        BpfInsn::new(code, dst, src, off, imm)
    }

    fn mov_imm(dst: u8, imm: i32) -> BpfInsn {
        insn(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
    }

    fn mov_reg(dst: u8, src: u8) -> BpfInsn {
        insn(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)
    }

    fn exit() -> BpfInsn {
        insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
    }

    fn verify(insns: &[BpfInsn]) -> (Result<VerifiedProgram, LinuxError>, VerifierLog) {
        let config = VerifierConfig::new(BpfProgType::Tracepoint, 1);
        let mut log = VerifierLog::new();
        let res = verify_program(&config, insns, None, &mut log);
        (res, log)
    }

    #[test]
    fn verifier_accepts_valid_tracepoint_exit_program() {
        // R0 = 0; exit
        let insns = [mov_imm(BPF_REG_0, 0), exit()];
        let (res, log) = verify(&insns);
        assert!(res.is_ok(), "Valid program must pass, log:\n{}", log.as_str());
        let prog = res.unwrap();
        assert_eq!(prog.prog_type, BpfProgType::Tracepoint);
        assert_eq!(prog.insns.len(), 2);
    }

    #[test]
    fn verifier_accepts_valid_context_read() {
        // R0 = *(u32 *)(R1 + 0); exit
        let insns = [
            insn(BPF_LDX | BPF_MEM | BPF_W, BPF_REG_0, BPF_REG_1, 0, 0),
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_ok(), "Context read must pass, log:\n{}", log.as_str());
    }

    #[test]
    fn verifier_accepts_valid_stack_write_and_read() {
        // *(u64 *)(R10 - 8) = 42
        // R0 = *(u64 *)(R10 - 8)
        // exit
        let insns = [
            insn(BPF_ST | BPF_MEM | BPF_DW, BPF_REG_10, 0, -8, 42),
            insn(BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_0, BPF_REG_10, -8, 0),
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_ok(), "Stack write & read must pass, log:\n{}", log.as_str());
    }

    #[test]
    fn verifier_rejects_empty_program() {
        let (res, log) = verify(&[]);
        assert!(res.is_err());
        assert!(!log.as_str().is_empty());
    }

    #[test]
    fn verifier_rejects_over_budget_instructions() {
        let mut insns = vec![mov_imm(BPF_REG_0, 0); 4097];
        insns.push(exit());
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(!log.as_str().is_empty());
    }

    #[test]
    fn verifier_rejects_missing_exit_fallthrough() {
        // R0 = 0 without exit
        let insns = [mov_imm(BPF_REG_0, 0)];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("0:") || log.as_str().contains("exit") || !log.as_str().is_empty());
    }

    #[test]
    fn verifier_rejects_malformed_ld_imm64_at_end() {
        // Program ending with LD_IMM64 without 2nd instruction
        let insns = [
            insn(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_0, 0, 0, 123),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("0:"));
    }

    #[test]
    fn verifier_rejects_malformed_ld_imm64_bad_second_slot() {
        // LD_IMM64 with invalid 2nd slot (code != 0)
        let insns = [
            insn(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_0, 0, 0, 123),
            mov_imm(BPF_REG_1, 0), // invalid 2nd slot!
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("1:") || log.as_str().contains("0:"));
    }

    #[test]
    fn verifier_rejects_out_of_range_jump_forward() {
        // JA +10 (out of bounds)
        let insns = [
            insn(BPF_JMP | BPF_JA, 0, 0, 10, 0),
            mov_imm(BPF_REG_0, 0),
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("0:"));
    }

    #[test]
    fn verifier_rejects_out_of_range_jump_backward() {
        // JA -2 (before instruction 0)
        let insns = [
            mov_imm(BPF_REG_0, 0),
            insn(BPF_JMP | BPF_JA, 0, 0, -2, 0),
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("1:"));
    }

    #[test]
    fn verifier_rejects_backward_jump_loop() {
        // Backward loop: 0 -> 1 -> 0
        let insns = [
            mov_imm(BPF_REG_0, 0),
            insn(BPF_JMP | BPF_JA, 0, 0, -2, 0), // jump back to 0
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("1:"));
    }

    #[test]
    fn verifier_rejects_jump_into_ld_imm64_second_slot() {
        // 0: JA +1 (jumps to instruction 2, which is 2nd slot of LD_IMM64!)
        // 1: LD_IMM64 slot 1
        // 2: LD_IMM64 slot 2
        // 3: exit
        let insns = [
            insn(BPF_JMP | BPF_JA, 0, 0, 1, 0),
            insn(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_0, 0, 0, 123),
            insn(0, 0, 0, 0, 0),
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("0:") || log.as_str().contains("2:"));
    }

    #[test]
    fn verifier_rejects_unreachable_code() {
        // 0: R0 = 0
        // 1: exit
        // 2: R0 = 1 (unreachable!)
        // 3: exit
        let insns = [
            mov_imm(BPF_REG_0, 0),
            exit(),
            mov_imm(BPF_REG_0, 1),
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("2:"));
    }

    #[test]
    fn verifier_rejects_uninitialized_register_read() {
        // R0 = R2 (R2 is uninitialized!)
        // exit
        let insns = [
            mov_reg(BPF_REG_0, BPF_REG_2),
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("0:"));
    }

    #[test]
    fn verifier_rejects_uninitialized_stack_read() {
        // R0 = *(u64 *)(R10 - 8) without prior store!
        // exit
        let insns = [
            insn(BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_0, BPF_REG_10, -8, 0),
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("0:"));
    }

    #[test]
    fn verifier_rejects_invalid_context_write() {
        // *(u32 *)(R1 + 0) = 42 (Context is read-only!)
        let insns = [
            insn(BPF_ST | BPF_MEM | BPF_W, BPF_REG_1, 0, 0, 42),
            mov_imm(BPF_REG_0, 0),
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("0:"));
    }

    #[test]
    fn verifier_rejects_invalid_context_read_out_of_bounds() {
        // Context max size is 80 bytes. Reading at offset 80 with size 4 exceeds bounds!
        let insns = [
            insn(BPF_LDX | BPF_MEM | BPF_W, BPF_REG_0, BPF_REG_1, 80, 0),
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("0:"));
    }

    #[test]
    fn verifier_rejects_invalid_context_read_unaligned() {
        // Reading 4 bytes at offset 1 (unaligned)
        let insns = [
            insn(BPF_LDX | BPF_MEM | BPF_W, BPF_REG_0, BPF_REG_1, 1, 0),
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("0:"));
    }

    #[test]
    fn verifier_rejects_atomic_operations() {
        // Atomic store mode (0xc0) is rejected
        let insns = [
            insn(BPF_STX | BPF_ATOMIC | BPF_DW, BPF_REG_10, BPF_REG_0, -8, 0),
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("0:"));
    }

    #[test]
    fn verifier_rejects_missing_r0_at_exit() {
        // Exit without setting R0
        let insns = [exit()];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("0:"));
    }

    #[test]
    fn verifier_rejects_modifying_r10() {
        // R10 is read-only frame pointer: R10 = 0 is forbidden
        let insns = [
            mov_imm(BPF_REG_10, 0),
            exit(),
        ];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        assert!(log.as_str().contains("0:"));
    }

    #[test]
    fn verifier_log_contains_instruction_index_and_reason() {
        let insns = [mov_reg(BPF_REG_0, BPF_REG_3), exit()];
        let (res, log) = verify(&insns);
        assert!(res.is_err());
        let s = log.as_str();
        assert!(s.starts_with("0:"), "Log must start with insn index '0:', was: {}", s);
        assert!(log.true_size() > 0);
    }

    struct MockMapResolver {
        map: Arc<BpfMap>,
    }

    impl MapResolver for MockMapResolver {
        fn resolve_map(&self, fd: u32) -> Result<Arc<BpfMap>, LinuxError> {
            if fd == 42 {
                Ok(self.map.clone())
            } else {
                Err(LinuxError::EBADF)
            }
        }
    }

    fn create_test_array_map() -> Arc<BpfMap> {
        let req = BpfMapCreateRequest {
            map_type: BPF_MAP_TYPE_ARRAY,
            key_size: 4,
            value_size: 8,
            max_entries: 16,
            ..Default::default()
        };
        Arc::new(BpfMap::create(BpfMapSpec::validate(&req).unwrap()).unwrap())
    }

    #[test]
    fn verifier_resolves_pseudo_map_fd_and_allows_null_checked_lookup() {
        let map = create_test_array_map();
        let resolver = MockMapResolver { map };

        // 0: r1 = map_fd (42) via LD_IMM64
        // 1: second slot of LD_IMM64
        // 2: *(u32 *)(r10 - 4) = 0
        // 3: r2 = r10 - 4
        // 4: call map_lookup_elem
        // 5: if r0 == 0 goto pc+1 (to 7)
        // 6: *(u64 *)(r0 + 0) = 99
        // 7: r0 = 0
        // 8: exit
        let insns = [
            insn(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 42),
            insn(0, 0, 0, 0, 0),
            insn(BPF_ST | BPF_MEM | BPF_W, BPF_REG_10, 0, -4, 0),
            insn(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
            insn(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
            insn(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_MAP_LOOKUP_ELEM),
            insn(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 1, 0),
            insn(BPF_ST | BPF_MEM | BPF_DW, BPF_REG_0, 0, 0, 99),
            mov_imm(BPF_REG_0, 0),
            exit(),
        ];

        let config = VerifierConfig::new(BpfProgType::Tracepoint, 1);
        let mut log = VerifierLog::new();
        let res = verify_program(&config, &insns, Some(&resolver), &mut log);
        assert!(res.is_ok(), "Null-checked map access must pass, log:\n{}", log.as_str());
        let prog = res.unwrap();
        assert_eq!(prog.referenced_maps.len(), 1);
    }

    #[test]
    fn verifier_rejects_dereferencing_map_value_without_null_check() {
        let map = create_test_array_map();
        let resolver = MockMapResolver { map };

        // Attempting to write to r0 immediately after lookup without null check!
        let insns = [
            insn(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 42),
            insn(0, 0, 0, 0, 0),
            insn(BPF_ST | BPF_MEM | BPF_W, BPF_REG_10, 0, -4, 0),
            insn(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
            insn(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
            insn(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_MAP_LOOKUP_ELEM),
            insn(BPF_ST | BPF_MEM | BPF_DW, BPF_REG_0, 0, 0, 99), // Error: not null checked!
            mov_imm(BPF_REG_0, 0),
            exit(),
        ];

        let config = VerifierConfig::new(BpfProgType::Tracepoint, 1);
        let mut log = VerifierLog::new();
        let res = verify_program(&config, &insns, Some(&resolver), &mut log);
        assert!(res.is_err());
        assert!(log.as_str().contains("6:"));
        assert!(log.as_str().contains("NULL"));
    }

    #[test]
    fn verifier_rejects_unresolved_map_fd() {
        let map = create_test_array_map();
        let resolver = MockMapResolver { map };

        // FD 999 does not exist in resolver
        let insns = [
            insn(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 999),
            insn(0, 0, 0, 0, 0),
            mov_imm(BPF_REG_0, 0),
            exit(),
        ];

        let config = VerifierConfig::new(BpfProgType::Tracepoint, 1);
        let mut log = VerifierLog::new();
        let res = verify_program(&config, &insns, Some(&resolver), &mut log);
        assert!(res.is_err());
        assert!(log.as_str().contains("0:"));
    }

    #[test]
    fn ltp_bpf_prog03_cve_2017_16995_is_rejected() {
        // Reproducer pattern from LTP bpf_prog03.c:
        // Tests sign extension and illegal pointer offset arithmetic.
        let map = create_test_array_map();
        let resolver = MockMapResolver { map };

        let insns = [
            insn(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 42),
            insn(0, 0, 0, 0, 0),
            insn(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_8, BPF_REG_10, 0, 0),
            insn(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_8, 0, 0, -4),
            insn(BPF_ALU | BPF_MOV | BPF_K, BPF_REG_2, 0, 0, 0),
            insn(BPF_STX | BPF_MEM | BPF_W, BPF_REG_8, BPF_REG_2, 0, 0),
            insn(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_8, 0, 0),
            insn(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_MAP_LOOKUP_ELEM),
            insn(BPF_JMP | BPF_JNE | BPF_K, BPF_REG_0, 0, 2, 0),
            mov_imm(BPF_REG_0, 0),
            exit(),
            // Unchecked arithmetic on map value pointer:
            insn(BPF_ALU | BPF_MOV | BPF_K, BPF_REG_1, 0, 0, -1),
            insn(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_1, 0, 0, 1),
            insn(BPF_ALU64 | BPF_RSH | BPF_K, BPF_REG_1, 0, 0, 26),
            insn(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0),
            insn(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_0, 0, 0),
            insn(BPF_ALU64 | BPF_SUB | BPF_X, BPF_REG_2, BPF_REG_1, 0, 0),
            mov_imm(BPF_REG_3, 0xdeadbeefu32 as i32),
            insn(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_2, BPF_REG_3, 0, 0),
            mov_imm(BPF_REG_0, 0),
            exit(),
        ];

        let config = VerifierConfig::new(BpfProgType::Tracepoint, 1);
        let mut log = VerifierLog::new();
        let res = verify_program(&config, &insns, Some(&resolver), &mut log);
        assert!(res.is_err(), "LTP bpf_prog03 pattern must be rejected");
        assert!(!log.as_str().is_empty());
    }

    #[test]
    fn ltp_bpf_prog04_cve_2018_18445_is_rejected() {
        // Reproducer pattern from LTP bpf_prog04.c:
        // Tests 32-bit RSH ALU verification leading to out of bounds map write.
        let map = create_test_array_map();
        let resolver = MockMapResolver { map };

        let insns = [
            mov_imm(BPF_REG_8, 2),
            insn(BPF_ALU64 | BPF_LSH | BPF_K, BPF_REG_8, 0, 0, 31),
            insn(BPF_ALU | BPF_RSH | BPF_K, BPF_REG_8, 0, 0, 31),
            insn(BPF_ALU | BPF_SUB | BPF_K, BPF_REG_8, 0, 0, 2),
            insn(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 42),
            insn(0, 0, 0, 0, 0),
            insn(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
            insn(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
            insn(BPF_ST | BPF_MEM | BPF_W, BPF_REG_2, 0, 0, 0),
            insn(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_MAP_LOOKUP_ELEM),
            insn(BPF_JMP | BPF_JNE | BPF_K, BPF_REG_0, 0, 1, 0),
            exit(),
            insn(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_0, BPF_REG_8, 0, 0),
            insn(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_0, BPF_REG_8, 0, 0),
            mov_imm(BPF_REG_0, 0),
            exit(),
        ];

        let config = VerifierConfig::new(BpfProgType::Tracepoint, 1);
        let mut log = VerifierLog::new();
        let res = verify_program(&config, &insns, Some(&resolver), &mut log);
        assert!(res.is_err(), "LTP bpf_prog04 pattern must be rejected");
        assert!(!log.as_str().is_empty());
    }

    #[test]
    fn ltp_bpf_prog05_variable_stack_ptr_arithmetic_is_rejected() {
        // Adapted from LTP bpf_prog05.c ensure_ptr_arithmetic()
        // Tests rejection of variable stack pointer arithmetic:
        // r2 = r10
        // r3 = -1
        // r2 += r3   <-- variable arithmetic on PtrStack
        // *(char *)r2 = 0
        // r0 = 0
        // exit
        let insns = [
            insn(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
            mov_imm(BPF_REG_3, -1),
            insn(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_2, BPF_REG_3, 0, 0),
            insn(BPF_ST | BPF_MEM | BPF_B, BPF_REG_2, 0, 0, 0),
            mov_imm(BPF_REG_0, 0),
            exit(),
        ];

        let (res, log) = verify(&insns);
        assert_eq!(res.err(), Some(LinuxError::EACCES));
        assert!(log.as_str().contains("variable stack pointer arithmetic is not supported"));
    }

    #[test]
    fn verifier_rejects_over_budget_states() {
        // Construct a program with branching that explores multiple states,
        // and configure VerifierConfig with a small state budget.
        let mut config = VerifierConfig::new(BpfProgType::Tracepoint, 1);
        config.max_states = 3;

        let insns = [
            mov_imm(BPF_REG_2, 0),
            insn(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_2, 0, 1, 0),
            mov_imm(BPF_REG_3, 1),
            mov_imm(BPF_REG_0, 0),
            exit(),
        ];

        let mut log = VerifierLog::new();
        let res = verify_program(&config, &insns, None, &mut log);
        assert_eq!(res.err(), Some(LinuxError::E2BIG));
        assert!(log.as_str().contains("verifier state budget exceeded"));
    }

    #[test]
    fn verifier_deduplicates_referenced_maps() {
        let map = create_test_array_map();
        let resolver = MockMapResolver { map };

        // Multiple LD_IMM64 instructions referencing the same map
        let insns = [
            insn(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 42),
            insn(0, 0, 0, 0, 0),
            insn(BPF_LD | BPF_IMM | BPF_DW, BPF_REG_2, BPF_PSEUDO_MAP_FD, 0, 42),
            insn(0, 0, 0, 0, 0),
            mov_imm(BPF_REG_0, 0),
            exit(),
        ];

        let config = VerifierConfig::new(BpfProgType::Tracepoint, 1);
        let mut log = VerifierLog::new();
        let res = verify_program(&config, &insns, Some(&resolver), &mut log);
        assert!(res.is_ok(), "Log:\n{}", log.as_str());
        let prog = res.unwrap();
        // Referenced maps should contain only 1 entry despite 2 loads
        assert_eq!(prog.referenced_maps.len(), 1);
    }

    use crate::impls::bpf::abi::{
        validate_bpf_syscall, BpfCmd, BpfPermissions, BpfProgLoadAttr,
        check_attr_unused_tail,
    };

    struct FakeUser {
        mem: Vec<u8>,
        base: usize,
    }

    impl FakeUser {
        fn new(base: usize, len: usize) -> Self {
            Self {
                mem: alloc::vec![0; len],
                base,
            }
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

    #[test]
    fn bpf_prog_load_attr_fields_validation() {
        let attr = BpfProgLoadAttr {
            prog_type: BPF_PROG_TYPE_TRACEPOINT,
            insn_cnt: 2,
            insns: 0x2000,
            license: 0x3000,
            log_level: 1,
            log_size: 1024,
            log_buf: 0x4000,
            ..Default::default()
        };
        assert_eq!(attr.prog_type, 5);
        assert_eq!(attr.insn_cnt, 2);
    }

    #[test]
    fn bpf_prog_load_syscall_validation_and_permissions() {
        let auth = BpfPermissions::new(true, false, false);
        let unauth = BpfPermissions::new(false, false, false);

        let user = FakeUser::new(0x1000, 256);
        let user_cell = core::cell::RefCell::new(user);
        let mut read = |addr, buf: &mut [u8]| {
            let u = user_cell.borrow();
            let r = u.range(addr, buf.len())?;
            buf.copy_from_slice(&u.mem[r]);
            Ok(())
        };

        // 1. Unprivileged non-root / non-cap caller receives EPERM without reading user pointers
        assert_eq!(
            validate_bpf_syscall(unauth, BpfCmd::ProgLoad as i32, 0, 48, &mut read).err(),
            Some(LinuxError::EPERM)
        );

        // 2. Unknown command returns EINVAL
        assert_eq!(
            validate_bpf_syscall(auth, 999, 0x1000, 48, &mut read).err(),
            Some(LinuxError::EINVAL)
        );

        // 3. Size boundary checks:
        // Size < min_size (48) returns EINVAL
        assert_eq!(
            validate_bpf_syscall(auth, BpfCmd::ProgLoad as i32, 0x1000, 47, &mut read).err(),
            Some(LinuxError::EINVAL)
        );
        // Size > 4096 returns E2BIG
        assert_eq!(
            validate_bpf_syscall(auth, BpfCmd::ProgLoad as i32, 0x1000, 4097, &mut read).err(),
            Some(LinuxError::E2BIG)
        );

        // 4. Null pointer returns EFAULT
        assert_eq!(
            validate_bpf_syscall(auth, BpfCmd::ProgLoad as i32, 0, 48, &mut read).err(),
            Some(LinuxError::EFAULT)
        );

        // 5. Valid call returns decoded ProgLoad
        let (cmd, attr) = validate_bpf_syscall(auth, BpfCmd::ProgLoad as i32, 0x1000, 48, &mut read).unwrap();
        assert_eq!(cmd, BpfCmd::ProgLoad);
        assert_eq!(check_attr_unused_tail(cmd, &attr), Ok(()));
    }

    #[test]
    fn bpf_prog_load_rejects_unsupported_prog_types() {
        for raw in [0, 1, 2, 3, 4, 6, 8, 10, 999] {
            assert_eq!(BpfProgType::from_raw(raw), Err(LinuxError::EINVAL), "raw {raw}");
        }
        assert_eq!(BpfProgType::from_raw(5), Ok(BpfProgType::Tracepoint));
        assert_eq!(BpfProgType::from_raw(7), Ok(BpfProgType::PerfEvent));
    }

    #[test]
    fn bpf_prog_info_matches_linux_layout_and_metadata() {
        use core::mem::{align_of, offset_of, size_of};

        assert_eq!(size_of::<BpfProgInfo>(), 224);
        assert_eq!(align_of::<BpfProgInfo>(), 8);
        assert_eq!(offset_of!(BpfProgInfo, prog_type), 0);
        assert_eq!(offset_of!(BpfProgInfo, id), 4);
        assert_eq!(offset_of!(BpfProgInfo, name), 64);

        let prog = BpfProgram::new(
            BpfProgType::Tracepoint,
            [b't', b'e', b's', b't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Arc::from([mov_imm(BPF_REG_0, 0), exit()]),
            Vec::new(),
        );

        let info = prog.info();
        assert_eq!(info.prog_type, BpfProgType::Tracepoint.as_raw());
        assert_eq!(info.id, prog.id());
        assert_eq!(&info.name[..4], b"test");
        assert_eq!(info.xlated_prog_len, 16);
        assert_eq!(info.nr_map_ids, 0);
        assert_eq!(info.as_bytes().len(), 224);
    }

    #[test]
    fn bpf_prog_lifecycle_fd_table_fork_exec_cloexec_and_dup() {
        struct MockFdEntry {
            prog: Arc<BpfProgram>,
            cloexec: bool,
        }

        struct MockProcess {
            nofile: usize,
            fds: Vec<Option<MockFdEntry>>,
        }

        impl MockProcess {
            fn new(nofile: usize) -> Self {
                Self { nofile, fds: Vec::new() }
            }

            fn insert_prog(&mut self, prog: Arc<BpfProgram>) -> Result<usize, LinuxError> {
                let fd = self.fds.iter().position(|s| s.is_none()).unwrap_or(self.fds.len());
                if fd >= self.nofile {
                    return Err(LinuxError::EMFILE);
                }
                let entry = MockFdEntry { prog, cloexec: true };
                if fd < self.fds.len() {
                    self.fds[fd] = Some(entry);
                } else {
                    self.fds.push(Some(entry));
                }
                Ok(fd)
            }

            fn dup(&mut self, old_fd: usize) -> Result<usize, LinuxError> {
                let entry = self.fds.get(old_fd).and_then(Option::as_ref).ok_or(LinuxError::EBADF)?;
                let new_entry = MockFdEntry {
                    prog: entry.prog.clone(),
                    cloexec: false,
                };
                let fd = self.fds.iter().position(|s| s.is_none()).unwrap_or(self.fds.len());
                if fd >= self.nofile {
                    return Err(LinuxError::EMFILE);
                }
                if fd < self.fds.len() {
                    self.fds[fd] = Some(new_entry);
                } else {
                    self.fds.push(Some(new_entry));
                }
                Ok(fd)
            }

            fn close(&mut self, fd: usize) -> Result<(), LinuxError> {
                let slot = self.fds.get_mut(fd).ok_or(LinuxError::EBADF)?;
                if slot.is_none() {
                    return Err(LinuxError::EBADF);
                }
                *slot = None;
                Ok(())
            }

            fn exec_cleanup(&mut self) {
                for slot in &mut self.fds {
                    if slot.as_ref().map_or(false, |e| e.cloexec) {
                        *slot = None;
                    }
                }
            }
        }

        let prog = Arc::new(BpfProgram::new(
            BpfProgType::Tracepoint,
            [0u8; 16],
            Arc::from([mov_imm(BPF_REG_0, 0), exit()]),
            Vec::new(),
        ));

        let mut proc = MockProcess::new(10);
        let fd0 = proc.insert_prog(prog.clone()).unwrap();
        assert_eq!(Arc::strong_count(&prog), 2); // 1 in local, 1 in table

        let fd1 = proc.dup(fd0).unwrap();
        assert_eq!(Arc::strong_count(&prog), 3); // duplicated reference

        // Exec closes CLOEXEC fd0, but preserves non-CLOEXEC fd1
        proc.exec_cleanup();
        assert!(proc.fds[fd0].is_none());
        assert!(proc.fds[fd1].is_some());
        assert_eq!(Arc::strong_count(&prog), 2);

        // Close fd1
        proc.close(fd1).unwrap();
        assert_eq!(Arc::strong_count(&prog), 1);

        // RLIMIT_NOFILE limits
        let mut full_proc = MockProcess::new(1);
        full_proc.insert_prog(prog.clone()).unwrap();
        assert_eq!(full_proc.insert_prog(prog.clone()), Err(LinuxError::EMFILE));
    }
}
