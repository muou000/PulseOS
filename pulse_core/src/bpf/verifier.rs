//! eBPF instruction verifier for PulseOS.

use alloc::{collections::VecDeque, string::String, sync::Arc, vec, vec::Vec};

use axerrno::LinuxError;

use super::{insn::*, map::BpfMap, program::BpfProgType};

pub const BPF_MAXINSNS: usize = 4096;
pub const BPF_MAX_STATES: usize = 65536;
pub const BPF_STACK_SIZE: usize = 512;
pub const MAX_CONTEXT_SIZE: usize = 80;

#[derive(Clone, Copy, Debug)]
pub struct VerifierConfig {
    pub prog_type: BpfProgType,
    pub log_level: u32,
    pub max_insns: usize,
    pub max_states: usize,
}

impl VerifierConfig {
    pub fn new(prog_type: BpfProgType, log_level: u32) -> Self {
        Self {
            prog_type,
            log_level,
            max_insns: BPF_MAXINSNS,
            max_states: BPF_MAX_STATES,
        }
    }
}

pub trait MapResolver {
    fn resolve_map(&self, fd: u32) -> Result<Arc<BpfMap>, LinuxError>;
}

pub struct VerifierLog {
    buffer: String,
    true_size: usize,
}

impl VerifierLog {
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
            true_size: 0,
        }
    }

    pub fn append(&mut self, idx: usize, msg: &str) {
        let line = alloc::format!("{}: {}\n", idx, msg);
        self.true_size += line.len();
        self.buffer.push_str(&line);
    }

    pub fn as_str(&self) -> &str {
        &self.buffer
    }

    pub fn true_size(&self) -> usize {
        self.true_size
    }

    pub fn copy_to_user_slice(&self, out: &mut [u8]) -> usize {
        if out.is_empty() {
            return 0;
        }
        let bytes = self.buffer.as_bytes();
        let copy_len = core::cmp::min(bytes.len(), out.len() - 1);
        out[..copy_len].copy_from_slice(&bytes[..copy_len]);
        out[copy_len] = 0;
        copy_len
    }
}

impl Default for VerifierLog {
    fn default() -> Self {
        Self::new()
    }
}

pub struct VerifiedProgram {
    pub prog_type: BpfProgType,
    pub insns: Arc<[BpfInsn]>,
    pub referenced_maps: Vec<Arc<BpfMap>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegType {
    NotInit,
    Scalar,
    PtrContext { off: i32 },
    PtrStack { off: i32 },
    PtrMap { map_idx: usize },
    PtrMapValue { map_idx: usize, off: i32, null_checked: bool },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierState {
    pub regs: [RegType; 11],
    pub stack_init: [bool; BPF_STACK_SIZE],
}

impl VerifierState {
    pub fn initial() -> Self {
        let mut regs = [RegType::NotInit; 11];
        regs[BPF_REG_1 as usize] = RegType::PtrContext { off: 0 };
        regs[BPF_REG_10 as usize] = RegType::PtrStack { off: 0 };

        Self {
            regs,
            stack_init: [false; BPF_STACK_SIZE],
        }
    }
}

fn validate_jump_target(
    from: usize,
    off: i16,
    n: usize,
    is_ld_imm64_slot2: &[bool],
    log: &mut VerifierLog,
) -> Result<usize, LinuxError> {
    let target = (from as isize) + 1 + (off as isize);
    if target < 0 || target >= n as isize {
        log.append(from, &alloc::format!("out of range jump target {}", target));
        return Err(LinuxError::EINVAL);
    }
    let target_u = target as usize;
    if is_ld_imm64_slot2[target_u] {
        log.append(from, "jump into second slot of LD_IMM64");
        return Err(LinuxError::EINVAL);
    }
    if target <= from as isize {
        log.append(from, "backward jump / loop detected");
        return Err(LinuxError::EINVAL);
    }
    Ok(target_u)
}

pub fn verify_program(
    config: &VerifierConfig,
    insns: &[BpfInsn],
    map_resolver: Option<&dyn MapResolver>,
    log: &mut VerifierLog,
) -> Result<VerifiedProgram, LinuxError> {
    let n = insns.len();
    if n == 0 {
        log.append(0, "program has 0 instructions");
        return Err(LinuxError::EINVAL);
    }
    if n > config.max_insns {
        log.append(0, "program exceeds maximum instruction limit");
        return Err(LinuxError::E2BIG);
    }

    // -----------------------------------------------------------------
    // Pass 1: Syntactic, opcode, register and CFG validation (DAG pass)
    // -----------------------------------------------------------------
    let mut is_ld_imm64_slot2 = vec![false; n];
    let mut i = 0;
    while i < n {
        let insn = &insns[i];

        if insn.is_ld_imm64() {
            if i + 1 >= n {
                log.append(i, "incomplete LD_IMM64 instruction at end of program");
                return Err(LinuxError::EINVAL);
            }
            let slot2 = &insns[i + 1];
            if slot2.code != 0 || slot2.dst_reg() != 0 || slot2.src_reg() != 0 || slot2.off != 0 {
                log.append(i + 1, "invalid second slot of LD_IMM64 instruction");
                return Err(LinuxError::EINVAL);
            }
            is_ld_imm64_slot2[i + 1] = true;
            i += 2;
            continue;
        }

        if matches!(insn.class(), BPF_LD | BPF_LDX | BPF_ST | BPF_STX) {
            if insn.mode() == BPF_ATOMIC {
                log.append(i, "atomic operations are not supported in this slice");
                return Err(LinuxError::EINVAL);
            }

            if matches!(insn.mode(), BPF_ABS | BPF_IND | BPF_LEN | BPF_MSH) {
                log.append(i, "unsupported legacy packet mode");
                return Err(LinuxError::EINVAL);
            }
        }

        if insn.dst_reg() > 10 || insn.src_reg() > 10 {
            log.append(i, "invalid register index > 10");
            return Err(LinuxError::EINVAL);
        }

        // R10 is read-only frame pointer
        if insn.dst_reg() == BPF_REG_10 {
            let class = insn.class();
            if matches!(class, BPF_ALU | BPF_ALU64 | BPF_LD | BPF_LDX) {
                log.append(i, "cannot modify read-only frame pointer R10");
                return Err(LinuxError::EINVAL);
            }
        }

        let class = insn.class();
        if !matches!(class, BPF_LD | BPF_LDX | BPF_ST | BPF_STX | BPF_ALU | BPF_JMP | BPF_JMP32 | BPF_ALU64) {
            log.append(i, "unknown instruction class");
            return Err(LinuxError::EINVAL);
        }

        i += 1;
    }

    // Build edges and check jumps
    let mut cfg_edges: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut i = 0;
    while i < n {
        if is_ld_imm64_slot2[i] {
            i += 1;
            continue;
        }

        let insn = &insns[i];
        let next_pc = if insn.is_ld_imm64() { i + 2 } else { i + 1 };

        if insn.is_exit() {
            // terminal instruction
            i += 1;
            continue;
        }

        if insn.is_ja() {
            let target_u = validate_jump_target(i, insn.off, n, &is_ld_imm64_slot2, log)?;
            cfg_edges[i].push(target_u);
        } else if insn.is_jmp() || insn.is_jmp32() {
            if insn.is_call() {
                if next_pc >= n {
                    log.append(i, "program falls off end after helper call");
                    return Err(LinuxError::EINVAL);
                }
                cfg_edges[i].push(next_pc);
            } else {
                // Conditional jump
                let target_u = validate_jump_target(i, insn.off, n, &is_ld_imm64_slot2, log)?;
                if next_pc >= n {
                    log.append(i, "program falls off end on fall-through");
                    return Err(LinuxError::EINVAL);
                }
                cfg_edges[i].push(next_pc);
                cfg_edges[i].push(target_u);
            }
        } else {
            // Non-jump instruction
            if next_pc >= n {
                log.append(i, "program falls off end without exit");
                return Err(LinuxError::EINVAL);
            }
            cfg_edges[i].push(next_pc);
        }

        i = next_pc;
    }

    // Check reachability from instruction 0
    let mut reachable = vec![false; n];
    let mut reach_queue = VecDeque::new();
    reach_queue.push_back(0);
    reachable[0] = true;

    while let Some(pc) = reach_queue.pop_front() {
        if insns[pc].is_ld_imm64() && pc + 1 < n {
            reachable[pc + 1] = true;
        }
        for &succ in &cfg_edges[pc] {
            if !reachable[succ] {
                reachable[succ] = true;
                reach_queue.push_back(succ);
            }
        }
    }

    for idx in 0..n {
        if !reachable[idx] && !is_ld_imm64_slot2[idx] {
            log.append(idx, "unreachable instruction");
            return Err(LinuxError::EINVAL);
        }
    }

    // -----------------------------------------------------------------
    // Pass 2: Abstract state simulation and safety verification
    // -----------------------------------------------------------------
    let mut referenced_maps: Vec<Arc<BpfMap>> = Vec::new();
    let mut relocations: Vec<(usize, usize)> = Vec::new();
    let mut worklist: VecDeque<(usize, VerifierState)> = VecDeque::new();
    let mut explored: Vec<(usize, VerifierState)> = Vec::new();
    let mut state_count = 0;

    worklist.push_back((0, VerifierState::initial()));

    while let Some((pc, mut state)) = worklist.pop_front() {
        state_count += 1;
        if state_count > config.max_states {
            log.append(pc, "verifier state budget exceeded");
            return Err(LinuxError::E2BIG);
        }

        if explored.iter().any(|(p, s)| *p == pc && s == &state) {
            continue;
        }
        explored.push((pc, state.clone()));

        let insn = &insns[pc];
        let next_pc = if insn.is_ld_imm64() { pc + 2 } else { pc + 1 };
        let dst = insn.dst_reg() as usize;
        let src = insn.src_reg() as usize;

        if insn.is_ld_imm64() {
            if insn.src_reg() == BPF_PSEUDO_MAP_FD {
                let map_fd = insn.imm as u32;
                let resolver = map_resolver.ok_or_else(|| {
                    log.append(pc, "no map resolver provided to resolve map fd");
                    LinuxError::EBADF
                })?;
                let map = resolver.resolve_map(map_fd).map_err(|e| {
                    log.append(pc, &alloc::format!("failed to resolve map fd {}: {:?}", map_fd, e));
                    e
                })?;
                let map_idx = if let Some(idx) = referenced_maps.iter().position(|m| m.id() == map.id()) {
                    idx
                } else {
                    let idx = referenced_maps.len();
                    referenced_maps.push(map);
                    idx
                };
                if !relocations.iter().any(|(p, _)| *p == pc) {
                    relocations.push((pc, map_idx));
                }
                state.regs[dst] = RegType::PtrMap { map_idx };
            } else {
                state.regs[dst] = RegType::Scalar;
            }
            worklist.push_back((next_pc, state));
            continue;
        }

        let class = insn.class();
        match class {
            BPF_ALU | BPF_ALU64 => {
                let op = insn.op();
                let is_src_imm = insn.is_src_imm();

                if !is_src_imm && state.regs[src] == RegType::NotInit {
                    log.append(pc, &alloc::format!("read uninitialized register R{}", src));
                    return Err(LinuxError::EACCES);
                }

                if op == BPF_MOV {
                    if is_src_imm {
                        state.regs[dst] = RegType::Scalar;
                    } else {
                        state.regs[dst] = state.regs[src];
                    }
                } else {
                    if state.regs[dst] == RegType::NotInit {
                        log.append(pc, &alloc::format!("read uninitialized register R{}", dst));
                        return Err(LinuxError::EACCES);
                    }

                    if op == BPF_ADD || op == BPF_SUB {
                        match state.regs[dst] {
                            RegType::PtrStack { off } => {
                                if !is_src_imm {
                                    log.append(pc, "variable stack pointer arithmetic is not supported");
                                    return Err(LinuxError::EACCES);
                                }
                                let delta = insn.imm as i32;
                                let new_off = if op == BPF_ADD { off + delta } else { off - delta };
                                if new_off < -(BPF_STACK_SIZE as i32) || new_off > 0 {
                                    log.append(pc, &alloc::format!("stack pointer offset out of bounds: {}", new_off));
                                    return Err(LinuxError::EACCES);
                                }
                                state.regs[dst] = RegType::PtrStack { off: new_off };
                            }
                            RegType::PtrContext { off } => {
                                if !is_src_imm {
                                    log.append(pc, "variable context pointer arithmetic is not supported");
                                    return Err(LinuxError::EACCES);
                                }
                                let delta = insn.imm as i32;
                                let new_off = if op == BPF_ADD { off + delta } else { off - delta };
                                if new_off < 0 || new_off > (MAX_CONTEXT_SIZE as i32) {
                                    log.append(pc, &alloc::format!("context pointer offset out of bounds: {}", new_off));
                                    return Err(LinuxError::EACCES);
                                }
                                state.regs[dst] = RegType::PtrContext { off: new_off };
                            }
                            RegType::Scalar => {
                                if !is_src_imm && state.regs[src] != RegType::Scalar {
                                    log.append(pc, "cannot add pointer to scalar");
                                    return Err(LinuxError::EACCES);
                                }
                                state.regs[dst] = RegType::Scalar;
                            }
                            RegType::PtrMapValue { map_idx, off, null_checked } => {
                                if !null_checked {
                                    log.append(pc, "cannot perform arithmetic on unchecked map value pointer");
                                    return Err(LinuxError::EACCES);
                                }
                                if !is_src_imm {
                                    log.append(pc, "variable pointer arithmetic on map value is not supported");
                                    return Err(LinuxError::EACCES);
                                }
                                let delta = insn.imm as i32;
                                let new_off = if op == BPF_ADD { off + delta } else { off - delta };
                                let val_size = referenced_maps[map_idx].spec().value_size() as i32;
                                if new_off < 0 || new_off > val_size {
                                    log.append(pc, "map value pointer offset out of bounds");
                                    return Err(LinuxError::EACCES);
                                }
                                state.regs[dst] = RegType::PtrMapValue { map_idx, off: new_off, null_checked: true };
                            }
                            _ => {
                                log.append(pc, "invalid pointer arithmetic on map pointer");
                                return Err(LinuxError::EACCES);
                            }
                        }
                    } else {
                        if state.regs[dst] != RegType::Scalar {
                            log.append(pc, "invalid ALU operation on pointer");
                            return Err(LinuxError::EACCES);
                        }
                        if !is_src_imm && state.regs[src] != RegType::Scalar {
                            log.append(pc, "invalid ALU operation with pointer source");
                            return Err(LinuxError::EACCES);
                        }
                        state.regs[dst] = RegType::Scalar;
                    }
                }
                worklist.push_back((next_pc, state));
            }

            BPF_LDX => {
                // dst = *(size *)(src + off)
                if state.regs[src] == RegType::NotInit {
                    log.append(pc, &alloc::format!("read uninitialized register R{}", src));
                    return Err(LinuxError::EACCES);
                }

                let size_bytes = insn.mem_size_bytes()?;
                match state.regs[src] {
                    RegType::PtrContext { off: ctx_off } => {
                        let eff_off = ctx_off + (insn.off as i32);
                        if eff_off < 0 || eff_off + (size_bytes as i32) > (MAX_CONTEXT_SIZE as i32) {
                            log.append(pc, &alloc::format!("invalid context access at offset {} size {}", eff_off, size_bytes));
                            return Err(LinuxError::EACCES);
                        }
                        if eff_off % (size_bytes as i32) != 0 {
                            log.append(pc, &alloc::format!("unaligned context access at offset {} size {}", eff_off, size_bytes));
                            return Err(LinuxError::EACCES);
                        }
                        state.regs[dst] = RegType::Scalar;
                    }
                    RegType::PtrStack { off: stk_off } => {
                        let eff_off = stk_off + (insn.off as i32);
                        if eff_off < -(BPF_STACK_SIZE as i32) || eff_off + (size_bytes as i32) > 0 {
                            log.append(pc, &alloc::format!("invalid stack access at offset {} size {}", eff_off, size_bytes));
                            return Err(LinuxError::EACCES);
                        }
                        if (-eff_off) % (size_bytes as i32) != 0 {
                            log.append(pc, &alloc::format!("unaligned stack access at offset {} size {}", eff_off, size_bytes));
                            return Err(LinuxError::EACCES);
                        }
                        let start_idx = (BPF_STACK_SIZE as i32 + eff_off) as usize;
                        for b in 0..size_bytes {
                            if !state.stack_init[start_idx + b] {
                                log.append(pc, &alloc::format!("read uninitialized stack at offset {}", eff_off + b as i32));
                                return Err(LinuxError::EACCES);
                            }
                        }
                        state.regs[dst] = RegType::Scalar;
                    }
                    RegType::PtrMapValue { map_idx, off: map_off, null_checked } => {
                        if !null_checked {
                            log.append(pc, "map value pointer must be checked for NULL before dereference");
                            return Err(LinuxError::EACCES);
                        }
                        let eff_off = map_off + (insn.off as i32);
                        let val_size = referenced_maps[map_idx].spec().value_size() as i32;
                        if eff_off < 0 || eff_off + (size_bytes as i32) > val_size {
                            log.append(pc, &alloc::format!("map value access out of bounds at offset {} size {}", eff_off, size_bytes));
                            return Err(LinuxError::EACCES);
                        }
                        state.regs[dst] = RegType::Scalar;
                    }
                    _ => {
                        log.append(pc, &alloc::format!("invalid load from non-pointer register R{}", src));
                        return Err(LinuxError::EACCES);
                    }
                }
                worklist.push_back((next_pc, state));
            }

            BPF_ST | BPF_STX => {
                // *(size *)(dst + off) = src / imm
                if state.regs[dst] == RegType::NotInit {
                    log.append(pc, &alloc::format!("read uninitialized register R{}", dst));
                    return Err(LinuxError::EACCES);
                }
                if class == BPF_STX && state.regs[src] == RegType::NotInit {
                    log.append(pc, &alloc::format!("read uninitialized register R{}", src));
                    return Err(LinuxError::EACCES);
                }

                let size_bytes = insn.mem_size_bytes()?;
                match state.regs[dst] {
                    RegType::PtrContext { .. } => {
                        log.append(pc, "cannot write to read-only context");
                        return Err(LinuxError::EACCES);
                    }
                    RegType::PtrStack { off: stk_off } => {
                        let eff_off = stk_off + (insn.off as i32);
                        if eff_off < -(BPF_STACK_SIZE as i32) || eff_off + (size_bytes as i32) > 0 {
                            log.append(pc, &alloc::format!("invalid stack write at offset {} size {}", eff_off, size_bytes));
                            return Err(LinuxError::EACCES);
                        }
                        if (-eff_off) % (size_bytes as i32) != 0 {
                            log.append(pc, &alloc::format!("unaligned stack write at offset {} size {}", eff_off, size_bytes));
                            return Err(LinuxError::EACCES);
                        }
                        let start_idx = (BPF_STACK_SIZE as i32 + eff_off) as usize;
                        for b in 0..size_bytes {
                            state.stack_init[start_idx + b] = true;
                        }
                    }
                    RegType::PtrMapValue { map_idx, off: map_off, null_checked } => {
                        if !null_checked {
                            log.append(pc, "map value pointer must be checked for NULL before dereference");
                            return Err(LinuxError::EACCES);
                        }
                        let eff_off = map_off + (insn.off as i32);
                        let val_size = referenced_maps[map_idx].spec().value_size() as i32;
                        if eff_off < 0 || eff_off + (size_bytes as i32) > val_size {
                            log.append(pc, &alloc::format!("map value write out of bounds at offset {} size {}", eff_off, size_bytes));
                            return Err(LinuxError::EACCES);
                        }
                    }
                    _ => {
                        log.append(pc, &alloc::format!("invalid store to non-pointer register R{}", dst));
                        return Err(LinuxError::EACCES);
                    }
                }
                worklist.push_back((next_pc, state));
            }

            BPF_JMP | BPF_JMP32 => {
                if insn.is_exit() {
                    if state.regs[BPF_REG_0 as usize] == RegType::NotInit {
                        log.append(pc, "R0 not initialized at exit");
                        return Err(LinuxError::EACCES);
                    }
                    if matches!(state.regs[BPF_REG_0 as usize], RegType::PtrContext { .. } | RegType::PtrStack { .. } | RegType::PtrMap { .. } | RegType::PtrMapValue { .. }) {
                        log.append(pc, "R0 contains pointer at exit");
                        return Err(LinuxError::EACCES);
                    }
                    // Path completes successfully
                    continue;
                }

                if insn.is_ja() {
                    let target = (pc as isize + 1 + insn.off as isize) as usize;
                    worklist.push_back((target, state));
                    continue;
                }

                if insn.is_call() {
                    let helper_id = insn.imm;
                    match helper_id {
                        BPF_FUNC_MAP_LOOKUP_ELEM => {
                            let map_reg = state.regs[BPF_REG_1 as usize];
                            let key_reg = state.regs[BPF_REG_2 as usize];
                            let map_idx = match map_reg {
                                RegType::PtrMap { map_idx } => map_idx,
                                _ => {
                                    log.append(pc, "bpf_map_lookup_elem R1 must be a valid BPF map pointer");
                                    return Err(LinuxError::EACCES);
                                }
                            };
                            let key_off = match key_reg {
                                RegType::PtrStack { off } => off,
                                _ => {
                                    log.append(pc, "bpf_map_lookup_elem R2 must be a pointer to stack key");
                                    return Err(LinuxError::EACCES);
                                }
                            };
                            let key_size = referenced_maps[map_idx].spec().key_size() as usize;
                            if key_off < -(BPF_STACK_SIZE as i32) || key_off + (key_size as i32) > 0 {
                                log.append(pc, "key pointer out of stack bounds");
                                return Err(LinuxError::EACCES);
                            }
                            let start_idx = (BPF_STACK_SIZE as i32 + key_off) as usize;
                            for b in 0..key_size {
                                if !state.stack_init[start_idx + b] {
                                    log.append(pc, "read uninitialized key on stack");
                                    return Err(LinuxError::EACCES);
                                }
                            }

                            // Clobber caller-saved registers
                            state.regs[BPF_REG_1 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_2 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_3 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_4 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_5 as usize] = RegType::NotInit;

                            state.regs[BPF_REG_0 as usize] = RegType::PtrMapValue {
                                map_idx,
                                off: 0,
                                null_checked: false,
                            };
                            worklist.push_back((next_pc, state));
                        }
                        BPF_FUNC_MAP_UPDATE_ELEM => {
                            let map_reg = state.regs[BPF_REG_1 as usize];
                            let key_reg = state.regs[BPF_REG_2 as usize];
                            let val_reg = state.regs[BPF_REG_3 as usize];
                            let flags_reg = state.regs[BPF_REG_4 as usize];
                            let map_idx = match map_reg {
                                RegType::PtrMap { map_idx } => map_idx,
                                _ => {
                                    log.append(pc, "bpf_map_update_elem R1 must be a valid BPF map pointer");
                                    return Err(LinuxError::EACCES);
                                }
                            };
                            if referenced_maps[map_idx].spec().map_flags() & super::map::BPF_F_RDONLY_PROG != 0 {
                                log.append(pc, "cannot write to read-only map");
                                return Err(LinuxError::EACCES);
                            }
                            let key_off = match key_reg {
                                RegType::PtrStack { off } => off,
                                _ => {
                                    log.append(pc, "bpf_map_update_elem R2 must be a pointer to stack key");
                                    return Err(LinuxError::EACCES);
                                }
                            };
                            let key_size = referenced_maps[map_idx].spec().key_size() as usize;
                            if key_off < -(BPF_STACK_SIZE as i32) || key_off + (key_size as i32) > 0 {
                                log.append(pc, "key pointer out of stack bounds");
                                return Err(LinuxError::EACCES);
                            }
                            let start_idx = (BPF_STACK_SIZE as i32 + key_off) as usize;
                            for b in 0..key_size {
                                if !state.stack_init[start_idx + b] {
                                    log.append(pc, "read uninitialized key on stack");
                                    return Err(LinuxError::EACCES);
                                }
                            }
                            match val_reg {
                                RegType::PtrStack { off } => {
                                    let val_size = referenced_maps[map_idx].spec().value_size() as usize;
                                    if off < -(BPF_STACK_SIZE as i32) || off + (val_size as i32) > 0 {
                                        log.append(pc, "value pointer out of stack bounds");
                                        return Err(LinuxError::EACCES);
                                    }
                                    let v_start = (BPF_STACK_SIZE as i32 + off) as usize;
                                    for b in 0..val_size {
                                        if !state.stack_init[v_start + b] {
                                            log.append(pc, "read uninitialized value on stack");
                                            return Err(LinuxError::EACCES);
                                        }
                                    }
                                }
                                RegType::PtrMapValue { null_checked, .. } => {
                                    if !null_checked {
                                        log.append(pc, "map value pointer must be null checked before passing to update");
                                        return Err(LinuxError::EACCES);
                                    }
                                }
                                _ => {
                                    log.append(pc, "bpf_map_update_elem R3 must be a pointer to value");
                                    return Err(LinuxError::EACCES);
                                }
                            }
                            if !matches!(flags_reg, RegType::Scalar) {
                                log.append(pc, "bpf_map_update_elem R4 flags must be a scalar");
                                return Err(LinuxError::EACCES);
                            }

                            // Clobber caller-saved registers
                            state.regs[BPF_REG_1 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_2 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_3 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_4 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_5 as usize] = RegType::NotInit;

                            state.regs[BPF_REG_0 as usize] = RegType::Scalar;
                            worklist.push_back((next_pc, state));
                        }
                        BPF_FUNC_MAP_DELETE_ELEM => {
                            let map_reg = state.regs[BPF_REG_1 as usize];
                            let key_reg = state.regs[BPF_REG_2 as usize];
                            let map_idx = match map_reg {
                                RegType::PtrMap { map_idx } => map_idx,
                                _ => {
                                    log.append(pc, "bpf_map_delete_elem R1 must be a valid BPF map pointer");
                                    return Err(LinuxError::EACCES);
                                }
                            };
                            if referenced_maps[map_idx].spec().map_type() == super::map::BpfMapType::Array {
                                log.append(pc, "cannot delete from array map");
                                return Err(LinuxError::EINVAL);
                            }
                            if referenced_maps[map_idx].spec().map_flags() & super::map::BPF_F_RDONLY_PROG != 0 {
                                log.append(pc, "cannot delete from read-only map");
                                return Err(LinuxError::EACCES);
                            }
                            let key_off = match key_reg {
                                RegType::PtrStack { off } => off,
                                _ => {
                                    log.append(pc, "bpf_map_delete_elem R2 must be a pointer to stack key");
                                    return Err(LinuxError::EACCES);
                                }
                            };
                            let key_size = referenced_maps[map_idx].spec().key_size() as usize;
                            if key_off < -(BPF_STACK_SIZE as i32) || key_off + (key_size as i32) > 0 {
                                log.append(pc, "key pointer out of stack bounds");
                                return Err(LinuxError::EACCES);
                            }
                            let start_idx = (BPF_STACK_SIZE as i32 + key_off) as usize;
                            for b in 0..key_size {
                                if !state.stack_init[start_idx + b] {
                                    log.append(pc, "read uninitialized key on stack");
                                    return Err(LinuxError::EACCES);
                                }
                            }

                            // Clobber caller-saved registers
                            state.regs[BPF_REG_1 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_2 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_3 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_4 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_5 as usize] = RegType::NotInit;

                            state.regs[BPF_REG_0 as usize] = RegType::Scalar;
                            worklist.push_back((next_pc, state));
                        }
                        BPF_FUNC_KTIME_GET_NS => {
                            // Clobber caller-saved registers
                            state.regs[BPF_REG_1 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_2 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_3 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_4 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_5 as usize] = RegType::NotInit;

                            state.regs[BPF_REG_0 as usize] = RegType::Scalar;
                            worklist.push_back((next_pc, state));
                        }
                        BPF_FUNC_GET_SMP_PROCESSOR_ID => {
                            // Clobber caller-saved registers
                            state.regs[BPF_REG_1 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_2 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_3 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_4 as usize] = RegType::NotInit;
                            state.regs[BPF_REG_5 as usize] = RegType::NotInit;

                            state.regs[BPF_REG_0 as usize] = RegType::Scalar;
                            worklist.push_back((next_pc, state));
                        }
                        _ => {
                            log.append(pc, &alloc::format!("unsupported helper call ID {}", helper_id));
                            return Err(LinuxError::EINVAL);
                        }
                    }
                    continue;
                }

                // Conditional jump
                if state.regs[dst] == RegType::NotInit {
                    log.append(pc, &alloc::format!("read uninitialized register R{}", dst));
                    return Err(LinuxError::EACCES);
                }
                if insn.is_src_reg() && state.regs[src] == RegType::NotInit {
                    log.append(pc, &alloc::format!("read uninitialized register R{}", src));
                    return Err(LinuxError::EACCES);
                }

                let target = (pc as isize + 1 + insn.off as isize) as usize;
                let mut state_jump = state.clone();
                let mut state_fall = state;

                // Handle NULL-checking comparison against 0
                let is_imm_zero = insn.is_src_imm() && insn.imm == 0;
                let op = insn.op();

                if is_imm_zero {
                    if let RegType::PtrMapValue { map_idx, off, .. } = state_jump.regs[dst] {
                        if op == BPF_JNE {
                            state_jump.regs[dst] = RegType::PtrMapValue { map_idx, off, null_checked: true };
                            state_fall.regs[dst] = RegType::Scalar;
                        } else if op == BPF_JEQ {
                            state_jump.regs[dst] = RegType::Scalar;
                            state_fall.regs[dst] = RegType::PtrMapValue { map_idx, off, null_checked: true };
                        }
                    }
                }

                worklist.push_back((next_pc, state_fall));
                worklist.push_back((target, state_jump));
            }

            _ => {
                log.append(pc, "unhandled instruction class");
                return Err(LinuxError::EINVAL);
            }
        }
    }

    let mut relocated_insns = insns.to_vec();
    for (pc, map_idx) in relocations {
        relocated_insns[pc].imm = map_idx as i32;
    }

    Ok(VerifiedProgram {
        prog_type: config.prog_type,
        insns: Arc::from(relocated_insns),
        referenced_maps,
    })
}
