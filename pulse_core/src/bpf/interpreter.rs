//! BPF portable virtual interpreter for PulseOS.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use axerrno::LinuxError;

use super::{insn::*, map::{BpfMap, BPF_MAP_MAX_KEY_SIZE}};

pub const BPF_STACK_SIZE: usize = 512;
pub const BPF_MAX_STEPS: usize = 65536;
pub const BPF_MAX_RECURSION_DEPTH: usize = 4;
pub const BPF_MAX_LOOKUP_REFS: usize = 64;
pub const BPF_MAX_CPUS: usize = 16;

static RECURSION_DEPTH_PER_CPU: [AtomicUsize; BPF_MAX_CPUS] = [const { AtomicUsize::new(0) }; BPF_MAX_CPUS];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpfVmError {
    StepLimitExceeded,
    RecursionLimitExceeded,
    InvalidInstruction,
    UninitializedRegister(u8),
    UninitializedStack { offset: i32, size: usize },
    NullPointerDereference,
    OutOfBoundsAccess,
    UnalignedMemoryAccess,
    ReadOnlyAccess,
    InvalidHelperCall(i32),
    HelperFailed(LinuxError),
    DivideByZero,
}

impl From<BpfVmError> for LinuxError {
    fn from(err: BpfVmError) -> Self {
        match err {
            BpfVmError::StepLimitExceeded => LinuxError::E2BIG,
            BpfVmError::RecursionLimitExceeded => LinuxError::EBUSY,
            BpfVmError::InvalidInstruction => LinuxError::EINVAL,
            BpfVmError::UninitializedRegister(_) => LinuxError::EACCES,
            BpfVmError::UninitializedStack { .. } => LinuxError::EACCES,
            BpfVmError::NullPointerDereference => LinuxError::EFAULT,
            BpfVmError::OutOfBoundsAccess => LinuxError::EFAULT,
            BpfVmError::UnalignedMemoryAccess => LinuxError::EINVAL,
            BpfVmError::ReadOnlyAccess => LinuxError::EACCES,
            BpfVmError::InvalidHelperCall(_) => LinuxError::EINVAL,
            BpfVmError::HelperFailed(e) => e,
            BpfVmError::DivideByZero => LinuxError::EINVAL,
        }
    }
}

pub trait BpfEnv {
    fn ktime_get_ns(&self) -> u64;
    fn get_smp_processor_id(&self) -> u32;
}

#[derive(Default)]
pub struct DefaultBpfEnv;

impl BpfEnv for DefaultBpfEnv {
    fn ktime_get_ns(&self) -> u64 {
        #[cfg(target_os = "none")]
        {
            axhal::time::wall_time_nanos()
        }
        #[cfg(not(target_os = "none"))]
        {
            1_000_000_000
        }
    }

    fn get_smp_processor_id(&self) -> u32 {
        #[cfg(target_os = "none")]
        {
            axhal::percpu::this_cpu_id() as u32
        }
        #[cfg(not(target_os = "none"))]
        {
            0
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmValue {
    Uninit,
    Scalar(u64),
    PtrContext { offset: usize },
    PtrStack { offset: usize },
    PtrMap { map_idx: usize },
    PtrMapValueArray {
        map_idx: usize,
        entry_idx: u32,
        offset: usize,
    },
    PtrMapValueHash {
        map_idx: usize,
        lookup_id: u8,
        offset: usize,
    },
    Null,
}

impl VmValue {
    pub fn as_scalar(self) -> Result<u64, BpfVmError> {
        match self {
            Self::Scalar(v) => Ok(v),
            Self::Null => Ok(0),
            Self::Uninit => Err(BpfVmError::UninitializedRegister(0)),
            _ => Err(BpfVmError::InvalidInstruction),
        }
    }

    pub fn is_null(self) -> bool {
        matches!(self, Self::Null | Self::Scalar(0))
    }
}

#[derive(Clone, Copy)]
struct ActiveLookup {
    map_idx: usize,
    key: [u8; BPF_MAP_MAX_KEY_SIZE as usize],
    key_len: usize,
}

struct RecursionGuard(usize);
impl Drop for RecursionGuard {
    fn drop(&mut self) {
        RECURSION_DEPTH_PER_CPU[self.0].fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn execute(
    insns: &[BpfInsn],
    maps: &[Arc<BpfMap>],
    context: &[u8],
    env: &dyn BpfEnv,
) -> Result<u64, BpfVmError> {
    let cpu_id = (env.get_smp_processor_id() as usize) % BPF_MAX_CPUS;
    let depth = RECURSION_DEPTH_PER_CPU[cpu_id].fetch_add(1, Ordering::SeqCst);
    if depth >= BPF_MAX_RECURSION_DEPTH {
        RECURSION_DEPTH_PER_CPU[cpu_id].fetch_sub(1, Ordering::SeqCst);
        return Err(BpfVmError::RecursionLimitExceeded);
    }
    let _guard = RecursionGuard(cpu_id);

    let mut regs = [VmValue::Uninit; 11];
    regs[BPF_REG_1 as usize] = VmValue::PtrContext { offset: 0 };
    regs[BPF_REG_10 as usize] = VmValue::PtrStack { offset: BPF_STACK_SIZE };

    let mut stack = [0u8; BPF_STACK_SIZE];
    let mut stack_init = [false; BPF_STACK_SIZE];

    let mut lookups: alloc::vec::Vec<ActiveLookup> = alloc::vec::Vec::new();

    let mut pc = 0;
    let mut steps = 0;
    let n = insns.len();

    while pc < n {
        steps += 1;
        if steps > BPF_MAX_STEPS {
            return Err(BpfVmError::StepLimitExceeded);
        }

        let insn = &insns[pc];
        let dst = insn.dst_reg() as usize;
        let src = insn.src_reg() as usize;
        let class = insn.class();

        match class {
            BPF_LD => {
                if insn.is_ld_imm64() {
                    if insn.src_reg() == BPF_PSEUDO_MAP_FD {
                        let map_idx = insn.imm as usize;
                        regs[dst] = VmValue::PtrMap { map_idx };
                    } else {
                        let imm_lo = insn.imm as u32 as u64;
                        let imm_hi = if pc + 1 < n { insns[pc + 1].imm as u32 as u64 } else { 0 };
                        let val = (imm_hi << 32) | imm_lo;
                        regs[dst] = VmValue::Scalar(val);
                    }
                    pc += 2;
                    continue;
                } else {
                    return Err(BpfVmError::InvalidInstruction);
                }
            }

            BPF_ALU => {
                let op = insn.op();
                let is_src_imm = insn.is_src_imm();

                if op == BPF_MOV {
                    let val = if is_src_imm {
                        insn.imm as u32 as u64
                    } else {
                        regs[src].as_scalar()? as u32 as u64
                    };
                    regs[dst] = VmValue::Scalar(val);
                    pc += 1;
                    continue;
                }

                let dst_val = regs[dst].as_scalar()? as u32;
                let src_val = if is_src_imm {
                    insn.imm as u32
                } else {
                    regs[src].as_scalar()? as u32
                };

                let res = match op {
                    BPF_ADD => dst_val.wrapping_add(src_val),
                    BPF_SUB => dst_val.wrapping_sub(src_val),
                    BPF_MUL => dst_val.wrapping_mul(src_val),
                    BPF_DIV => {
                        if src_val == 0 {
                            return Err(BpfVmError::DivideByZero);
                        }
                        dst_val / src_val
                    }
                    BPF_MOD => {
                        if src_val == 0 {
                            return Err(BpfVmError::DivideByZero);
                        }
                        dst_val % src_val
                    }
                    BPF_OR => dst_val | src_val,
                    BPF_AND => dst_val & src_val,
                    BPF_LSH => dst_val.wrapping_shl(src_val & 31),
                    BPF_RSH => dst_val.wrapping_shr(src_val & 31),
                    BPF_ARSH => ((dst_val as i32).wrapping_shr(src_val & 31)) as u32,
                    BPF_NEG => (dst_val as i32).wrapping_neg() as u32,
                    BPF_XOR => dst_val ^ src_val,
                    BPF_END => match insn.imm {
                        16 => (dst_val as u16).to_le() as u32,
                        32 => dst_val.to_le(),
                        _ => return Err(BpfVmError::InvalidInstruction),
                    },
                    _ => return Err(BpfVmError::InvalidInstruction),
                };

                regs[dst] = VmValue::Scalar(res as u64);
                pc += 1;
                continue;
            }

            BPF_ALU64 => {
                let op = insn.op();
                let is_src_imm = insn.is_src_imm();

                if op == BPF_MOV {
                    if is_src_imm {
                        regs[dst] = VmValue::Scalar(insn.imm as i64 as u64);
                    } else {
                        regs[dst] = regs[src];
                    }
                    pc += 1;
                    continue;
                }

                if op == BPF_ADD || op == BPF_SUB {
                    match regs[dst] {
                        VmValue::PtrStack { offset } => {
                            let delta = if is_src_imm {
                                insn.imm as i64
                            } else {
                                regs[src].as_scalar()? as i64
                            };
                            let eff_delta = if op == BPF_ADD { delta } else { -delta };
                            let new_off = (offset as i64 + eff_delta) as usize;
                            regs[dst] = VmValue::PtrStack { offset: new_off };
                            pc += 1;
                            continue;
                        }
                        VmValue::PtrContext { offset } => {
                            let delta = if is_src_imm {
                                insn.imm as i64
                            } else {
                                regs[src].as_scalar()? as i64
                            };
                            let eff_delta = if op == BPF_ADD { delta } else { -delta };
                            let new_off = (offset as i64 + eff_delta) as usize;
                            regs[dst] = VmValue::PtrContext { offset: new_off };
                            pc += 1;
                            continue;
                        }
                        VmValue::PtrMapValueArray {
                            map_idx,
                            entry_idx,
                            offset,
                        } => {
                            let delta = if is_src_imm {
                                insn.imm as i64
                            } else {
                                regs[src].as_scalar()? as i64
                            };
                            let eff_delta = if op == BPF_ADD { delta } else { -delta };
                            let new_off = offset
                                .checked_add_signed(eff_delta as isize)
                                .ok_or(BpfVmError::OutOfBoundsAccess)?;
                            let map = maps.get(map_idx).ok_or(BpfVmError::OutOfBoundsAccess)?;
                            if new_off > map.spec().value_size() as usize {
                                return Err(BpfVmError::OutOfBoundsAccess);
                            }
                            regs[dst] = VmValue::PtrMapValueArray {
                                map_idx,
                                entry_idx,
                                offset: new_off,
                            };
                            pc += 1;
                            continue;
                        }
                        VmValue::PtrMapValueHash {
                            map_idx,
                            lookup_id,
                            offset,
                        } => {
                            let delta = if is_src_imm {
                                insn.imm as i64
                            } else {
                                regs[src].as_scalar()? as i64
                            };
                            let eff_delta = if op == BPF_ADD { delta } else { -delta };
                            let new_off = offset
                                .checked_add_signed(eff_delta as isize)
                                .ok_or(BpfVmError::OutOfBoundsAccess)?;
                            let map = maps.get(map_idx).ok_or(BpfVmError::OutOfBoundsAccess)?;
                            if new_off > map.spec().value_size() as usize {
                                return Err(BpfVmError::OutOfBoundsAccess);
                            }
                            regs[dst] = VmValue::PtrMapValueHash {
                                map_idx,
                                lookup_id,
                                offset: new_off,
                            };
                            pc += 1;
                            continue;
                        }
                        _ => {}
                    }
                }

                let dst_val = regs[dst].as_scalar()?;
                let src_val = if is_src_imm {
                    insn.imm as i64 as u64
                } else {
                    regs[src].as_scalar()?
                };

                let res = match op {
                    BPF_ADD => dst_val.wrapping_add(src_val),
                    BPF_SUB => dst_val.wrapping_sub(src_val),
                    BPF_MUL => dst_val.wrapping_mul(src_val),
                    BPF_DIV => {
                        if src_val == 0 {
                            return Err(BpfVmError::DivideByZero);
                        }
                        dst_val / src_val
                    }
                    BPF_MOD => {
                        if src_val == 0 {
                            return Err(BpfVmError::DivideByZero);
                        }
                        dst_val % src_val
                    }
                    BPF_OR => dst_val | src_val,
                    BPF_AND => dst_val & src_val,
                    BPF_LSH => dst_val.wrapping_shl((src_val & 63) as u32),
                    BPF_RSH => dst_val.wrapping_shr((src_val & 63) as u32),
                    BPF_ARSH => ((dst_val as i64).wrapping_shr((src_val & 63) as u32)) as u64,
                    BPF_NEG => (dst_val as i64).wrapping_neg() as u64,
                    BPF_XOR => dst_val ^ src_val,
                    BPF_END => match insn.imm {
                        64 => dst_val.to_le(),
                        _ => return Err(BpfVmError::InvalidInstruction),
                    },
                    _ => return Err(BpfVmError::InvalidInstruction),
                };

                regs[dst] = VmValue::Scalar(res);
                pc += 1;
                continue;
            }

            BPF_LDX => {
                let size = insn.mem_size_bytes().map_err(|_| BpfVmError::InvalidInstruction)?;
                let off = insn.off as isize;

                match regs[src] {
                    VmValue::PtrContext { offset } => {
                        let eff = offset.checked_add_signed(off).ok_or(BpfVmError::OutOfBoundsAccess)?;
                        if eff + size > context.len() {
                            return Err(BpfVmError::OutOfBoundsAccess);
                        }
                        if eff % size != 0 {
                            return Err(BpfVmError::UnalignedMemoryAccess);
                        }
                        let val = match size {
                            1 => context[eff] as u64,
                            2 => u16::from_ne_bytes(context[eff..eff + 2].try_into().unwrap()) as u64,
                            4 => u32::from_ne_bytes(context[eff..eff + 4].try_into().unwrap()) as u64,
                            8 => u64::from_ne_bytes(context[eff..eff + 8].try_into().unwrap()),
                            _ => return Err(BpfVmError::InvalidInstruction),
                        };
                        regs[dst] = VmValue::Scalar(val);
                    }
                    VmValue::PtrStack { offset } => {
                        let eff = offset.checked_add_signed(off).ok_or(BpfVmError::OutOfBoundsAccess)?;
                        if eff + size > BPF_STACK_SIZE {
                            return Err(BpfVmError::OutOfBoundsAccess);
                        }
                        for b in 0..size {
                            if !stack_init[eff + b] {
                                return Err(BpfVmError::UninitializedStack {
                                    offset: eff as i32 - BPF_STACK_SIZE as i32,
                                    size,
                                });
                            }
                        }
                        let val = match size {
                            1 => stack[eff] as u64,
                            2 => u16::from_ne_bytes(stack[eff..eff + 2].try_into().unwrap()) as u64,
                            4 => u32::from_ne_bytes(stack[eff..eff + 4].try_into().unwrap()) as u64,
                            8 => u64::from_ne_bytes(stack[eff..eff + 8].try_into().unwrap()),
                            _ => return Err(BpfVmError::InvalidInstruction),
                        };
                        regs[dst] = VmValue::Scalar(val);
                    }
                    VmValue::PtrMapValueArray {
                        map_idx,
                        entry_idx,
                        offset,
                    } => {
                        let eff = offset.checked_add_signed(off).ok_or(BpfVmError::OutOfBoundsAccess)?;
                        let map = maps.get(map_idx).ok_or(BpfVmError::OutOfBoundsAccess)?;
                        let mut buf = [0u8; 8];
                        map.read_value_bytes(&entry_idx.to_ne_bytes(), eff, &mut buf[..size])
                            .map_err(|_| BpfVmError::OutOfBoundsAccess)?;
                        let val = match size {
                            1 => buf[0] as u64,
                            2 => u16::from_ne_bytes(buf[..2].try_into().unwrap()) as u64,
                            4 => u32::from_ne_bytes(buf[..4].try_into().unwrap()) as u64,
                            8 => u64::from_ne_bytes(buf[..8].try_into().unwrap()),
                            _ => return Err(BpfVmError::InvalidInstruction),
                        };
                        regs[dst] = VmValue::Scalar(val);
                    }
                    VmValue::PtrMapValueHash {
                        map_idx,
                        lookup_id,
                        offset,
                    } => {
                        let eff = offset.checked_add_signed(off).ok_or(BpfVmError::OutOfBoundsAccess)?;
                        let map = maps.get(map_idx).ok_or(BpfVmError::OutOfBoundsAccess)?;
                        let l = &lookups[lookup_id as usize];
                        let mut buf = [0u8; 8];
                        map.read_value_bytes(&l.key[..l.key_len], eff, &mut buf[..size])
                            .map_err(|_| BpfVmError::OutOfBoundsAccess)?;
                        let val = match size {
                            1 => buf[0] as u64,
                            2 => u16::from_ne_bytes(buf[..2].try_into().unwrap()) as u64,
                            4 => u32::from_ne_bytes(buf[..4].try_into().unwrap()) as u64,
                            8 => u64::from_ne_bytes(buf[..8].try_into().unwrap()),
                            _ => return Err(BpfVmError::InvalidInstruction),
                        };
                        regs[dst] = VmValue::Scalar(val);
                    }
                    VmValue::Null | VmValue::Scalar(0) => {
                        return Err(BpfVmError::NullPointerDereference);
                    }
                    _ => return Err(BpfVmError::InvalidInstruction),
                }

                pc += 1;
                continue;
            }

            BPF_ST | BPF_STX => {
                let size = insn.mem_size_bytes().map_err(|_| BpfVmError::InvalidInstruction)?;
                let off = insn.off as isize;
                let val: u64 = if class == BPF_ST {
                    insn.imm as u32 as u64
                } else {
                    regs[src].as_scalar()?
                };
                let bytes = val.to_ne_bytes();

                match regs[dst] {
                    VmValue::PtrContext { .. } => {
                        return Err(BpfVmError::ReadOnlyAccess);
                    }
                    VmValue::PtrStack { offset } => {
                        let eff = offset.checked_add_signed(off).ok_or(BpfVmError::OutOfBoundsAccess)?;
                        if eff + size > BPF_STACK_SIZE {
                            return Err(BpfVmError::OutOfBoundsAccess);
                        }
                        stack[eff..eff + size].copy_from_slice(&bytes[..size]);
                        stack_init[eff..eff + size].fill(true);
                    }
                    VmValue::PtrMapValueArray {
                        map_idx,
                        entry_idx,
                        offset,
                    } => {
                        let eff = offset.checked_add_signed(off).ok_or(BpfVmError::OutOfBoundsAccess)?;
                        let map = maps.get(map_idx).ok_or(BpfVmError::OutOfBoundsAccess)?;
                        map.write_value_bytes(&entry_idx.to_ne_bytes(), eff, &bytes[..size])
                            .map_err(|_| BpfVmError::OutOfBoundsAccess)?;
                    }
                    VmValue::PtrMapValueHash {
                        map_idx,
                        lookup_id,
                        offset,
                    } => {
                        let eff = offset.checked_add_signed(off).ok_or(BpfVmError::OutOfBoundsAccess)?;
                        let map = maps.get(map_idx).ok_or(BpfVmError::OutOfBoundsAccess)?;
                        let l = &lookups[lookup_id as usize];
                        map.write_value_bytes(&l.key[..l.key_len], eff, &bytes[..size])
                            .map_err(|_| BpfVmError::OutOfBoundsAccess)?;
                    }
                    VmValue::Null | VmValue::Scalar(0) => {
                        return Err(BpfVmError::NullPointerDereference);
                    }
                    _ => return Err(BpfVmError::InvalidInstruction),
                }

                pc += 1;
                continue;
            }

            BPF_JMP | BPF_JMP32 => {
                if insn.is_exit() {
                    return regs[BPF_REG_0 as usize].as_scalar();
                }

                if insn.is_ja() {
                    let target = (pc as isize + 1 + insn.off as isize) as usize;
                    pc = target;
                    continue;
                }

                if insn.is_call() {
                    match insn.imm {
                        BPF_FUNC_MAP_LOOKUP_ELEM => {
                            let map_idx = match regs[BPF_REG_1 as usize] {
                                VmValue::PtrMap { map_idx } => map_idx,
                                _ => return Err(BpfVmError::InvalidInstruction),
                            };
                            let map = maps.get(map_idx).ok_or(BpfVmError::OutOfBoundsAccess)?;
                            let key_size = map.spec().key_size() as usize;

                            let key_off = match regs[BPF_REG_2 as usize] {
                                VmValue::PtrStack { offset } => offset,
                                _ => return Err(BpfVmError::InvalidInstruction),
                            };
                            if key_off + key_size > BPF_STACK_SIZE {
                                return Err(BpfVmError::OutOfBoundsAccess);
                            }
                            let key_bytes = &stack[key_off..key_off + key_size];

                            match map.spec().map_type() {
                                super::map::BpfMapType::Array => {
                                    let idx = u32::from_ne_bytes(
                                        key_bytes.try_into().map_err(|_| BpfVmError::InvalidInstruction)?,
                                    );
                                    if idx < map.spec().max_entries() {
                                        regs[BPF_REG_0 as usize] = VmValue::PtrMapValueArray {
                                            map_idx,
                                            entry_idx: idx,
                                            offset: 0,
                                        };
                                    } else {
                                        regs[BPF_REG_0 as usize] = VmValue::Null;
                                    }
                                }
                                super::map::BpfMapType::Hash => {
                                    let mut test_out = alloc::vec![0u8; map.spec().value_size() as usize];
                                    if map.lookup(key_bytes, &mut test_out).is_ok() {
                                        if lookups.len() >= BPF_MAX_LOOKUP_REFS {
                                            return Err(BpfVmError::OutOfBoundsAccess);
                                        }
                                        let lid = lookups.len();
                                        let mut entry = ActiveLookup {
                                            map_idx,
                                            key: [0u8; BPF_MAP_MAX_KEY_SIZE as usize],
                                            key_len: key_size,
                                        };
                                        entry.key[..key_size].copy_from_slice(key_bytes);
                                        lookups.push(entry);
                                        regs[BPF_REG_0 as usize] = VmValue::PtrMapValueHash {
                                            map_idx,
                                            lookup_id: lid as u8,
                                            offset: 0,
                                        };
                                    } else {
                                        regs[BPF_REG_0 as usize] = VmValue::Null;
                                    }
                                }
                                super::map::BpfMapType::PerfEventArray => {
                                    regs[BPF_REG_0 as usize] = VmValue::Null;
                                }
                            }

                            regs[1..=5].fill(VmValue::Uninit);
                            pc += 1;
                            continue;
                        }

                        BPF_FUNC_MAP_UPDATE_ELEM => {
                            let map_idx = match regs[BPF_REG_1 as usize] {
                                VmValue::PtrMap { map_idx } => map_idx,
                                _ => return Err(BpfVmError::InvalidInstruction),
                            };
                            let map = maps.get(map_idx).ok_or(BpfVmError::OutOfBoundsAccess)?;
                            let key_size = map.spec().key_size() as usize;
                            let val_size = map.spec().value_size() as usize;

                            let key_off = match regs[BPF_REG_2 as usize] {
                                VmValue::PtrStack { offset } => offset,
                                _ => return Err(BpfVmError::InvalidInstruction),
                            };
                            if key_off + key_size > BPF_STACK_SIZE {
                                return Err(BpfVmError::OutOfBoundsAccess);
                            }
                            let key_bytes = &stack[key_off..key_off + key_size];

                            let mut val_buf = alloc::vec![0u8; val_size];
                            match regs[BPF_REG_3 as usize] {
                                VmValue::PtrStack { offset } => {
                                    if offset + val_size > BPF_STACK_SIZE {
                                        return Err(BpfVmError::OutOfBoundsAccess);
                                    }
                                    val_buf.copy_from_slice(&stack[offset..offset + val_size]);
                                }
                                VmValue::PtrMapValueArray {
                                    map_idx: src_map,
                                    entry_idx,
                                    offset,
                                } => {
                                    let src = maps.get(src_map).ok_or(BpfVmError::OutOfBoundsAccess)?;
                                    src.read_value_bytes(&entry_idx.to_ne_bytes(), offset, &mut val_buf)
                                        .map_err(BpfVmError::HelperFailed)?;
                                }
                                VmValue::PtrMapValueHash {
                                    map_idx: src_map,
                                    lookup_id,
                                    offset,
                                } => {
                                    let src = maps.get(src_map).ok_or(BpfVmError::OutOfBoundsAccess)?;
                                    let l = lookups.get(lookup_id as usize).ok_or(BpfVmError::OutOfBoundsAccess)?;
                                    src.read_value_bytes(&l.key[..l.key_len], offset, &mut val_buf)
                                        .map_err(BpfVmError::HelperFailed)?;
                                }
                                _ => return Err(BpfVmError::InvalidInstruction),
                            }

                            let flags = regs[BPF_REG_4 as usize].as_scalar()?;
                            let ret = match map.update(key_bytes, &val_buf, flags) {
                                Ok(()) => 0,
                                Err(e) => (-(e.code() as i64)) as u64,
                            };

                            regs[BPF_REG_0 as usize] = VmValue::Scalar(ret);
                            regs[1..=5].fill(VmValue::Uninit);
                            pc += 1;
                            continue;
                        }

                        BPF_FUNC_MAP_DELETE_ELEM => {
                            let map_idx = match regs[BPF_REG_1 as usize] {
                                VmValue::PtrMap { map_idx } => map_idx,
                                _ => return Err(BpfVmError::InvalidInstruction),
                            };
                            let map = maps.get(map_idx).ok_or(BpfVmError::OutOfBoundsAccess)?;
                            let key_size = map.spec().key_size() as usize;

                            let key_off = match regs[BPF_REG_2 as usize] {
                                VmValue::PtrStack { offset } => offset,
                                _ => return Err(BpfVmError::InvalidInstruction),
                            };
                            if key_off + key_size > BPF_STACK_SIZE {
                                return Err(BpfVmError::OutOfBoundsAccess);
                            }
                            let key_bytes = &stack[key_off..key_off + key_size];

                            let ret = match map.delete(key_bytes) {
                                Ok(()) => 0,
                                Err(e) => (-(e.code() as i64)) as u64,
                            };

                            regs[BPF_REG_0 as usize] = VmValue::Scalar(ret);
                            regs[1..=5].fill(VmValue::Uninit);
                            pc += 1;
                            continue;
                        }

                        BPF_FUNC_KTIME_GET_NS => {
                            let ns = env.ktime_get_ns();
                            regs[BPF_REG_0 as usize] = VmValue::Scalar(ns);
                            regs[1..=5].fill(VmValue::Uninit);
                            pc += 1;
                            continue;
                        }

                        BPF_FUNC_GET_SMP_PROCESSOR_ID => {
                            let cpu = env.get_smp_processor_id() as u64;
                            regs[BPF_REG_0 as usize] = VmValue::Scalar(cpu);
                            regs[1..=5].fill(VmValue::Uninit);
                            pc += 1;
                            continue;
                        }

                        BPF_FUNC_PERF_EVENT_OUTPUT => {
                            let map_idx = match regs[BPF_REG_2 as usize] {
                                VmValue::PtrMap { map_idx } => map_idx,
                                _ => return Err(BpfVmError::InvalidInstruction),
                            };
                            let map = maps.get(map_idx).ok_or(BpfVmError::OutOfBoundsAccess)?;
                            if map.spec().map_type() != super::map::BpfMapType::PerfEventArray {
                                return Err(BpfVmError::InvalidInstruction);
                            }
                            let flags = regs[BPF_REG_3 as usize].as_scalar()?;
                            let cpu_idx = (flags & BPF_F_INDEX_MASK) as u32;
                            let current_cpu = env.get_smp_processor_id();
                            let target_cpu = if cpu_idx == (BPF_F_CURRENT_CPU as u32) {
                                current_cpu
                            } else {
                                cpu_idx
                            };
                            if target_cpu >= map.spec().max_entries() || target_cpu != current_cpu {
                                regs[BPF_REG_0 as usize] = VmValue::Scalar((-(LinuxError::EINVAL.code() as i64)) as u64);
                                regs[1..=5].fill(VmValue::Uninit);
                                pc += 1;
                                continue;
                            }
                            let size = regs[BPF_REG_5 as usize].as_scalar()? as usize;
                            if size > 65535 {
                                return Err(BpfVmError::OutOfBoundsAccess);
                            }

                            let mut data_buf = alloc::vec![0u8; size];
                            match regs[BPF_REG_4 as usize] {
                                VmValue::PtrStack { offset } => {
                                    if offset.checked_add(size).map_or(true, |end| end > BPF_STACK_SIZE) {
                                        return Err(BpfVmError::OutOfBoundsAccess);
                                    }
                                    data_buf.copy_from_slice(&stack[offset..offset + size]);
                                }
                                VmValue::PtrMapValueArray {
                                    map_idx: src_map,
                                    entry_idx,
                                    offset,
                                } => {
                                    let src = maps.get(src_map).ok_or(BpfVmError::OutOfBoundsAccess)?;
                                    src.read_value_bytes(&entry_idx.to_ne_bytes(), offset, &mut data_buf)
                                        .map_err(BpfVmError::HelperFailed)?;
                                }
                                VmValue::PtrMapValueHash {
                                    map_idx: src_map,
                                    lookup_id,
                                    offset,
                                } => {
                                    let src = maps.get(src_map).ok_or(BpfVmError::OutOfBoundsAccess)?;
                                    let l = lookups.get(lookup_id as usize).ok_or(BpfVmError::OutOfBoundsAccess)?;
                                    src.read_value_bytes(&l.key[..l.key_len], offset, &mut data_buf)
                                        .map_err(BpfVmError::HelperFailed)?;
                                }
                                VmValue::PtrContext { offset } => {
                                    if offset.checked_add(size).map_or(true, |end| end > context.len()) {
                                        return Err(BpfVmError::OutOfBoundsAccess);
                                    }
                                    data_buf.copy_from_slice(&context[offset..offset + size]);
                                }
                                _ => return Err(BpfVmError::InvalidInstruction),
                            }

                            let ret = match map.output_perf_event(target_cpu, &data_buf) {
                                Ok(()) => 0,
                                Err(e) => (-(e.code() as i64)) as u64,
                            };

                            regs[BPF_REG_0 as usize] = VmValue::Scalar(ret);
                            regs[1..=5].fill(VmValue::Uninit);
                            pc += 1;
                            continue;
                        }

                        _ => return Err(BpfVmError::InvalidHelperCall(insn.imm)),
                    }
                }

                // Conditional jump
                let is_32 = class == BPF_JMP32;
                let op = insn.op();
                let is_src_imm = insn.is_src_imm();

                // Check NULL pointer comparisons against 0
                let take_jump = if is_src_imm && insn.imm == 0 {
                    match regs[dst] {
                        VmValue::PtrMapValueArray { .. } | VmValue::PtrMapValueHash { .. } => {
                            match op {
                                BPF_JEQ => false,
                                BPF_JNE => true,
                                _ => return Err(BpfVmError::InvalidInstruction),
                            }
                        }
                        VmValue::Null => match op {
                            BPF_JEQ => true,
                            BPF_JNE => false,
                            _ => return Err(BpfVmError::InvalidInstruction),
                        },
                        _ => {
                            let dst_val = regs[dst].as_scalar()?;
                            let (d_u, s_u) = if is_32 {
                                (dst_val as u32 as u64, 0u64)
                            } else {
                                (dst_val, 0u64)
                            };
                            let (d_s, s_s) = if is_32 {
                                (dst_val as i32 as i64, 0i64)
                            } else {
                                (dst_val as i64, 0i64)
                            };
                            eval_jump_condition(op, d_u, s_u, d_s, s_s)?
                        }
                    }
                } else {
                    let dst_val = regs[dst].as_scalar()?;
                    let src_val = if is_src_imm {
                        insn.imm as i64 as u64
                    } else {
                        regs[src].as_scalar()?
                    };

                    let (d_u, s_u) = if is_32 {
                        (dst_val as u32 as u64, src_val as u32 as u64)
                    } else {
                        (dst_val, src_val)
                    };
                    let (d_s, s_s) = if is_32 {
                        (dst_val as i32 as i64, src_val as i32 as i64)
                    } else {
                        (dst_val as i64, src_val as i64)
                    };

                    eval_jump_condition(op, d_u, s_u, d_s, s_s)?
                };

                if take_jump {
                    let target = (pc as isize + 1 + insn.off as isize) as usize;
                    pc = target;
                } else {
                    pc += 1;
                }
                continue;
            }

            _ => return Err(BpfVmError::InvalidInstruction),
        }
    }

    Err(BpfVmError::InvalidInstruction)
}

fn eval_jump_condition(op: u8, d_u: u64, s_u: u64, d_s: i64, s_s: i64) -> Result<bool, BpfVmError> {
    match op {
        BPF_JEQ => Ok(d_u == s_u),
        BPF_JNE => Ok(d_u != s_u),
        BPF_JGT => Ok(d_u > s_u),
        BPF_JGE => Ok(d_u >= s_u),
        BPF_JLT => Ok(d_u < s_u),
        BPF_JSGT => Ok(d_s > s_s),
        BPF_JSGE => Ok(d_s >= s_s),
        BPF_JSLT => Ok(d_s < s_s),
        BPF_JSLE => Ok(d_s <= s_s),
        BPF_JSET => Ok((d_u & s_u) != 0),
        BPF_JLE => Ok(d_u <= s_u),
        _ => Err(BpfVmError::InvalidInstruction),
    }
}


