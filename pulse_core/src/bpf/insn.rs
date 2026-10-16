//! Standard eBPF instruction encoding and opcode definitions.

use axerrno::LinuxError;

pub const BPF_REG_0: u8 = 0;
pub const BPF_REG_1: u8 = 1;
pub const BPF_REG_2: u8 = 2;
pub const BPF_REG_3: u8 = 3;
pub const BPF_REG_4: u8 = 4;
pub const BPF_REG_5: u8 = 5;
pub const BPF_REG_6: u8 = 6;
pub const BPF_REG_7: u8 = 7;
pub const BPF_REG_8: u8 = 8;
pub const BPF_REG_9: u8 = 9;
pub const BPF_REG_10: u8 = 10;

// Instruction classes (bits 0..2)
pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_JMP32: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07;

// Size modifiers (bits 3..4)
pub const BPF_W: u8 = 0x00; // 32-bit word
pub const BPF_H: u8 = 0x08; // 16-bit half word
pub const BPF_B: u8 = 0x10; // 8-bit byte
pub const BPF_DW: u8 = 0x18; // 64-bit double word

// Mode modifiers (bits 5..7)
pub const BPF_IMM: u8 = 0x00;
pub const BPF_ABS: u8 = 0x20;
pub const BPF_IND: u8 = 0x40;
pub const BPF_MEM: u8 = 0x60;
pub const BPF_LEN: u8 = 0x80;
pub const BPF_MSH: u8 = 0xa0;
pub const BPF_ATOMIC: u8 = 0xc0;

// ALU operations (bits 4..7)
pub const BPF_ADD: u8 = 0x00;
pub const BPF_SUB: u8 = 0x10;
pub const BPF_MUL: u8 = 0x20;
pub const BPF_DIV: u8 = 0x30;
pub const BPF_OR: u8 = 0x40;
pub const BPF_AND: u8 = 0x50;
pub const BPF_LSH: u8 = 0x60;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_NEG: u8 = 0x80;
pub const BPF_MOD: u8 = 0x90;
pub const BPF_XOR: u8 = 0xa0;
pub const BPF_MOV: u8 = 0xb0;
pub const BPF_ARSH: u8 = 0xc0;
pub const BPF_END: u8 = 0xd0;

// Source operand flag (bit 3)
pub const BPF_K: u8 = 0x00; // immediate
pub const BPF_X: u8 = 0x08; // src register

// JMP operations (bits 4..7)
pub const BPF_JA: u8 = 0x00;
pub const BPF_JEQ: u8 = 0x10;
pub const BPF_JGT: u8 = 0x20;
pub const BPF_JGE: u8 = 0x30;
pub const BPF_JSET: u8 = 0x40;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_JSGT: u8 = 0x60;
pub const BPF_JSGE: u8 = 0x70;
pub const BPF_CALL: u8 = 0x80;
pub const BPF_EXIT: u8 = 0x90;
pub const BPF_JLT: u8 = 0xa0;
pub const BPF_JLE: u8 = 0xb0;
pub const BPF_JSLT: u8 = 0xc0;
pub const BPF_JSLE: u8 = 0xd0;

// Special pseudo src registers for LD_IMM64
pub const BPF_PSEUDO_MAP_FD: u8 = 1;
pub const BPF_PSEUDO_MAP_VALUE: u8 = 2;

// Standard Helper IDs
pub const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;
pub const BPF_FUNC_MAP_UPDATE_ELEM: i32 = 2;
pub const BPF_FUNC_MAP_DELETE_ELEM: i32 = 3;
pub const BPF_FUNC_KTIME_GET_NS: i32 = 5;
pub const BPF_FUNC_GET_SMP_PROCESSOR_ID: i32 = 8;
pub const BPF_FUNC_PERF_EVENT_OUTPUT: i32 = 25;
pub const BPF_FUNC_RINGBUF_OUTPUT: i32 = 130;
pub const BPF_FUNC_RINGBUF_RESERVE: i32 = 131;
pub const BPF_FUNC_RINGBUF_SUBMIT: i32 = 132;
pub const BPF_FUNC_RINGBUF_DISCARD: i32 = 133;
pub const BPF_FUNC_RINGBUF_QUERY: i32 = 134;

pub const BPF_RB_NO_WAKEUP: u64 = 1 << 0;
pub const BPF_RB_FORCE_WAKEUP: u64 = 1 << 1;

pub const BPF_F_INDEX_MASK: u64 = 0xffff_ffff;
pub const BPF_F_CURRENT_CPU: u64 = BPF_F_INDEX_MASK;

/// 8-byte eBPF instruction matching `struct bpf_insn`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct BpfInsn {
    pub code: u8,
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

impl BpfInsn {
    pub const fn new(code: u8, dst_reg: u8, src_reg: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: (src_reg << 4) | (dst_reg & 0x0f),
            off,
            imm,
        }
    }

    #[inline(always)]
    pub const fn dst_reg(&self) -> u8 {
        self.regs & 0x0f
    }

    #[inline(always)]
    pub const fn src_reg(&self) -> u8 {
        (self.regs >> 4) & 0x0f
    }

    #[inline(always)]
    pub const fn class(&self) -> u8 {
        self.code & 0x07
    }

    #[inline(always)]
    pub const fn size(&self) -> u8 {
        self.code & 0x18
    }

    #[inline(always)]
    pub const fn mode(&self) -> u8 {
        self.code & 0xe0
    }

    #[inline(always)]
    pub const fn op(&self) -> u8 {
        self.code & 0xf0
    }

    #[inline(always)]
    pub const fn is_src_reg(&self) -> bool {
        (self.code & 0x08) == BPF_X
    }

    #[inline(always)]
    pub const fn is_src_imm(&self) -> bool {
        (self.code & 0x08) == BPF_K
    }

    #[inline(always)]
    pub const fn is_ld_imm64(&self) -> bool {
        self.code == (BPF_LD | BPF_IMM | BPF_DW)
    }

    #[inline(always)]
    pub const fn is_exit(&self) -> bool {
        self.code == (BPF_JMP | BPF_EXIT)
    }

    #[inline(always)]
    pub const fn is_call(&self) -> bool {
        self.code == (BPF_JMP | BPF_CALL)
    }

    #[inline(always)]
    pub const fn is_ja(&self) -> bool {
        self.code == (BPF_JMP | BPF_JA)
    }

    #[inline(always)]
    pub const fn is_jmp(&self) -> bool {
        self.class() == BPF_JMP
    }

    #[inline(always)]
    pub const fn is_jmp32(&self) -> bool {
        self.class() == BPF_JMP32
    }

    pub fn mem_size_bytes(&self) -> Result<usize, LinuxError> {
        match self.size() {
            BPF_B => Ok(1),
            BPF_H => Ok(2),
            BPF_W => Ok(4),
            BPF_DW => Ok(8),
            _ => Err(LinuxError::EINVAL),
        }
    }
}
