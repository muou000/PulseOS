//! Bounded frame-pointer capture and its fixed, read-only sample extension.
//!
//! Readers supply exactly one 16-byte frame record from the sampled address
//! space. This module never dereferences addresses, allocates, or acquires a
//! lock. Its output belongs to one interrupted privilege domain; it never
//! infers a user caller from a kernel frame or uses the sampler's live stack.

use crate::{PerfEventContext, PerfSampleContext};

pub const DEFAULT_STACK_DEPTH: u16 = 32;
pub const MAX_STACK_DEPTH: usize = 64;
pub const DEFAULT_STACK_BYTE_LIMIT: u32 = 512;
const FRAME_BYTES: u32 = 16;

/// Registers copied from the interrupted trap frame, before it can resume.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StackRegisters {
    pub ip: u64,
    pub sp: u64,
    pub fp: u64,
    pub ra: u64,
}

/// The sampled IP occupies one depth entry. Bytes bound frame-record reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackLimits {
    pub depth: u16,
    pub bytes: u32,
}

impl Default for StackLimits {
    fn default() -> Self {
        Self {
            depth: DEFAULT_STACK_DEPTH,
            bytes: DEFAULT_STACK_BYTE_LIMIT,
        }
    }
}

/// Mutually exclusive reason why capture stopped; wire values are stable.
///
/// `Complete` means a valid frame record ended in a zero previous FP. It does
/// not promise recovery of inlined, tail-called, or omitted-FP activations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum StackStatus {
    Complete             = 0,
    NoFramePointer       = 1,
    InvalidFrame         = 2,
    NonMonotonicFrame    = 3,
    ReadFault            = 4,
    InvalidReturnAddress = 5,
    DepthLimit           = 6,
    ByteLimit            = 7,
    AddressOverflow      = 8,
    InvalidInstructionPointer = 9,
    Unavailable          = 10,
    Busy                 = 11,
    UnsupportedAbi       = 12,
    InvalidLimit         = 13,
}

impl StackStatus {
    pub const fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            0 => Self::Complete,
            1 => Self::NoFramePointer,
            2 => Self::InvalidFrame,
            3 => Self::NonMonotonicFrame,
            4 => Self::ReadFault,
            5 => Self::InvalidReturnAddress,
            6 => Self::DepthLimit,
            7 => Self::ByteLimit,
            8 => Self::AddressOverflow,
            9 => Self::InvalidInstructionPointer,
            10 => Self::Unavailable,
            11 => Self::Busy,
            12 => Self::UnsupportedAbi,
            13 => Self::InvalidLimit,
            _ => return None,
        })
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete_at_terminator",
            Self::NoFramePointer => "no_frame_pointer",
            Self::InvalidFrame => "invalid_frame",
            Self::NonMonotonicFrame => "nonmonotonic_frame",
            Self::ReadFault => "read_fault",
            Self::InvalidReturnAddress => "invalid_return_address",
            Self::DepthLimit => "depth_limit",
            Self::ByteLimit => "byte_limit",
            Self::AddressOverflow => "address_overflow",
            Self::InvalidInstructionPointer => "invalid_instruction_pointer",
            Self::Unavailable => "unavailable",
            Self::Busy => "busy",
            Self::UnsupportedAbi => "unsupported_abi",
            Self::InvalidLimit => "invalid_limit",
        }
    }

    pub const fn classification(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::NoFramePointer
            | Self::InvalidInstructionPointer
            | Self::Unavailable
            | Self::Busy
            | Self::UnsupportedAbi
            | Self::InvalidLimit => "unavailable",
            _ => "partial",
        }
    }
}

/// Owned, fixed-capacity result, frozen before the interrupted task resumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrozenStack {
    pub registers: StackRegisters,
    /// Elapsed capture time in nanoseconds, not an absolute timestamp. The
    /// walker initializes this to zero; the IRQ caller measures and fills it.
    pub capture_ns: u64,
    pub depth_limit: u16,
    pub len: u16,
    pub status: StackStatus,
    /// Bytes in fully read frame records, including an invalid returned frame.
    /// A failed reader may have touched a partial frame; it is not counted as
    /// a successful read, and capture stops immediately without retrying it.
    pub bytes_read: u32,
    pub byte_limit: u32,
    pub ips: [u64; MAX_STACK_DEPTH],
}

impl FrozenStack {
    fn empty(registers: StackRegisters, limits: StackLimits, status: StackStatus) -> Self {
        Self {
            registers,
            capture_ns: 0,
            depth_limit: limits.depth,
            len: 0,
            status,
            bytes_read: 0,
            byte_limit: limits.bytes,
            ips: [0; MAX_STACK_DEPTH],
        }
    }

    /// Preserve a known sampled IP when no reader is available. The caller
    /// supplies trap registers; this does not validate executable mappings.
    pub fn unavailable(registers: StackRegisters, status: StackStatus) -> Self {
        let mut stack = Self::empty(registers, StackLimits::default(), status);
        if registers.ip != 0 {
            stack.ips[0] = registers.ip;
            stack.len = 1;
        }
        stack
    }
}

/// Walk the RV64/LA64 frame-record subset from frozen trap registers.
///
/// `read_frame` receives FP-16 and returns little-endian previous-FP/return-IP
/// bytes. Its owner must enforce the memory lifetime, privilege, no-fault, and
/// nonblocking contracts. `valid_ip` must validate executable addresses in the
/// sampled privilege domain (including architecture alignment). Saved RA is
/// preserved as metadata, never guessed into a missing frame. No fixed
/// instruction width is subtracted from either kind of instruction address.
///
/// This function performs at most 63 reads, and never reads after a failed
/// attempt. A zero previous FP terminates only after a valid saved return IP.
/// Invalid depth configurations perform no reads and return `InvalidLimit`.
pub fn walk_frame_pointers(
    registers: StackRegisters,
    limits: StackLimits,
    mut read_frame: impl FnMut(u64) -> Result<[u8; 16], StackStatus>,
    mut valid_ip: impl FnMut(u64) -> bool,
) -> FrozenStack {
    let mut stack = FrozenStack::empty(registers, limits, StackStatus::InvalidLimit);
    if limits.depth == 0 || usize::from(limits.depth) > MAX_STACK_DEPTH {
        return stack;
    }
    if registers.ip == 0 || !valid_ip(registers.ip) {
        stack.status = StackStatus::InvalidInstructionPointer;
        return stack;
    }
    stack.ips[0] = registers.ip;
    stack.len = 1;
    if registers.fp == 0 {
        stack.status = StackStatus::NoFramePointer;
        return stack;
    }
    let Some(minimum_fp) = registers.sp.checked_add(u64::from(FRAME_BYTES)) else {
        stack.status = StackStatus::AddressOverflow;
        return stack;
    };
    let mut fp = registers.fp;
    loop {
        if fp % u64::from(FRAME_BYTES) != 0 || fp < minimum_fp {
            stack.status = StackStatus::InvalidFrame;
            return stack;
        }
        if stack.len == limits.depth {
            stack.status = StackStatus::DepthLimit;
            return stack;
        }
        let Some(address) = fp.checked_sub(u64::from(FRAME_BYTES)) else {
            stack.status = StackStatus::AddressOverflow;
            return stack;
        };
        let Some(next_bytes) = stack.bytes_read.checked_add(FRAME_BYTES) else {
            stack.status = StackStatus::AddressOverflow;
            return stack;
        };
        if next_bytes > limits.bytes {
            stack.status = StackStatus::ByteLimit;
            return stack;
        }
        let bytes = match read_frame(address) {
            Ok(bytes) => bytes,
            Err(status) => {
                // Reader failure cannot manufacture a successful terminator
                // or a limit reason that the walker itself did not observe.
                stack.status = match status {
                    StackStatus::Busy
                    | StackStatus::Unavailable
                    | StackStatus::UnsupportedAbi
                    | StackStatus::InvalidFrame => status,
                    _ => StackStatus::ReadFault,
                };
                return stack;
            }
        };
        stack.bytes_read = next_bytes;
        let previous_fp = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let return_ip = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        if return_ip == 0 || !valid_ip(return_ip) {
            stack.status = StackStatus::InvalidReturnAddress;
            return stack;
        }
        stack.ips[usize::from(stack.len)] = return_ip;
        stack.len += 1;
        if previous_fp == 0 {
            stack.status = StackStatus::Complete;
            return stack;
        }
        if previous_fp <= fp {
            stack.status = StackStatus::NonMonotonicFrame;
            return stack;
        }
        fp = previous_fp;
    }
}

/// The original 64-byte v2 context followed by the required stack extension.
/// A BPF program may copy this read-only context into map scratch storage;
/// it does not need to fit the 640 bytes in the interpreter's 512-byte stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerfStackSampleContext {
    pub base: PerfSampleContext,
    pub source_id: u64,
    pub stack: FrozenStack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackDecodeError {
    Length,
    UnsupportedVersion,
    UnsupportedFlags,
    InvalidContext,
    InvalidStack,
}

impl PerfStackSampleContext {
    pub const SIZE: usize = 640;
    pub const EXTENSION_VERSION: u16 = 3;

    /// Encode scalars explicitly; no Rust layout, padding, or pointers escape.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0; Self::SIZE];
        bytes[..64].copy_from_slice(&self.base.to_bytes());
        bytes[64..72].copy_from_slice(&self.source_id.to_le_bytes());
        bytes[72..80].copy_from_slice(&self.stack.registers.sp.to_le_bytes());
        bytes[80..88].copy_from_slice(&self.stack.registers.fp.to_le_bytes());
        bytes[88..96].copy_from_slice(&self.stack.registers.ra.to_le_bytes());
        bytes[96..104].copy_from_slice(&self.stack.capture_ns.to_le_bytes());
        bytes[104..106].copy_from_slice(&Self::EXTENSION_VERSION.to_le_bytes());
        bytes[106..108].copy_from_slice(&self.stack.depth_limit.to_le_bytes());
        bytes[108..110].copy_from_slice(&self.stack.len.to_le_bytes());
        bytes[110..112].copy_from_slice(&(self.stack.status as u16).to_le_bytes());
        bytes[112..116].copy_from_slice(&self.stack.bytes_read.to_le_bytes());
        bytes[116..120].copy_from_slice(&self.stack.byte_limit.to_le_bytes());
        // flags@120 is zero: only the sampled privilege domain is present.
        for (index, ip) in self.stack.ips.iter().enumerate() {
            let offset = 128 + index * 8;
            bytes[offset..offset + 8].copy_from_slice(&ip.to_le_bytes());
        }
        bytes
    }

    /// Validate the fixed wire contract without looking up current mappings or
    /// task identities. Historical samples must not depend on current state.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StackDecodeError> {
        if bytes.len() != Self::SIZE {
            return Err(StackDecodeError::Length);
        }
        let u16_at = |offset| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
        let u32_at = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let u64_at = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        if u32_at(60) != 2 || u16_at(104) != Self::EXTENSION_VERSION {
            return Err(StackDecodeError::UnsupportedVersion);
        }
        if u64_at(120) != 0 {
            return Err(StackDecodeError::UnsupportedFlags);
        }
        let base = PerfSampleContext {
            base: PerfEventContext::new(
                u64_at(0),
                u64_at(8),
                u64_at(16),
                u32_at(24),
                u32_at(28),
                u32_at(32),
                u64_at(40),
            ),
            ip: u64_at(48),
            mode: u32_at(56),
            version: 2,
        };
        let source_id = u64_at(64);
        if base.base.sample_period == 0
            || base.base.timestamp_ns == 0
            || base.base.task_id == 0
            || base.ip == 0
            || source_id == 0
            || u32_at(36) != 0
            || !matches!(base.mode, 1 | 2)
            || (base.mode == 2 && (base.base.pid == 0 || base.base.tid == 0))
        {
            return Err(StackDecodeError::InvalidContext);
        }
        let status = StackStatus::from_u16(u16_at(110)).ok_or(StackDecodeError::InvalidStack)?;
        let mut stack = FrozenStack {
            registers: StackRegisters {
                ip: base.ip,
                sp: u64_at(72),
                fp: u64_at(80),
                ra: u64_at(88),
            },
            capture_ns: u64_at(96),
            depth_limit: u16_at(106),
            len: u16_at(108),
            status,
            bytes_read: u32_at(112),
            byte_limit: u32_at(116),
            ips: [0; MAX_STACK_DEPTH],
        };
        if stack.depth_limit == 0
            || usize::from(stack.depth_limit) > MAX_STACK_DEPTH
            || stack.len > stack.depth_limit
            || stack.bytes_read > stack.byte_limit
            || stack.bytes_read % FRAME_BYTES != 0
            || stack.bytes_read > (MAX_STACK_DEPTH as u32 - 1) * FRAME_BYTES
        {
            return Err(StackDecodeError::InvalidStack);
        }
        for (index, ip) in stack.ips.iter_mut().enumerate() {
            *ip = u64_at(128 + index * 8);
        }
        let len = usize::from(stack.len);
        if stack.ips[len..].iter().any(|&ip| ip != 0)
            || stack.ips[..len].iter().any(|&ip| ip == 0)
            || (len > 0 && stack.ips[0] != base.ip)
            || (len == 0
                && !matches!(
                    status,
                    StackStatus::InvalidInstructionPointer | StackStatus::InvalidLimit
                ))
            || (status == StackStatus::Complete && len < 2)
            || (status == StackStatus::NoFramePointer
                && (stack.registers.fp != 0 || len != 1 || stack.bytes_read != 0))
            || (status == StackStatus::DepthLimit && stack.len != stack.depth_limit)
            || stack.bytes_read
                != match (len, status) {
                    (0, _) => 0,
                    (_, StackStatus::InvalidReturnAddress) => len as u32 * FRAME_BYTES,
                    _ => (len as u32 - 1) * FRAME_BYTES,
                }
            || (status == StackStatus::ByteLimit
                && stack.bytes_read.saturating_add(FRAME_BYTES) <= stack.byte_limit)
        {
            return Err(StackDecodeError::InvalidStack);
        }
        Ok(Self {
            base,
            source_id,
            stack,
        })
    }
}
