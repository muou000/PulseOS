// Based on the LoongArch unaligned emulator used by tgoskits/StarryOS.

use core::{arch::asm, fmt};

use loongArch64::register::badv;

use crate::{GeneralRegisters, TrapFrame};

core::arch::global_asm!(include_asm_macros!(), include_str!("unaligned.S"));

unsafe extern "C" {
    fn _unaligned_read(
        address: u64,
        value: &mut u64,
        size: u64,
        signed: bool,
        fault_address: &mut u64,
    ) -> i32;
    fn _unaligned_write(address: u64, value: u64, size: u64, fault_address: &mut u64) -> i32;
}

/// The memory operation performed by an emulated unaligned instruction.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnalignedAccessType {
    /// A load from memory.
    Read,
    /// A store to memory.
    Write,
}

/// A decoded LoongArch unaligned memory operation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UnalignedAccess {
    address: u64,
    size: u8,
    access_type: UnalignedAccessType,
    register: usize,
    register_file: RegisterFile,
    signed: bool,
}

impl UnalignedAccess {
    /// Returns the first byte address of the operation.
    pub const fn address(&self) -> u64 {
        self.address
    }

    /// Returns the number of bytes accessed by the operation.
    pub const fn size(&self) -> usize {
        self.size as usize
    }

    /// Returns whether the operation reads or writes memory.
    pub const fn access_type(&self) -> UnalignedAccessType {
        self.access_type
    }

    const fn page_fault(&self, fault_address: u64) -> UnalignedError {
        UnalignedError::PageFault(UnalignedPageFault {
            fault_address,
            access_address: self.address,
            size: self.size,
            access_type: self.access_type,
        })
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum RegisterFile {
    General,
    FloatingPoint,
}

/// A page fault encountered during an emulated byte access.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UnalignedPageFault {
    fault_address: u64,
    access_address: u64,
    size: u8,
    access_type: UnalignedAccessType,
}

impl UnalignedPageFault {
    /// Returns the exact byte address that faulted.
    pub const fn fault_address(&self) -> u64 {
        self.fault_address
    }

    /// Returns the first byte address of the emulated operation.
    pub const fn access_address(&self) -> u64 {
        self.access_address
    }

    /// Returns the total size of the emulated operation.
    pub const fn size(&self) -> usize {
        self.size as usize
    }

    /// Returns whether the failed operation was a read or write.
    pub const fn access_type(&self) -> UnalignedAccessType {
        self.access_type
    }
}

/// Error returned while decoding or emulating an unaligned instruction.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnalignedError {
    /// A byte access faulted and must be classified by the owning address space.
    PageFault(UnalignedPageFault),
    /// The faulting instruction is not supported by this emulator.
    UnsupportedInstruction {
        /// The unaligned address reported by the CPU.
        address: u64,
        /// The instruction word that could not be decoded.
        instruction: u32,
    },
}

impl fmt::Display for UnalignedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PageFault(fault) => write!(
                f,
                "unaligned {:?} page fault at {:#x} while accessing {:#x} (n={})",
                fault.access_type, fault.fault_address, fault.access_address, fault.size,
            ),
            Self::UnsupportedInstruction {
                address,
                instruction,
            } => write!(
                f,
                "unsupported unaligned instruction {instruction:#010x} at {address:#x}"
            ),
        }
    }
}

impl core::error::Error for UnalignedError {}

fn unaligned_read(
    access: &UnalignedAccess,
    value: &mut u64,
    signed: bool,
) -> Result<(), UnalignedError> {
    let mut fault_address = access.address;
    if unsafe {
        _unaligned_read(
            access.address,
            value,
            access.size.into(),
            signed,
            &mut fault_address,
        )
    } == -1
    {
        return Err(access.page_fault(fault_address));
    }
    Ok(())
}

fn unaligned_write(access: &UnalignedAccess, value: u64) -> Result<(), UnalignedError> {
    let mut fault_address = access.address;
    if unsafe {
        _unaligned_write(
            access.address,
            value,
            access.size.into(),
            &mut fault_address,
        )
    } == -1
    {
        return Err(access.page_fault(fault_address));
    }
    Ok(())
}

macro_rules! define_fpr_accessors {
    ($(($index:literal, $write:ident, $read:ident)),+ $(,)?) => {
        $(
            #[inline]
            fn $write(value: u64) {
                unsafe {
                    asm!(
                        concat!("movgr2fr.d $f", stringify!($index), ", {value}"),
                        value = in(reg) value,
                    )
                }
            }

            #[inline]
            fn $read() -> u64 {
                let value: u64;
                unsafe {
                    asm!(
                        concat!("movfr2gr.d {value}, $f", stringify!($index)),
                        value = out(reg) value,
                    )
                }
                value
            }
        )+

        fn write_fpr(index: usize, value: u64) {
            match index {
                $($index => $write(value),)+
                _ => unreachable!("LoongArch floating-point register index is five bits"),
            }
        }

        fn read_fpr(index: usize) -> u64 {
            match index {
                $($index => $read(),)+
                _ => unreachable!("LoongArch floating-point register index is five bits"),
            }
        }
    };
}

define_fpr_accessors!(
    (0, write_fpr_0, read_fpr_0),
    (1, write_fpr_1, read_fpr_1),
    (2, write_fpr_2, read_fpr_2),
    (3, write_fpr_3, read_fpr_3),
    (4, write_fpr_4, read_fpr_4),
    (5, write_fpr_5, read_fpr_5),
    (6, write_fpr_6, read_fpr_6),
    (7, write_fpr_7, read_fpr_7),
    (8, write_fpr_8, read_fpr_8),
    (9, write_fpr_9, read_fpr_9),
    (10, write_fpr_10, read_fpr_10),
    (11, write_fpr_11, read_fpr_11),
    (12, write_fpr_12, read_fpr_12),
    (13, write_fpr_13, read_fpr_13),
    (14, write_fpr_14, read_fpr_14),
    (15, write_fpr_15, read_fpr_15),
    (16, write_fpr_16, read_fpr_16),
    (17, write_fpr_17, read_fpr_17),
    (18, write_fpr_18, read_fpr_18),
    (19, write_fpr_19, read_fpr_19),
    (20, write_fpr_20, read_fpr_20),
    (21, write_fpr_21, read_fpr_21),
    (22, write_fpr_22, read_fpr_22),
    (23, write_fpr_23, read_fpr_23),
    (24, write_fpr_24, read_fpr_24),
    (25, write_fpr_25, read_fpr_25),
    (26, write_fpr_26, read_fpr_26),
    (27, write_fpr_27, read_fpr_27),
    (28, write_fpr_28, read_fpr_28),
    (29, write_fpr_29, read_fpr_29),
    (30, write_fpr_30, read_fpr_30),
    (31, write_fpr_31, read_fpr_31),
);

const LDH_OP: u32 = 0xa1;
const LDHU_OP: u32 = 0xa9;
const LDW_OP: u32 = 0xa2;
const LDWU_OP: u32 = 0xaa;
const LDD_OP: u32 = 0xa3;
const STH_OP: u32 = 0xa5;
const STW_OP: u32 = 0xa6;
const STD_OP: u32 = 0xa7;

const LDPTRW_OP: u32 = 0x24;
const LDPTRD_OP: u32 = 0x26;
const STPTRW_OP: u32 = 0x25;
const STPTRD_OP: u32 = 0x27;

const LDXH_OP: u32 = 0x7048;
const LDXHU_OP: u32 = 0x7008;
const LDXW_OP: u32 = 0x7010;
const LDXWU_OP: u32 = 0x7050;
const LDXD_OP: u32 = 0x7018;
const STXH_OP: u32 = 0x7028;
const STXW_OP: u32 = 0x7030;
const STXD_OP: u32 = 0x7038;

const FLDS_OP: u32 = 0xac;
const FLDD_OP: u32 = 0xae;
const FSTS_OP: u32 = 0xad;
const FSTD_OP: u32 = 0xaf;

const FSTXS_OP: u32 = 0x7070;
const FSTXD_OP: u32 = 0x7078;
const FLDXS_OP: u32 = 0x7060;
const FLDXD_OP: u32 = 0x7068;

fn decode_unaligned_access(
    instruction: u32,
    address: u64,
) -> Result<UnalignedAccess, UnalignedError> {
    let register = (instruction & 0x1f) as usize;
    let op22 = instruction >> 22;
    let op24 = instruction >> 24;
    let op15 = instruction >> 15;

    let (access_type, size, register_file, signed) =
        if op22 == LDD_OP || op24 == LDPTRD_OP || op15 == LDXD_OP {
            (UnalignedAccessType::Read, 8, RegisterFile::General, true)
        } else if op22 == LDW_OP || op24 == LDPTRW_OP || op15 == LDXW_OP {
            (UnalignedAccessType::Read, 4, RegisterFile::General, true)
        } else if op22 == LDWU_OP || op15 == LDXWU_OP {
            (UnalignedAccessType::Read, 4, RegisterFile::General, false)
        } else if op22 == LDH_OP || op15 == LDXH_OP {
            (UnalignedAccessType::Read, 2, RegisterFile::General, true)
        } else if op22 == LDHU_OP || op15 == LDXHU_OP {
            (UnalignedAccessType::Read, 2, RegisterFile::General, false)
        } else if op22 == STD_OP || op24 == STPTRD_OP || op15 == STXD_OP {
            (UnalignedAccessType::Write, 8, RegisterFile::General, false)
        } else if op22 == STW_OP || op24 == STPTRW_OP || op15 == STXW_OP {
            (UnalignedAccessType::Write, 4, RegisterFile::General, false)
        } else if op22 == STH_OP || op15 == STXH_OP {
            (UnalignedAccessType::Write, 2, RegisterFile::General, false)
        } else if op22 == FLDD_OP || op15 == FLDXD_OP {
            (
                UnalignedAccessType::Read,
                8,
                RegisterFile::FloatingPoint,
                true,
            )
        } else if op22 == FLDS_OP || op15 == FLDXS_OP {
            (
                UnalignedAccessType::Read,
                4,
                RegisterFile::FloatingPoint,
                true,
            )
        } else if op22 == FSTD_OP || op15 == FSTXD_OP {
            (
                UnalignedAccessType::Write,
                8,
                RegisterFile::FloatingPoint,
                false,
            )
        } else if op22 == FSTS_OP || op15 == FSTXS_OP {
            (
                UnalignedAccessType::Write,
                4,
                RegisterFile::FloatingPoint,
                false,
            )
        } else {
            return Err(UnalignedError::UnsupportedInstruction {
                address,
                instruction,
            });
        };

    Ok(UnalignedAccess {
        address,
        size,
        access_type,
        register,
        register_file,
        signed,
    })
}

impl TrapFrame {
    /// Emulates the unaligned operation described by the current trap CSRs.
    ///
    /// # Safety
    ///
    /// This must only be called for a valid LoongArch address-alignment trap.
    pub unsafe fn emulate_unaligned(&mut self) -> Result<(), UnalignedError> {
        unsafe { self.emulate_unaligned_at(badv::read().vaddr() as u64) }
    }

    /// Decodes the faulting memory instruction without performing the access.
    ///
    /// # Safety
    ///
    /// The saved instruction pointer must identify a readable instruction.
    pub unsafe fn decode_unaligned_access_at(
        &self,
        fault_address: u64,
    ) -> Result<UnalignedAccess, UnalignedError> {
        let instruction = unsafe { core::ptr::read(self.era as *const u32) };
        decode_unaligned_access(instruction, fault_address)
    }

    /// Emulates an unaligned operation using a captured fault address.
    ///
    /// # Safety
    ///
    /// This must only be called for the trap represented by this frame.
    pub unsafe fn emulate_unaligned_at(
        &mut self,
        fault_address: u64,
    ) -> Result<(), UnalignedError> {
        let access = unsafe { self.decode_unaligned_access_at(fault_address)? };
        unsafe { self.emulate_unaligned_access(access) }
    }

    /// Executes a previously decoded unaligned operation.
    ///
    /// The destination register and `ERA` are committed only after all byte
    /// accesses succeed. Before a store, callers must validate and stabilize
    /// the entire destination range to avoid a partial write.
    ///
    /// # Safety
    ///
    /// `access` must have been decoded from this frame at the current `ERA`.
    pub unsafe fn emulate_unaligned_access(
        &mut self,
        access: UnalignedAccess,
    ) -> Result<(), UnalignedError> {
        let mut value = 0_u64;
        let regs = unsafe {
            core::mem::transmute::<&mut GeneralRegisters, &mut [usize; 32]>(&mut self.regs)
        };

        match access.access_type {
            UnalignedAccessType::Read => {
                unaligned_read(&access, &mut value, access.signed)?;
                match access.register_file {
                    RegisterFile::General => regs[access.register] = value as usize,
                    RegisterFile::FloatingPoint => write_fpr(access.register, value),
                }
            }
            UnalignedAccessType::Write => {
                value = match access.register_file {
                    RegisterFile::General => regs[access.register] as u64,
                    RegisterFile::FloatingPoint => read_fpr(access.register),
                };
                unaligned_write(&access, value)?;
            }
        }

        self.era += 4;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_integer_load_store_forms() {
        let load = decode_unaligned_access((LDD_OP << 22) | 7, 0x1003).unwrap();
        assert_eq!(load.access_type(), UnalignedAccessType::Read);
        assert_eq!(load.size(), 8);
        assert_eq!(load.register, 7);

        let store = decode_unaligned_access((STXW_OP << 15) | 11, 0x1fff).unwrap();
        assert_eq!(store.access_type(), UnalignedAccessType::Write);
        assert_eq!(store.size(), 4);
        assert_eq!(store.register, 11);
    }

    #[test]
    fn rejects_non_memory_opcode() {
        assert!(matches!(
            decode_unaligned_access(0, 0x1001),
            Err(UnalignedError::UnsupportedInstruction { .. })
        ));
    }
}
