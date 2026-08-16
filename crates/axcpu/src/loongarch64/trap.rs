#[cfg(feature = "ls2k1000")]
use loongArch64::register::badi;
use loongArch64::register::{
    badv,
    estat::{self, Exception, Trap},
};

use super::context::TrapFrame;
use crate::trap::{AddressError, PageFaultFlags};

core::arch::global_asm!(
    include_asm_macros!(),
    include_str!("trap.S"),
    trapframe_size = const (core::mem::size_of::<TrapFrame>()),
    ls2k1000 = const if cfg!(feature = "ls2k1000") { 1 } else { 0 },
);

fn handle_breakpoint(era: &mut usize) {
    debug!("Exception(Breakpoint) @ {era:#x} ");
    *era += 4;
}

fn handle_page_fault_at(
    tf: &mut TrapFrame,
    mut access_flags: PageFaultFlags,
    is_user: bool,
    vaddr: memory_addr::VirtAddr,
) {
    if is_user {
        access_flags |= PageFaultFlags::USER;
    }
    if !handle_trap!(PAGE_FAULT, tf, vaddr, access_flags, is_user) {
        panic!(
            "Unhandled {} Page Fault @ {:#x}, fault_vaddr={:#x} ({:?}):\n{:#x?}",
            if is_user { "PLV3" } else { "PLV0" },
            tf.era,
            vaddr,
            access_flags,
            tf,
        );
    }
}

fn handle_page_fault(tf: &mut TrapFrame, access_flags: PageFaultFlags, is_user: bool) {
    handle_page_fault_at(tf, access_flags, is_user, va!(badv::read().raw()));
}

/// LS2K1000 may report an instruction-fetch PPI with BADV left at zero. Only
/// the LS2K1000 build enables this hardware workaround.
#[cfg(feature = "ls2k1000")]
#[inline]
fn ppi_is_instruction_fetch(badi: u32) -> bool {
    matches!(badi >> 22, 0x0a | 0x0b) // addi.w / addi.d
}

#[cfg(feature = "ls2k1000")]
#[inline]
fn handle_user_page_privilege_illegal(tf: &mut TrapFrame) {
    let badv_addr = va!(badv::read().raw());
    let bad_instruction = badi::read().inst();
    if badv_addr.as_usize() == 0 && ppi_is_instruction_fetch(bad_instruction) {
        let fetch_addr = memory_addr::VirtAddr::from(tf.era);
        crate::asm::flush_tlb(Some(fetch_addr));
        handle_page_fault_at(tf, PageFaultFlags::EXECUTE, true, fetch_addr);
    } else {
        crate::asm::flush_tlb(Some(badv_addr));
        handle_page_fault_at(tf, PageFaultFlags::USER, true, badv_addr);
    }
}

#[cfg(not(feature = "ls2k1000"))]
#[inline]
fn handle_user_page_privilege_illegal(tf: &mut TrapFrame) {
    let badv_addr = va!(badv::read().raw());
    crate::asm::flush_tlb(Some(badv_addr));
    handle_page_fault_at(tf, PageFaultFlags::USER, true, badv_addr);
}

#[unsafe(no_mangle)]
fn loongarch64_trap_handler(tf: &mut TrapFrame, from_user: bool) {
    let estat = estat::read();

    match estat.cause() {
        #[cfg(feature = "uspace")]
        Trap::Exception(Exception::Syscall) => {
            tf.era += 4;
            tf.regs.a0 = crate::trap::handle_syscall(tf, tf.regs.a7) as usize;
        }
        Trap::Exception(Exception::LoadPageFault)
        | Trap::Exception(Exception::PageNonReadableFault) => {
            handle_page_fault(tf, PageFaultFlags::READ, from_user)
        }
        Trap::Exception(Exception::InstructionNotExist)
        | Trap::Exception(Exception::InstructionPrivilegeIllegal) => {
            let handled = if from_user {
                handle_trap!(ILLEGAL_INSTRUCTION, tf, tf.era, from_user)
            } else {
                false
            };
            if !handled {
                panic!("Instruction fault in kernel at {:#x}:\n{:#x?}", tf.era, tf);
            }
        }
        Trap::Exception(Exception::FetchInstructionAddressError)
        | Trap::Exception(Exception::MemoryAccessAddressError) => {
            let handled = if from_user {
                handle_trap!(
                    ADDRESS_ERROR,
                    tf,
                    badv::read().raw(),
                    AddressError::BadAddress,
                    from_user
                )
            } else {
                false
            };
            if !handled {
                panic!(
                    "Bad address error in kernel at era={:#x}, badv={:#x}:\n{:#x?}",
                    tf.era,
                    badv::read().raw(),
                    tf
                );
            }
        }
        Trap::Exception(Exception::AddressNotAligned) => {
            let fault_address = badv::read().raw();
            let handled = if from_user {
                handle_trap!(
                    ADDRESS_ERROR,
                    tf,
                    fault_address,
                    AddressError::Misaligned,
                    from_user
                )
            } else {
                #[cfg(feature = "ls2k1000")]
                {
                    unsafe { tf.emulate_unaligned_at(fault_address as u64) }.is_ok()
                }
                #[cfg(not(feature = "ls2k1000"))]
                {
                    false
                }
            };
            if !handled {
                panic!(
                    "Misaligned address error in kernel at era={:#x}, badv={:#x}:\n{:#x?}",
                    tf.era,
                    badv::read().raw(),
                    tf
                );
            }
        }
        Trap::Exception(Exception::StorePageFault)
        | Trap::Exception(Exception::PageModifyFault) => {
            handle_page_fault(tf, PageFaultFlags::WRITE, from_user)
        }
        Trap::Exception(Exception::FetchPageFault)
        | Trap::Exception(Exception::PageNonExecutableFault) => {
            handle_page_fault(tf, PageFaultFlags::EXECUTE, from_user);
        }
        Trap::Exception(Exception::PagePrivilegeIllegal) if from_user => {
            handle_user_page_privilege_illegal(tf);
        }
        Trap::Exception(Exception::Breakpoint) => handle_breakpoint(&mut tf.era),
        Trap::Interrupt(_) => {
            let irq_num: usize = estat.is().trailing_zeros() as usize;
            handle_trap!(IRQ, irq_num);
        }
        _ => {
            let handled = if from_user {
                handle_trap!(ILLEGAL_INSTRUCTION, tf, tf.era, from_user)
            } else {
                false
            };
            if !handled {
                panic!(
                    "Unhandled trap {:?} (raw ESTAT: {:#x}) @ {:#x}:\n{:#x?}",
                    estat.cause(),
                    estat.raw(),
                    tf.era,
                    tf
                );
            }
        }
    }

    #[cfg(feature = "uspace")]
    if from_user {
        crate::trap::handle_user_return(tf);
    }
}
