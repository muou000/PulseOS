use loongArch64::register::{
    badv,
    estat::{self, Exception, Trap},
};

use super::context::TrapFrame;
use crate::trap::PageFaultFlags;

core::arch::global_asm!(
    include_asm_macros!(),
    include_str!("trap.S"),
    trapframe_size = const (core::mem::size_of::<TrapFrame>()),
);

fn handle_breakpoint(era: &mut usize) {
    debug!("Exception(Breakpoint) @ {era:#x} ");
    *era += 4;
}

fn handle_page_fault(tf: &TrapFrame, mut access_flags: PageFaultFlags, is_user: bool) {
    if is_user {
        access_flags |= PageFaultFlags::USER;
    }
    let vaddr = va!(badv::read().raw());
    if !handle_trap!(PAGE_FAULT, vaddr, access_flags, is_user) {
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
            } else { false };
            if !handled {
                panic!("Instruction fault in kernel at {:#x}:\n{:#x?}", tf.era, tf);
            }
        }
        Trap::Exception(Exception::FetchInstructionAddressError)
        | Trap::Exception(Exception::MemoryAccessAddressError)
        | Trap::Exception(Exception::AddressNotAligned) => {
            let handled = if from_user {
                handle_trap!(ADDRESS_ERROR, tf, tf.era, from_user)
            } else { false };
            if !handled {
                panic!("Address error in kernel at {:#x}:\n{:#x?}", tf.era, tf);
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
            handle_page_fault(tf, PageFaultFlags::USER, from_user);
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
