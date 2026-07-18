use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use axplat::{
    irq::{HandlerTable, IpiError, IpiTarget, IrqHandler, IrqIf},
    mem::pa,
};
use loongArch64::{
    iocsr::{iocsr_read_w, iocsr_write_w},
    register::{
        ecfg::{self, LineBasedInterrupt},
        ticlr,
    },
};

mod eiointc;
mod irq_common;
mod pch_pic;

use irq_common::{
    EIOINTC_CPU_IRQ, IPI_IRQ, RAW_IPI_IRQ, RAW_TIMER_IRQ, TIMER_IRQ, is_external_irq,
};

/// The maximum number of IRQs.
pub const MAX_IRQ_COUNT: usize = 256;
const IOCSR_IPI_STATUS: usize = 0x1000;
const IOCSR_IPI_ENABLE: usize = 0x1004;
const IOCSR_IPI_CLEAR: usize = 0x100c;
const IOCSR_IPI_SEND: usize = 0x1040;
const IOCSR_IPI_SEND_CPU_SHIFT: u32 = 16;
const IOCSR_IPI_SEND_BLOCKING: u32 = 1 << 31;
const IPI_VECTOR: u32 = 0;

static IRQ_HANDLER_TABLE: HandlerTable<MAX_IRQ_COUNT> = HandlerTable::new();
static TIMER_HANDLER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static IPI_HANDLER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static ONLINE_CPUS: AtomicUsize = AtomicUsize::new(0);

const _: () = assert!(crate::config::devices::TIMER_IRQ == TIMER_IRQ);
const _: () = assert!(crate::config::devices::IPI_IRQ == IPI_IRQ);

struct IrqIfImpl;

#[impl_plat_interface]
impl IrqIf for IrqIfImpl {
    /// Enables or disables the given IRQ.
    fn set_enable(irq_num: usize, enabled: bool) {
        if irq_num == IPI_IRQ {
            iocsr_write_w(IOCSR_IPI_ENABLE, if enabled { u32::MAX } else { 0 });
            set_local_line(LineBasedInterrupt::IPI, enabled);
        } else if irq_num == TIMER_IRQ {
            set_local_line(LineBasedInterrupt::TIMER, enabled);
        } else if is_external_irq(irq_num) && irq_num < 64 {
            // PCH-PIC pins: unmask in PCH-PIC and keep EIOINTC enabled
            if let Some(pic) = pch_pic::PCH_PIC.get() {
                pic.set_enable(irq_num, enabled);
            }
            eiointc::set_enable(irq_num, enabled);
        } else if is_external_irq(irq_num) {
            // PCH-MSI pins (64..255): directly connected to EIOINTC, bypasses PCH-PIC entirely
            eiointc::set_enable(irq_num, enabled);
        } else {
            warn!("invalid IRQ {}", irq_num);
        }
    }

    /// Registers an IRQ handler for the given IRQ.
    fn register(irq_num: usize, handler: IrqHandler) -> bool {
        let registered = if irq_num == TIMER_IRQ {
            register_local_handler(&TIMER_HANDLER, handler)
        } else if irq_num == IPI_IRQ {
            register_local_handler(&IPI_HANDLER, handler)
        } else if is_external_irq(irq_num) {
            IRQ_HANDLER_TABLE.register_handler(irq_num, handler)
        } else {
            false
        };
        if registered {
            Self::set_enable(irq_num, true);
            return true;
        }
        warn!("register handler for IRQ {} failed", irq_num);
        false
    }

    /// Unregisters the IRQ handler for the given IRQ.
    fn unregister(irq: usize) -> Option<IrqHandler> {
        let handler = if irq == TIMER_IRQ {
            unregister_local_handler(&TIMER_HANDLER)
        } else if irq == IPI_IRQ {
            unregister_local_handler(&IPI_HANDLER)
        } else if is_external_irq(irq) {
            IRQ_HANDLER_TABLE.unregister_handler(irq)
        } else {
            None
        };
        if handler.is_some() {
            Self::set_enable(irq, false);
        }
        handler
    }

    /// Handles the IRQ.
    fn handle(irq: usize, _cpu_id: usize) {
        if irq == RAW_IPI_IRQ {
            let mut status = iocsr_read_w(IOCSR_IPI_STATUS);
            if status == 0 {
                debug!("Spurious IPI");
                return;
            }
            iocsr_write_w(IOCSR_IPI_CLEAR, status);
            while status != 0 {
                status &= status - 1;
                if !handle_local_irq(&IPI_HANDLER, IPI_IRQ) {
                    warn!("Unhandled IPI IRQ");
                }
            }
        } else if irq == RAW_TIMER_IRQ {
            ticlr::clear_timer_interrupt();
            if !handle_local_irq(&TIMER_HANDLER, TIMER_IRQ) {
                warn!("Unhandled Timer IRQ");
            }
        } else if irq == EIOINTC_CPU_IRQ {
            if let Some(irq_num) = eiointc::claim_irq() {
                trace!("EIOINTC IRQ {}", irq_num);
                if !IRQ_HANDLER_TABLE.handle(irq_num) {
                    warn!("Unhandled EIOINTC IRQ {}", irq_num);
                }
                eiointc::complete_irq(irq_num);
            } else {
                debug!("Spurious EIOINTC interrupt");
            }
        } else {
            warn!("Unhandled CPU-local IRQ {}", irq);
        }
    }

    fn cpu_online(cpu_id: usize) {
        if cpu_id < usize::BITS as usize {
            iocsr_write_w(IOCSR_IPI_ENABLE, u32::MAX);
            set_local_line(LineBasedInterrupt::IPI, true);
            ONLINE_CPUS.fetch_or(1usize << cpu_id, Ordering::Release);
        }
    }

    /// Sends an inter-processor interrupt (IPI) to the specified target CPU or all CPUs.
    fn send_ipi(_irq_num: usize, target: IpiTarget) -> Result<(), IpiError> {
        match target {
            IpiTarget::Current { cpu_id } | IpiTarget::Other { cpu_id } => {
                send_ipi_to_cpu(cpu_id)?;
            }
            IpiTarget::AllExceptCurrent { cpu_id, cpu_num } => {
                for target_cpu in 0..cpu_num {
                    if target_cpu != cpu_id {
                        send_ipi_to_cpu(target_cpu)?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn register_local_handler(slot: &AtomicPtr<()>, handler: IrqHandler) -> bool {
    slot.compare_exchange(
        core::ptr::null_mut(),
        handler as *mut (),
        Ordering::AcqRel,
        Ordering::Acquire,
    )
    .is_ok()
}

fn unregister_local_handler(slot: &AtomicPtr<()>) -> Option<IrqHandler> {
    let handler = slot.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if handler.is_null() {
        None
    } else {
        // SAFETY: Only pointers converted from IrqHandler are stored in this slot.
        Some(unsafe { core::mem::transmute::<*mut (), IrqHandler>(handler) })
    }
}

fn handle_local_irq(slot: &AtomicPtr<()>, irq: usize) -> bool {
    let handler = slot.load(Ordering::Acquire);
    if handler.is_null() {
        false
    } else {
        // SAFETY: Only pointers converted from IrqHandler are stored in this slot.
        unsafe { core::mem::transmute::<*mut (), IrqHandler>(handler)(irq) };
        true
    }
}

fn set_local_line(line: LineBasedInterrupt, enabled: bool) {
    let old_value = ecfg::read().lie();
    ecfg::set_lie(if enabled {
        old_value | line
    } else {
        old_value & !line
    });
}

fn send_ipi_to_cpu(cpu_id: usize) -> Result<(), IpiError> {
    if cpu_id >= crate::config::plat::MAX_CPU_NUM || cpu_id >= usize::BITS as usize {
        return Err(IpiError::InvalidTarget);
    }
    if ONLINE_CPUS.load(Ordering::Acquire) & (1usize << cpu_id) == 0 {
        return Err(IpiError::CpuOffline);
    }
    let cpu_id = u32::try_from(cpu_id).map_err(|_| IpiError::InvalidTarget)?;
    let value = cpu_id << IOCSR_IPI_SEND_CPU_SHIFT | IOCSR_IPI_SEND_BLOCKING | IPI_VECTOR;
    iocsr_write_w(IOCSR_IPI_SEND, value);
    Ok(())
}

pub(crate) fn init_early() {
    eiointc::init();
    pch_pic::init(pa!(crate::config::devices::PCH_PIC_PADDR));
    // QEMU routes the EIOINTC cascade through CPU HWI1 (IRQ 3).
    let old_value = ecfg::read().lie();
    ecfg::set_lie(old_value | LineBasedInterrupt::HWI1);
}
