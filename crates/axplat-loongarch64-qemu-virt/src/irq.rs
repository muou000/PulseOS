use axplat::irq::{HandlerTable, IpiTarget, IrqHandler, IrqIf};
use axplat::mem::pa;
use loongArch64::register::{
    ecfg::{self, LineBasedInterrupt},
    ticlr,
};

mod pch_pic;
mod eiointc;

/// The maximum number of IRQs.
pub const MAX_IRQ_COUNT: usize = 256;

/// The base IRQ number for PCH-PIC interrupts.
pub const PCH_PIC_IRQ_BASE: usize = 32;

static IRQ_HANDLER_TABLE: HandlerTable<MAX_IRQ_COUNT> = HandlerTable::new();

struct IrqIfImpl;

#[impl_plat_interface]
impl IrqIf for IrqIfImpl {
    /// Enables or disables the given IRQ.
    fn set_enable(irq_num: usize, enabled: bool) {
        if irq_num == crate::config::devices::TIMER_IRQ {
            let old_value = ecfg::read().lie();
            let new_value = match enabled {
                true => old_value | LineBasedInterrupt::TIMER,
                false => old_value & !LineBasedInterrupt::TIMER,
            };
            ecfg::set_lie(new_value);
        } else if (PCH_PIC_IRQ_BASE..PCH_PIC_IRQ_BASE + 64).contains(&irq_num) {
            if let Some(pic) = pch_pic::PCH_PIC.get() {
                pic.set_enable(irq_num - PCH_PIC_IRQ_BASE, enabled);
            }
        }
    }

    /// Registers an IRQ handler for the given IRQ.
    fn register(irq_num: usize, handler: IrqHandler) -> bool {
        if IRQ_HANDLER_TABLE.register_handler(irq_num, handler) {
            Self::set_enable(irq_num, true);
            return true;
        }
        warn!("register handler for IRQ {} failed", irq_num);
        false
    }

    /// Unregisters the IRQ handler for the given IRQ.
    fn unregister(irq: usize) -> Option<IrqHandler> {
        Self::set_enable(irq, false);
        IRQ_HANDLER_TABLE.unregister_handler(irq)
    }

    /// Handles the IRQ.
    fn handle(irq: usize) {
        if irq == crate::config::devices::TIMER_IRQ {
            ticlr::clear_timer_interrupt();
            if !IRQ_HANDLER_TABLE.handle(irq) {
                warn!("Unhandled Timer IRQ");
            }
        } else if irq == loongArch64::register::estat::Interrupt::HWI0 as usize {
            // External interrupt from EIOINTC/PCH-PIC
            let mut pending = eiointc::get_pending();
            while pending != 0 {
                let pch_irq = pending.trailing_zeros() as usize;
                let global_irq = PCH_PIC_IRQ_BASE + pch_irq;
                trace!("PCH-PIC IRQ {}", pch_irq);
                if !IRQ_HANDLER_TABLE.handle(global_irq) {
                    warn!("Unhandled PCH-PIC IRQ {}", pch_irq);
                }
                if let Some(pic) = pch_pic::PCH_PIC.get() {
                    pic.clear_irq(pch_irq);
                }
                pending &= !(1u64 << pch_irq);
            }
        } else {
            trace!("IRQ {}", irq);
            if !IRQ_HANDLER_TABLE.handle(irq) {
                warn!("Unhandled IRQ {}", irq);
            }
        }
    }

    /// Sends an inter-processor interrupt (IPI) to the specified target CPU or all CPUs.
    fn send_ipi(_irq_num: usize, _target: IpiTarget) {
        todo!()
    }
}

pub(crate) fn init_early() {
    eiointc::init();
    pch_pic::init(pa!(crate::config::devices::PCH_PIC_PADDR));
    // Enable HWI0 in ECFG
    let old_value = ecfg::read().lie();
    ecfg::set_lie(old_value | LineBasedInterrupt::HWI0);
}
