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
        } else if irq_num < 64 {
            // PCH-PIC pins: unmask in PCH-PIC and keep EIOINTC enabled
            if let Some(pic) = pch_pic::PCH_PIC.get() {
                pic.set_enable(irq_num, enabled);
            }
            eiointc::set_enable(irq_num, enabled);
        } else if irq_num < 256 {
            // PCH-MSI pins (64..255): directly connected to EIOINTC, bypasses PCH-PIC entirely
            eiointc::set_enable(irq_num, enabled);
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
            // External interrupt from EIOINTC
            info!("HWI0 interrupt received, scanning EIOINTC pending");
            let mut any_pending = false;
            for group in 0..4 {
                let mut pending = eiointc::get_pending_group(group);
                while pending != 0 {
                    any_pending = true;
                    let bit = pending.trailing_zeros() as usize;
                    let irq_num = group * 64 + bit;
                    let global_irq = irq_num;
                    info!("EIOINTC IRQ group={} bit={} irq_num={} global_irq={}", group, bit, irq_num, global_irq);
                    eiointc::clear_pending(irq_num);
                    if irq_num < 64 {
                        if let Some(pic) = pch_pic::PCH_PIC.get() {
                            pic.clear_irq(irq_num);
                        }
                    }
                    if !IRQ_HANDLER_TABLE.handle(global_irq) {
                        warn!("Unhandled EIOINTC IRQ {}", irq_num);
                    }
                    pending &= !(1u64 << bit);
                }
            }
            if !any_pending {
                info!("HWI0: no pending IRQs found in EIOINTC ISR");
            }
        } else {
            info!("IRQ {}", irq);
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
