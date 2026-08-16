use core::{
    ptr::{read_volatile, write_volatile},
    sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering},
};

use axplat::irq::{HandlerTable, IpiError, IpiTarget, IrqHandler, IrqIf};
use loongArch64::{
    iocsr::{iocsr_read_w, iocsr_write_w},
    register::{
        ecfg::{self, LineBasedInterrupt},
        ticlr,
    },
};

/// The LS2K1000 LIOINTC exposes 32 input lines.
pub const MAX_IRQ_COUNT: usize = 32;
const CPU_LOCAL_IRQ_FLAG: usize = 1 << (usize::BITS - 1);
const RAW_TIMER_IRQ: usize = 11;
const RAW_IPI_IRQ: usize = 12;
const TIMER_IRQ: usize = CPU_LOCAL_IRQ_FLAG | RAW_TIMER_IRQ;
const IPI_IRQ: usize = CPU_LOCAL_IRQ_FLAG | RAW_IPI_IRQ;
const CPU_HWI_BASE_IRQ: usize = 2;
const LIOINTC_PARENT_COUNT: usize = 4;
const LIOINTC_ROUTE_CPU0: u8 = 1;
const LIOINTC_ROUTE_INT_SHIFT: usize = 4;
const LIOINTC_ROUTE_BASE: usize = 0x00;
const LIOINTC_ENABLE: usize = 0x28;
const LIOINTC_DISABLE: usize = 0x2c;
const LIOINTC_POLARITY: usize = 0x30;
const LIOINTC_EDGE: usize = 0x34;
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
// The hard IRQ path reads only this atomic and the ISR MMIO register. It does
// not acquire a controller lock, which keeps external IRQ dispatch safe while
// task context enables or disables individual inputs.
static LIOINTC_ENABLED: AtomicU32 = AtomicU32::new(0);

const _: () = assert!(crate::config::devices::TIMER_IRQ == TIMER_IRQ);
const _: () = assert!(crate::config::devices::IPI_IRQ == IPI_IRQ);

struct IrqIfImpl;

#[impl_plat_interface]
impl IrqIf for IrqIfImpl {
    fn set_enable(irq_num: usize, enabled: bool) {
        if irq_num == IPI_IRQ {
            iocsr_write_w(IOCSR_IPI_ENABLE, if enabled { u32::MAX } else { 0 });
            set_local_line(LineBasedInterrupt::IPI, enabled);
        } else if irq_num == TIMER_IRQ {
            set_local_line(LineBasedInterrupt::TIMER, enabled);
        } else if irq_num < MAX_IRQ_COUNT {
            set_liointc_enable(irq_num, enabled);
        } else {
            warn!("invalid LS2K1000 IRQ {irq_num}");
        }
    }

    fn register(irq_num: usize, handler: IrqHandler) -> bool {
        let registered = if irq_num == TIMER_IRQ {
            register_local_handler(&TIMER_HANDLER, handler)
        } else if irq_num == IPI_IRQ {
            register_local_handler(&IPI_HANDLER, handler)
        } else if irq_num < MAX_IRQ_COUNT {
            IRQ_HANDLER_TABLE.register_handler(irq_num, handler)
        } else {
            false
        };
        if registered {
            Self::set_enable(irq_num, true);
        } else {
            warn!("register handler for LS2K1000 IRQ {irq_num} failed");
        }
        registered
    }

    fn unregister(irq_num: usize) -> Option<IrqHandler> {
        if (irq_num == TIMER_IRQ || irq_num == IPI_IRQ)
            && ONLINE_CPUS.load(Ordering::Acquire).count_ones() > 1
        {
            warn!("cannot unregister CPU-local IRQ {irq_num} while multiple CPUs are online");
            return None;
        }

        let handler = if irq_num == TIMER_IRQ {
            unregister_local_handler(&TIMER_HANDLER)
        } else if irq_num == IPI_IRQ {
            unregister_local_handler(&IPI_HANDLER)
        } else if irq_num < MAX_IRQ_COUNT {
            IRQ_HANDLER_TABLE.unregister_handler(irq_num)
        } else {
            None
        };
        if handler.is_some() {
            Self::set_enable(irq_num, false);
        }
        handler
    }

    fn handle(irq: usize, _cpu_id: usize) {
        if irq == RAW_IPI_IRQ {
            let mut status = iocsr_read_w(IOCSR_IPI_STATUS);
            if status == 0 {
                debug!("spurious LS2K1000 IPI");
                return;
            }
            iocsr_write_w(IOCSR_IPI_CLEAR, status);
            while status != 0 {
                status &= status - 1;
                if !handle_local_irq(&IPI_HANDLER, IPI_IRQ) {
                    warn!("unhandled LS2K1000 IPI");
                }
            }
        } else if irq == RAW_TIMER_IRQ {
            ticlr::clear_timer_interrupt();
            if !handle_local_irq(&TIMER_HANDLER, TIMER_IRQ) {
                warn!("unhandled LS2K1000 timer IRQ");
            }
        } else if irq == crate::topology::liointc_cascade_irq() {
            let mut pending = liointc_pending();
            if pending == 0 {
                debug!("spurious LS2K1000 LIOINTC IRQ");
                return;
            }
            while pending != 0 {
                let input = pending.trailing_zeros() as usize;
                pending &= pending - 1;
                if !IRQ_HANDLER_TABLE.handle(input) {
                    warn!("unhandled LS2K1000 LIOINTC input {input}");
                }
            }
        } else {
            warn!("unrouted LS2K1000 CPU-local IRQ {irq}");
        }
    }

    fn cpu_online(cpu_id: usize) {
        if cpu_id < usize::BITS as usize {
            iocsr_write_w(IOCSR_IPI_ENABLE, u32::MAX);
            set_local_line(LineBasedInterrupt::IPI, true);
            ONLINE_CPUS.fetch_or(1usize << cpu_id, Ordering::Release);
        }
    }

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
    (!handler.is_null()).then(|| unsafe { core::mem::transmute::<*mut (), IrqHandler>(handler) })
}

fn handle_local_irq(slot: &AtomicPtr<()>, irq: usize) -> bool {
    let handler = slot.load(Ordering::Acquire);
    if handler.is_null() {
        false
    } else {
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

fn set_liointc_enable(input: usize, enabled: bool) {
    let mask = 1u32 << input;
    if enabled {
        unsafe { write_volatile((liointc_regs_vaddr() + LIOINTC_ENABLE) as *mut u32, mask) };
        LIOINTC_ENABLED.fetch_or(mask, Ordering::Release);
    } else {
        LIOINTC_ENABLED.fetch_and(!mask, Ordering::AcqRel);
        unsafe { write_volatile((liointc_regs_vaddr() + LIOINTC_DISABLE) as *mut u32, mask) };
    }
}

fn liointc_pending() -> u32 {
    let pending = unsafe { read_volatile(liointc_isr_vaddr() as *const u32) };
    pending & LIOINTC_ENABLED.load(Ordering::Acquire)
}

fn liointc_regs_vaddr() -> usize {
    crate::mem::phys_to_virt(axplat::mem::pa!(crate::topology::liointc_paddr())).as_usize()
}

fn liointc_isr_vaddr() -> usize {
    crate::mem::phys_to_virt(axplat::mem::pa!(crate::topology::liointc_isr_paddr())).as_usize()
}

fn send_ipi_to_cpu(cpu_id: usize) -> Result<(), IpiError> {
    if cpu_id >= crate::topology::cpu_count() || cpu_id >= usize::BITS as usize {
        return Err(IpiError::InvalidTarget);
    }
    if ONLINE_CPUS.load(Ordering::Acquire) & (1usize << cpu_id) == 0 {
        return Err(IpiError::CpuOffline);
    }
    let hardware_cpu_id = crate::topology::hardware_cpu_id(cpu_id)
        .ok_or(IpiError::InvalidTarget)
        .and_then(|id| u32::try_from(id).map_err(|_| IpiError::InvalidTarget))?;
    let value = hardware_cpu_id << IOCSR_IPI_SEND_CPU_SHIFT | IOCSR_IPI_SEND_BLOCKING | IPI_VECTOR;
    iocsr_write_w(IOCSR_IPI_SEND, value);
    Ok(())
}

pub(crate) fn init_early() {
    let route = liointc_route_value(crate::topology::liointc_cascade_irq())
        .expect("LS2K1000 DTB supplied an invalid LIOINTC CPU parent IRQ");
    let regs = liointc_regs_vaddr();
    for input in 0..MAX_IRQ_COUNT {
        unsafe { write_volatile((regs + LIOINTC_ROUTE_BASE + input) as *mut u8, route) };
    }
    unsafe {
        write_volatile((regs + LIOINTC_DISABLE) as *mut u32, u32::MAX);
        write_volatile((regs + LIOINTC_EDGE) as *mut u32, 0);
        // POL=0 is active-high level-sensitive, matching the reference DTB.
        write_volatile((regs + LIOINTC_POLARITY) as *mut u32, 0);
    }
    LIOINTC_ENABLED.store(0, Ordering::Release);
    let cascade = crate::topology::liointc_cascade_irq();
    set_local_line(
        LineBasedInterrupt::from_bits_retain(1usize << cascade),
        true,
    );
}

const fn liointc_route_value(cascade_irq: usize) -> Option<u8> {
    match cascade_irq.checked_sub(CPU_HWI_BASE_IRQ) {
        Some(parent) if parent < LIOINTC_PARENT_COUNT => {
            Some(LIOINTC_ROUTE_CPU0 | (1 << (LIOINTC_ROUTE_INT_SHIFT + parent)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_reference_cascade_hwi1_to_cpu0_int1() {
        assert_eq!(liointc_route_value(3), Some(0x21));
    }

    #[test]
    fn rejects_cpu_interrupts_outside_liointc_parent_lines() {
        assert_eq!(liointc_route_value(1), None);
        assert_eq!(liointc_route_value(6), None);
    }
}
