//! Platform-level Interrupt Controller (PLIC) support.

use core::sync::atomic::{AtomicPtr, Ordering};

use axplat::irq::{HandlerTable, IpiError, IpiTarget, IrqHandler, IrqIf};
use riscv::register::sie;
use sbi_rt::HartMask;

/// `Interrupt` bit in `scause`
pub(super) const INTC_IRQ_BASE: usize = 1 << (usize::BITS - 1);

/// Supervisor software interrupt in `scause`
pub(super) const S_SOFT: usize = INTC_IRQ_BASE + 1;

/// Supervisor timer interrupt in `scause`
pub(super) const S_TIMER: usize = INTC_IRQ_BASE + 5;

/// Supervisor external interrupt in `scause`
pub(super) const S_EXT: usize = INTC_IRQ_BASE + 9;

static TIMER_HANDLER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

static IPI_HANDLER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// The maximum number of IRQs.
pub const MAX_IRQ_COUNT: usize = 1024;

static IRQ_HANDLER_TABLE: HandlerTable<MAX_IRQ_COUNT> = HandlerTable::new();

macro_rules! with_cause {
    (
        $cause:expr, @S_TIMER =>
        $timer_op:expr, @S_SOFT =>
        $ipi_op:expr, @S_EXT =>
        $ext_op:expr, @EX_IRQ =>
        $plic_op:expr $(,)?
    ) => {
        match $cause {
            S_TIMER => $timer_op,
            S_SOFT => $ipi_op,
            S_EXT => $ext_op,
            other => {
                if other & INTC_IRQ_BASE == 0 {
                    // Device-side interrupts read from PLIC
                    $plic_op
                } else {
                    // Other CPU-side interrupts
                    panic!("Unknown IRQ cause: {}", other);
                }
            }
        }
    };
}

pub(super) fn init_primary(_cpu_id: usize) {
    crate::plic::init_primary();
    enable_local_interrupts();
}

pub(super) fn init_secondary(cpu_id: usize) {
    crate::plic::init_secondary(cpu_id);
    enable_local_interrupts();
}

fn enable_local_interrupts() {
    unsafe {
        sie::set_ssoft();
        sie::set_stimer();
        sie::set_sext();
    }
}

struct IrqIfImpl;

#[impl_plat_interface]
impl IrqIf for IrqIfImpl {
    /// Enables or disables the given IRQ.
    fn set_enable(irq: usize, enabled: bool) {
        if irq & INTC_IRQ_BASE == 0 && crate::plic::is_valid_irq(irq) {
            crate::plic::set_source_enabled(irq, enabled);
        }
    }

    /// Registers an IRQ handler for the given IRQ.
    ///
    /// It also enables the IRQ if the registration succeeds. It returns `false` if
    /// the registration failed.
    ///
    /// The `irq` parameter has the following semantics
    /// 1. If its highest bit is 1, it means it is an interrupt on the CPU side. Its
    /// value comes from `scause`, where [`S_SOFT`] represents software interrupt
    /// and [`S_TIMER`] represents timer interrupt. If its value is [`S_EXT`], it
    /// means it is an external interrupt, and the real IRQ number needs to
    /// be obtained from PLIC.
    /// 2. If its highest bit is 0, it means it is an interrupt on the device side,
    /// and its value is equal to the IRQ number provided by PLIC.
    fn register(irq: usize, handler: IrqHandler) -> bool {
        with_cause!(
            irq,
            @S_TIMER => TIMER_HANDLER.compare_exchange(core::ptr::null_mut(), handler as *mut _, Ordering::AcqRel, Ordering::Acquire).is_ok(),
            @S_SOFT => IPI_HANDLER.compare_exchange(core::ptr::null_mut(), handler as *mut _, Ordering::AcqRel, Ordering::Acquire).is_ok(),
            @S_EXT => {
                warn!("External IRQ should be got from PLIC, not scause");
                false
            },
            @EX_IRQ => {
                if !crate::plic::is_valid_irq(irq) {
                    warn!("invalid PLIC IRQ {}", irq);
                    false
                } else if IRQ_HANDLER_TABLE.register_handler(irq, handler) {
                    Self::set_enable(irq, true);
                    true
                } else {
                    warn!("register handler for External IRQ {} failed", irq);
                    false
                }
            }
        )
    }

    /// Unregisters the IRQ handler for the given IRQ.
    ///
    /// It also disables the IRQ if the unregistration succeeds. It returns the
    /// existing handler if it is registered, `None` otherwise.
    fn unregister(irq: usize) -> Option<IrqHandler> {
        with_cause!(
            irq,
            @S_TIMER => {
                let handler = TIMER_HANDLER.swap(core::ptr::null_mut(), Ordering::AcqRel);
                if !handler.is_null() {
                    Some(unsafe { core::mem::transmute::<*mut (), IrqHandler>(handler) })
                } else {
                    None
                }
            },
            @S_SOFT => {
                let handler = IPI_HANDLER.swap(core::ptr::null_mut(), Ordering::AcqRel);
                if !handler.is_null() {
                    Some(unsafe { core::mem::transmute::<*mut (), IrqHandler>(handler) })
                } else {
                    None
                }
            },
            @S_EXT => {
                warn!("External IRQ should be got from PLIC, not scause");
                None
            },
            @EX_IRQ => {
                if crate::plic::is_valid_irq(irq) {
                    Self::set_enable(irq, false);
                    IRQ_HANDLER_TABLE.unregister_handler(irq)
                } else {
                    None
                }
            }
        )
    }

    /// Handles the IRQ.
    ///
    /// It is called by the common interrupt handler. It should look up in the
    /// IRQ handler table and calls the corresponding handler. If necessary, it
    /// also acknowledges the interrupt controller after handling.
    fn handle(irq: usize, cpu_id: usize) {
        with_cause!(
            irq,
            @S_TIMER => {
                trace!("IRQ: timer");
                let handler = TIMER_HANDLER.load(Ordering::Acquire);
                if !handler.is_null() {
                    // SAFETY: The handler is guaranteed to be a valid function pointer.
                    unsafe { core::mem::transmute::<*mut (), IrqHandler>(handler)(irq) };
                }
            },
            @S_SOFT => {
                trace!("IRQ: IPI");
                unsafe {
                    riscv::register::sip::clear_ssoft();
                }
                let handler = IPI_HANDLER.load(Ordering::Acquire);
                if !handler.is_null() {
                    // SAFETY: The handler is guaranteed to be a valid function pointer.
                    unsafe { core::mem::transmute::<*mut (), IrqHandler>(handler)(irq) };
                }
            },
            @S_EXT => {
                let irq_num = crate::plic::claim(cpu_id);
                if irq_num != 0 {
                    if !IRQ_HANDLER_TABLE.handle(irq_num as usize) {
                        warn!("Unhandled PLIC IRQ {}", irq_num);
                    }
                    crate::plic::complete(cpu_id, irq_num);
                }
            },
            @EX_IRQ => {
                unreachable!("Device-side IRQs should be handled by triggering the External Interrupt.");
            }
        )
    }

    fn cpu_online(cpu_id: usize) {
        crate::plic::cpu_online(cpu_id);
    }

    /// Sends an inter-processor interrupt (IPI) to the specified target CPU or all CPUs.
    fn send_ipi(_irq_num: usize, target: IpiTarget) -> Result<(), IpiError> {
        match target {
            IpiTarget::Current { cpu_id } => {
                send_ipi_to_cpu(cpu_id)?;
            }
            IpiTarget::Other { cpu_id } => {
                send_ipi_to_cpu(cpu_id)?;
            }
            IpiTarget::AllExceptCurrent { cpu_id, cpu_num } => {
                for i in 0..cpu_num {
                    if i != cpu_id {
                        send_ipi_to_cpu(i)?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn send_ipi_to_cpu(cpu_id: usize) -> Result<(), IpiError> {
    let hart_id = crate::topology::hart_id(cpu_id).ok_or(IpiError::InvalidTarget)?;
    if !crate::plic::is_cpu_online(cpu_id) {
        return Err(IpiError::CpuOffline);
    }
    let result = sbi_rt::send_ipi(HartMask::from_mask_base(1, hart_id));
    if result.is_ok() {
        Ok(())
    } else if result.error == sbi_rt::SbiRet::not_supported().error {
        Err(IpiError::NotSupported)
    } else {
        Err(IpiError::Firmware(result.error as isize))
    }
}
