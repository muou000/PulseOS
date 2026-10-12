//! Interrupt request (IRQ) handling.

use core::fmt;

pub use handler_table::HandlerTable;

/// The type if an IRQ handler.
pub type IrqHandler = handler_table::Handler;

/// Target specification for inter-processor interrupts (IPIs).
pub enum IpiTarget {
    /// Send to the current CPU.
    Current {
        /// The CPU ID of the current CPU.
        cpu_id: usize,
    },
    /// Send to a specific CPU.
    Other {
        /// The CPU ID of the target CPU.
        cpu_id: usize,
    },
    /// Send to all other CPUs.
    AllExceptCurrent {
        /// The CPU ID of the current CPU.
        cpu_id: usize,
        /// The total number of CPUs.
        cpu_num: usize,
    },
}

/// Error returned when an inter-processor interrupt cannot be delivered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpiError {
    /// The logical target CPU does not exist.
    InvalidTarget,
    /// The target CPU exists but is not online.
    CpuOffline,
    /// The platform does not support inter-processor interrupts.
    NotSupported,
    /// Platform firmware returned an error code.
    Firmware(isize),
}

impl fmt::Display for IpiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTarget => f.write_str("invalid IPI target CPU"),
            Self::CpuOffline => f.write_str("IPI target CPU is offline"),
            Self::NotSupported => f.write_str("inter-processor interrupts are not supported"),
            Self::Firmware(error) => write!(f, "firmware IPI error {error}"),
        }
    }
}

impl core::error::Error for IpiError {}

/// IRQ management interface.
#[def_plat_interface]
pub trait IrqIf {
    /// Enables or disables the given IRQ.
    fn set_enable(irq: usize, enabled: bool);

    /// Registers an IRQ handler for the given IRQ.
    ///
    /// It also enables the IRQ if the registration succeeds. It returns `false`
    /// if the registration failed.
    fn register(irq: usize, handler: IrqHandler) -> bool;

    /// Unregisters the IRQ handler for the given IRQ.
    ///
    /// It also disables the IRQ if the unregistration succeeds. It returns the
    /// existing handler if it is registered, `None` otherwise.
    fn unregister(irq: usize) -> Option<IrqHandler>;

    /// Handles the IRQ.
    ///
    /// It is called by the common interrupt handler. It should look up in the
    /// IRQ handler table and calls the corresponding handler. If necessary, it
    /// also acknowledges the interrupt controller after handling.
    fn handle(irq: usize, cpu_id: usize);

    /// Notifies the interrupt controller that a logical CPU is ready to receive IRQs.
    fn cpu_online(cpu_id: usize);

    /// Sends an inter-processor interrupt (IPI) to the specified target CPU or all CPUs.
    fn send_ipi(irq_num: usize, target: IpiTarget) -> Result<(), IpiError>;
}
