//! Interrupt management.

#[cfg(feature = "ipi")]
pub use axconfig::devices::IPI_IRQ;
use axcpu::trap::{IRQ, register_trap_handler};
#[cfg(feature = "ipi")]
pub use axplat::irq::{IpiError, IpiTarget, send_ipi};
pub use axplat::irq::{handle, register, set_enable, unregister};

/// IRQ handler.
///
/// # Warn
///
/// Make sure called in an interrupt context or hypervisor VM exit handler.
#[register_trap_handler(IRQ)]
pub fn irq_handler(vector: usize) -> bool {
    let guard = kernel_guard::NoPreempt::new();
    handle(vector, crate::percpu::this_cpu_id());
    drop(guard); // rescheduling may occur when preemption is re-enabled.
    true
}
