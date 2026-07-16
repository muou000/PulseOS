//! PLIC (Platform-Level Interrupt Controller) driver.
//!
//! Ref: <https://github.com/riscv/riscv-plic-spec/blob/master/riscv-plic-1.0.0.pdf>

use core::ptr::{read_volatile, write_volatile};
use crate::config::plat::PHYS_VIRT_OFFSET;
use kspin::SpinNoIrq;

static PLIC_LOCK: SpinNoIrq<()> = SpinNoIrq::new(());

/// The PLIC base virtual address.
const PLIC_BASE: usize = 0x0c00_0000 + PHYS_VIRT_OFFSET;

/// Interrupt priority register.
const PLIC_PRIORITY_BASE: usize = PLIC_BASE + 0x0;

/// Interrupt pending register.
#[allow(dead_code)]
const PLIC_PENDING_BASE: usize = PLIC_BASE + 0x1000;

/// Interrupt enable register.
const PLIC_ENABLE_BASE: usize = PLIC_BASE + 0x2000;

/// Context threshold and claim/complete register.
const PLIC_CONTEXT_BASE: usize = PLIC_BASE + 0x200000;

/// QEMU `virt` exposes interrupt source IDs 1..=1023. Source 0 is reserved.
const MAX_INTERRUPT_SOURCES: usize = 1024;
const ENABLE_WORDS_PER_CONTEXT: usize = MAX_INTERRUPT_SOURCES / 32;

#[inline]
pub(crate) const fn is_valid_irq(irq: usize) -> bool {
    irq > 0 && irq < MAX_INTERRUPT_SOURCES
}

/// Returns the S-mode context ID for a given hart.
///
/// In QEMU virt machine, each hart has two contexts:
/// - Context 2*N: Hart N M-mode
/// - Context 2*N + 1: Hart N S-mode
#[inline]
const fn s_mode_context(hart_id: usize) -> usize {
    2 * hart_id + 1
}

/// Sets the priority for a given interrupt source.
pub fn set_priority(irq: usize, priority: u32) {
    if !is_valid_irq(irq) {
        return;
    }
    let ptr = (PLIC_PRIORITY_BASE + irq * 4) as *mut u32;
    unsafe { write_volatile(ptr, priority) };
}

/// Enables or disables a given interrupt source for a given hart's S-mode context.
pub fn set_enable(hart_id: usize, irq: usize, enabled: bool) {
    if !is_valid_irq(irq) {
        return;
    }
    let context = s_mode_context(hart_id);
    let ptr = (PLIC_ENABLE_BASE + context * 0x80 + (irq / 32) * 4) as *mut u32;
    let mask = 1 << (irq % 32);
    let _guard = PLIC_LOCK.lock();
    unsafe {
        let mut val = read_volatile(ptr);
        if enabled {
            val |= mask;
        } else {
            val &= !mask;
        }
        write_volatile(ptr, val);
    }
}

/// Sets the interrupt threshold for a given hart's S-mode context.
pub fn set_threshold(hart_id: usize, threshold: u32) {
    let context = s_mode_context(hart_id);
    let ptr = (PLIC_CONTEXT_BASE + context * 0x1000) as *mut u32;
    unsafe { write_volatile(ptr, threshold) };
}

/// Claims an interrupt for a given hart's S-mode context.
///
/// Returns the ID of the highest priority pending interrupt.
pub fn claim(hart_id: usize) -> u32 {
    let context = s_mode_context(hart_id);
    let ptr = (PLIC_CONTEXT_BASE + context * 0x1000 + 4) as *mut u32;
    unsafe { read_volatile(ptr) }
}

/// Completes an interrupt for a given hart's S-mode context.
pub fn complete(hart_id: usize, irq: u32) {
    let context = s_mode_context(hart_id);
    let ptr = (PLIC_CONTEXT_BASE + context * 0x1000 + 4) as *mut u32;
    unsafe { write_volatile(ptr, irq) };
}

/// Initializes PLIC for the current hart's S-mode context.
pub fn init_hart(hart_id: usize) {
    // Firmware is allowed to leave priorities and enable bits configured.
    // Reset global source priorities once, before enabling any source in S-mode.
    if hart_id == 0 {
        for irq in 1..MAX_INTERRUPT_SOURCES {
            set_priority(irq, 0);
        }
    }

    let context = s_mode_context(hart_id);
    let _guard = PLIC_LOCK.lock();
    for word in 0..ENABLE_WORDS_PER_CONTEXT {
        let ptr = (PLIC_ENABLE_BASE + context * 0x80 + word * 4) as *mut u32;
        unsafe { write_volatile(ptr, 0) };
    }
    drop(_guard);
    set_threshold(hart_id, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_reserved_and_out_of_range_interrupt_sources() {
        assert!(!is_valid_irq(0));
        assert!(is_valid_irq(1));
        assert!(is_valid_irq(MAX_INTERRUPT_SOURCES - 1));
        assert!(!is_valid_irq(MAX_INTERRUPT_SOURCES));
        assert!(!is_valid_irq(usize::MAX));
    }

    #[test]
    fn maps_harts_to_supervisor_contexts() {
        assert_eq!(s_mode_context(0), 1);
        assert_eq!(s_mode_context(1), 3);
    }
}
