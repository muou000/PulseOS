//! PLIC (Platform-Level Interrupt Controller) driver.
//!
//! Ref: <https://github.com/riscv/riscv-plic-spec/blob/master/riscv-plic-1.0.0.pdf>

use core::ptr::{read_volatile, write_volatile};
use crate::config::plat::PHYS_VIRT_OFFSET;

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
    let ptr = (PLIC_PRIORITY_BASE + irq * 4) as *mut u32;
    unsafe { write_volatile(ptr, priority) };
}

/// Enables or disables a given interrupt source for a given hart's S-mode context.
pub fn set_enable(hart_id: usize, irq: usize, enabled: bool) {
    let context = s_mode_context(hart_id);
    let ptr = (PLIC_ENABLE_BASE + context * 0x80 + (irq / 32) * 4) as *mut u32;
    let mask = 1 << (irq % 32);
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
    set_threshold(hart_id, 0);
}
