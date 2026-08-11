//! PLIC (Platform-Level Interrupt Controller) driver.
//!
//! Ref: <https://github.com/riscv/riscv-plic-spec/blob/master/riscv-plic-1.0.0.pdf>

use core::ptr::{read_volatile, write_volatile};

use kspin::SpinNoIrq;

use crate::config::plat::PHYS_VIRT_OFFSET;

const MAX_INTERRUPT_SOURCES: usize = 1024;
const PRIORITY_OFFSET: usize = 0;
const ENABLE_OFFSET: usize = 0x2000;
const ENABLE_CONTEXT_STRIDE: usize = 0x80;
const CONTEXT_OFFSET: usize = 0x20_0000;
const CONTEXT_STRIDE: usize = 0x1000;

struct PlicState {
    source_enabled: [bool; MAX_INTERRUPT_SOURCES],
    online_cpus: usize,
}

impl PlicState {
    const fn new() -> Self {
        Self {
            source_enabled: [false; MAX_INTERRUPT_SOURCES],
            online_cpus: 0,
        }
    }
}

static PLIC_STATE: SpinNoIrq<PlicState> = SpinNoIrq::new(PlicState::new());

#[inline]
pub(crate) fn is_valid_irq(irq: usize) -> bool {
    irq > 0 && irq <= crate::topology::plic_ndev() && irq < MAX_INTERRUPT_SOURCES
}

/// Initializes global source priorities and every discovered S-mode context.
pub(crate) fn init_primary() {
    let mut state = PLIC_STATE.lock();
    *state = PlicState::new();
    for irq in 1..=crate::topology::plic_ndev().min(MAX_INTERRUPT_SOURCES - 1) {
        write_priority(irq, 0);
    }
    for cpu_id in 0..crate::topology::cpu_count() {
        clear_context_sources(cpu_id);
        write_threshold(cpu_id, 0);
    }
    debug!(
        "PLIC: base={:#x}, size={:#x}, sources={}",
        crate::topology::plic_base(),
        crate::topology::plic_size(),
        crate::topology::plic_ndev()
    );
}

/// Restores the local threshold after firmware starts a secondary hart.
pub(crate) fn init_secondary(cpu_id: usize) {
    let _state = PLIC_STATE.lock();
    clear_context_sources(cpu_id);
    write_threshold(cpu_id, 0);
}

/// Publishes a CPU as an eligible external-interrupt target and rebalances routes.
pub(crate) fn cpu_online(cpu_id: usize) {
    if cpu_id >= crate::topology::cpu_count() || cpu_id >= usize::BITS as usize {
        warn!("cannot online invalid PLIC CPU {cpu_id}");
        return;
    }
    let mut state = PLIC_STATE.lock();
    let bit = 1usize << cpu_id;
    if state.online_cpus & bit != 0 {
        return;
    }
    clear_context_sources(cpu_id);
    write_threshold(cpu_id, 0);
    state.online_cpus |= bit;
    for irq in 1..=crate::topology::plic_ndev().min(MAX_INTERRUPT_SOURCES - 1) {
        if state.source_enabled[irq] {
            route_source(&state, irq);
        }
    }
}

pub(crate) fn is_cpu_online(cpu_id: usize) -> bool {
    cpu_id < usize::BITS as usize && PLIC_STATE.lock().online_cpus & (1usize << cpu_id) != 0
}

/// Atomically updates software source state, priority, and context enable bits.
pub(crate) fn set_source_enabled(irq: usize, enabled: bool) {
    if !is_valid_irq(irq) {
        return;
    }
    let mut state = PLIC_STATE.lock();
    state.source_enabled[irq] = enabled;
    write_priority(irq, u32::from(enabled));
    route_source(&state, irq);
}

/// Claims the highest-priority pending interrupt for a logical CPU.
pub(crate) fn claim(cpu_id: usize) -> u32 {
    let Some(address) = context_address(cpu_id, 4) else {
        return 0;
    };
    // SAFETY: topology validated this context against the PLIC MMIO range.
    unsafe { read_volatile(address as *const u32) }
}

/// Completes an interrupt for a logical CPU.
pub(crate) fn complete(cpu_id: usize, irq: u32) {
    let Some(address) = context_address(cpu_id, 4) else {
        return;
    };
    // SAFETY: topology validated this context against the PLIC MMIO range.
    unsafe { write_volatile(address as *mut u32, irq) };
}

fn route_source(state: &PlicState, irq: usize) {
    for cpu_id in 0..crate::topology::cpu_count() {
        write_enable(cpu_id, irq, false);
    }
    if !state.source_enabled[irq] {
        return;
    }
    if let Some(cpu_id) = select_target_cpu(state.online_cpus, irq) {
        write_enable(cpu_id, irq, true);
    }
}

fn select_target_cpu(online_cpus: usize, irq: usize) -> Option<usize> {
    let online_count = online_cpus.count_ones() as usize;
    if online_count == 0 {
        return None;
    }
    let target_index = (irq - 1) % online_count;
    (0..usize::BITS as usize)
        .filter(|cpu_id| online_cpus & (1usize << cpu_id) != 0)
        .nth(target_index)
}

fn clear_context_sources(cpu_id: usize) {
    let word_count = crate::topology::plic_ndev() / 32 + 1;
    for word in 0..word_count {
        let Some(address) = enable_word_address(cpu_id, word) else {
            return;
        };
        // SAFETY: topology validated this context against the PLIC MMIO range.
        unsafe { write_volatile(address as *mut u32, 0) };
    }
}

fn write_priority(irq: usize, priority: u32) {
    let address = plic_base_vaddr() + PRIORITY_OFFSET + irq * 4;
    // SAFETY: irq is bounded by the DTB-validated number of sources.
    unsafe { write_volatile(address as *mut u32, priority) };
}

fn write_enable(cpu_id: usize, irq: usize, enabled: bool) {
    let Some(address) = enable_word_address(cpu_id, irq / 32) else {
        return;
    };
    let mask = 1u32 << (irq % 32);
    // SAFETY: all callers hold PLIC_STATE, serializing the read-modify-write.
    unsafe {
        let value = read_volatile(address as *const u32);
        write_volatile(
            address as *mut u32,
            if enabled { value | mask } else { value & !mask },
        );
    }
}

fn write_threshold(cpu_id: usize, threshold: u32) {
    let Some(address) = context_address(cpu_id, 0) else {
        return;
    };
    // SAFETY: topology validated this context against the PLIC MMIO range.
    unsafe { write_volatile(address as *mut u32, threshold) };
}

fn enable_word_address(cpu_id: usize, word: usize) -> Option<usize> {
    let context = crate::topology::plic_context(cpu_id)?;
    Some(
        plic_base_vaddr()
            + ENABLE_OFFSET
            + context * ENABLE_CONTEXT_STRIDE
            + word * core::mem::size_of::<u32>(),
    )
}

fn context_address(cpu_id: usize, register_offset: usize) -> Option<usize> {
    let context = crate::topology::plic_context(cpu_id)?;
    Some(plic_base_vaddr() + CONTEXT_OFFSET + context * CONTEXT_STRIDE + register_offset)
}

fn plic_base_vaddr() -> usize {
    crate::topology::plic_base() + PHYS_VIRT_OFFSET
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_online_cpus() {
        let online = (1 << 0) | (1 << 3) | (1 << 5);
        assert_eq!(select_target_cpu(online, 1), Some(0));
        assert_eq!(select_target_cpu(online, 2), Some(3));
        assert_eq!(select_target_cpu(online, 3), Some(5));
        assert_eq!(select_target_cpu(online, 4), Some(0));
        assert_eq!(select_target_cpu(0, 1), None);
    }
}
