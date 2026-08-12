//! Wrapper functions for assembly instructions.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use memory_addr::{PhysAddr, VirtAddr};
use riscv::{
    asm,
    register::{satp, sstatus, stvec},
};

static KERNEL_PAGE_TABLE_ROOT: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_SFENCE_REQUIRED: AtomicBool = AtomicBool::new(false);
const SATP_ASID_SHIFT: usize = 44;
const SATP_ASID_MASK: usize = 0xffff;
const ASID_MASK_UNINITIALIZED: usize = usize::MAX;
static HARDWARE_ASID_MASK: AtomicUsize = AtomicUsize::new(ASID_MASK_UNINITIALIZED);

/// Allows the current CPU to respond to interrupts.
#[inline]
pub fn enable_irqs() {
    unsafe { sstatus::set_sie() }
}

/// Enable user memory access in supervisor mode (SUM).
#[inline]
pub fn enable_user_access() {
    unsafe { sstatus::set_sum() }
}

/// Disable supervisor access to user memory (SUM).
#[inline]
pub fn disable_user_access() {
    unsafe { sstatus::clear_sum() }
}

/// Returns whether supervisor access to user memory is enabled.
#[inline]
pub fn user_access_enabled() -> bool {
    sstatus::read().sum()
}

/// Makes the current CPU to ignore interrupts.
#[inline]
pub fn disable_irqs() {
    unsafe { sstatus::clear_sie() }
}

/// Returns whether the current CPU is allowed to respond to interrupts.
#[inline]
pub fn irqs_enabled() -> bool {
    sstatus::read().sie()
}

/// Relaxes the current CPU and waits for interrupts.
///
/// It must be called with interrupts enabled, otherwise it will never return.
#[inline]
pub fn wait_for_irqs() {
    riscv::asm::wfi()
}

/// Waits for a locally enabled interrupt while the global SIE bit is clear.
///
/// RISC-V requires WFI wakeup to be independent of the global interrupt-enable
/// bit. Keeping SIE clear lets an idle loop check its run queue and enter WFI
/// without losing an interrupt in between; the caller handles the pending
/// interrupt after restoring SIE.
#[inline]
pub fn wait_for_irqs_disabled() {
    debug_assert!(!irqs_enabled());
    riscv::asm::wfi()
}

/// Halt the current CPU.
#[inline]
pub fn halt() {
    disable_irqs();
    riscv::asm::wfi() // should never return
}

/// Reads the current page table root register for user space (`satp`).
///
/// RISC-V does not have a separate page table root register for user and
/// kernel space, so this operation is the same as [`read_kernel_page_table`].
///
/// Returns the physical address of the page table root.
#[inline]
pub fn read_user_page_table() -> PhysAddr {
    pa!(satp::read().ppn() << 12)
}

/// Returns the address-space ID currently installed in `satp`.
#[inline]
pub fn read_current_asid() -> usize {
    let satp_value: usize;
    unsafe { core::arch::asm!("csrr {}, satp", out(reg) satp_value) };
    (satp_value >> SATP_ASID_SHIFT) & SATP_ASID_MASK
}

/// Returns the mask of ASID bits implemented by the current RISC-V platform.
///
/// A zero mask means that `satp.ASID` is read-only zero and every page-table
/// root switch must be followed by an `SFENCE.VMA`.
#[inline]
pub fn hardware_asid_mask() -> usize {
    match HARDWARE_ASID_MASK.load(Ordering::Acquire) {
        ASID_MASK_UNINITIALIZED => 0,
        mask => mask,
    }
}

/// Returns whether the current RISC-V platform has usable hardware ASIDs.
#[inline]
pub fn has_hardware_asids() -> bool {
    hardware_asid_mask() != 0
}

/// Installs the platform TLB invalidation policy.
///
/// This is configured by `axhal` during platform initialization so the CPU
/// layer does not need a platform-specific Cargo feature.
#[inline]
pub fn set_global_sfence_required(required: bool) {
    GLOBAL_SFENCE_REQUIRED.store(required, Ordering::Release);
}

/// Returns whether the platform requires global RISC-V TLB fences.
#[inline]
pub fn global_sfence_required() -> bool {
    GLOBAL_SFENCE_REQUIRED.load(Ordering::Acquire)
}

unsafe fn detect_hardware_asid_mask() -> usize {
    let original: usize;
    unsafe { core::arch::asm!("csrr {}, satp", out(reg) original) };
    let probe = original | (SATP_ASID_MASK << SATP_ASID_SHIFT);
    unsafe {
        core::arch::asm!("csrw satp, {}", in(reg) probe);
    }
    let probed: usize;
    unsafe { core::arch::asm!("csrr {}, satp", out(reg) probed) };
    unsafe {
        core::arch::asm!("csrw satp, {}", in(reg) original);
    }
    let mask = (probed >> SATP_ASID_SHIFT) & SATP_ASID_MASK;
    asm::sfence_vma_all();
    HARDWARE_ASID_MASK.store(mask, Ordering::Release);
    mask
}

/// Reads the current page table root register for kernel space (`satp`).
///
/// RISC-V does not have a separate page table root register for user and
/// kernel space. The kernel root is therefore recorded when it is installed,
/// so creating a kernel task while a user address space is active does not
/// capture that user's page table.
///
/// Returns the physical address of the page table root.
#[inline]
pub fn read_kernel_page_table() -> PhysAddr {
    let root = KERNEL_PAGE_TABLE_ROOT.load(Ordering::Acquire);
    if root == 0 {
        read_user_page_table()
    } else {
        pa!(root)
    }
}

/// Writes the register to update the current page table root for user space
/// (`satp`).
///
/// RISC-V does not have a separate page table root register for user
/// and kernel space, so this operation is the same as [`write_kernel_page_table`].
///
/// Note that the TLB is **NOT** flushed after this operation.
///
/// # Safety
///
/// This function is unsafe as it changes the virtual memory address space.
#[inline]
pub unsafe fn write_user_page_table(root_paddr: PhysAddr, asid: usize) {
    let hardware_asid = asid & hardware_asid_mask();
    unsafe { satp::set(satp::Mode::Sv39, hardware_asid, root_paddr.as_usize() >> 12) };
}

/// Writes the register to update the current page table root for user space
/// (`satp`).
///
/// RISC-V does not have a separate page table root register for user
/// and kernel space, so this operation is the same as [`write_user_page_table`].
///
/// Note that the TLB is **NOT** flushed after this operation.
///
/// # Safety
///
/// This function is unsafe as it changes the virtual memory address space.
#[inline]
pub unsafe fn write_kernel_page_table(root_paddr: PhysAddr) {
    unsafe { write_user_page_table(root_paddr, 0) };
    KERNEL_PAGE_TABLE_ROOT.store(root_paddr.as_usize(), Ordering::Release);
    if HARDWARE_ASID_MASK.load(Ordering::Acquire) == ASID_MASK_UNINITIALIZED {
        unsafe { detect_hardware_asid_mask() };
    }
}

/// Flushes the TLB.
///
/// If `vaddr` is [`None`], flushes the entire TLB. Otherwise, flushes the TLB
/// entry that maps the given virtual address.
#[inline]
pub fn flush_tlb(vaddr: Option<VirtAddr>) {
    if global_sfence_required() {
        let _ = vaddr;
        asm::sfence_vma_all();
    } else if let Some(vaddr) = vaddr {
        asm::sfence_vma(0, vaddr.as_usize())
    } else {
        asm::sfence_vma_all();
    }
}

/// Flushes non-global TLB entries belonging to the given address-space ID.
#[inline]
pub fn flush_tlb_asid(asid: usize) {
    if global_sfence_required() || !has_hardware_asids() {
        let _ = asid;
        flush_tlb(None)
    } else {
        asm::sfence_vma(asid & hardware_asid_mask(), 0)
    }
}

/// Flushes one virtual-address translation belonging to the given ASID.
#[inline]
pub fn flush_tlb_asid_vaddr(asid: usize, vaddr: VirtAddr) {
    if global_sfence_required() || !has_hardware_asids() {
        let _ = (asid, vaddr);
        flush_tlb(None)
    } else {
        asm::sfence_vma(asid & hardware_asid_mask(), vaddr.as_usize())
    }
}

/// Flushes translations after a `satp` root change when ASID tagging is absent.
#[inline]
pub fn flush_tlb_after_satp_write() {
    if !has_hardware_asids() {
        flush_tlb(None);
    }
}

/// Writes the Supervisor Trap Vector Base Address register (`stvec`).
///
/// # Safety
///
/// This function is unsafe as it changes the exception handling behavior of the
/// current CPU.
#[inline]
pub unsafe fn write_trap_vector_base(stvec: usize) {
    let mut reg = stvec::read();
    reg.set_address(stvec);
    reg.set_trap_mode(stvec::TrapMode::Direct);
    unsafe { stvec::write(reg) }
}

/// Reads the thread pointer of the current CPU (`tp`).
///
/// It is used to implement TLS (Thread Local Storage).
#[inline]
pub fn read_thread_pointer() -> usize {
    let tp;
    unsafe { core::arch::asm!("mv {}, tp", out(reg) tp) };
    tp
}

/// Writes the thread pointer of the current CPU (`tp`).
///
/// It is used to implement TLS (Thread Local Storage).
///
/// # Safety
///
/// This function is unsafe as it changes the CPU states.
#[inline]
pub unsafe fn write_thread_pointer(tp: usize) {
    unsafe { core::arch::asm!("mv tp, {}", in(reg) tp) }
}
