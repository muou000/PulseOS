//! RISC-V specific page table structures.

use core::sync::atomic::{AtomicBool, Ordering};

use page_table_entry::riscv::Rv64PTE;

use crate::{PageTable64, PagingMetaData};

static GLOBAL_SFENCE_REQUIRED: AtomicBool = AtomicBool::new(false);

/// Installs the platform TLB invalidation policy.
///
/// The generic page-table crate cannot depend on a platform crate, so the
/// architecture-specific policy is configured by the owning HAL at boot.
#[inline]
pub fn set_global_sfence_required(required: bool) {
    GLOBAL_SFENCE_REQUIRED.store(required, Ordering::Release);
}

#[inline]
fn riscv_flush_tlb(vaddr: Option<memory_addr::VirtAddr>) {
    if GLOBAL_SFENCE_REQUIRED.load(Ordering::Acquire) {
        let _ = vaddr;
        unsafe {
            core::arch::asm!("sfence.vma x0, x0");
        }
        return;
    }

    let mut satp_val: usize;
    unsafe {
        core::arch::asm!("csrr {}, satp", out(reg) satp_val);
    }
    let asid = (satp_val >> 44) & 0xffff; // Extract ASID (bits 44-59)
    if let Some(vaddr) = vaddr {
        unsafe {
            core::arch::asm!(
                "sfence.vma {}, {}",
                in(reg) vaddr.as_usize(),
                in(reg) asid
            );
        }
    } else {
        unsafe {
            core::arch::asm!(
                "sfence.vma x0, {}",
                in(reg) asid
            );
        }
    }
}

/// A virtual address that can be used in RISC-V Sv39 and Sv48 page tables.
pub trait SvVirtAddr: memory_addr::MemoryAddr + Send + Sync {
    /// Flush the TLB.
    fn flush_tlb(vaddr: Option<Self>);
}

impl SvVirtAddr for memory_addr::VirtAddr {
    #[inline]
    fn flush_tlb(vaddr: Option<Self>) {
        riscv_flush_tlb(vaddr.map(|vaddr| vaddr.into()))
    }
}

/// Metadata of RISC-V Sv39 page tables.
pub struct Sv39MetaData<VA: SvVirtAddr> {
    _virt_addr: core::marker::PhantomData<VA>,
}

/// Metadata of RISC-V Sv48 page tables.
pub struct Sv48MetaData<VA: SvVirtAddr> {
    _virt_addr: core::marker::PhantomData<VA>,
}

impl<VA: SvVirtAddr> PagingMetaData for Sv39MetaData<VA> {
    const LEVELS: usize = 3;
    const PA_MAX_BITS: usize = 56;
    const VA_MAX_BITS: usize = 39;
    type VirtAddr = VA;

    #[inline]
    fn flush_tlb(vaddr: Option<VA>) {
        <VA as SvVirtAddr>::flush_tlb(vaddr);
    }
}

impl<VA: SvVirtAddr> PagingMetaData for Sv48MetaData<VA> {
    const LEVELS: usize = 4;
    const PA_MAX_BITS: usize = 56;
    const VA_MAX_BITS: usize = 48;
    type VirtAddr = VA;

    #[inline]
    fn flush_tlb(vaddr: Option<VA>) {
        <VA as SvVirtAddr>::flush_tlb(vaddr);
    }
}

/// Sv39: Page-Based 39-bit (3 levels) Virtual-Memory System.
pub type Sv39PageTable<H> = PageTable64<Sv39MetaData<memory_addr::VirtAddr>, Rv64PTE, H>;

/// Sv48: Page-Based 48-bit (4 levels) Virtual-Memory System.
pub type Sv48PageTable<H> = PageTable64<Sv48MetaData<memory_addr::VirtAddr>, Rv64PTE, H>;
