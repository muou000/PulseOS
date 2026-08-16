//! Helper functions to initialize the CPU states on systems bootstrapping.

use loongArch64::register::{MemoryAccessType, crmd, stlbps, tlbidx, tlbrehi, tlbrentry};
use memory_addr::PhysAddr;
use page_table_multiarch::loongarch64::LA64MetaData;

const DMW_CACHED_BASE: usize = 0x9000_0000_0000_0000;
const DMW_VIRT_MASK: usize = 0x0fff_ffff_ffff_ffff;

unsafe extern "C" {
    fn exception_entry_base();
}

/// Initializes TLB and MMU related registers on the current CPU.
///
/// It sets the TLB Refill exception entry (`TLBRENTY`), page table root address,
/// and finally enables the mapped address translation mode.
///
/// - TLBRENTY: <https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html#tlb-refill-exception-entry-base-address>
/// - CRMD: <https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html#current-mode-information>
pub fn init_mmu(root_paddr: PhysAddr, phys_virt_offset: usize) {
    init_mmu_with_user_root(root_paddr, pa!(0), phys_virt_offset);
}

/// Initializes the MMU with explicit temporary roots for both address halves.
///
/// Most platforms retain a writable page at PA 0 as the invalid lower-half
/// root during early boot. Physical boards whose firmware does not describe PA
/// 0 as RAM can instead provide a self-referential invalid table in their
/// kernel image.
pub fn init_mmu_with_user_root(
    root_paddr: PhysAddr,
    user_root_paddr: PhysAddr,
    phys_virt_offset: usize,
) {
    unsafe extern "C" {
        fn handle_tlb_refill();
    }

    // Configure TLB
    const PS_4K: usize = 0x0c; // Page Size 4KB
    let tlbrentry_addr = handle_tlb_refill as *const () as usize;
    let tlbrentry_paddr = if tlbrentry_addr >= phys_virt_offset {
        pa!(tlbrentry_addr - phys_virt_offset)
    } else {
        pa!(tlbrentry_addr & 0x0fff_ffff_ffff_ffff)
    };
    tlbidx::set_ps(PS_4K);
    stlbps::set_ps(PS_4K);
    tlbrehi::set_ps(PS_4K);
    tlbrentry::set_tlbrentry(tlbrentry_paddr.as_usize());

    // Configure page table walking
    unsafe {
        crate::asm::write_pwc(LA64MetaData::PWCL_VALUE, LA64MetaData::PWCH_VALUE);
        crate::asm::write_kernel_page_table(root_paddr);
        crate::asm::write_user_page_table(user_root_paddr);
    }
    crate::asm::flush_tlb(None);

    // Update CRMD atomically.  In particular, do not expose the intermediate
    // state where direct addressing is disabled before paged translation is
    // enabled: the next instruction fetch can otherwise observe neither
    // translation mode on physical hardware.
    let mut crmd_bits = crmd::read().raw();
    // Firmware may enter a raw U-Boot application at a non-kernel PLV. The
    // bootstrap mappings are PLV0-only, so establish the kernel execution
    // context before the first TLB refill can return to the high mapping.
    // Keep interrupts disabled until the platform installs its own trap entry.
    crmd_bits &= !0b11; // PLV = 0
    crmd_bits &= !(1 << 2); // IE = 0
    crmd_bits &= !(1 << 3); // DA
    crmd_bits |= 1 << 4; // PG
    crmd_bits &= !(0b11 << 5);
    crmd_bits |= (MemoryAccessType::CoherentCached as usize) << 5; // DATF
    crmd_bits &= !(0b11 << 7);
    crmd_bits |= (MemoryAccessType::CoherentCached as usize) << 7; // DATM
    unsafe {
        core::arch::asm!("csrwr {}, 0x0", in(reg) crmd_bits, options(nostack));
    }
}

/// Initializes trap handling on the current CPU.
///
/// In detail, it initializes the exception vector on LoongArch64 platforms.
pub fn init_trap() {
    set_exception_entry(exception_entry_base as *const () as usize);
}

/// Installs the general exception entry while the CPU is still executing
/// through the cached direct-mapped window.
///
/// `EENTRY` is a virtual address for general exceptions. Before paging is
/// enabled, the linked high address must therefore be converted to the same
/// DMW1 alias used by the bootstrap code. Once paging is enabled, callers
/// should use [`init_trap`] so the canonical high virtual address is kept.
pub fn init_trap_early(phys_virt_offset: usize) {
    // This function itself runs through DMW1 before paging is enabled.  A
    // PC-relative function address can therefore already be the DMW alias
    // (`0x9000...`) rather than the linked high-half address.  Subtracting the
    // high-half offset from that alias would add an extra 4 GiB on LS2K1000.
    // Accept either representation, matching the TLB entry conversion below.
    let entry_paddr = exception_entry_paddr(phys_virt_offset);
    set_exception_entry(DMW_CACHED_BASE | entry_paddr);
}

/// Installs the general exception entry in the mapped, canonical kernel
/// address space after paging has been enabled.
///
/// The early entry is a cached DMW alias so that exceptions raised while the
/// bootstrap code is still in direct mode can be serviced.  Once `PG=1`, the
/// same vector is also reachable through the kernel page table; switching
/// EENTRY to that canonical address makes the transition explicit and avoids
/// relying on implementation-specific DMW precedence for general exceptions.
pub fn init_trap_mapped_early(phys_virt_offset: usize) {
    let entry_paddr = exception_entry_paddr(phys_virt_offset);
    set_exception_entry(phys_virt_offset.wrapping_add(entry_paddr));
}

#[inline]
fn exception_entry_paddr(phys_virt_offset: usize) -> usize {
    let entry_addr = exception_entry_base as *const () as usize;
    if entry_addr >= phys_virt_offset {
        entry_addr.wrapping_sub(phys_virt_offset)
    } else {
        entry_addr & DMW_VIRT_MASK
    }
}

fn set_exception_entry(entry: usize) {
    unsafe {
        crate::asm::write_exception_entry_base(entry);
    }
}
