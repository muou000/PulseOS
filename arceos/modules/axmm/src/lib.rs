//! [ArceOS](https://github.com/arceos-org/arceos) memory management module.

#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;

mod aspace;
mod backend;

use axalloc::init_frame_table;
use axerrno::{AxError, AxResult};
use axhal::{
    mem::{MemRegionFlags, PhysMemRegion, phys_to_virt},
    paging::MappingFlags,
};
use kspin::SpinNoIrq;
use lazyinit::LazyInit;
use memory_addr::{MemoryAddr, PhysAddr, VirtAddr, va};
use memory_set::MappingError;

pub use self::{
    aspace::{
        AddrSpace, AddrSpaceCloneResult, AddrSpaceMutation, AddrSpaceUnmapPreparation,
        PageFaultOutcome, PageFaultResult, PageTableLockManager, TlbShootdown,
    },
    backend::{
        AnonPageLoad, AnonPagePrepared, Backend, FilePageLoad, FilePagePrepared, FileWritebacks,
    },
};

static KERNEL_ASPACE: LazyInit<SpinNoIrq<AddrSpace>> = LazyInit::new();

fn mapping_err_to_ax_err(err: MappingError) -> AxError {
    if !matches!(err, MappingError::AlreadyExists) {
        warn!("Mapping error: {err:?}");
    }
    match err {
        MappingError::InvalidParam => AxError::InvalidInput,
        MappingError::AlreadyExists => AxError::AlreadyExists,
        MappingError::BadState => AxError::BadState,
    }
}

fn reg_flag_to_map_flag(f: MemRegionFlags) -> MappingFlags {
    let mut ret = MappingFlags::empty();
    if f.contains(MemRegionFlags::READ) {
        ret |= MappingFlags::READ;
    }
    if f.contains(MemRegionFlags::WRITE) {
        ret |= MappingFlags::WRITE;
    }
    if f.contains(MemRegionFlags::EXECUTE) {
        ret |= MappingFlags::EXECUTE;
    }
    if f.contains(MemRegionFlags::DEVICE) {
        ret |= MappingFlags::DEVICE;
    }
    if f.contains(MemRegionFlags::UNCACHED) {
        ret |= MappingFlags::UNCACHED;
    }
    ret
}

/// Creates a new address space for kernel itself.
pub fn new_kernel_aspace() -> AxResult<AddrSpace> {
    let mut aspace = AddrSpace::new_empty(
        va!(axconfig::plat::KERNEL_ASPACE_BASE),
        axconfig::plat::KERNEL_ASPACE_SIZE,
    )?;
    for r in axhal::mem::memory_regions() {
        // mapped range should contain the whole region if it is not aligned.
        let start = r.paddr.align_down_4k();
        let end = (r.paddr + r.size).align_up_4k();
        aspace.map_linear(
            phys_to_virt(start),
            start,
            end - start,
            reg_flag_to_map_flag(r.flags),
        )?;
    }
    Ok(aspace)
}

/// Creates a new address space for user processes.
pub fn new_user_aspace(base: VirtAddr, size: usize) -> AxResult<AddrSpace> {
    let mut aspace = AddrSpace::new_empty(base, size)?;
    if !cfg!(target_arch = "aarch64") && !cfg!(target_arch = "loongarch64") {
        // ARMv8 (aarch64) and LoongArch64 use separate page tables for user space
        // (aarch64: TTBR0_EL1, LoongArch64: PGDL), so there is no need to copy the
        // kernel portion to the user page table.
        aspace.copy_mappings_from(&kernel_aspace().lock())?;
    }
    Ok(aspace)
}

/// Returns the globally unique kernel address space.
pub fn kernel_aspace() -> &'static SpinNoIrq<AddrSpace> {
    &KERNEL_ASPACE
}

/// Returns the root physical address of the kernel page table.
pub fn kernel_page_table_root() -> PhysAddr {
    KERNEL_ASPACE.lock().page_table_root()
}

/// Increase mapping refcount for a shared frame used by fork COW.
pub fn cow_inc_frame_ref(frame: PhysAddr) {
    backend::cow_inc_frame_ref(frame);
}

/// Decrease mapping refcount for a shared frame used by fork COW.
pub fn cow_dec_frame_ref(frame: PhysAddr) {
    backend::cow_dec_frame_ref(frame);
}

fn frame_table_bounds(
    regions: impl IntoIterator<Item = PhysMemRegion>,
) -> Option<(PhysAddr, PhysAddr)> {
    let mut max_paddr = PhysAddr::from(0);
    let mut min_paddr = PhysAddr::from(usize::MAX);

    for region in regions {
        // The allocator can return every FREE region, including RAM below a
        // platform's main high-memory window. Keep reference counts for all
        // such frames so COW and pinned mappings can release them correctly.
        if !region.flags.contains(MemRegionFlags::FREE) {
            continue;
        }

        let start = region.paddr.align_down_4k();
        let end = (region.paddr + region.size).align_up_4k();
        if start < min_paddr {
            min_paddr = start;
        }
        if end > max_paddr {
            max_paddr = end;
        }
    }

    (max_paddr > min_paddr).then_some((min_paddr, max_paddr))
}

/// Initializes virtual memory management.
///
/// It mainly sets up the kernel virtual memory address space and recreate a
/// fine-grained kernel page table.
pub fn init_memory_management() {
    info!("Initialize virtual memory management...");

    let (min_paddr, max_paddr) =
        frame_table_bounds(axhal::mem::memory_regions()).unwrap_or_else(|| {
            let start = PhysAddr::from(axconfig::plat::PHYS_MEMORY_BASE);
            (start, start + axconfig::plat::PHYS_MEMORY_SIZE)
        });

    let total_memory_size = max_paddr.as_usize() - min_paddr.as_usize();
    info!(
        "FrameTable: range [{:#x}, {:#x}), size {:#x}",
        min_paddr, max_paddr, total_memory_size
    );

    init_frame_table(min_paddr, total_memory_size);

    let kernel_aspace = new_kernel_aspace().expect("failed to initialize kernel address space");
    debug!("kernel address space init OK: {:#x?}", kernel_aspace);
    KERNEL_ASPACE.init_once(SpinNoIrq::new(kernel_aspace));
    unsafe {
        axhal::asm::write_kernel_page_table(kernel_page_table_root());
        axhal::asm::flush_tlb(None);
    }
    #[cfg(target_arch = "riscv64")]
    {
        let hardware_asid_mask = axhal::asm::hardware_asid_mask();
        debug!(
            "RISC-V hardware ASID: {} bits (mask {:#x}), global sfence: {}",
            hardware_asid_mask.count_ones(),
            hardware_asid_mask,
            axhal::asm::global_sfence_required()
        );
    }
}

#[cfg(test)]
mod tests {
    use axhal::mem::PhysMemRegion;
    use memory_addr::PhysAddr;

    use super::frame_table_bounds;

    #[test]
    fn frame_table_bounds_include_discontiguous_free_ram() {
        let low = PhysMemRegion::new_ram(0x1_000, 0x0fff_f000, "low RAM");
        let reserved = PhysMemRegion::new_reserved(0x1000_0000, 0x1000, "mmio hole");
        let high = PhysMemRegion::new_ram(0x8000_0000, 0x1000_0000, "high RAM");

        let (start, end) = frame_table_bounds([low, reserved, high]).unwrap();
        assert_eq!(start, PhysAddr::from(0x1_000));
        assert_eq!(end, PhysAddr::from(0x9000_0000));
    }
}

/// Initializes kernel paging for secondary CPUs.
pub fn init_memory_management_secondary() {
    unsafe {
        axhal::asm::write_kernel_page_table(kernel_page_table_root());
        axhal::asm::flush_tlb(None);
    }
}
