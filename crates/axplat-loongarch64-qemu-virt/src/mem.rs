use axplat::mem::{MemIf, PAGE_SIZE_4K, PhysAddr, RawRange, VirtAddr, pa, va};

use crate::config::devices::MMIO_RANGES;
use crate::config::plat::{PHYS_MEMORY_BASE, PHYS_MEMORY_SIZE, PHYS_VIRT_OFFSET};

const LOW_MEMORY_SIZE: usize = 0x1000_0000;
pub(crate) const RAM_RANGES: [RawRange; 2] = [
    (0, LOW_MEMORY_SIZE),
    (PHYS_MEMORY_BASE, PHYS_MEMORY_SIZE - LOW_MEMORY_SIZE),
];
const RESERVED_RAM_RANGES: [RawRange; 1] = [(0, PAGE_SIZE_4K)];

struct MemIfImpl;

pub const fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
    va!(paddr.as_usize() + PHYS_VIRT_OFFSET)
}

#[impl_plat_interface]
impl MemIf for MemIfImpl {
    /// Returns all physical memory (RAM) ranges on the platform.
    ///
    /// All memory ranges except reserved ranges (including the kernel loaded
    /// range) are free for allocation.
    fn phys_ram_ranges() -> &'static [RawRange] {
        // QEMU virt exposes the first 256 MiB below the MMIO hole and places
        // the remainder at PHYS_MEMORY_BASE.
        &RAM_RANGES
    }

    /// Returns all reserved physical memory ranges on the platform.
    ///
    /// Reserved memory can be contained in [`phys_ram_ranges`], they are not
    /// allocatable but should be mapped to kernel's address space.
    ///
    /// Note that the ranges returned should not include the range where the
    /// kernel is loaded.
    fn reserved_phys_ram_ranges() -> &'static [RawRange] {
        // Empty LoongArch directory entries contain physical address zero.
        // The branchless TLB-refill walk therefore uses PA 0 as its shared
        // invalid lower-level table; it must remain zero and unallocatable.
        &RESERVED_RAM_RANGES
    }

    /// Returns all device memory (MMIO) ranges on the platform.
    fn mmio_ranges() -> &'static [RawRange] {
        &MMIO_RANGES
    }

    fn flush_dcache_range(_paddr: PhysAddr, _size: usize) {}

    /// Translates a physical address to a virtual address.
    fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
        phys_to_virt(paddr)
    }

    /// Translates a virtual address to a physical address.
    fn virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
        pa!(vaddr.as_usize() - PHYS_VIRT_OFFSET)
    }
}
