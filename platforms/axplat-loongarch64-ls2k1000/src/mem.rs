use core::sync::atomic::{AtomicBool, Ordering};

mod ranges;
use ranges::{RangeList, RangeStorage};

use axplat::mem::{MemIf, PAGE_SIZE_4K, PhysAddr, RawRange, VirtAddr, pa, va};
use fdt_raw::Fdt;

use crate::{
    config::{
        devices::MMIO_RANGES,
        plat::{PHYS_MEMORY_BASE, PHYS_MEMORY_SIZE, PHYS_VIRT_OFFSET},
    },
    mp_common::firmware_to_phys,
};

const MAX_RAM_RANGES: usize = 8;
const MAX_RESERVED_RANGES: usize = 32;

// Select one complete layout, so repeated initialization cannot mix RAM from
// one invocation with reserved ranges from another. This is a writer claim,
// not a readiness flag; each RangeStorage publishes its own count afterward.
static MEMORY_PUBLICATION_CLAIMED: AtomicBool = AtomicBool::new(false);
static RAM_RANGES: RangeStorage<MAX_RAM_RANGES> = RangeStorage::new();
static RESERVED_RANGES: RangeStorage<MAX_RESERVED_RANGES> = RangeStorage::new();

struct MemIfImpl;

pub(crate) fn ram_ranges() -> &'static [RawRange] {
    let ranges = RAM_RANGES.get();
    assert!(
        !ranges.is_empty(),
        "LS2K1000 RAM was queried before the firmware DTB was parsed"
    );
    ranges
}

pub const fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
    va!(paddr.as_usize() + PHYS_VIRT_OFFSET)
}

#[impl_plat_interface]
impl MemIf for MemIfImpl {
    fn phys_ram_ranges() -> &'static [RawRange] {
        ram_ranges()
    }

    fn reserved_phys_ram_ranges() -> &'static [RawRange] {
        RESERVED_RANGES.get()
    }

    fn mmio_ranges() -> &'static [RawRange] {
        &MMIO_RANGES
    }

    fn flush_dcache_range(_paddr: PhysAddr, _size: usize) {
        unsafe { core::arch::asm!("dbar 0", options(nostack, preserves_flags)) };
    }

    fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
        phys_to_virt(paddr)
    }

    fn virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
        pa!(vaddr.as_usize() - PHYS_VIRT_OFFSET)
    }
}

pub(super) fn init_from_fdt(fdt: &Fdt<'_>, dtb_paddr: usize) {
    let mut ram = RangeList::<MAX_RAM_RANGES>::new();
    let configured_end = PHYS_MEMORY_BASE.saturating_add(PHYS_MEMORY_SIZE);

    for memory in fdt.memory() {
        for region in memory.regions() {
            let (Ok(firmware_start), Ok(size)) = (
                usize::try_from(region.address),
                usize::try_from(region.size),
            ) else {
                continue;
            };
            let Some(start) = firmware_to_phys(firmware_start) else {
                continue;
            };
            let Some(end) = start.checked_add(size) else {
                continue;
            };

            let start = start.max(PHYS_MEMORY_BASE);
            let end = end.min(configured_end);
            if start < end && !ram.push((start, end - start)) {
                warn!("too many LS2K1000 DTB RAM ranges; ignoring [{start:#x}, {end:#x})");
            }
        }
    }
    ram.normalize();

    assert!(
        !ram.is_empty(),
        "LS2K1000 DTB contains no usable RAM in the configured address envelope"
    );

    let mut candidates = RangeList::<MAX_RESERVED_RANGES>::new();
    assert!(
        candidates.push((dtb_paddr, fdt.header().totalsize as usize)),
        "DTB reserved-memory range capacity exhausted"
    );

    for reservation in fdt.memory_reservations() {
        assert!(
            push_u64_range(&mut candidates, reservation.address, reservation.size),
            "invalid or excessive DTB memreserve entry"
        );
    }

    for node in fdt.reserved_memory() {
        if let Some(regions) = node.reg() {
            for region in regions {
                if let Some(size) = region.size {
                    assert!(
                        push_u64_range(&mut candidates, region.address, size),
                        "invalid or excessive /reserved-memory entry"
                    );
                }
            }
        }
    }

    let mut reserved = RangeList::<MAX_RESERVED_RANGES>::new();
    for candidate in candidates.as_slice() {
        let aligned = align_reserved(*candidate).expect("invalid DTB reserved-memory range");
        for ram_range in ram.as_slice() {
            if let Some(intersection) = intersect(aligned, *ram_range) {
                assert!(
                    reserved.push(intersection),
                    "DTB reserved-memory intersection capacity exhausted"
                );
            }
        }
    }
    reserved.normalize();

    publish_memory_layout(ram, reserved);
}

fn publish_memory_layout(
    mut ram: RangeList<MAX_RAM_RANGES>,
    mut reserved: RangeList<MAX_RESERVED_RANGES>,
) {
    // The BSP reaches this via init_early -> init_platform_from_dtb ->
    // init_from_fdt, before starting secondary CPUs. Keep repeated calls
    // harmless too; RangeStorage enforces one-time writes for its safe API.
    if MEMORY_PUBLICATION_CLAIMED.swap(true, Ordering::Relaxed) {
        return;
    }
    ram.normalize();
    reserved.normalize();
    RAM_RANGES.publish(&ram);
    RESERVED_RANGES.publish(&reserved);
}

fn push_u64_range<const N: usize>(ranges: &mut RangeList<N>, start: u64, size: u64) -> bool {
    let (Ok(firmware_start), Ok(size)) = (usize::try_from(start), usize::try_from(size)) else {
        return false;
    };
    let Some(start) = firmware_to_phys(firmware_start) else {
        return false;
    };
    start.checked_add(size).is_some() && ranges.push((start, size))
}

fn align_reserved((start, size): RawRange) -> Option<RawRange> {
    let end = start.checked_add(size)?;
    let aligned_start = start & !(PAGE_SIZE_4K - 1);
    let aligned_end = end.checked_add(PAGE_SIZE_4K - 1)? & !(PAGE_SIZE_4K - 1);
    (aligned_start < aligned_end).then_some((aligned_start, aligned_end - aligned_start))
}

fn intersect((a_start, a_size): RawRange, (b_start, b_size): RawRange) -> Option<RawRange> {
    let start = a_start.max(b_start);
    let end = a_start
        .checked_add(a_size)?
        .min(b_start.checked_add(b_size)?);
    (start < end).then_some((start, end - start))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligns_and_intersects_reserved_ranges() {
        let aligned = align_reserved((0x0a00_0123, 0x1000)).unwrap();
        assert_eq!(aligned, (0x0a00_0000, 0x2000));
        assert_eq!(
            intersect(aligned, (0x0a00_1000, 0x1000)),
            Some((0x0a00_1000, 0x1000))
        );
    }
}
