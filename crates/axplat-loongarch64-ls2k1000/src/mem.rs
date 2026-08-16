use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

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

static MEMORY_INITIALIZED: AtomicBool = AtomicBool::new(false);
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
    if MEMORY_INITIALIZED.swap(true, Ordering::AcqRel) {
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

struct RangeStorage<const N: usize> {
    ranges: UnsafeCell<[RawRange; N]>,
    count: AtomicUsize,
}

unsafe impl<const N: usize> Sync for RangeStorage<N> {}

impl<const N: usize> RangeStorage<N> {
    const fn new() -> Self {
        Self {
            ranges: UnsafeCell::new([(0, 0); N]),
            count: AtomicUsize::new(0),
        }
    }

    fn publish(&self, ranges: &RangeList<N>) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                ranges.as_slice().as_ptr(),
                self.ranges.get().cast::<RawRange>(),
                ranges.len(),
            )
        };
        self.count.store(ranges.len(), Ordering::Release);
    }

    fn get(&'static self) -> &'static [RawRange] {
        let count = self.count.load(Ordering::Acquire);
        unsafe { core::slice::from_raw_parts((*self.ranges.get()).as_ptr(), count) }
    }
}

#[derive(Clone, Copy)]
struct RangeList<const N: usize> {
    ranges: [RawRange; N],
    count: usize,
}

impl<const N: usize> RangeList<N> {
    const fn new() -> Self {
        Self {
            ranges: [(0, 0); N],
            count: 0,
        }
    }

    fn push(&mut self, range: RawRange) -> bool {
        if range.1 == 0 {
            return true;
        }
        if self.count < N {
            self.ranges[self.count] = range;
            self.count += 1;
            true
        } else {
            false
        }
    }

    fn normalize(&mut self) {
        self.ranges[..self.count].sort_unstable_by_key(|range| range.0);
        let mut output = 0usize;
        for input in 0..self.count {
            let (start, size) = self.ranges[input];
            let Some(end) = start.checked_add(size) else {
                continue;
            };
            if output > 0 {
                let (previous_start, previous_size) = self.ranges[output - 1];
                let previous_end = previous_start.saturating_add(previous_size);
                if start <= previous_end {
                    self.ranges[output - 1].1 = previous_end.max(end) - previous_start;
                    continue;
                }
            }
            self.ranges[output] = (start, end - start);
            output += 1;
        }
        self.count = output;
    }

    const fn is_empty(&self) -> bool {
        self.count == 0
    }

    const fn len(&self) -> usize {
        self.count
    }

    fn as_slice(&self) -> &[RawRange] {
        &self.ranges[..self.count]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_discontiguous_ls2k1000_ranges() {
        let mut ranges = RangeList::<4>::new();
        assert!(ranges.push((0x0020_0000, 0x0fe0_0000)));
        assert!(ranges.push((0x9000_0000, 0x3000_0000)));
        ranges.normalize();
        assert_eq!(
            ranges.as_slice(),
            &[(0x0020_0000, 0x0fe0_0000), (0x9000_0000, 0x3000_0000)]
        );
    }

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
