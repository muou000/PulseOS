use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use axplat::mem::{MemIf, PAGE_SIZE_4K, PhysAddr, RawRange, VirtAddr, pa, va};
use fdt_raw::Fdt;

use crate::{
    boot_common::{QEMU_BOOT_INFO_SIZE, QEMU_FDT_MAX_SIZE, QEMU_LOW_MEMORY_SIZE},
    config::{
        devices::MMIO_RANGES,
        plat::{PHYS_MEMORY_BASE, PHYS_MEMORY_SIZE, PHYS_VIRT_OFFSET},
    },
};

const MAX_RAM_RANGES: usize = 8;
const MAX_RESERVED_RANGES: usize = 32;
const LOW_MEMORY_SIZE: usize = QEMU_LOW_MEMORY_SIZE;
const HIGH_MEMORY_SIZE: usize = PHYS_MEMORY_SIZE - LOW_MEMORY_SIZE;
const FALLBACK_RAM_RANGES: [RawRange; 2] =
    [(0, LOW_MEMORY_SIZE), (PHYS_MEMORY_BASE, HIGH_MEMORY_SIZE)];
const FALLBACK_RESERVED_RANGES: [RawRange; 1] = [(0, QEMU_BOOT_INFO_SIZE + QEMU_FDT_MAX_SIZE)];

static MEMORY_INITIALIZED: AtomicBool = AtomicBool::new(false);
static RAM_RANGES: RangeStorage<MAX_RAM_RANGES> = RangeStorage::new();
static RESERVED_RANGES: RangeStorage<MAX_RESERVED_RANGES> = RangeStorage::new();

struct MemIfImpl;

pub(crate) fn ram_ranges() -> &'static [RawRange] {
    let ranges = RAM_RANGES.get();
    if ranges.is_empty() {
        &FALLBACK_RAM_RANGES
    } else {
        ranges
    }
}

fn reserved_ram_ranges() -> &'static [RawRange] {
    let ranges = RESERVED_RANGES.get();
    if ranges.is_empty() {
        &FALLBACK_RESERVED_RANGES
    } else {
        ranges
    }
}

pub const fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
    va!(paddr.as_usize() + PHYS_VIRT_OFFSET)
}

#[impl_plat_interface]
impl MemIf for MemIfImpl {
    /// Returns all physical memory (RAM) ranges on the platform.
    fn phys_ram_ranges() -> &'static [RawRange] {
        ram_ranges()
    }

    /// Returns all reserved physical memory ranges on the platform.
    fn reserved_phys_ram_ranges() -> &'static [RawRange] {
        // QEMU direct kernel boot keeps [0, 1 MiB) as boot-info ROM and
        // reserves the next 1 MiB for the live FDT. Its first page is also the
        // invalid lower-level table used by TLB refill.
        reserved_ram_ranges()
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

pub(super) fn init_fallback() {
    let mut ram = RangeList::<MAX_RAM_RANGES>::new();
    for range in FALLBACK_RAM_RANGES {
        assert!(ram.push(range), "fallback RAM range capacity exhausted");
    }
    let mut reserved = RangeList::<MAX_RESERVED_RANGES>::new();
    assert!(
        reserved.push(FALLBACK_RESERVED_RANGES[0]),
        "fallback reserved-memory range capacity exhausted"
    );
    publish_memory_layout(ram, reserved);
}

pub(super) fn init_from_fdt(fdt: &Fdt<'_>, dtb_paddr: usize) {
    let mut ram = RangeList::<MAX_RAM_RANGES>::new();
    for memory in fdt.memory() {
        for region in memory.regions() {
            let (Ok(start), Ok(size)) = (
                usize::try_from(region.address),
                usize::try_from(region.size),
            ) else {
                continue;
            };
            push_fdt_ram_range(&mut ram, start, size);
        }
    }
    ram.normalize();
    if ram.is_empty() {
        warn!("DTB contains no usable QEMU virt RAM ranges; using configured defaults");
        init_fallback();
        return;
    }

    let mut candidates = RangeList::<MAX_RESERVED_RANGES>::new();
    // Keep QEMU's direct-boot ROM and live DTB ahead of firmware-provided
    // entries so fixed capacity can never make either range allocatable.
    assert!(
        candidates.push(FALLBACK_RESERVED_RANGES[0]),
        "DTB reserved-memory range capacity exhausted"
    );
    assert!(
        candidates.push((dtb_paddr, fdt.header().totalsize as usize)),
        "DTB reserved-memory range capacity exhausted"
    );
    for reservation in fdt.memory_reservations() {
        assert!(
            push_u64_range(&mut candidates, reservation.address, reservation.size),
            "invalid or excessive DTB memreserve entries"
        );
    }
    for node in fdt.reserved_memory() {
        if let Some(regions) = node.reg() {
            for region in regions {
                if let Some(size) = region.size {
                    assert!(
                        push_u64_range(&mut candidates, region.address, size),
                        "invalid or excessive /reserved-memory entries"
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

fn push_fdt_ram_range(ram: &mut RangeList<MAX_RAM_RANGES>, start: usize, size: usize) {
    let Some(end) = start.checked_add(size) else {
        warn!("ignoring overflowing DTB RAM range [{start:#x}, size={size:#x}]");
        return;
    };

    for allowed in FALLBACK_RAM_RANGES {
        if let Some(intersection) = intersect((start, end - start), allowed) {
            if !ram.push(intersection) {
                warn!(
                    "too many DTB RAM ranges; ignoring [{:#x}, {:#x})",
                    intersection.0,
                    intersection.0 + intersection.1
                );
            }
        }
    }
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
    let (Ok(start), Ok(size)) = (usize::try_from(start), usize::try_from(size)) else {
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

// SAFETY: the BSP writes each storage once before publishing count with Release;
// all later accesses are immutable and load count with Acquire.
unsafe impl<const N: usize> Sync for RangeStorage<N> {}

impl<const N: usize> RangeStorage<N> {
    const fn new() -> Self {
        Self {
            ranges: UnsafeCell::new([(0, 0); N]),
            count: AtomicUsize::new(0),
        }
    }

    fn publish(&self, ranges: &RangeList<N>) {
        // SAFETY: publish_memory_layout permits only the first BSP invocation.
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
        // SAFETY: count is published only after the first count entries are initialized.
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
    fn limits_fdt_memory_to_qemu_ram_windows() {
        let mut ranges = RangeList::<4>::new();

        push_fdt_ram_range(&mut ranges, 0, LOW_MEMORY_SIZE + PAGE_SIZE_4K);
        push_fdt_ram_range(
            &mut ranges,
            PHYS_MEMORY_BASE - PAGE_SIZE_4K,
            PAGE_SIZE_4K * 2,
        );
        ranges.normalize();

        assert_eq!(
            ranges.as_slice(),
            &[(0, LOW_MEMORY_SIZE), (PHYS_MEMORY_BASE, PAGE_SIZE_4K)]
        );
    }

    #[test]
    fn normalizes_unsorted_overlapping_ranges() {
        let mut ranges = RangeList::<4>::new();
        assert!(ranges.push((0x3000, 0x1000)));
        assert!(ranges.push((0x1000, 0x1800)));
        assert!(ranges.push((0x2000, 0x2000)));
        ranges.normalize();
        assert_eq!(ranges.as_slice(), &[(0x1000, 0x3000)]);
    }

    #[test]
    fn aligns_and_intersects_reserved_ranges() {
        let aligned = align_reserved((0x1801, 0x1000)).unwrap();
        assert_eq!(aligned, (0x1000, 0x2000));
        assert_eq!(intersect(aligned, (0x2000, 0x1000)), Some((0x2000, 0x1000)));
    }

    #[test]
    fn fallback_reserves_qemu_boot_info_and_fdt_slot() {
        assert_eq!(
            FALLBACK_RESERVED_RANGES,
            [(0, QEMU_BOOT_INFO_SIZE + QEMU_FDT_MAX_SIZE)]
        );
    }
}
