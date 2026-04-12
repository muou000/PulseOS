use alloc::collections::BTreeMap;
use axalloc::global_allocator;
use axhal::mem::{phys_to_virt, virt_to_phys};
use axhal::paging::{MappingFlags, PageSize, PageTable};
use kspin::SpinNoIrq;
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, PageIter4K, PhysAddr, VirtAddr};

use super::Backend;

static FRAME_REFS: SpinNoIrq<BTreeMap<usize, usize>> = SpinNoIrq::new(BTreeMap::new());

pub(crate) fn cow_inc_frame_ref(frame: PhysAddr) {
    let key = frame.as_usize();
    let mut refs = FRAME_REFS.lock();
    refs.entry(key).and_modify(|c| *c += 1).or_insert(2);
}

fn drop_frame_mapping_ref(frame: PhysAddr) -> bool {
    let key = frame.as_usize();
    let mut refs = FRAME_REFS.lock();
    match refs.get_mut(&key) {
        Some(cnt) if *cnt > 1 => {
            *cnt -= 1;
            false
        }
        Some(_) => {
            refs.remove(&key);
            true
        }
        None => true,
    }
}

pub(super) fn alloc_frame(zeroed: bool) -> Option<PhysAddr> {
    let vaddr = VirtAddr::from(global_allocator().alloc_pages(1, PAGE_SIZE_4K).ok()?);
    if zeroed {
        unsafe { core::ptr::write_bytes(vaddr.as_mut_ptr(), 0, PAGE_SIZE_4K) };
    }
    let paddr = virt_to_phys(vaddr);
    Some(paddr)
}

pub(super) fn dealloc_frame(frame: PhysAddr) {
    if !drop_frame_mapping_ref(frame) {
        return;
    }
    let vaddr = phys_to_virt(frame);
    global_allocator().dealloc_pages(vaddr.as_usize(), 1);
}

impl Backend {
    /// Creates a new allocation mapping backend.
    pub const fn new_alloc(populate: bool) -> Self {
        Self::Alloc { populate }
    }

    pub(crate) fn map_alloc(
        &self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        pt: &mut PageTable,
        populate: bool,
    ) -> bool {
        debug!(
            "map_alloc: [{:#x}, {:#x}) {:?} (populate={})",
            start,
            start + size,
            flags,
            populate
        );
        if populate {
            // allocate all possible physical frames for populated mapping.
            for addr in PageIter4K::new(start, start + size).unwrap() {
                if let Some(frame) = alloc_frame(true) {
                    if let Ok(tlb) = pt.map(addr, frame, PageSize::Size4K, flags) {
                        tlb.ignore(); // TLB flush on map is unnecessary, as there are no outdated mappings.
                    } else {
                        return false;
                    }
                }
            }
            true
        } else {
            // Map to a empty entry for on-demand mapping.
            let flags = MappingFlags::empty();
            pt.map_region(start, |_| 0.into(), size, flags, false, false)
                .map(|tlb| tlb.ignore())
                .is_ok()
        }
    }

    pub(crate) fn unmap_alloc(
        &self,
        start: VirtAddr,
        size: usize,
        pt: &mut PageTable,
        _populate: bool,
    ) -> bool {
        debug!("unmap_alloc: [{:#x}, {:#x})", start, start + size);
        for addr in PageIter4K::new(start, start + size).unwrap() {
            if let Ok((frame, page_size, tlb)) = pt.unmap(addr) {
                // Deallocate the physical frame if there is a mapping in the
                // page table.
                if page_size.is_huge() {
                    return false;
                }
                tlb.flush();
                dealloc_frame(frame);
            } else {
                // Deallocation is needn't if the page is not mapped.
            }
        }
        true
    }

    pub(crate) fn handle_page_fault_alloc(
        &self,
        vaddr: VirtAddr,
        orig_flags: MappingFlags,
        pt: &mut PageTable,
        populate: bool,
    ) -> bool {
        if let Ok((old_frame, old_flags, _)) = pt.query(vaddr.align_down_4k()) {
            // Lazy anonymous mappings install an empty placeholder PTE first.
            // Their first access should allocate a fresh zeroed frame rather
            // than taking the COW path.
            //
            // Note: mprotect() may update placeholder PTE flags before the
            // first access, so `old_flags` can become non-empty while the
            // backing frame is still absent (old_frame == 0).
            if old_flags.is_empty() || old_frame.as_usize() == 0 {
                if populate {
                    return false;
                }
                if let Some(frame) = alloc_frame(true) {
                    return pt
                        .remap(vaddr, frame, orig_flags)
                        .map(|(_, tlb)| tlb.flush())
                        .is_ok();
                }
                return false;
            }

            if orig_flags.contains(MappingFlags::WRITE) && !old_flags.contains(MappingFlags::WRITE) {
                if let Some(new_frame) = alloc_frame(false) {
                    let src = phys_to_virt(old_frame).as_ptr() as *const u8;
                    let dst = phys_to_virt(new_frame).as_mut_ptr() as *mut u8;
                    unsafe {
                        core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE_4K);
                    }

                    if pt
                        .remap(vaddr, new_frame, orig_flags)
                        .map(|(_, tlb)| tlb.flush())
                        .is_ok()
                    {
                        dealloc_frame(old_frame);
                        true
                    } else {
                        dealloc_frame(new_frame);
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else if populate {
            false
        } else if let Some(frame) = alloc_frame(true) {
            // Allocate a physical frame lazily and map it to the fault address.
            // `vaddr` does not need to be aligned. It will be automatically
            // aligned during `pt.remap` regardless of the page size.
            pt.remap(vaddr, frame, orig_flags)
                .map(|(_, tlb)| tlb.flush())
                .is_ok()
        } else {
            false
        }
    }
}
