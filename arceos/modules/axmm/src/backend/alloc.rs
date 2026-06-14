use axalloc::global_allocator;
use axhal::mem::{phys_to_virt, virt_to_phys};
use axhal::paging::{MappingFlags, PageSize, PageTable};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, PageIter4K, PhysAddr, VirtAddr};

use super::Backend;
use crate::frameinfo::frame_table;

pub(crate) fn cow_inc_frame_ref(frame: PhysAddr) {
    frame_table().inc_ref(frame);
}

pub(crate) fn cow_dec_frame_ref(frame: PhysAddr) -> bool {
    drop_frame_mapping_ref(frame)
}

pub(crate) fn cow_mark_frame_used(frame: PhysAddr) {
    frame_table().mark_used(frame);
}

fn drop_frame_mapping_ref(frame: PhysAddr) -> bool {
    frame_table().dec_ref(frame) == 0
}

pub(crate) trait ProtectPageTable {
    fn query_page(&self, page: VirtAddr) -> Option<(PhysAddr, MappingFlags)>;
    fn protect_page(&mut self, page: VirtAddr, new_flags: MappingFlags) -> bool;
}

impl ProtectPageTable for PageTable {
    fn query_page(&self, page: VirtAddr) -> Option<(PhysAddr, MappingFlags)> {
        self.query(page).ok().map(|(frame, old_flags, _)| (frame, old_flags))
    }

    fn protect_page(&mut self, page: VirtAddr, new_flags: MappingFlags) -> bool {
        self.protect(page, new_flags)
            .map(|(_, tlb)| tlb.ignore())
            .is_ok()
    }
}

pub(crate) fn protect_pages<P>(
    start: VirtAddr,
    size: usize,
    new_flags: MappingFlags,
    allow_missing: bool,
    allow_placeholder: bool,
    pt: &mut P,
) -> bool
where
    P: ProtectPageTable,
{
    for page in PageIter4K::new(start, start + size).unwrap() {
        let Some((frame, _old_flags)) = pt.query_page(page) else {
            if allow_missing {
                continue;
            }
            error!(
                "protect_pages: missing page in populated mapping: {:#x}, {:?}",
                page, new_flags
            );
            return false;
        };

        if frame.as_usize() == 0 {
            if allow_placeholder {
                continue;
            }
            error!(
                "protect_pages: placeholder page in populated mapping: {:#x}, {:?}",
                page, new_flags
            );
            return false;
        }

        if !pt.protect_page(page, new_flags) {
            error!(
                "protect_pages: failed to protect page: {:#x}, {:?}",
                page, new_flags
            );
            return false;
        }
    }

    true
}
pub(super) fn alloc_frame(zeroed: bool) -> Option<PhysAddr> {
    let vaddr = VirtAddr::from(global_allocator().alloc_pages(1, PAGE_SIZE_4K).ok()?);
    if zeroed {
        unsafe { core::ptr::write_bytes(vaddr.as_mut_ptr(), 0, PAGE_SIZE_4K) };
    }
    let paddr = virt_to_phys(vaddr);
    cow_mark_frame_used(paddr);
    Some(paddr)
}

pub(super) fn dealloc_frame(frame: PhysAddr) {
    if !cow_dec_frame_ref(frame) {
        return;
    }
    global_allocator().dealloc_pages(phys_to_virt(frame).as_usize(), 1);
}

impl Backend {
    /// Creates a new allocation mapping backend.
    pub const fn new_alloc(populate: bool) -> Self {
        Self::Alloc { populate, grows_down: false }
    }

    /// Creates a new allocation mapping backend that grows down.
    pub const fn new_alloc_grows_down(populate: bool, grows_down: bool) -> Self {
        Self::Alloc { populate, grows_down }
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
            let mut mapped_pages = 0usize;
            for addr in PageIter4K::new(start, start + size).unwrap() {
                let Some(frame) = alloc_frame(true) else {
                    if mapped_pages != 0 {
                        let _ = self.unmap_alloc(start, mapped_pages * PAGE_SIZE_4K, pt, true);
                    }
                    return false;
                };
                if let Ok(tlb) = pt.map(addr, frame, PageSize::Size4K, flags) {
                    tlb.ignore(); // TLB flush on map is unnecessary, as there are no outdated mappings.
                    mapped_pages += 1;
                } else {
                    dealloc_frame(frame);
                    if mapped_pages != 0 {
                        let _ = self.unmap_alloc(start, mapped_pages * PAGE_SIZE_4K, pt, true);
                    }
                    return false;
                }
            }
            true
        } else {
            // Keep only the virtual area metadata. Physical frames and the
            // backing page-table entries will both be instantiated on demand
            // in the page-fault path, which avoids consuming page-table pages
            // for large untouched mappings such as pthread stacks.
            let _ = (start, size, pt);
            true
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
                if frame.as_usize() != 0 {
                    dealloc_frame(frame);
                }
            } else {
                // Deallocation is needn't if the page is not mapped.
            }
        }
        true
    }

    pub(crate) fn handle_page_fault_alloc(
        &self,
        vaddr: VirtAddr,
        area_end: VirtAddr,
        orig_flags: MappingFlags,
        pt: &mut PageTable,
        populate: bool,
    ) -> bool {
        let page = vaddr.align_down_4k();
        let query_res = pt.query(page);
        let is_placeholder = match query_res {
            Ok((old_frame, old_flags, _)) => old_flags.is_empty() || old_frame.as_usize() == 0,
            _ => false,
        };
        let is_unmapped = query_res.is_err();

        if (is_unmapped || is_placeholder) && !populate {
            let mut current_page = page;
            let mut handled_any = false;
            for _ in 0..4 {
                if current_page >= area_end {
                    break;
                }
                let cur_query = pt.query(current_page);
                let need_map = match cur_query {
                    Err(_) => Some(true),
                    Ok((frame, _, _)) if frame.as_usize() == 0 => Some(false),
                    _ => None,
                };
                if let Some(is_map) = need_map {
                    if let Some(frame) = alloc_frame(true) {
                        let ok = if is_map {
                            pt.map(current_page, frame, PageSize::Size4K, orig_flags)
                                .map(|tlb| tlb.flush())
                                .is_ok()
                        } else {
                            pt.remap(current_page, frame, orig_flags)
                                .map(|(_, tlb)| tlb.flush())
                                .is_ok()
                        };
                        if ok {
                            handled_any = true;
                        } else {
                            dealloc_frame(frame);
                            break;
                        }
                    } else {
                        break;
                    }
                }
                current_page += PAGE_SIZE_4K;
            }
            return handled_any;
        }
        if let Ok((old_frame, old_flags, _)) = pt.query(page) {
            // Lazy anonymous mappings install an empty placeholder PTE first.
            // Their first access should allocate a fresh zeroed frame rather
            // than taking the COW path.
            //
            // Note: mprotect() may update placeholder PTE flags before the
            // first access, so `old_flags` can become non-empty while the
            // backing frame is still absent (old_frame == 0).
            if old_flags.is_empty() || old_frame.as_usize() == 0 {
                if populate {
                    debug!(
                        "handle_page_fault_alloc: reject=placeholder_in_populated_mapping vaddr={:#x} page={:#x} fault_flags={:?} pte_flags={:?} frame={:#x} backend_populate={}",
                        vaddr,
                        page,
                        orig_flags,
                        old_flags,
                        old_frame,
                        populate
                    );
                    return false;
                }
                if let Some(frame) = alloc_frame(true) {
                    let ok = pt
                        .remap(page, frame, orig_flags)
                        .map(|(_, tlb)| tlb.flush())
                        .is_ok();
                    if !ok {
                        debug!(
                            "handle_page_fault_alloc: reject=placeholder_remap_failed vaddr={:#x} page={:#x} fault_flags={:?} pte_flags={:?} old_frame={:#x} new_frame={:#x} backend_populate={}",
                            vaddr,
                            page,
                            orig_flags,
                            old_flags,
                            old_frame,
                            frame,
                            populate
                        );
                        dealloc_frame(frame);
                    }
                    return ok;
                }
                error!(
                    "handle_page_fault_alloc: reject=placeholder_alloc_failed vaddr={:#x} page={:#x} fault_flags={:?} pte_flags={:?} frame={:#x} backend_populate={}",
                    vaddr,
                    page,
                    orig_flags,
                    old_flags,
                    old_frame,
                    populate
                );
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
                        .remap(page, new_frame, orig_flags)
                        .map(|(_, tlb)| tlb.flush())
                        .is_ok()
                    {
                        dealloc_frame(old_frame);
                        true
                    } else {
                        error!(
                            "handle_page_fault_alloc: reject=cow_remap_failed vaddr={:#x} page={:#x} fault_flags={:?} pte_flags={:?} old_frame={:#x} new_frame={:#x} backend_populate={}",
                            vaddr,
                            page,
                            orig_flags,
                            old_flags,
                            old_frame,
                            new_frame,
                            populate
                        );
                        dealloc_frame(new_frame);
                        false
                    }
                } else {
                    error!(
                        "handle_page_fault_alloc: reject=cow_alloc_failed vaddr={:#x} page={:#x} fault_flags={:?} pte_flags={:?} frame={:#x} backend_populate={}",
                        vaddr,
                        page,
                        orig_flags,
                        old_flags,
                        old_frame,
                        populate
                    );
                    false
                }
            } else {
                // PTE already has the requested R/W/X permissions or the
                // access doesn't require a write upgrade. Check if any other
                // flags need upgrading (e.g., USER flag for PagePrivilegeIllegal
                // handling on loongarch64).
                let new_flags = old_flags | orig_flags;
                if pt
                    .remap(page, old_frame, new_flags)
                    .map(|(_, tlb)| tlb.flush())
                    .is_ok()
                {
                    return true;
                }
                error!(
                    "handle_page_fault_alloc: reject=flag_upgrade_remap_failed vaddr={:#x} page={:#x} fault_flags={:?} pte_flags={:?} new_flags={:?} frame={:#x} backend_populate={}",
                    vaddr,
                    page,
                    orig_flags,
                    old_flags,
                    new_flags,
                    old_frame,
                    populate
                );
                false
            }
        } else if populate {
            error!(
                "handle_page_fault_alloc: reject=query_miss_in_populated_mapping vaddr={:#x} page={:#x} fault_flags={:?} backend_populate={}",
                vaddr,
                page,
                orig_flags,
                populate
            );
            false
        } else if let Some(frame) = alloc_frame(true) {
            // Allocate a physical frame lazily and map it to the fault address.
            // `vaddr` does not need to be aligned. `pt.map()` will create the
            // intermediate page-table levels on demand for true lazy mappings.
            let ok = pt
                .map(page, frame, PageSize::Size4K, orig_flags)
                .map(|tlb| tlb.flush())
                .is_ok();
            if !ok {
                error!(
                    "handle_page_fault_alloc: reject=query_miss_map_failed vaddr={:#x} page={:#x} fault_flags={:?} new_frame={:#x} backend_populate={}",
                    vaddr,
                    page,
                    orig_flags,
                    frame,
                    populate
                );
                dealloc_frame(frame);
            }
            ok
        } else {
            error!(
                "handle_page_fault_alloc: reject=query_miss_alloc_failed vaddr={:#x} page={:#x} fault_flags={:?} backend_populate={}",
                vaddr,
                page,
                orig_flags,
                populate
            );
            false
        }
    }

    pub(crate) fn protect_alloc(
        &self,
        start: VirtAddr,
        size: usize,
        new_flags: MappingFlags,
        pt: &mut PageTable,
        populate: bool,
    ) -> bool {
        debug!(
            "protect_alloc: [{:#x}, {:#x}) {:?} (populate={})",
            start,
            start + size,
            new_flags,
            populate
        );
        protect_pages(start, size, new_flags, !populate, !populate, pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cow_refcount_roundtrip() {
        let frame = PhysAddr::from(axconfig::plat::PHYS_MEMORY_BASE);
        // Note: FRAME_TABLE should be initialized before running this test.
        // In a real test environment, this might need more setup.
        
        frame_table().get_ref(frame); // ensure it doesn't panic if initialized

        cow_inc_frame_ref(frame); // 0 -> 1 -> 2
        assert_eq!(frame_table().get_ref(frame), 2);

        assert!(!cow_dec_frame_ref(frame)); // 2 -> 1
        assert_eq!(frame_table().get_ref(frame), 1);

        assert!(cow_dec_frame_ref(frame)); // 1 -> 0
        assert_eq!(frame_table().get_ref(frame), 0);
    }
}
