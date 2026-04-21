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
        let page = vaddr.align_down_4k();
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
                        .remap(vaddr, frame, orig_flags)
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
                        .remap(vaddr, new_frame, orig_flags)
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
                error!(
                    "handle_page_fault_alloc: reject=no_alloc_path_matched vaddr={:#x} page={:#x} fault_flags={:?} pte_flags={:?} frame={:#x} backend_populate={}",
                    vaddr,
                    page,
                    orig_flags,
                    old_flags,
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
            // `vaddr` does not need to be aligned. It will be automatically
            // aligned during `pt.remap` regardless of the page size.
            let ok = pt
                .remap(vaddr, frame, orig_flags)
                .map(|(_, tlb)| tlb.flush())
                .is_ok();
            if !ok {
                error!(
                    "handle_page_fault_alloc: reject=query_miss_remap_failed vaddr={:#x} page={:#x} fault_flags={:?} new_frame={:#x} backend_populate={}",
                    vaddr,
                    page,
                    orig_flags,
                    frame,
                    populate
                );
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
