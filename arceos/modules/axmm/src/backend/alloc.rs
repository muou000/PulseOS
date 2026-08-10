use alloc::vec::Vec;
use axalloc::global_allocator;
use axerrno::{AxError, AxResult};
use axhal::mem::{flush_dcache_range, phys_to_virt, virt_to_phys};
use axhal::paging::{MappingFlags, PageSize, PageTable};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, PageIter4K, PhysAddr, VirtAddr};
use memory_set::MappingMutation;

use super::Backend;
use axalloc::frame_table;

const MAX_FAULT_BATCH_PAGES: usize = 4;

#[derive(Debug)]
pub struct AnonPageLoad {
    page: VirtAddr,
    page_count: usize,
}

impl AnonPageLoad {
    pub fn prepare(self) -> AxResult<AnonPagePrepared> {
        let requested_pages = self.page_count;
        let (frames, page_count) =
            alloc_frame_batch(requested_pages, true).ok_or(AxError::NoMemory)?;
        for frame in frames.iter().take(page_count) {
            flush_dcache_range(*frame, PAGE_SIZE_4K);
        }
        axfs::buildstorm_stat_add!(MM_ANON_FAULT_PREPARED_PAGES, page_count);
        if page_count < requested_pages {
            axfs::buildstorm_stat_inc!(MM_ANON_FAULT_SHORT_PREPARES);
        }
        Ok(AnonPagePrepared {
            page: self.page,
            frames,
            page_count,
            mapped_mask: 0,
        })
    }
}

pub struct AnonPagePrepared {
    page: VirtAddr,
    frames: [PhysAddr; MAX_FAULT_BATCH_PAGES],
    page_count: usize,
    mapped_mask: u8,
}

impl AnonPagePrepared {
    fn matches(&self, page: VirtAddr) -> bool {
        self.page == page
    }

    fn page_count(&self) -> usize {
        self.page_count
    }

    fn mark_mapped(&mut self, index: usize) {
        debug_assert!(index < self.page_count);
        self.mapped_mask |= 1 << index;
    }

    fn frame(&self, index: usize) -> PhysAddr {
        debug_assert!(index < self.page_count);
        self.frames[index]
    }
}

impl Drop for AnonPagePrepared {
    fn drop(&mut self) {
        for index in 0..self.page_count {
            if self.mapped_mask & (1 << index) == 0 {
                dealloc_frame(self.frame(index));
            }
        }
    }
}

pub(crate) fn cow_inc_frame_ref(frame: PhysAddr) {
    let table = frame_table();
    if table.contains(frame) {
        table.inc_ref(frame);
    }
}

pub(crate) fn cow_dec_frame_ref(frame: PhysAddr) -> bool {
    let table = frame_table();
    if table.contains(frame) {
        table.dec_ref(frame) == 0
    } else {
        false
    }
}

pub(crate) fn cow_mark_frame_used(frame: PhysAddr) {
    let table = frame_table();
    if table.contains(frame) {
        table.mark_used(frame);
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
    mutation: &mut impl MappingMutation<VirtAddr>,
) -> bool
where
    P: ProtectPageTable,
{
    for page in PageIter4K::new(start, start + size).unwrap() {
        let Some((frame, old_flags)) = pt.query_page(page) else {
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

        if old_flags == super::effective_pte_flags(new_flags) {
            continue;
        }

        if !pt.protect_page(page, new_flags) {
            error!(
                "protect_pages: failed to protect page: {:#x}, {:?}",
                page, new_flags
            );
            return false;
        }
        mutation.record(page, PAGE_SIZE_4K);
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

fn dealloc_frame_runs(frames: &mut [PhysAddr]) {
    if frames.is_empty() {
        return;
    }
    frames.sort_unstable_by_key(|frame| frame.as_usize());
    let allocator = global_allocator();
    let mut run_start = frames[0].as_usize();
    let mut run_len = 1;
    for frame in frames.iter().skip(1) {
        let paddr = frame.as_usize();
        if paddr == run_start.saturating_add(run_len * PAGE_SIZE_4K) {
            run_len += 1;
        } else {
            allocator.dealloc_pages(phys_to_virt(PhysAddr::from(run_start)).as_usize(), run_len);
            run_start = paddr;
            run_len = 1;
        }
    }
    allocator.dealloc_pages(phys_to_virt(PhysAddr::from(run_start)).as_usize(), run_len);
}

pub(super) fn dealloc_frames(mut frames: Vec<PhysAddr>) {
    frames.retain(|frame| cow_dec_frame_ref(*frame));
    dealloc_frame_runs(&mut frames);
}

pub(super) fn dealloc_frame_values(frames: &mut [usize]) {
    let mut count = 0;
    for index in 0..frames.len() {
        let frame = PhysAddr::from(frames[index]);
        if cow_dec_frame_ref(frame) {
            frames[count] = frame.as_usize();
            count += 1;
        }
    }
    frames[..count].sort_unstable();
    if count == 0 {
        return;
    }
    let allocator = global_allocator();
    let mut run_start = frames[0];
    let mut run_len = 1;
    for &paddr in &frames[1..count] {
        if paddr == run_start.saturating_add(run_len * PAGE_SIZE_4K) {
            run_len += 1;
        } else {
            allocator.dealloc_pages(phys_to_virt(PhysAddr::from(run_start)).as_usize(), run_len);
            run_start = paddr;
            run_len = 1;
        }
    }
    allocator.dealloc_pages(phys_to_virt(PhysAddr::from(run_start)).as_usize(), run_len);
}

fn alloc_frame_batch(
    num_pages: usize,
    zeroed: bool,
) -> Option<([PhysAddr; MAX_FAULT_BATCH_PAGES], usize)> {
    if num_pages == 0 || num_pages > MAX_FAULT_BATCH_PAGES {
        return None;
    }

    let mut vaddrs = [0usize; MAX_FAULT_BATCH_PAGES];
    let page_count = global_allocator().alloc_page_batch(&mut vaddrs[..num_pages]);
    if page_count == 0 {
        return None;
    }

    let mut frames = [PhysAddr::from(0); MAX_FAULT_BATCH_PAGES];
    for (index, vaddr) in vaddrs.into_iter().take(page_count).enumerate() {
        let vaddr = VirtAddr::from(vaddr);
        if zeroed {
            unsafe { core::ptr::write_bytes(vaddr.as_mut_ptr(), 0, PAGE_SIZE_4K) };
        }
        let frame = virt_to_phys(vaddr);
        cow_mark_frame_used(frame);
        frames[index] = frame;
    }
    Some((frames, page_count))
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
                        let mut reclaim = super::DeferredReclaims::default();
                        let _ = self.unmap_alloc(
                            start,
                            mapped_pages * PAGE_SIZE_4K,
                            pt,
                            true,
                            &mut reclaim,
                            &mut (),
                        );
                        reclaim.reclaim();
                    }
                    return false;
                };
                flush_dcache_range(frame, PAGE_SIZE_4K);
                if let Ok(tlb) = pt.map(addr, frame, PageSize::Size4K, flags) {
                    tlb.ignore(); // TLB flush on map is unnecessary, as there are no outdated mappings.
                    mapped_pages += 1;
                } else {
                    dealloc_frame(frame);
                    if mapped_pages != 0 {
                        let mut reclaim = super::DeferredReclaims::default();
                        let _ = self.unmap_alloc(
                            start,
                            mapped_pages * PAGE_SIZE_4K,
                            pt,
                            true,
                            &mut reclaim,
                            &mut (),
                        );
                        reclaim.reclaim();
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
        reclaim: &mut super::DeferredReclaims,
        mutation: &mut impl MappingMutation<VirtAddr>,
    ) -> bool {
        debug!("unmap_alloc: [{:#x}, {:#x})", start, start + size);
        let result =
            pt.unmap_present_range(start, size, false, |addr, frame, _flags, page_size| {
                debug_assert_eq!(page_size, PageSize::Size4K);
                if frame.as_usize() != 0 {
                    mutation.record(addr, PAGE_SIZE_4K);
                    reclaim.defer_frame(frame);
                }
            });
        result.is_ok()
    }

    pub(crate) fn page_fault_alloc_request(
        &self,
        vaddr: VirtAddr,
        area_end: VirtAddr,
        pt: &crate::PageTableLockManager,
    ) -> Option<AnonPageLoad> {
        match self {
            Self::Alloc { populate: false, .. } => {}
            Self::Cow(cow) => {
                return cow.inner().page_fault_alloc_request(vaddr, area_end, pt);
            }
            _ => return None,
        }

        let page = vaddr.align_down_4k();
        let mut page_count = 0;
        let mut check_page = page;
        'probe: while page_count < MAX_FAULT_BATCH_PAGES && check_page < area_end {
            // A read guard spans one 2 MiB page-table subtree. Keep it while
            // probing the contiguous fault batch, then reacquire only if the
            // batch crosses that boundary.
            let pt_guard = pt.read_for_addr(check_page);
            while page_count < MAX_FAULT_BATCH_PAGES
                && check_page < area_end
                && pt_guard.covers(check_page)
            {
                axfs::buildstorm_stat_inc!(MM_ANON_FAULT_PTE_READ_PROBES);
                let needs_mapping = match pt_guard.query(check_page) {
                    Err(_) => true,
                    Ok((frame, _, _)) => frame.as_usize() == 0,
                };
                if !needs_mapping {
                    break 'probe;
                }
                page_count += 1;
                check_page += PAGE_SIZE_4K;
            }
        }

        if page_count == 0 {
            axfs::buildstorm_stat_inc!(MM_ANON_FAULT_EMPTY_REQUESTS);
            return None;
        }
        axfs::buildstorm_stat_inc!(MM_ANON_FAULT_BATCHES);
        if page_count == MAX_FAULT_BATCH_PAGES {
            axfs::buildstorm_stat_inc!(MM_ANON_FAULT_FULL_BATCHES);
        }
        axfs::buildstorm_stat_add!(MM_ANON_FAULT_REQUESTED_PAGES, page_count);
        Some(AnonPageLoad { page, page_count })
    }

    pub(crate) fn handle_prepared_page_fault_alloc(
        &self,
        vaddr: VirtAddr,
        area_end: VirtAddr,
        orig_flags: MappingFlags,
        pt: &crate::PageTableLockManager,
        prepared: &mut AnonPagePrepared,
    ) -> bool {
        let page = vaddr.align_down_4k();
        if !prepared.matches(page) {
            return false;
        }

        let mut handled_any = false;
        let mut mapped_pages = 0usize;
        let mut keep_mapping = true;
        let mut index = 0;
        while index < prepared.page_count() && keep_mapping {
            let current_page = page + index * PAGE_SIZE_4K;
            if current_page >= area_end {
                break;
            }
            axfs::buildstorm_stat_inc!(MM_ANON_FAULT_PTE_WRITE_GUARD_ACQUIRES);
            let mut pt_guard = pt.lock_for_addr(current_page);

            while index < prepared.page_count() {
                let current_page = page + index * PAGE_SIZE_4K;
                if current_page >= area_end || !pt_guard.covers(current_page) {
                    break;
                }
                let frame = prepared.frame(index);
                let mut mapped_successfully = false;
                let mut already_mapped = false;
                axfs::buildstorm_stat_inc!(MM_ANON_FAULT_PTE_WRITE_LOCKS);
                match pt_guard.query(current_page) {
                    Err(_) => {
                        if pt_guard
                            .map(current_page, frame, PageSize::Size4K, orig_flags)
                            .map(|tlb| {
                                tlb.flush();
                                axfs::buildstorm_stat_inc!(MM_ANON_FAULT_LOCAL_TLB_FLUSHES);
                            })
                            .is_ok()
                        {
                            mapped_successfully = true;
                            handled_any = true;
                        }
                    }
                    Ok((current_frame, _, _)) if current_frame.as_usize() == 0 => {
                        if pt_guard
                            .remap(current_page, frame, orig_flags)
                            .map(|(_, tlb)| {
                                tlb.flush();
                                axfs::buildstorm_stat_inc!(MM_ANON_FAULT_LOCAL_TLB_FLUSHES);
                            })
                            .is_ok()
                        {
                            mapped_successfully = true;
                            handled_any = true;
                        }
                    }
                    Ok((current_frame, _, _)) if current_frame.as_usize() != 0 => {
                        already_mapped = true;
                        if current_page == page {
                            handled_any = true;
                        }
                    }
                    _ => {}
                }

                if mapped_successfully {
                    prepared.mark_mapped(index);
                    mapped_pages += 1;
                } else if !already_mapped {
                    keep_mapping = false;
                    break;
                }
                index += 1;
            }
        }
        axfs::buildstorm_stat_add!(MM_ANON_FAULT_MAPPED_PAGES, mapped_pages);
        let _ = mapped_pages;
        handled_any
    }

    pub(crate) fn handle_page_fault_alloc(
        &self,
        vaddr: VirtAddr,
        area_end: VirtAddr,
        orig_flags: MappingFlags,
        pt: &crate::PageTableLockManager,
        populate: bool,
    ) -> bool {
        let page = vaddr.align_down_4k();
        if !populate
            && let Some(load) = self.page_fault_alloc_request(vaddr, area_end, pt)
        {
            let Ok(mut prepared) = load.prepare() else {
                return false;
            };
            return self.handle_prepared_page_fault_alloc(
                vaddr,
                area_end,
                orig_flags,
                pt,
                &mut prepared,
            );
        }
        let query_res = pt.read_for_addr(page).query(page);
        if let Ok((old_frame, old_flags, _)) = query_res {
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
                    flush_dcache_range(frame, PAGE_SIZE_4K);
                    let mut pt_guard = pt.lock_for_addr(page);
                    // Re-verify
                    if let Ok((curr_frame, curr_flags, _)) = pt_guard.query(page) {
                        if curr_flags.is_empty() || curr_frame.as_usize() == 0 {
                            let ok = pt_guard
                                .remap(page, frame, orig_flags)
                                .map(|(_, tlb)| tlb.flush())
                                .is_ok();
                            if ok {
                                return true;
                            }
                        }
                    }
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
                return false;
            }

            // PTE already has some flags. Check if any flags need upgrading
            // (e.g., USER flag, or WRITE flag on non-cloned pages).
            let mut pt_guard = pt.lock_for_addr(page);
            if let Ok((curr_frame, curr_flags, _)) = pt_guard.query(page) {
                if curr_frame == old_frame {
                    let new_flags = curr_flags | orig_flags;
                    if new_flags == curr_flags {
                        return true;
                    }
                    return pt_guard
                        .remap(page, old_frame, new_flags)
                        .map(|(_, tlb)| tlb.ignore())
                        .is_ok();
                }
            }
            false
        } else if let Some(frame) = alloc_frame(true) {
            flush_dcache_range(frame, PAGE_SIZE_4K);
            // MADV_DONTNEED may evict a page from an eagerly populated
            // anonymous mapping. It must still fault back to a zeroed frame.
            // Allocate a physical frame lazily and map it to the fault address.
            // `vaddr` does not need to be aligned. `pt.map()` will create the
            // intermediate page-table levels on demand for true lazy mappings.
            let mut pt_guard = pt.lock_for_addr(page);
            // Re-verify
            if let Ok((curr_frame, _, _)) = pt_guard.query(page) {
                if curr_frame.as_usize() != 0 {
                    dealloc_frame(frame);
                    return true;
                }
            }
            let ok = pt_guard
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
        mutation: &mut impl MappingMutation<VirtAddr>,
    ) -> bool {
        debug!(
            "protect_alloc: [{:#x}, {:#x}) {:?} (populate={})",
            start,
            start + size,
            new_flags,
            populate
        );
        protect_pages(
            start,
            size,
            new_flags,
            !populate,
            !populate,
            pt,
            mutation,
        )
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
