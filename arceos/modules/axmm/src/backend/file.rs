use alloc::{sync::Arc, vec::Vec};

use axerrno::{AxError, AxResult};
use axfs::{CachedFile, FileFlags, SHARED_PAGE_BATCH_CAPACITY, SharedPagePaddrs};
use axhal::{
    mem::{flush_dcache_range, phys_to_virt},
    paging::{MappingFlags, PageSize, PageTable},
};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, PageIter4K, PhysAddr, VirtAddr};
use memory_set::MappingMutation;
use spin::Mutex;

use super::{
    Backend,
    alloc::{alloc_frame, dealloc_frame},
};

fn sync_executable_mapping(flags: MappingFlags) {
    if !flags.contains(MappingFlags::EXECUTE) {
        return;
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence.i", options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        core::arch::asm!("dbar 0; ibar 0", options(nostack, preserves_flags));
    }
}

const FILE_FAULT_AROUND_PAGES: usize = SHARED_PAGE_BATCH_CAPACITY;
const COLD_FILE_FAULT_AROUND_PAGES: usize = 4;
const _: () = assert!(FILE_FAULT_AROUND_PAGES > 0 && FILE_FAULT_AROUND_PAGES <= u16::BITS as usize);
const _: () = assert!(
    COLD_FILE_FAULT_AROUND_PAGES > 0 && COLD_FILE_FAULT_AROUND_PAGES <= FILE_FAULT_AROUND_PAGES
);

fn file_page_read_window(
    mapping_start: VirtAddr,
    file_offset: usize,
    mapped_bytes: usize,
    file_size: usize,
    page_addr: VirtAddr,
) -> Option<(u64, usize)> {
    let relative = page_addr.as_usize().checked_sub(mapping_start.as_usize())?;
    let mapping_end = file_offset.checked_add(mapped_bytes)?;
    let limit_offset = mapping_end.min(file_size);
    let file_offset = file_offset.checked_add(relative)?;

    if file_offset >= limit_offset {
        return None;
    }

    let read_len = (limit_offset - file_offset).min(PAGE_SIZE_4K);
    Some((file_offset as u64, read_len))
}

fn file_prefetch_range(
    mapping_start: VirtAddr,
    file_offset: usize,
    mapped_bytes: usize,
    file_size: usize,
    first_page: VirtAddr,
    area_end: VirtAddr,
) -> Option<(u32, usize)> {
    let (first_offset, _) = file_page_read_window(
        mapping_start,
        file_offset,
        mapped_bytes,
        file_size,
        first_page,
    )?;
    let page_number = u32::try_from(first_offset / PAGE_SIZE_4K as u64).ok()?;
    let mut page_count = 0;
    while page_count < FILE_FAULT_AROUND_PAGES {
        let byte_offset = page_count.checked_mul(PAGE_SIZE_4K)?;
        let candidate = first_page.checked_add(byte_offset)?;
        if candidate >= area_end
            || file_page_read_window(
                mapping_start,
                file_offset,
                mapped_bytes,
                file_size,
                candidate,
            )
            .is_none()
        {
            break;
        }
        page_count += 1;
    }
    (page_count != 0).then_some((page_number, page_count))
}

#[derive(Debug, Default)]
struct FileReadAheadState {
    next_page: Option<u32>,
}

impl FileReadAheadState {
    fn is_sequential(&self, page_number: u32) -> bool {
        self.next_page == Some(page_number)
    }

    fn plan(&mut self, page_number: u32, max_pages: usize) -> usize {
        let max_pages = max_pages.max(1);
        let sequential = self.is_sequential(page_number);
        let page_count = if sequential {
            max_pages
        } else {
            max_pages.min(COLD_FILE_FAULT_AROUND_PAGES)
        };
        if sequential {
            axfs::buildstorm_stat_inc!(MM_FILE_FAULT_SEQUENTIAL_BATCHES);
            if page_count == FILE_FAULT_AROUND_PAGES {
                axfs::buildstorm_stat_inc!(MM_FILE_FAULT_SEQUENTIAL_FULL_BATCHES);
            }
            axfs::buildstorm_stat_add!(MM_FILE_FAULT_SEQUENTIAL_REQUESTED_PAGES, page_count);
        } else {
            axfs::buildstorm_stat_inc!(MM_FILE_FAULT_COLD_BATCHES);
            if page_count == COLD_FILE_FAULT_AROUND_PAGES {
                axfs::buildstorm_stat_inc!(MM_FILE_FAULT_COLD_FULL_BATCHES);
            }
            axfs::buildstorm_stat_add!(MM_FILE_FAULT_COLD_REQUESTED_PAGES, page_count);
        }
        self.next_page = u32::try_from(page_count)
            .ok()
            .and_then(|count| page_number.checked_add(count));
        page_count
    }

    fn finish(&mut self, page_number: u32, requested: usize, actual: usize) {
        let requested_end = u32::try_from(requested)
            .ok()
            .and_then(|count| page_number.checked_add(count));
        if self.next_page == requested_end {
            self.next_page = u32::try_from(actual)
                .ok()
                .and_then(|count| page_number.checked_add(count));
        }
    }
}

#[derive(Clone)]
pub struct FileMapping {
    start: VirtAddr,
    file: CachedFile,
    file_flags: FileFlags,
    file_offset: usize,
    file_bytes: usize,
    shared: bool,
    read_ahead: Arc<Mutex<FileReadAheadState>>,
    _write_access: Option<axfs::WriteAccessGuard>,
}

#[derive(Clone)]
pub struct FilePageLoad {
    file: CachedFile,
    page_number: u32,
    page_count: usize,
    sequential: bool,
    may_write: bool,
    read_ahead: Arc<Mutex<FileReadAheadState>>,
}

pub struct FilePagePrepared {
    file: CachedFile,
    requested_page: u32,
    sequential: bool,
    pages: SharedPagePaddrs,
    mapped_mask: u16,
}

pub(super) struct FileWriteback {
    file: CachedFile,
    page_numbers: Vec<u32>,
    sync: bool,
}

impl FileWriteback {
    pub(super) fn for_unmap(file: CachedFile) -> Self {
        Self {
            file,
            page_numbers: Vec::new(),
            sync: false,
        }
    }

    pub(super) fn push_page(&mut self, page_number: u32) {
        self.page_numbers.push(page_number);
    }

    pub(super) fn is_empty(&self) -> bool {
        self.page_numbers.is_empty()
    }

    pub(super) fn complete(self) -> AxResult {
        for page_number in self.page_numbers {
            self.file
                .mark_page_dirty(page_number)
                .map_err(|_| AxError::Io)?;
        }
        if self.sync {
            self.file.sync(false).map_err(|_| AxError::Io)?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for FilePageLoad {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FilePageLoad")
            .field("page_number", &self.page_number)
            .finish_non_exhaustive()
    }
}

impl FilePageLoad {
    pub fn prepare(self) -> AxResult<FilePagePrepared> {
        let requested_pages = self.page_count;
        let frames = self
            .file
            .get_shared_page_paddrs(self.page_number, requested_pages, self.may_write)
            .inspect_err(|error| {
                error!(
                    "file-backed page load failed: page_number={}, page_count={}, may_write={}, \
                     error={:?}",
                    self.page_number, requested_pages, self.may_write, error
                );
            })?;
        for (_, frame) in frames.iter() {
            flush_dcache_range(*frame, PAGE_SIZE_4K);
        }
        let prepared_pages = frames.len();
        axfs::buildstorm_stat_add!(MM_FILE_FAULT_PREPARED_PAGES, prepared_pages);
        if self.sequential {
            axfs::buildstorm_stat_add!(MM_FILE_FAULT_SEQUENTIAL_PREPARED_PAGES, prepared_pages);
        } else {
            axfs::buildstorm_stat_add!(MM_FILE_FAULT_COLD_PREPARED_PAGES, prepared_pages);
        }
        if prepared_pages < requested_pages {
            axfs::buildstorm_stat_inc!(MM_FILE_FAULT_SHORT_PREPARES);
        }
        self.read_ahead
            .lock()
            .finish(self.page_number, requested_pages, prepared_pages);
        Ok(FilePagePrepared {
            file: self.file,
            requested_page: self.page_number,
            sequential: self.sequential,
            pages: frames,
            mapped_mask: 0,
        })
    }
}

impl core::fmt::Debug for FilePagePrepared {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FilePagePrepared")
            .field("requested_page", &self.requested_page)
            .field("page_count", &self.pages.len())
            .finish_non_exhaustive()
    }
}

impl Drop for FilePagePrepared {
    fn drop(&mut self) {
        for (index, (_, frame)) in self.pages.iter().enumerate() {
            let mapped = 1u16
                .checked_shl(index as u32)
                .is_some_and(|bit| self.mapped_mask & bit != 0);
            if !mapped {
                dealloc_frame(*frame);
            }
        }
    }
}

impl FilePagePrepared {
    fn matches(&self, file: &CachedFile, page_number: u32) -> bool {
        self.requested_page == page_number && self.file.shares_page_cache_with(file)
    }

    fn page(&self, index: usize) -> Option<(u32, PhysAddr)> {
        let page = *self.pages.get(index)?;
        let bit = 1u16.checked_shl(index as u32)?;
        (self.mapped_mask & bit == 0).then_some(page)
    }

    fn take_frame(&mut self, index: usize) -> Option<PhysAddr> {
        let (_, frame) = *self.pages.get(index)?;
        let bit = 1u16.checked_shl(index as u32)?;
        if self.mapped_mask & bit != 0 {
            return None;
        }
        self.mapped_mask |= bit;
        Some(frame)
    }
}

impl FileMapping {
    pub(crate) fn update_address(&mut self, new_start: VirtAddr, new_size: usize) {
        self.start = new_start;
        self.file_bytes = new_size;
    }

    pub(crate) fn permits(&self, flags: MappingFlags) -> bool {
        if flags.contains(MappingFlags::READ) && !self.file_flags.contains(FileFlags::READ) {
            return false;
        }
        if flags.contains(MappingFlags::WRITE) {
            if self.shared {
                if !self.file_flags.contains(FileFlags::WRITE) {
                    return false;
                }
            } else {
                if !self.file_flags.contains(FileFlags::READ) {
                    return false;
                }
            }
        }
        if flags.contains(MappingFlags::EXECUTE) && !self.file_flags.contains(FileFlags::READ) {
            return false;
        }
        true
    }

    pub fn is_shared(&self) -> bool {
        self.shared
    }

    pub fn file_offset(&self) -> usize {
        self.file_offset
    }

    pub fn file(&self) -> &CachedFile {
        &self.file
    }

    pub fn file_bytes(&self) -> usize {
        self.file.size() as usize
    }

    pub(crate) fn is_page_cached(&self, page_addr: VirtAddr) -> bool {
        let Some((file_offset, _)) = self.page_read_window(page_addr) else {
            return false;
        };
        let Ok(page_number) = u32::try_from(file_offset / PAGE_SIZE_4K as u64) else {
            return false;
        };
        self.file.shared_page_paddr(page_number).is_ok()
    }

    fn page_read_window_at_size(
        &self,
        page_addr: VirtAddr,
        file_size: usize,
    ) -> Option<(u64, usize)> {
        file_page_read_window(
            self.start,
            self.file_offset,
            self.file_bytes,
            file_size,
            page_addr,
        )
    }

    fn page_read_window(&self, page_addr: VirtAddr) -> Option<(u64, usize)> {
        self.page_read_window_at_size(page_addr, self.file_bytes())
    }

    fn prefetch_after(&self, first_page: VirtAddr, area_end: VirtAddr, file_size: usize) {
        let Some((page_number, page_count)) = file_prefetch_range(
            self.start,
            self.file_offset,
            self.file_bytes,
            file_size,
            first_page,
            area_end,
        ) else {
            return;
        };
        self.file.prefetch_pages(page_number, page_count);
    }

    pub(crate) fn page_load_request(
        &self,
        vaddr: VirtAddr,
        area_end: VirtAddr,
        orig_flags: MappingFlags,
        pt: &crate::PageTableLockManager,
    ) -> Option<FilePageLoad> {
        if !self.permits(orig_flags) {
            return None;
        }

        let page_addr = vaddr.align_down_4k();
        let file_size = self.file_bytes();
        let (file_offset, _) = self.page_read_window_at_size(page_addr, file_size)?;
        axfs::buildstorm_stat_inc!(MM_FILE_FAULT_PTE_READ_PROBES);
        if pt
            .read_for_addr(page_addr)
            .query(page_addr)
            .is_ok_and(|(frame, ..)| frame.as_usize() != 0)
        {
            return None;
        }

        let page_number = u32::try_from(file_offset / PAGE_SIZE_4K as u64).ok()?;
        let mut max_pages = 0;
        while max_pages < FILE_FAULT_AROUND_PAGES {
            let candidate = page_addr.checked_add(max_pages * PAGE_SIZE_4K)?;
            if candidate >= area_end
                || self
                    .page_read_window_at_size(candidate, file_size)
                    .is_none()
            {
                break;
            }
            max_pages += 1;
        }
        let mut read_ahead = self.read_ahead.lock();
        let sequential = read_ahead.is_sequential(page_number);
        let page_count = read_ahead.plan(page_number, max_pages);
        drop(read_ahead);
        Some(FilePageLoad {
            file: self.file.clone(),
            page_number,
            page_count,
            sequential,
            may_write: self.shared && self.file_flags.contains(FileFlags::WRITE),
            read_ahead: self.read_ahead.clone(),
        })
    }
}

impl Backend {
    pub(crate) fn new_file(
        start: VirtAddr,
        file: CachedFile,
        file_flags: FileFlags,
        file_offset: usize,
        file_bytes: usize,
        shared: bool,
        write_access: Option<axfs::WriteAccessGuard>,
    ) -> Self {
        Self::File(FileMapping {
            start,
            file,
            file_flags,
            file_offset,
            file_bytes,
            shared,
            read_ahead: Arc::new(Mutex::new(FileReadAheadState::default())),
            _write_access: write_access,
        })
    }

    pub(crate) fn map_file(
        &self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        pt: &mut PageTable,
        mapping: &FileMapping,
    ) -> bool {
        debug!(
            "map_file: [{:#x}, {:#x}) {:?} offset={:#x} bytes={:#x} shared={}",
            start,
            start + size,
            flags,
            mapping.file_offset,
            mapping.file_bytes,
            mapping.shared,
        );
        if !mapping.permits(flags) {
            return false;
        }
        let _ = (start, size, pt);
        true
    }

    pub(crate) fn unmap_file(
        &self,
        start: VirtAddr,
        size: usize,
        pt: &mut PageTable,
        reclaim: &mut super::DeferredReclaims,
        mutation: &mut impl MappingMutation<VirtAddr>,
    ) -> bool {
        debug!("unmap_file: [{:#x}, {:#x})", start, start + size);
        if size == 0 {
            return true;
        }
        if start.checked_add(size).is_none() {
            return false;
        }
        // If this is a shared mapping, writeback dirty pages before unmapping.
        let mapping = match self {
            Backend::File(m) => m,
            _ => return false,
        };
        let file_size = mapping.file_bytes();
        let mut writeback = None;
        let result = pt.unmap_present_range(start, size, false, |addr, frame, flags, page_size| {
            debug_assert_eq!(page_size, PageSize::Size4K);
            if frame.as_usize() != 0 {
                mutation.record(addr, PAGE_SIZE_4K);
                if mapping.shared
                    && flags.contains(MappingFlags::WRITE)
                    && let Some((file_offset, _)) =
                        mapping.page_read_window_at_size(addr, file_size)
                {
                    let pn = (file_offset / PAGE_SIZE_4K as u64) as u32;
                    writeback
                        .get_or_insert_with(|| FileWriteback::for_unmap(mapping.file.clone()))
                        .push_page(pn);
                }
                reclaim.defer_frame(frame);
            }
        });
        if let Some(writeback) = writeback
            && !writeback.is_empty()
        {
            reclaim.defer_file_writeback(writeback);
        }
        result.is_ok()
    }

    /// Write back all resident pages in the given range to the underlying file.
    /// Only meaningful for shared file mappings.
    pub(super) fn prepare_file_writeback_range_impl(
        &self,
        start: VirtAddr,
        size: usize,
        sync: bool,
        pt: &crate::PageTableLockManager,
    ) -> Result<Option<FileWriteback>, ()> {
        let mapping = match self {
            Backend::File(m) => m,
            _ => return Err(()),
        };
        if !mapping.shared {
            return Ok(None);
        }
        if size == 0 {
            return Ok(None);
        }
        let pages = PageIter4K::new(start, start + size).ok_or(())?;
        let mut page_numbers = Vec::new();
        for addr in pages {
            if let Ok((frame, flags, _)) = pt.read_for_addr(addr).query(addr)
                && flags.contains(MappingFlags::WRITE)
            {
                if frame.as_usize() != 0 {
                    let Some((file_offset, _)) = mapping.page_read_window(addr) else {
                        continue;
                    };
                    let pn = (file_offset / PAGE_SIZE_4K as u64) as u32;
                    page_numbers.push(pn);
                }
            }
        }
        Ok(Some(FileWriteback {
            file: mapping.file.clone(),
            page_numbers,
            sync,
        }))
    }

    pub(crate) fn handle_page_fault_file(
        &self,
        vaddr: VirtAddr,
        _area_end: VirtAddr,
        orig_flags: MappingFlags,
        pt: &crate::PageTableLockManager,
        mapping: &FileMapping,
        access_flags: MappingFlags,
        reclaim: &mut super::DeferredReclaims,
    ) -> bool {
        if !mapping.permits(orig_flags) {
            return false;
        }

        let page_addr = vaddr.align_down_4k();
        let current_file_bytes = mapping.file_bytes();
        let relative = page_addr
            .as_usize()
            .saturating_sub(mapping.start.as_usize());
        if relative >= (current_file_bytes + PAGE_SIZE_4K - 1) & !(PAGE_SIZE_4K - 1) {
            return false;
        }

        let query_res = pt.read_for_addr(page_addr).query(page_addr);
        if let Ok((old_frame, old_flags, _)) = query_res {
            if old_frame.as_usize() != 0 {
                // If it's a private mapping and we are trying to write to a read-only mapped page:
                if !mapping.shared
                    && orig_flags.contains(MappingFlags::WRITE)
                    && access_flags.contains(MappingFlags::WRITE)
                    && !old_flags.contains(MappingFlags::WRITE)
                {
                    // Copy-on-Write (COW) for private file mapping
                    let Some(new_frame) = alloc_frame(false) else {
                        return false;
                    };
                    flush_dcache_range(old_frame, PAGE_SIZE_4K);
                    let src = phys_to_virt(old_frame).as_ptr();
                    let dst = phys_to_virt(new_frame).as_mut_ptr();
                    unsafe {
                        core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE_4K);
                    }
                    flush_dcache_range(new_frame, PAGE_SIZE_4K);

                    let mut pt_guard = pt.lock_for_addr(page_addr);
                    if let Ok((curr_frame, curr_flags, _)) = pt_guard.query(page_addr) {
                        if curr_frame == old_frame && !curr_flags.contains(MappingFlags::WRITE) {
                            if let Ok((_, tlb)) = pt_guard.remap(page_addr, new_frame, orig_flags) {
                                tlb.ignore();
                                drop(pt_guard);
                                reclaim.defer_frame(old_frame);
                                sync_executable_mapping(orig_flags);
                                return true;
                            }
                        }
                    }
                    dealloc_frame(new_frame);
                    return false;
                }

                // If not a COW write fault, perform only a permission upgrade.
                // Private file pages remain read-only so the next write takes
                // the COW path without consulting the page cache here.
                let mut pt_guard = pt.lock_for_addr(page_addr);
                if let Ok((curr_frame, curr_flags, _)) = pt_guard.query(page_addr) {
                    if curr_frame == old_frame {
                        let mut new_flags = curr_flags | orig_flags;
                        if !mapping.shared {
                            new_flags &= !MappingFlags::WRITE;
                        }
                        if curr_flags.contains(new_flags) {
                            return true;
                        }
                        return pt_guard
                            .remap(page_addr, old_frame, new_flags)
                            .map(|(_, tlb)| {
                                tlb.ignore();
                                sync_executable_mapping(new_flags);
                            })
                            .is_ok();
                    }
                }
                return true;
            }
        }

        // Missing file pages are prepared outside the address-space lock.
        false
    }

    pub(crate) fn handle_prepared_page_fault_file(
        &self,
        vaddr: VirtAddr,
        area_end: VirtAddr,
        orig_flags: MappingFlags,
        pt: &crate::PageTableLockManager,
        mapping: &FileMapping,
        access_flags: MappingFlags,
        prepared: &mut FilePagePrepared,
    ) -> bool {
        if !mapping.permits(orig_flags) {
            return false;
        }

        let page_addr = vaddr.align_down_4k();
        let file_size = mapping.file_bytes();
        let Some((file_offset, _)) = mapping.page_read_window_at_size(page_addr, file_size) else {
            return false;
        };
        let Ok(page_number) = u32::try_from(file_offset / PAGE_SIZE_4K as u64) else {
            return false;
        };
        if !prepared.matches(&mapping.file, page_number) {
            return false;
        }

        let mut candidates = [None; FILE_FAULT_AROUND_PAGES];
        let mut candidate_count = 0;
        for index in 0..prepared.pages.len() {
            let Some((candidate_page_number, _)) = prepared.page(index) else {
                break;
            };
            let Some(delta) = candidate_page_number.checked_sub(page_number) else {
                break;
            };
            let Some(byte_delta) = (delta as usize).checked_mul(PAGE_SIZE_4K) else {
                break;
            };
            let Some(candidate_addr) = page_addr.checked_add(byte_delta) else {
                break;
            };
            if candidate_addr >= area_end {
                break;
            }
            let Some((candidate_offset, _)) =
                mapping.page_read_window_at_size(candidate_addr, file_size)
            else {
                break;
            };
            if candidate_offset / PAGE_SIZE_4K as u64 != candidate_page_number as u64 {
                break;
            }
            let Some(slot) = candidates.get_mut(candidate_count) else {
                break;
            };
            *slot = Some((index, candidate_addr));
            candidate_count += 1;
        }
        if candidate_count == 0 {
            return false;
        }

        let private_write = !mapping.shared
            && orig_flags.contains(MappingFlags::WRITE)
            && access_flags.contains(MappingFlags::WRITE);
        let Some((requested_index, _)) = candidates[0] else {
            return false;
        };
        let Some((_, requested_frame)) = prepared.page(requested_index) else {
            return false;
        };
        let mut private_frame = if private_write {
            let Some(frame) = alloc_frame(false) else {
                return false;
            };
            flush_dcache_range(requested_frame, PAGE_SIZE_4K);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    phys_to_virt(requested_frame).as_ptr(),
                    phys_to_virt(frame).as_mut_ptr(),
                    PAGE_SIZE_4K,
                );
            }
            flush_dcache_range(frame, PAGE_SIZE_4K);
            Some(frame)
        } else {
            None
        };

        let mut requested_handled = false;
        let mut mapped_executable = false;
        let mut mapped_pages = 0usize;
        let mut candidate_cursor = 0;
        while candidate_cursor < candidate_count {
            let Some((_, first_addr)) = candidates[candidate_cursor] else {
                return false;
            };
            axfs::buildstorm_stat_inc!(MM_FILE_FAULT_PTE_WRITE_GUARD_ACQUIRES);
            let mut pt_guard = pt.lock_for_addr(first_addr);

            while candidate_cursor < candidate_count {
                let Some((index, candidate_addr)) = candidates[candidate_cursor] else {
                    return false;
                };
                if !pt_guard.covers(candidate_addr) {
                    break;
                }
                let requested = candidate_addr == page_addr;
                axfs::buildstorm_stat_inc!(MM_FILE_FAULT_PTE_WRITE_LOCKS);
                // This guard serializes the PTE for `candidate_addr`, so retain
                // the query result for the map/remap decision below.
                let remap_empty = match pt_guard.query(candidate_addr) {
                    Ok((current, current_flags, _)) if current.as_usize() != 0 => {
                        if requested {
                            requested_handled = !access_flags.contains(MappingFlags::WRITE)
                                || current_flags.contains(MappingFlags::WRITE);
                        }
                        candidate_cursor += 1;
                        continue;
                    }
                    Ok(_) => true,
                    Err(_) => false,
                };

                let Some((_, cache_frame)) = prepared.page(index) else {
                    candidate_cursor += 1;
                    continue;
                };
                let use_private_frame = requested && private_write;
                let frame = if use_private_frame {
                    private_frame.unwrap()
                } else {
                    cache_frame
                };
                let map_flags = if mapping.shared || use_private_frame {
                    orig_flags
                } else {
                    orig_flags & !MappingFlags::WRITE
                };
                let mapped = if remap_empty {
                    pt_guard
                        .remap(candidate_addr, frame, map_flags)
                        .map(|(_, tlb)| tlb)
                } else {
                    pt_guard.map(candidate_addr, frame, PageSize::Size4K, map_flags)
                };
                let Ok(tlb) = mapped else {
                    candidate_cursor += 1;
                    continue;
                };
                tlb.flush();
                axfs::buildstorm_stat_inc!(MM_FILE_FAULT_LOCAL_TLB_FLUSHES);
                mapped_executable |= map_flags.contains(MappingFlags::EXECUTE);
                mapped_pages += 1;
                if use_private_frame {
                    private_frame.take();
                } else {
                    prepared.take_frame(index);
                }
                if requested {
                    requested_handled = true;
                }
                candidate_cursor += 1;
            }
        }
        if let Some(frame) = private_frame {
            dealloc_frame(frame);
        }
        if mapped_executable {
            sync_executable_mapping(orig_flags);
        }
        axfs::buildstorm_stat_add!(MM_FILE_FAULT_MAPPED_PAGES, mapped_pages);
        if prepared.sequential {
            axfs::buildstorm_stat_add!(MM_FILE_FAULT_SEQUENTIAL_MAPPED_PAGES, mapped_pages);
        } else {
            axfs::buildstorm_stat_add!(MM_FILE_FAULT_COLD_MAPPED_PAGES, mapped_pages);
        }
        if requested_handled
            && mapped_pages != 0
            && prepared.sequential
            && let Some(next_page) = page_addr.checked_add(candidate_count * PAGE_SIZE_4K)
        {
            // Submit only after the current batch is visible in the page table;
            // the task itself uses the existing cache single-flight protocol.
            mapping.prefetch_after(next_page, area_end, file_size);
        }
        requested_handled
    }

    pub(crate) fn protect_file(
        &self,
        start: VirtAddr,
        size: usize,
        new_flags: MappingFlags,
        pt: &mut PageTable,
        mapping: &FileMapping,
        mutation: &mut impl MappingMutation<VirtAddr>,
    ) -> bool {
        debug!(
            "protect_file: [{:#x}, {:#x}) {:?} offset={:#x} bytes={:#x}",
            start,
            start + size,
            new_flags,
            mapping.file_offset,
            mapping.file_bytes
        );

        if !mapping.permits(new_flags) {
            return false;
        }

        for page in PageIter4K::new(start, start + size).unwrap() {
            let Some((frame, old_flags, _)) = pt.query(page).ok() else {
                continue; // allow missing
            };

            if frame.as_usize() == 0 {
                continue; // allow placeholder
            }

            // Never acquire page-cache locks while the address-space write
            // lock is held. Private file pages stay read-only and take the
            // existing COW fault path on their next write. This is also safe
            // for pages that have already been copied, at the cost of one
            // additional copy after a permission transition.
            let flags = if mapping.shared {
                new_flags
            } else {
                new_flags & !MappingFlags::WRITE
            };

            if old_flags == super::effective_pte_flags(flags) {
                continue;
            }

            if pt
                .protect(page, flags)
                .map(|(_, tlb)| tlb.ignore())
                .is_err()
            {
                error!(
                    "protect_file: failed to protect page: {:#x}, {:?}",
                    page, flags
                );
                return false;
            }
            mutation.record(page, PAGE_SIZE_4K);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use memory_addr::{PAGE_SIZE_4K, VirtAddr};

    use super::{
        COLD_FILE_FAULT_AROUND_PAGES, FILE_FAULT_AROUND_PAGES, FileReadAheadState,
        file_page_read_window, file_prefetch_range,
    };

    #[test]
    fn page_window_tracks_truncate_and_extend_without_exceeding_mapping() {
        let start = VirtAddr::from(0x10_0000);
        let page = PAGE_SIZE_4K;

        assert_eq!(
            file_page_read_window(start, 0, 4 * page, page + 123, start + page),
            Some((page as u64, 123))
        );
        assert_eq!(
            file_page_read_window(start, 0, 4 * page, page + 123, start + 2 * page),
            None
        );

        assert_eq!(
            file_page_read_window(start, 0, 4 * page, 3 * page + 17, start + 3 * page),
            Some(((3 * page) as u64, 17))
        );
        assert_eq!(
            file_page_read_window(start, 0, 4 * page, 8 * page, start + 4 * page),
            None
        );
    }

    #[test]
    fn page_window_respects_file_offset_and_checked_bounds() {
        let start = VirtAddr::from(0x20_0000);
        let page = PAGE_SIZE_4K;

        assert_eq!(
            file_page_read_window(start, page, 2 * page, 3 * page, start),
            Some((page as u64, page))
        );
        assert_eq!(
            file_page_read_window(start, page, 2 * page, page, start),
            None
        );
        assert_eq!(
            file_page_read_window(start, usize::MAX, page, usize::MAX, start),
            None
        );
        assert_eq!(
            file_page_read_window(start, 0, page, page, start - page),
            None
        );
    }

    #[test]
    fn prefetch_range_is_bounded_by_mapping_and_file_end() {
        let start = VirtAddr::from(0x30_0000);
        let page = PAGE_SIZE_4K;

        assert_eq!(
            file_prefetch_range(
                start,
                0,
                32 * page,
                64 * page,
                start + 16 * page,
                start + 40 * page
            ),
            Some((16, FILE_FAULT_AROUND_PAGES))
        );
        assert_eq!(
            file_prefetch_range(
                start,
                0,
                20 * page,
                64 * page,
                start + 16 * page,
                start + 40 * page
            ),
            Some((16, 4))
        );
        assert_eq!(
            file_prefetch_range(
                start,
                0,
                32 * page,
                18 * page,
                start + 16 * page,
                start + 40 * page
            ),
            Some((16, 2))
        );
    }

    #[test]
    fn readahead_advances_over_fault_around_window() {
        let mut state = FileReadAheadState::default();
        assert_eq!(state.plan(10, 4), 4);
        state.finish(10, 4, 4);
        assert_eq!(state.plan(14, 4), 4);
        state.finish(14, 4, 4);
        assert_eq!(state.plan(18, 4), 4);
    }

    #[test]
    fn readahead_resets_after_nonsequential_fault() {
        let mut state = FileReadAheadState::default();
        assert_eq!(state.plan(3, 4), 4);
        assert_eq!(state.plan(20, 4), 4);
        assert_eq!(state.plan(24, 4), 4);
    }

    #[test]
    fn cold_fault_is_capped_below_the_sequential_window() {
        let mut state = FileReadAheadState::default();
        assert_eq!(
            state.plan(3, FILE_FAULT_AROUND_PAGES),
            COLD_FILE_FAULT_AROUND_PAGES
        );
        assert_eq!(
            state.plan(
                3 + COLD_FILE_FAULT_AROUND_PAGES as u32,
                FILE_FAULT_AROUND_PAGES
            ),
            FILE_FAULT_AROUND_PAGES
        );
    }

    #[test]
    fn readahead_tracks_short_result_at_mapping_end() {
        let mut state = FileReadAheadState::default();
        assert_eq!(state.plan(7, 2), 2);
        state.finish(7, 2, 1);
        assert_eq!(state.plan(8, 4), 4);
    }

    #[test]
    fn readahead_overflow_disables_sequential_hint() {
        let mut state = FileReadAheadState::default();
        assert_eq!(state.plan(u32::MAX, 4), 4);
        assert_eq!(state.plan(0, 4), 4);
    }
}
