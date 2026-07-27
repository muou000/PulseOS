use alloc::{sync::Arc, vec::Vec};

use axerrno::{AxError, AxResult};
use axfs::{CachedFile, FileFlags};
use axhal::{
    mem::phys_to_virt,
    paging::{MappingFlags, PageSize, PageTable},
};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, PageIter4K, PhysAddr, VirtAddr};
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

#[allow(dead_code)]
fn read_file_page(
    mapping: &FileMapping,
    dst: &mut [u8],
    file_offset: u64,
    read_len: usize,
) -> bool {
    let mut filled = 0;
    while filled < read_len {
        match mapping
            .file
            .read_at(&mut dst[filled..read_len], file_offset + filled as u64)
        {
            Ok(0) => return false,
            Ok(bytes) => filled += bytes,
            Err(_) => return false,
        }
    }
    true
}

/// Write a page's content (from physical frame) back to the CachedFile.
#[allow(dead_code)]
fn writeback_phys_page(mapping: &FileMapping, page_addr: VirtAddr, frame_paddr: PhysAddr) -> bool {
    let Some((file_offset, write_len)) = mapping.page_read_window(page_addr) else {
        return true;
    };
    if write_len == 0 {
        return true;
    }
    let src = unsafe { core::slice::from_raw_parts(phys_to_virt(frame_paddr).as_ptr(), write_len) };
    match mapping.file.write_at(src, file_offset) {
        Ok(written) => written == write_len,
        Err(_) => false,
    }
}

const FILE_FAULT_AROUND_PAGES: usize = 4;

#[derive(Debug, Default)]
struct FileReadAheadState {
    next_page: Option<u32>,
}

impl FileReadAheadState {
    fn plan(&mut self, page_number: u32, max_pages: usize) -> usize {
        let max_pages = max_pages.max(1);
        let page_count = if self.next_page == Some(page_number) {
            max_pages
        } else {
            1
        };
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
    may_write: bool,
    read_ahead: Arc<Mutex<FileReadAheadState>>,
}

struct PreparedFilePage {
    page_number: u32,
    frame: Option<PhysAddr>,
}

pub struct FilePagePrepared {
    file: CachedFile,
    requested_page: u32,
    pages: Vec<PreparedFilePage>,
}

pub(super) struct FileWriteback {
    file: CachedFile,
    page_numbers: Vec<u32>,
    sync: bool,
}

impl FileWriteback {
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
        let frames = self
            .file
            .get_shared_page_paddrs(self.page_number, self.page_count, self.may_write)
            .map_err(|_| AxError::Io)?;
        self.read_ahead
            .lock()
            .finish(self.page_number, self.page_count, frames.len());
        Ok(FilePagePrepared {
            file: self.file,
            requested_page: self.page_number,
            pages: frames
                .into_iter()
                .map(|(page_number, frame)| PreparedFilePage {
                    page_number,
                    frame: Some(frame),
                })
                .collect(),
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
        for page in &mut self.pages {
            if let Some(frame) = page.frame.take() {
                dealloc_frame(frame);
            }
        }
    }
}

impl FilePagePrepared {
    fn matches(&self, file: &CachedFile, page_number: u32) -> bool {
        self.requested_page == page_number && self.file.shares_page_cache_with(file)
    }

    fn page(&self, index: usize) -> Option<(u32, PhysAddr)> {
        let page = self.pages.get(index)?;
        Some((page.page_number, page.frame?))
    }

    fn take_frame(&mut self, index: usize) -> Option<PhysAddr> {
        self.pages.get_mut(index)?.frame.take()
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
        axfs::cached_file_size(self.file.location())
            .map(|len| len as usize)
            .unwrap_or(self.file_bytes)
    }

    fn page_read_window(&self, page_addr: VirtAddr) -> Option<(u64, usize)> {
        let relative = page_addr.as_usize().checked_sub(self.start.as_usize())?;
        let file_size_on_disk = self.file_bytes();
        let limit_offset = (self.file_offset + self.file_bytes).min(file_size_on_disk);
        let file_offset = self.file_offset.checked_add(relative)?;

        if file_offset >= limit_offset {
            return None;
        }

        let read_len = (limit_offset - file_offset).min(PAGE_SIZE_4K);
        Some((file_offset as u64, read_len))
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
        let (file_offset, _) = self.page_read_window(page_addr)?;
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
            if candidate >= area_end || self.page_read_window(candidate).is_none() {
                break;
            }
            max_pages += 1;
        }
        let page_count = self.read_ahead.lock().plan(page_number, max_pages);
        Some(FilePageLoad {
            file: self.file.clone(),
            page_number,
            page_count,
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
    ) -> bool {
        debug!("unmap_file: [{:#x}, {:#x})", start, start + size);
        if size == 0 {
            return true;
        }
        let Some(pages) = PageIter4K::new(start, start + size) else {
            return false;
        };
        // If this is a shared mapping, writeback dirty pages before unmapping.
        let mapping = match self {
            Backend::File(m) => m,
            _ => return false,
        };
        for addr in pages {
            if let Ok((frame, page_size, tlb)) = pt.unmap(addr) {
                if page_size != PageSize::Size4K {
                    return false;
                }
                // The owning AddrSpace batches the ASID shootdown after its
                // write lock is released.
                tlb.ignore();
                if frame.as_usize() != 0 {
                    if mapping.shared {
                        if let Some((file_offset, _)) = mapping.page_read_window(addr) {
                            let pn = (file_offset / PAGE_SIZE_4K as u64) as u32;
                            let _ = mapping.file.mark_page_dirty(pn);
                        }
                    }
                    reclaim.defer_frame(frame);
                }
            }
        }
        true
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
            if let Ok((frame, _flags, _)) = pt.read_for_addr(addr).query(addr) {
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
                    let src = phys_to_virt(old_frame).as_ptr();
                    let dst = phys_to_virt(new_frame).as_mut_ptr();
                    unsafe {
                        core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE_4K);
                    }

                    let mut pt_guard = pt.lock_for_addr(page_addr);
                    if let Ok((curr_frame, curr_flags, _)) = pt_guard.query(page_addr) {
                        if curr_frame == old_frame && !curr_flags.contains(MappingFlags::WRITE) {
                            if let Ok((_, tlb)) = pt_guard.remap(page_addr, new_frame, orig_flags) {
                                tlb.flush();
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
                                tlb.flush();
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
        let Some((file_offset, _)) = mapping.page_read_window(page_addr) else {
            return false;
        };
        let Ok(page_number) = u32::try_from(file_offset / PAGE_SIZE_4K as u64) else {
            return false;
        };
        if !prepared.matches(&mapping.file, page_number) {
            return false;
        }

        let mut candidates = Vec::with_capacity(prepared.pages.len());
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
            let Some((candidate_offset, _)) = mapping.page_read_window(candidate_addr) else {
                break;
            };
            if candidate_offset / PAGE_SIZE_4K as u64 != candidate_page_number as u64 {
                break;
            }
            candidates.push((index, candidate_addr));
        }
        let Some((_, last_addr)) = candidates.last().copied() else {
            return false;
        };

        let private_write = !mapping.shared
            && orig_flags.contains(MappingFlags::WRITE)
            && access_flags.contains(MappingFlags::WRITE);
        let requested_index = candidates[0].0;
        let Some((_, requested_frame)) = prepared.page(requested_index) else {
            return false;
        };
        let mut private_frame = if private_write {
            let Some(frame) = alloc_frame(false) else {
                return false;
            };
            unsafe {
                core::ptr::copy_nonoverlapping(
                    phys_to_virt(requested_frame).as_ptr(),
                    phys_to_virt(frame).as_mut_ptr(),
                    PAGE_SIZE_4K,
                );
            }
            Some(frame)
        } else {
            None
        };

        let range_size = last_addr
            .checked_add(PAGE_SIZE_4K)
            .map(|end| end - page_addr)
            .unwrap_or(PAGE_SIZE_4K);
        let mut pt_guard = pt.lock_for_range(page_addr, range_size);
        let mut requested_handled = false;
        let mut mapped_executable = false;
        for (index, candidate_addr) in candidates {
            let requested = candidate_addr == page_addr;
            if let Ok((current, current_flags, _)) = pt_guard.query(candidate_addr)
                && current.as_usize() != 0
            {
                if requested {
                    requested_handled = !access_flags.contains(MappingFlags::WRITE)
                        || current_flags.contains(MappingFlags::WRITE);
                }
                continue;
            }

            let Some((_, cache_frame)) = prepared.page(index) else {
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
            let mapped = match pt_guard.query(candidate_addr) {
                Ok((current, ..)) if current.as_usize() == 0 => pt_guard
                    .remap(candidate_addr, frame, map_flags)
                    .map(|(_, tlb)| tlb),
                Err(_) => pt_guard.map(candidate_addr, frame, PageSize::Size4K, map_flags),
                _ => continue,
            };
            let Ok(tlb) = mapped else {
                continue;
            };
            tlb.flush();
            mapped_executable |= map_flags.contains(MappingFlags::EXECUTE);
            if use_private_frame {
                private_frame.take();
            } else {
                prepared.take_frame(index);
            }
            if requested {
                requested_handled = true;
            }
        }
        drop(pt_guard);
        if let Some(frame) = private_frame {
            dealloc_frame(frame);
        }
        if mapped_executable {
            sync_executable_mapping(orig_flags);
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
            let Some((frame, _old_flags, _)) = pt.query(page).ok() else {
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

            if pt.protect(page, flags).map(|(_, tlb)| tlb.flush()).is_err() {
                error!(
                    "protect_file: failed to protect page: {:#x}, {:?}",
                    page, flags
                );
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::FileReadAheadState;

    #[test]
    fn readahead_advances_over_fault_around_window() {
        let mut state = FileReadAheadState::default();
        assert_eq!(state.plan(10, 4), 1);
        state.finish(10, 1, 1);
        assert_eq!(state.plan(11, 4), 4);
        state.finish(11, 4, 4);
        assert_eq!(state.plan(15, 4), 4);
    }

    #[test]
    fn readahead_resets_after_nonsequential_fault() {
        let mut state = FileReadAheadState::default();
        assert_eq!(state.plan(3, 4), 1);
        assert_eq!(state.plan(20, 4), 1);
        assert_eq!(state.plan(21, 4), 4);
    }

    #[test]
    fn readahead_tracks_short_result_at_mapping_end() {
        let mut state = FileReadAheadState::default();
        assert_eq!(state.plan(7, 2), 1);
        assert_eq!(state.plan(8, 2), 2);
        state.finish(8, 2, 1);
        assert_eq!(state.plan(9, 4), 4);
    }

    #[test]
    fn readahead_overflow_disables_sequential_hint() {
        let mut state = FileReadAheadState::default();
        assert_eq!(state.plan(u32::MAX, 4), 1);
        assert_eq!(state.plan(0, 4), 1);
    }
}
