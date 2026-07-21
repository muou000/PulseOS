use axerrno::{AxError, AxResult};
use axfs::{CachedFile, FileFlags};
use axhal::{
    mem::phys_to_virt,
    paging::{MappingFlags, PageSize, PageTable},
};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, PageIter4K, PhysAddr, VirtAddr};

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
fn read_file_page(mapping: &FileMapping, dst: &mut [u8], file_offset: u64, read_len: usize) -> bool {
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
    let src = unsafe {
        core::slice::from_raw_parts(phys_to_virt(frame_paddr).as_ptr(), write_len)
    };
    match mapping.file.write_at(src, file_offset) {
        Ok(written) => written == write_len,
        Err(_) => false,
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
}

#[derive(Clone)]
pub struct FilePageLoad {
    file: CachedFile,
    page_number: u32,
    may_write: bool,
}

pub struct FilePagePrepared {
    file: CachedFile,
    page_number: u32,
    frame: Option<PhysAddr>,
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
        loop {
            self.file
                .ensure_page_resident(self.page_number)
                .map_err(|_| AxError::Io)?;
            match self
                .file
                .try_pin_shared_page_paddr(self.page_number, self.may_write)
                .map_err(|_| AxError::Io)?
            {
                Some(frame) => {
                    return Ok(FilePagePrepared {
                        file: self.file,
                        page_number: self.page_number,
                        frame: Some(frame),
                    });
                }
                None => continue,
            }
        }
    }
}

impl core::fmt::Debug for FilePagePrepared {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FilePagePrepared")
            .field("page_number", &self.page_number)
            .field("frame", &self.frame)
            .finish_non_exhaustive()
    }
}

impl Drop for FilePagePrepared {
    fn drop(&mut self) {
        if let Some(frame) = self.frame.take() {
            dealloc_frame(frame);
        }
    }
}

impl FilePagePrepared {
    fn matches(&self, file: &CachedFile, page_number: u32) -> bool {
        self.page_number == page_number && self.file.shares_page_cache_with(file)
    }

    fn frame(&self) -> Option<PhysAddr> {
        self.frame
    }

    fn take_frame(&mut self) -> Option<PhysAddr> {
        self.frame.take()
    }
}

impl FileMapping {

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
        axfs::cached_file_size(self.file.location()).map(|len| len as usize).unwrap_or(self.file_bytes)
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
        orig_flags: MappingFlags,
        pt: &crate::PageTableLockManager,
    ) -> Option<FilePageLoad> {
        if !self.permits(orig_flags) {
            return None;
        }

        let page_addr = vaddr.align_down_4k();
        let (file_offset, _) = self.page_read_window(page_addr)?;
        if pt
            .lock_for_addr(page_addr)
            .query(page_addr)
            .is_ok_and(|(frame, _, _)| frame.as_usize() != 0)
        {
            return None;
        }

        let page_number = u32::try_from(file_offset / PAGE_SIZE_4K as u64).ok()?;
        Some(FilePageLoad {
            file: self.file.clone(),
            page_number,
            may_write: self.shared && self.file_flags.contains(FileFlags::WRITE),
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
    ) -> Self {
        Self::File(FileMapping {
            start,
            file,
            file_flags,
            file_offset,
            file_bytes,
            shared,
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
                tlb.flush();
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
    pub(crate) fn writeback_file_range_impl(
        &self,
        start: VirtAddr,
        size: usize,
        sync: bool,
        pt: &crate::PageTableLockManager,
    ) -> bool {
        let mapping = match self {
            Backend::File(m) => m,
            _ => return false,
        };
        if !mapping.shared {
            return true; // Nothing to do for private mappings.
        }
        if size == 0 {
            return true;
        }
        let Some(pages) = PageIter4K::new(start, start + size) else {
            return false;
        };
        for addr in pages {
            if let Ok((frame, _flags, _)) = pt.lock_for_addr(addr).query(addr) {
                if frame.as_usize() != 0 {
                    let Some((file_offset, _)) = mapping.page_read_window(addr) else {
                        continue;
                    };
                    let pn = (file_offset / PAGE_SIZE_4K as u64) as u32;
                    if mapping.file.mark_page_dirty(pn).is_err() {
                        return false;
                    }
                }
            }
        }
        if sync {
            if mapping.file.sync(false).is_err() {
                return false;
            }
        }
        true
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
        let relative = page_addr.as_usize().saturating_sub(mapping.start.as_usize());
        if relative >= (current_file_bytes + PAGE_SIZE_4K - 1) & !(PAGE_SIZE_4K - 1) {
            return false;
        }

        let query_res = pt.lock_for_addr(page_addr).query(page_addr);
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
        let page_number = (file_offset / PAGE_SIZE_4K as u64) as u32;
        if !prepared.matches(&mapping.file, page_number) {
            return false;
        }
        let Some(frame) = prepared.frame() else {
            return false;
        };

        let mut pt_guard = pt.lock_for_addr(page_addr);
        if pt_guard
            .query(page_addr)
            .is_ok_and(|(current, _, _)| current.as_usize() != 0)
        {
            return true;
        }

        if mapping.shared {
            let mapped = pt_guard
                .map(page_addr, frame, PageSize::Size4K, orig_flags)
                .map(|tlb| {
                    tlb.flush();
                    sync_executable_mapping(orig_flags);
                })
                .is_ok();
            if mapped {
                prepared.take_frame();
            }
            return mapped;
        }

        if orig_flags.contains(MappingFlags::WRITE) && access_flags.contains(MappingFlags::WRITE) {
            let Some(new_frame) = alloc_frame(false) else {
                return false;
            };
            unsafe {
                core::ptr::copy_nonoverlapping(
                    phys_to_virt(frame).as_ptr(),
                    phys_to_virt(new_frame).as_mut_ptr(),
                    PAGE_SIZE_4K,
                );
            }
            let mapped = pt_guard
                .map(page_addr, new_frame, PageSize::Size4K, orig_flags)
                .map(|tlb| {
                    tlb.flush();
                    sync_executable_mapping(orig_flags);
                })
                .is_ok();
            if !mapped {
                dealloc_frame(new_frame);
            }
            return mapped;
        }

        let map_flags = orig_flags & !MappingFlags::WRITE;
        let mapped = pt_guard
            .map(page_addr, frame, PageSize::Size4K, map_flags)
            .map(|tlb| {
                tlb.flush();
                sync_executable_mapping(map_flags);
            })
            .is_ok();
        if mapped {
            prepared.take_frame();
        }
        mapped
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
