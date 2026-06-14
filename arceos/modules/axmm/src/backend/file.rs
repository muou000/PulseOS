use axfs::{CachedFile, FileFlags};
use axhal::{
    mem::phys_to_virt,
    paging::{MappingFlags, PageSize, PageTable},
};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, PageIter4K, PhysAddr, VirtAddr};

use super::{
    Backend,
    alloc::{alloc_frame, dealloc_frame, protect_pages},
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
        self.file.location().len().map(|len| len as usize).unwrap_or(self.file_bytes)
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

    pub(crate) fn unmap_file(&self, start: VirtAddr, size: usize, pt: &mut PageTable) -> bool {
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
                        let Some((file_offset, _)) = mapping.page_read_window(addr) else {
                            continue;
                        };
                        let pn = (file_offset / PAGE_SIZE_4K as u64) as u32;
                        let _ = mapping.file.mark_page_dirty(pn);
                    } else {
                        dealloc_frame(frame);
                    }
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
        pt: &PageTable,
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
            if let Ok((frame, _flags, _)) = pt.query(addr) {
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
        orig_flags: MappingFlags,
        pt: &mut PageTable,
        mapping: &FileMapping,
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

        if let Ok((old_frame, old_flags, _)) = pt.query(page_addr) {
            if old_frame.as_usize() != 0 {
                let new_flags = old_flags | orig_flags;
                if old_flags.contains(new_flags) {
                    return true;
                }
                return pt
                    .remap(page_addr, old_frame, new_flags)
                    .map(|(_, tlb)| tlb.flush())
                    .is_ok();
            }
        }

        if mapping.shared {
            let Some((file_offset, _)) = mapping.page_read_window(page_addr) else {
                return false;
            };
            let pn = (file_offset / PAGE_SIZE_4K as u64) as u32;
            let frame = match mapping.file.get_shared_page_paddr(pn) {
                Ok(paddr) => paddr,
                Err(_) => return false,
            };

            return pt
                .map(page_addr, frame, PageSize::Size4K, orig_flags)
                .map(|tlb| {
                    tlb.flush();
                    sync_executable_mapping(orig_flags);
                })
                .is_ok();
        }

        let Some(frame) = alloc_frame(true) else {
            return false;
        };
        let dst = unsafe {
            core::slice::from_raw_parts_mut(phys_to_virt(frame).as_mut_ptr(), PAGE_SIZE_4K)
        };
        if let Some((file_offset, read_len)) = mapping.page_read_window(page_addr) {
            if !read_file_page(mapping, dst, file_offset, read_len) {
                dealloc_frame(frame);
                return false;
            }
        }

        if pt
            .map(page_addr, frame, PageSize::Size4K, orig_flags)
            .map(|tlb| {
                tlb.flush();
                sync_executable_mapping(orig_flags);
            })
            .is_ok()
        {
            true
        } else {
            dealloc_frame(frame);
            false
        }
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
        protect_pages(start, size, new_flags, true, true, pt)
    }
}
