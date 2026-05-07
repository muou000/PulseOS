use axfs::{CachedFile, FileFlags};
use axhal::{
    mem::phys_to_virt,
    paging::{MappingFlags, PageSize, PageTable},
};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, PageIter4K, VirtAddr};

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

#[derive(Clone)]
pub struct FileMapping {
    start: VirtAddr,
    file: CachedFile,
    file_flags: FileFlags,
    file_offset: usize,
    file_bytes: usize,
}

impl FileMapping {
    fn required_flags(flags: MappingFlags) -> FileFlags {
        let mut required = FileFlags::empty();
        if flags.contains(MappingFlags::READ) {
            required |= FileFlags::READ;
        }
        if flags.contains(MappingFlags::WRITE) {
            required |= FileFlags::WRITE;
        }
        if flags.contains(MappingFlags::EXECUTE) {
            required |= FileFlags::EXECUTE;
        }
        required
    }

    pub(crate) fn permits(&self, flags: MappingFlags) -> bool {
        self.file_flags.contains(Self::required_flags(flags))
    }

    fn page_read_window(&self, page_addr: VirtAddr) -> Option<(u64, usize)> {
        let relative = page_addr.as_usize().checked_sub(self.start.as_usize())?;
        if relative >= self.file_bytes {
            return None;
        }
        let read_len = (self.file_bytes - relative).min(PAGE_SIZE_4K);
        let file_offset = self.file_offset.checked_add(relative)?;
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
    ) -> Self {
        Self::File(FileMapping {
            start,
            file,
            file_flags,
            file_offset,
            file_bytes,
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
            "map_file: [{:#x}, {:#x}) {:?} offset={:#x} bytes={:#x}",
            start,
            start + size,
            flags,
            mapping.file_offset,
            mapping.file_bytes
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
        for addr in pages {
            if let Ok((frame, page_size, tlb)) = pt.unmap(addr) {
                if page_size != PageSize::Size4K {
                    return false;
                }
                tlb.flush();
                if frame.as_usize() != 0 {
                    dealloc_frame(frame);
                }
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
