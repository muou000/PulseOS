use core::fmt;

use axerrno::{AxError, AxResult, ax_err};
use axfs::{CachedFile, FileFlags};
use axhal::{
    mem::phys_to_virt,
    paging::{MappingFlags, PageSize, PageTable},
    trap::PageFaultFlags,
};
use memory_addr::{
    MemoryAddr, PAGE_SIZE_4K, PageIter4K, PhysAddr, VirtAddr, VirtAddrRange, is_aligned_4k,
};
use memory_set::{MemoryArea, MemorySet};

use crate::{backend::Backend, mapping_err_to_ax_err};

/// The virtual memory address space.
pub struct AddrSpace {
    va_range: VirtAddrRange,
    areas: MemorySet<Backend>,
    pt: PageTable,
}

impl AddrSpace {
    fn backend_kind(backend: &Backend) -> &'static str {
        match backend {
            Backend::Shared { .. } => "shared",
            Backend::Linear { .. } => "linear",
            Backend::Alloc { .. } => "alloc",
            Backend::File(_) => "file",
        }
    }

    /// Returns the address space base.
    pub const fn base(&self) -> VirtAddr {
        self.va_range.start
    }

    /// Returns the address space end.
    pub const fn end(&self) -> VirtAddr {
        self.va_range.end
    }

    /// Returns the address space size.
    pub fn size(&self) -> usize {
        self.va_range.size()
    }

    /// Returns the reference to the inner page table.
    pub const fn page_table(&self) -> &PageTable {
        &self.pt
    }

    /// Returns the root physical address of the inner page table.
    pub const fn page_table_root(&self) -> PhysAddr {
        self.pt.root_paddr()
    }

    /// Checks if the address space contains the given address range.
    pub fn contains_range(&self, start: VirtAddr, size: usize) -> bool {
        self.va_range
            .contains_range(VirtAddrRange::from_start_size(start, size))
    }

    /// Creates a new empty address space.
    pub fn new_empty(base: VirtAddr, size: usize) -> AxResult<Self> {
        Ok(Self {
            va_range: VirtAddrRange::from_start_size(base, size),
            areas: MemorySet::new(),
            pt: PageTable::try_new().map_err(|_| AxError::NoMemory)?,
        })
    }

    /// Copies page table mappings from another address space.
    ///
    /// It copies the page table entries only rather than the memory regions,
    /// usually used to copy a portion of the kernel space mapping to the
    /// user space.
    ///
    /// Returns an error if the two address spaces overlap.
    pub fn copy_mappings_from(&mut self, other: &AddrSpace) -> AxResult {
        if self.va_range.overlaps(other.va_range) {
            return ax_err!(InvalidInput, "address space overlap");
        }
        self.pt.copy_from(&other.pt, other.base(), other.size());
        Ok(())
    }

    /// Finds a free area that can accommodate the given size.
    ///
    /// The search starts from the given hint address, and the area should be within the given limit
    /// range.
    ///
    /// Returns the start address of the free area. Returns None if no such area is found.
    pub fn find_free_area(
        &self,
        hint: VirtAddr,
        size: usize,
        limit: VirtAddrRange,
    ) -> Option<VirtAddr> {
        self.areas.find_free_area(hint, size, limit, PAGE_SIZE_4K)
    }

    /// Add a new linear mapping.
    ///
    /// See [`Backend`] for more details about the mapping backends.
    ///
    /// The `flags` parameter indicates the mapping permissions and attributes.
    ///
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn map_linear(
        &mut self,
        start_vaddr: VirtAddr,
        start_paddr: PhysAddr,
        size: usize,
        flags: MappingFlags,
    ) -> AxResult {
        if !self.contains_range(start_vaddr, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start_vaddr.is_aligned_4k() || !start_paddr.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }

        let offset = start_vaddr.as_usize() - start_paddr.as_usize();
        let area = MemoryArea::new(start_vaddr, size, flags, Backend::new_linear(offset));
        self.areas
            .map(area, &mut self.pt, false)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// Add a new allocation mapping.
    ///
    /// See [`Backend`] for more details about the mapping backends.
    ///
    /// The `flags` parameter indicates the mapping permissions and attributes.
    ///
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn map_alloc(
        &mut self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        populate: bool,
    ) -> AxResult {
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }

        let area = MemoryArea::new(start, size, flags, Backend::new_alloc(populate));
        self.areas
            .map(area, &mut self.pt, false)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// Add a new file-backed on-demand mapping.
    pub fn map_file(
        &mut self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        file: CachedFile,
        file_flags: FileFlags,
        file_offset: usize,
        file_bytes: usize,
        shared: bool,
    ) -> AxResult {
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }

        let area = MemoryArea::new(
            start,
            size,
            flags,
            Backend::new_file(start, file, file_flags, file_offset, file_bytes, shared),
        );
        self.areas
            .map(area, &mut self.pt, false)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// Write back all resident dirty pages in the given range to their
    /// underlying files. Only shared file-backed mappings are affected.
    pub fn writeback_file_range(&self, start: VirtAddr, size: usize) -> AxResult {
        if size == 0 {
            return Ok(());
        }
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }

        let end = start + size;
        for area in self.areas.iter() {
            if area.end() <= start {
                continue;
            }
            if area.start() >= end {
                break;
            }
            let overlap_start = if area.start() > start { area.start() } else { start };
            let overlap_end = if area.end() < end { area.end() } else { end };
            if overlap_start < overlap_end {
                if !area.backend().writeback_file_range(overlap_start, overlap_end - overlap_start, &self.pt) {
                    return ax_err!(Io, "writeback failed");
                }
            }
        }
        Ok(())
    }

    /// Add a new mapping with an existing backend.
    pub fn map_with_backend(
        &mut self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        backend: Backend,
    ) -> AxResult {
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }

        let area = MemoryArea::new(start, size, flags, backend);
        self.areas
            .map(area, &mut self.pt, false)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }


    /// Maps the given physical pages into the address space at the specified
    /// virtual address range.  This is used for shared memory (shmget/shmat)
    /// where multiple processes must map the same physical frames.
    ///
    /// The caller must ensure:
    /// - `phys_pages.len() * PAGE_SIZE_4K == size`
    /// - `start` and `size` are 4K-aligned
    /// - The virtual range is free (not already mapped)
    pub fn map_phys_pages(
        &mut self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        phys_pages: &[PhysAddr],
    ) -> AxResult {
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }
        let expected = size / PAGE_SIZE_4K;
        if phys_pages.len() != expected {
            return ax_err!(InvalidInput, "phys_pages length mismatch");
        }

        // Register the area with Alloc(populate=false) so unmap works
        // without trying to dealloc shared frames.
        let area = MemoryArea::new(start, size, flags, Backend::new_alloc(false));
        self.areas
            .map(area, &mut self.pt, false)
            .map_err(mapping_err_to_ax_err)?;

        // Now manually map each physical page into the page table.
        let pages = PageIter4K::new(start, start + size).unwrap();
        for (vaddr, &frame) in pages.zip(phys_pages.iter()) {
            if let Ok(tlb) = self.pt.map(vaddr, frame, PageSize::Size4K, flags) {
                tlb.ignore();
            }
        }
        Ok(())
    }

    /// Removes mappings within the specified virtual address range.
    ///
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn unmap(&mut self, start: VirtAddr, size: usize) -> AxResult {
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }

        self.areas
            .unmap(start, size, &mut self.pt)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// To process data in this area with the given function.
    ///
    /// Now it supports reading and writing data in the given interval.
    fn process_area_data<F>(&self, start: VirtAddr, size: usize, mut f: F) -> AxResult
    where
        F: FnMut(VirtAddr, usize, usize),
    {
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        let mut cnt = 0;
        // If start is aligned to 4K, start_align_down will be equal to start_align_up.
        let end_align_up = (start + size).align_up_4k();
        for vaddr in PageIter4K::new(start.align_down_4k(), end_align_up)
            .expect("Failed to create page iterator")
        {
            let (mut paddr, ..) = self.pt.query(vaddr).map_err(|_| AxError::BadAddress)?;
            if paddr.as_usize() == 0 {
                // Placeholder PTEs are used for lazy mappings. They are not
                // readable/writable yet, so force the caller onto the page-fault
                // path instead of copying from the null physical frame.
                return Err(AxError::BadAddress);
            }

            let mut copy_size = (size - cnt).min(PAGE_SIZE_4K);

            if copy_size == 0 {
                break;
            }
            if vaddr == start.align_down_4k() && start.align_offset_4k() != 0 {
                let align_offset = start.align_offset_4k();
                copy_size = copy_size.min(PAGE_SIZE_4K - align_offset);
                paddr += align_offset;
            }
            f(phys_to_virt(paddr), cnt, copy_size);
            cnt += copy_size;
        }
        Ok(())
    }

    /// To read data from the address space.
    ///
    /// # Arguments
    ///
    /// * `start` - The start virtual address to read.
    /// * `buf` - The buffer to store the data.
    pub fn read(&self, start: VirtAddr, buf: &mut [u8]) -> AxResult {
        self.process_area_data(start, buf.len(), |src, offset, read_size| unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), buf.as_mut_ptr().add(offset), read_size);
        })
    }

    /// To write data to the address space.
    ///
    /// # Arguments
    ///
    /// * `start_vaddr` - The start virtual address to write.
    /// * `buf` - The buffer to write to the address space.
    pub fn write(&self, start: VirtAddr, buf: &[u8]) -> AxResult {
        self.process_area_data(start, buf.len(), |dst, offset, write_size| unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr().add(offset), dst.as_mut_ptr(), write_size);
        })
    }

    /// Updates mapping within the specified virtual address range.
    ///
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn protect(&mut self, start: VirtAddr, size: usize, flags: MappingFlags) -> AxResult {
        if size == 0 {
            return Ok(());
        }
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }
        if !self.can_access_range(start, size, MappingFlags::empty()) {
            return ax_err!(BadAddress, "address not mapped");
        }

        // Update both page-table permissions and MemorySet area flags.
        // Updating only page tables would make area metadata stale and break
        // future permission checks (e.g. page fault validation).
        self.areas
            .protect(start, size, |_| Some(flags), &mut self.pt)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// Updates only page-table permissions within the specified range.
    ///
    /// Unlike [`Self::protect`], this does not change MemorySet area flags.
    pub fn protect_pte_only(
        &mut self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
    ) -> AxResult {
        if size == 0 {
            return Ok(());
        }
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }
        if !self.can_access_range(start, size, MappingFlags::empty()) {
            return ax_err!(BadAddress, "address not mapped");
        }

        self.pt
            .protect_region(start, size, flags, true)
            .map_err(|_| AxError::BadState)?
            .ignore();
        Ok(())
    }

    /// Remap a single 4K page to a specified physical frame.
    pub fn remap_page(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: MappingFlags,
    ) -> AxResult {
        if !self.contains_range(vaddr, PAGE_SIZE_4K) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !vaddr.is_aligned_4k() || !paddr.is_aligned_4k() {
            return ax_err!(InvalidInput, "address not aligned");
        }

        if self.pt.query(vaddr).is_ok() {
            self.pt
                .remap(vaddr, paddr, flags)
                .map_err(|_| AxError::BadState)?
                .1
                .flush();
        } else {
            // True lazy mappings may not have allocated any intermediate page
            // tables yet, so COW install/remap must be able to materialize the
            // first concrete PTE on demand.
            self.pt
                .map(vaddr, paddr, PageSize::Size4K, flags)
                .map_err(|_| AxError::BadState)?
                .flush();
        }
        Ok(())
    }

    /// Removes all mappings in the address space.
    pub fn clear(&mut self) {
        self.areas.clear(&mut self.pt).unwrap();
    }

    /// Checks whether an access to the specified memory region is valid.
    ///
    /// Returns `true` if the memory region given by `range` is all mapped and
    /// has proper permission flags (i.e. containing `access_flags`).
    pub fn can_access_range(
        &self,
        start: VirtAddr,
        size: usize,
        access_flags: MappingFlags,
    ) -> bool {
        let mut range = VirtAddrRange::from_start_size(start, size);
        for area in self.areas.iter() {
            if area.end() <= range.start {
                continue;
            }
            if area.start() > range.start {
                return false;
            }

            // This area overlaps with the memory region
            if !area.flags().contains(access_flags) {
                return false;
            }

            range.start = area.end();
            if range.is_empty() {
                return true;
            }
        }

        false
    }

    /// Visits all mapped virtual memory areas tracked by this address space.
    pub fn for_each_area<F>(&self, mut f: F)
    where
        F: FnMut(VirtAddr, VirtAddr, MappingFlags),
    {
        for area in self.areas.iter() {
            f(area.start(), area.end(), area.flags());
        }
    }

    /// Visits all mapped virtual memory areas together with their backends.
    pub fn for_each_area_with_backend<F>(&self, mut f: F)
    where
        F: FnMut(VirtAddr, VirtAddr, MappingFlags, &Backend),
    {
        for area in self.areas.iter() {
            f(area.start(), area.end(), area.flags(), area.backend());
        }
    }

    /// Handles a page fault at the given address.
    ///
    /// `access_flags` indicates the access type that caused the page fault.
    ///
    /// Returns `true` if the page fault is handled successfully (not a real
    /// fault).
    pub fn handle_page_fault(&mut self, vaddr: VirtAddr, access_flags: PageFaultFlags) -> bool {
        let page = vaddr.align_down_4k();
        let pte_before = self
            .pt
            .query(page)
            .ok()
            .map(|(frame, flags, _)| (frame, flags));
        if !self.va_range.contains(vaddr) {
            error!(
                "handle_page_fault: reject=out_of_range vaddr={:#x} page={:#x} access={:?} \
                 aspace_range={:?} pte_before={:?}",
                vaddr, page, access_flags, self.va_range, pte_before
            );
            return false;
        }
        if let Some(area) = self.areas.find(vaddr) {
            let orig_flags = area.flags();
            let backend_kind = Self::backend_kind(area.backend());
            debug!(
                "handle_page_fault: vaddr={:#x} page={:#x} access={:?} area=[{:#x}, {:#x}) \
                 area_flags={:?} backend={} pte_before={:?}",
                vaddr,
                page,
                access_flags,
                area.start(),
                area.end(),
                orig_flags,
                backend_kind,
                pte_before
            );
            if orig_flags.contains(access_flags) {
                let handled = area
                    .backend()
                    .handle_page_fault(vaddr, orig_flags, &mut self.pt);
                if !handled {
                    let pte_after = self
                        .pt
                        .query(page)
                        .ok()
                        .map(|(frame, flags, _)| (frame, flags));
                    error!(
                        "handle_page_fault: reject=backend_not_handled vaddr={:#x} page={:#x} \
                         access={:?} area_flags={:?} backend={} pte_before={:?} pte_after={:?}",
                        vaddr, page, access_flags, orig_flags, backend_kind, pte_before, pte_after
                    );
                }
                return handled;
            }
            error!(
                "handle_page_fault: reject=area_permission vaddr={:#x} page={:#x} access={:?} \
                 area_flags={:?} backend={} pte_before={:?}",
                vaddr, page, access_flags, orig_flags, backend_kind, pte_before
            );
        } else {
            error!(
                "handle_page_fault: reject=no_area vaddr={:#x} page={:#x} access={:?} \
                 pte_before={:?}",
                vaddr, page, access_flags, pte_before
            );
        }
        false
    }

    /// Attempts to clone the current address space into a new one.
    pub fn try_clone(&mut self) -> AxResult<Self> {
        let mut new_aspace = Self::new_empty(self.va_range.start, self.va_range.size())?;

        if !cfg!(target_arch = "aarch64") && !cfg!(target_arch = "loongarch64") {
            new_aspace.copy_mappings_from(&*crate::kernel_aspace().lock())?;
        }

        for area in self.areas.iter() {
            // For Alloc backends, the child uses lazy allocation (populate=false)
            // so that fork doesn't eagerly duplicate all physical frames.
            let backend = match area.backend() {
                Backend::Alloc { .. } => Backend::new_alloc(false),
                other => other.clone(),
            };
            let new_area = MemoryArea::new(area.start(), area.size(), area.flags(), backend);
            new_aspace
                .areas
                .map(new_area, &mut new_aspace.pt, false)
                .map_err(mapping_err_to_ax_err)?;

            // Only iterate over pages that are actually mapped in the parent.
            for vaddr in PageIter4K::new(area.start(), area.end()).unwrap() {
                if let Ok((paddr, flags, _)) = self.pt.query(vaddr) {
                    if paddr.as_usize() == 0 {
                        // Skip unmaterialized lazy pages.
                        continue;
                    }

                    match area.backend() {
                        Backend::Alloc { .. } => {
                            // Eager copy for Alloc mappings.
                            let child_backend = Backend::new_alloc(false);
                            if !child_backend.handle_page_fault(vaddr, flags, &mut new_aspace.pt) {
                                return Err(AxError::NoMemory);
                            }
                            let (new_paddr, _, _) = new_aspace
                                .pt
                                .query(vaddr)
                                .map_err(|_| AxError::BadAddress)?;
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    phys_to_virt(paddr).as_ptr(),
                                    phys_to_virt(new_paddr).as_mut_ptr(),
                                    PAGE_SIZE_4K,
                                );
                            }
                        }
                        Backend::File(mapping) if !mapping.is_shared() => {
                            // Eager copy for private File mappings.
                            let child_backend = Backend::new_alloc(false);
                            if !child_backend.handle_page_fault(vaddr, flags, &mut new_aspace.pt) {
                                return Err(AxError::NoMemory);
                            }
                            let (new_paddr, _, _) = new_aspace
                                .pt
                                .query(vaddr)
                                .map_err(|_| AxError::BadAddress)?;
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    phys_to_virt(paddr).as_ptr(),
                                    phys_to_virt(new_paddr).as_mut_ptr(),
                                    PAGE_SIZE_4K,
                                );
                            }
                        }
                        Backend::File(_) => {
                            // Shared file mapping: map the same physical frame.
                            new_aspace
                                .pt
                                .map(vaddr, paddr, PageSize::Size4K, flags)
                                .map(|tlb| tlb.ignore())
                                .map_err(|_| AxError::NoMemory)?;
                        }
                        Backend::Linear { .. } | Backend::Shared { .. } => {
                            // Already handled by areas.map() via pt.map_region.
                        }
                    }
                }
            }
        }

        Ok(new_aspace)
    }
}

impl fmt::Debug for AddrSpace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AddrSpace")
            .field("va_range", &self.va_range)
            .field("page_table_root", &self.pt.root_paddr())
            .field("areas", &self.areas)
            .finish()
    }
}

impl Drop for AddrSpace {
    fn drop(&mut self) {
        self.clear();
    }
}
