use core::fmt;

use axerrno::{AxError, AxResult, ax_err};
use axfs::{CachedFile, FileFlags};
use axhal::{
    mem::{phys_to_virt, PhysAddr},
    paging::{MappingFlags, PageSize, PageTable},
    trap::PageFaultFlags,
};
use memory_addr::{
    MemoryAddr, PAGE_SIZE_4K, PageIter4K, VirtAddr, VirtAddrRange, is_aligned_4k,
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
            Backend::Cow(_) => "cow",
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
    pub fn writeback_file_range(&self, start: VirtAddr, size: usize, sync: bool) -> AxResult {
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
                if !area.backend().writeback_file_range(overlap_start, overlap_end - overlap_start, sync, &self.pt) {
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
        if buf.is_empty() {
            return Ok(());
        }
        if !self.can_access_range(start, buf.len(), MappingFlags::READ | MappingFlags::USER) {
            return Err(AxError::BadAddress);
        }
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
        if buf.is_empty() {
            return Ok(());
        }
        if !self.can_access_range(start, buf.len(), MappingFlags::WRITE | MappingFlags::USER) {
            return Err(AxError::BadAddress);
        }
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

    /// Checks if a virtual address range overlaps with any registered area.
    pub fn has_overlap(&self, start: VirtAddr, size: usize) -> bool {
        let range = VirtAddrRange::from_start_size(start, size);
        for area in self.areas.iter() {
            if area.end() <= range.start {
                continue;
            }
            if area.start() >= range.end {
                break;
            }
            return true;
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
                    .handle_page_fault(vaddr, area.end(), orig_flags, &mut self.pt);
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
            // Check for stack grows down auto-extension.
            // Find an area that starts immediately at page + PAGE_SIZE_4K and has GROWSDOWN.
            let next_page = page + PAGE_SIZE_4K;
            let mut growsdown_area_info = None;
            for area in self.areas.iter() {
                if area.start() == next_page {
                    if area.backend().is_grows_down() {
                        growsdown_area_info = Some(area.flags());
                    }
                    break;
                }
            }

            if let Some(flags) = growsdown_area_info {
                debug!(
                    "handle_page_fault: growing stack downward at {:#x} for next area start {:#x}",
                    page, next_page
                );
                // Linux stack_guard_gap check: do not allow stack to grow closer than 256 pages to an existing mapping.
                let guard_gap_size = 256 * PAGE_SIZE_4K;
                let guard_start = if page.as_usize() > guard_gap_size {
                    VirtAddr::from(page.as_usize() - guard_gap_size)
                } else {
                    VirtAddr::from(0)
                };
                let guard_size = page.as_usize() - guard_start.as_usize();
                if self.has_overlap(guard_start, guard_size) {
                    warn!(
                        "handle_page_fault: stack growth rejected at {:#x} due to overlap in guard gap [{:#x}, {:#x})",
                        page, guard_start, page
                    );
                    return false;
                }

                let backend = Backend::new_alloc_grows_down(false, true);
                if self.map_with_backend(page, PAGE_SIZE_4K, flags, backend).is_ok() {
                    return self.handle_page_fault(vaddr, access_flags);
                }
            }

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

        let mut areas_to_convert = alloc::vec::Vec::new();

        for area in self.areas.iter() {
            // Filter: only clone areas within the user address range.
            // On LoongArch64 and RISC-V 4-level paging, user space is < 0x8000_0000_0000.
            if area.start().as_usize() >= 0x8000_0000_0000usize {
                continue;
            }

            debug!("try_clone: cloning area [{:#x}, {:#x}) flags={:?} backend={}", 
                area.start(), area.end(), area.flags(), match area.backend() {
                    Backend::Alloc { .. } => "alloc",
                    Backend::File(_) => "file",
                    Backend::Cow(_) => "cow",
                    Backend::Linear { .. } => "linear",
                    Backend::Shared { .. } => "shared",
                }
            );

            let mut is_cow = false;
            let backend = match area.backend() {
                Backend::Cow(_) => {
                    is_cow = true;
                    area.backend().clone()
                }
                Backend::Alloc { .. } => {
                    is_cow = true;
                    let mut inner = area.backend().clone();
                    if let Backend::Alloc { ref mut populate, .. } = inner {
                        *populate = false;
                    }
                    Backend::Cow(crate::backend::CowMapping::new(alloc::boxed::Box::new(inner)))
                }
                Backend::File(mapping) if !mapping.is_shared() => {
                    is_cow = true;
                    Backend::Cow(crate::backend::CowMapping::new(alloc::boxed::Box::new(area.backend().clone())))
                }
                other => other.clone(),
            };

            let new_area = MemoryArea::new(area.start(), area.size(), area.flags(), backend.clone());
            if let Err(e) = new_aspace.areas.map(new_area, &mut new_aspace.pt, false) {
                new_aspace.clear();
                return Err(mapping_err_to_ax_err(e));
            }

            if is_cow {
                if !matches!(area.backend(), Backend::Cow(_)) {
                    areas_to_convert.push((area.start(), backend));
                }
            }

            // Only iterate over pages for lazy backends.
            // Linear and Shared (non-File) backends are already fully mapped by areas.map().
            let is_lazy = match area.backend() {
                Backend::Alloc { .. } | Backend::File(_) | Backend::Cow(_) => true,
                _ => false,
            };
            if !is_lazy {
                continue;
            }

            // Efficiently iterate only over actually mapped pages in this area.
            let mut vaddr = area.start();
            let area_end = area.end();
            while vaddr < area_end {
                match self.pt.query_skip(vaddr) {
                    Ok((paddr, flags, page_size)) => {
                        if paddr.as_usize() != 0 {
                            if is_cow {
                                crate::cow_inc_frame_ref(paddr);
                                let cow_flags = flags & !MappingFlags::WRITE;

                                // Demote parent if writable
                                if flags.contains(MappingFlags::WRITE) {
                                    if let Err(e) = self.pt.protect(vaddr, cow_flags) {
                                        error!("try_clone: failed to protect parent page {:#x}: {:?}", vaddr, e);
                                    }
                                }

                                // Map child
                                if let Err(e) = new_aspace.pt.map(vaddr, paddr, page_size, cow_flags).map(|tlb| tlb.ignore()) {
                                    error!("try_clone: failed to map child page {:#x}: {:?}", vaddr, e);
                                    if crate::backend::cow_dec_frame_ref(paddr) {
                                        axalloc::global_allocator().dealloc_pages(phys_to_virt(paddr).as_usize(), page_size as usize / PAGE_SIZE_4K);
                                    }
                                    new_aspace.clear();
                                    return Err(AxError::NoMemory);
                                }
                            } else if let Backend::File(mapping) = area.backend() {
                                if mapping.is_shared() {
                                    if let Err(e) = new_aspace.pt.map(vaddr, paddr, page_size, flags).map(|tlb| tlb.ignore()) {
                                        error!("try_clone: failed to map shared file page {:#x}: {:?}", vaddr, e);
                                        new_aspace.clear();
                                        return Err(AxError::NoMemory);
                                    }
                                }
                            }
                        }
                        // Advance to the next page of the same size, correctly aligned.
                        let next_vaddr = (vaddr.as_usize() & !(page_size as usize - 1)) + page_size as usize;
                        vaddr = VirtAddr::from(next_vaddr);
                    }
                    Err(skip_size) => {
                        // Skip to the start of the next unmapped block boundary of skip_size
                        let next_vaddr = (vaddr.as_usize() & !(skip_size - 1)) + skip_size;
                        vaddr = VirtAddr::from(next_vaddr);
                    }
                }
            }
        }

        // Mandatory full TLB flush for parent after permission demotion.
        axhal::asm::flush_tlb(None);

        for (start, backend) in areas_to_convert {
            if let Some(area) = self.areas.get_area_mut(start) {
                area.set_backend(backend);
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
