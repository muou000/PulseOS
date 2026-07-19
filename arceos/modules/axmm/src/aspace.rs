use core::fmt;

use axerrno::{AxError, AxResult, ax_err};
use axfs::{CachedFile, FileFlags};
use axhal::{
    mem::{phys_to_virt, PhysAddr},
    paging::{MappingFlags, PageSize, PageTable, PagingResult},
    trap::PageFaultFlags,
};
use memory_addr::{
    MemoryAddr, PAGE_SIZE_4K, PageIter4K, VirtAddr, VirtAddrRange, is_aligned_4k,
};
use memory_set::{MemoryArea, MemorySet};

use crate::{
    backend::{Backend, DeferredReclaims},
    mapping_err_to_ax_err,
};

/// A TLB shootdown that must run after releasing the address-space lock.
#[must_use = "a TLB shootdown must be completed after releasing the address-space lock"]
pub struct TlbShootdown {
    asids: alloc::vec::Vec<usize>,
    reclaims: DeferredReclaims,
}

impl TlbShootdown {
    fn new(asid: usize, reclaims: DeferredReclaims) -> Self {
        Self {
            asids: alloc::vec![asid],
            reclaims,
        }
    }

    fn without_reclaims(asid: usize) -> Self {
        Self::new(asid, DeferredReclaims::default())
    }

    /// Merges another deferred shootdown into this batch.
    pub fn merge(&mut self, other: Self) {
        let Self { asids, reclaims } = other;
        for asid in asids {
            if !self.asids.contains(&asid) {
                self.asids.push(asid);
            }
        }
        self.reclaims.append(reclaims);
    }

    /// Completes the shootdown without holding an address-space lock.
    pub fn complete_after_unlock(self) -> AxResult {
        let Self { asids, reclaims } = self;

        #[cfg(feature = "ipi")]
        {
            let _ = asids;
            match axipi::flush_tlb_all_cpus() {
                Ok(()) => {
                    reclaims.reclaim();
                    Ok(())
                }
                Err(shootdown_error) => {
                    let completed = shootdown_error.completion_guaranteed();
                    if completed {
                        warn!("{shootdown_error}");
                        reclaims.reclaim();
                        Ok(())
                    } else {
                        error!("{shootdown_error}");
                        // DeferredReclaims intentionally leaks mapping references
                        // when dropped before a completion guarantee.
                        drop(reclaims);
                        Err(AxError::BadState)
                    }
                }
            }
        }

        #[cfg(not(feature = "ipi"))]
        {
            for asid in asids {
                unsafe { flush_tlb_asid(asid) };
            }
            reclaims.reclaim();
            Ok(())
        }
    }
}

impl fmt::Debug for TlbShootdown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlbShootdown")
            .field("asids", &self.asids)
            .field("has_reclaims", &!self.reclaims.is_empty())
            .finish()
    }
}

/// A page-table mutation whose shootdown must be completed after unlocking.
#[must_use = "the mutation result may contain a required TLB shootdown"]
pub struct AddrSpaceMutation<T> {
    result: AxResult<T>,
    shootdown: Option<TlbShootdown>,
}

impl<T> AddrSpaceMutation<T> {
    fn new(result: AxResult<T>, shootdown: Option<TlbShootdown>) -> Self {
        Self { result, shootdown }
    }

    /// Splits the operation result from its deferred shootdown.
    pub fn into_parts(self) -> (AxResult<T>, Option<TlbShootdown>) {
        (self.result, self.shootdown)
    }

    /// Completes the deferred shootdown and then returns the operation result.
    pub fn complete_after_unlock(self) -> AxResult<T> {
        let (result, shootdown) = self.into_parts();
        if let Some(shootdown) = shootdown {
            shootdown.complete_after_unlock()?;
        }
        result
    }
}

/// The result of a page fault handling operation on [`AddrSpace`].
#[derive(Debug)]
pub enum PageFaultResult {
    /// The page fault completed without requiring a remote TLB shootdown.
    Handled(bool),
    /// The page fault completed and requires a remote TLB shootdown.
    HandledWithShootdown {
        handled: bool,
        shootdown: TlbShootdown,
    },
    /// The page fault requires the write lock of the address space (stack grows down).
    NeedWriteLock,
}

impl PageFaultResult {
    /// Returns the handling result, completing any deferred TLB shootdown first.
    ///
    /// This must only be called after the lock used to access the address space
    /// has been released. `None` means the fault needs to be retried with the
    /// address-space write lock.
    pub fn complete_after_unlock(self) -> AxResult<Option<bool>> {
        match self {
            Self::Handled(success) => Ok(Some(success)),
            Self::HandledWithShootdown { handled, shootdown } => {
                shootdown.complete_after_unlock()?;
                Ok(Some(handled))
            }
            Self::NeedWriteLock => Ok(None),
        }
    }
}

/// The result of cloning an address space, including the parent TLB update.
pub struct AddrSpaceCloneResult {
    result: AxResult<AddrSpace>,
    shootdown: TlbShootdown,
}

impl AddrSpaceCloneResult {
    /// Completes the parent TLB shootdown and returns the cloned address space.
    pub fn complete_after_unlock(self) -> AxResult<AddrSpace> {
        let Self { result, shootdown } = self;
        shootdown.complete_after_unlock()?;
        result
    }
}

pub struct PageTableLockManager {
    pt: spin::Mutex<PageTable>,
}

pub struct PageTableGuard<'a>(spin::MutexGuard<'a, PageTable>);

unsafe impl<'a> Send for PageTableGuard<'a> {}
unsafe impl<'a> Sync for PageTableGuard<'a> {}

impl<'a> core::ops::Deref for PageTableGuard<'a> {
    type Target = PageTable;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> core::ops::DerefMut for PageTableGuard<'a> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PageTableLockManager {
    pub fn new(pt: PageTable) -> Self {
        Self {
            pt: spin::Mutex::new(pt),
        }
    }

    #[inline]
    pub fn root_paddr(&self) -> PhysAddr {
        self.pt.lock().root_paddr()
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut PageTable {
        self.pt.get_mut()
    }

    pub fn lock(&self) -> PageTableGuard {
        PageTableGuard(self.pt.lock())
    }

    pub fn lock_for_addr(&self, _vaddr: VirtAddr) -> PageTableGuard {
        PageTableGuard(self.pt.lock())
    }
}

/// The virtual memory address space.
pub struct AddrSpace {
    va_range: VirtAddrRange,
    areas: MemorySet<Backend>,
    pt: PageTableLockManager,
    asid: usize,
    last_alloc_addr: core::sync::atomic::AtomicUsize,
}

impl AddrSpace {
    fn map_area(&mut self, area: MemoryArea<Backend>) -> memory_set::MappingResult {
        let mut reclaim = DeferredReclaims::default();
        let result = self.areas.map(area, &mut self.pt, false, &mut reclaim);
        debug_assert!(reclaim.is_empty());
        reclaim.reclaim();
        result
    }

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

    /// Query a virtual address mapping from the inner page table under lock.
    pub fn query_vaddr(&self, vaddr: VirtAddr) -> PagingResult<(PhysAddr, MappingFlags, PageSize)> {
        self.pt.lock_for_addr(vaddr).query(vaddr)
    }

    /// Returns the root physical address of the inner page table.
    pub fn page_table_root(&self) -> PhysAddr {
        self.pt.root_paddr()
    }

    /// Returns the ASID of this address space.
    pub fn asid(&self) -> usize {
        self.asid
    }

    /// Checks if the address space contains the given address range.
    pub fn contains_range(&self, start: VirtAddr, size: usize) -> bool {
        if let Some(range) = VirtAddrRange::try_from_start_size(start, size) {
            self.va_range.contains_range(range)
        } else {
            false
        }
    }

    /// Creates a new empty address space.
    pub fn new_empty(base: VirtAddr, size: usize) -> AxResult<Self> {
        let asid = ASID_ALLOCATOR.lock().alloc();
        Ok(Self {
            va_range: VirtAddrRange::from_start_size(base, size),
            areas: MemorySet::new(),
            pt: PageTableLockManager::new(PageTable::try_new().map_err(|_| AxError::NoMemory)?),
            asid,
            last_alloc_addr: core::sync::atomic::AtomicUsize::new(base.as_usize()),
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
        self.pt.get_mut().copy_from(&*other.pt.lock(), other.base(), other.size());
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
        // `self.areas::find_free_area` requires the size to be multiple of the alignment.
        // So we pass 4K alignment here.
        let is_hint_base = hint == self.va_range.start;
        let search_hint = if is_hint_base {
            let last_alloc = self.last_alloc_addr.load(core::sync::atomic::Ordering::Acquire);
            if last_alloc >= self.va_range.start.as_usize() && last_alloc < self.va_range.end.as_usize() {
                VirtAddr::from(last_alloc)
            } else {
                hint
            }
        } else {
            hint
        };

        if let Some(vaddr) = self.areas.find_free_area(search_hint, size, limit, PAGE_SIZE_4K) {
            if is_hint_base {
                self.last_alloc_addr.store(vaddr.as_usize() + size, core::sync::atomic::Ordering::Release);
            }
            return Some(vaddr);
        }

        if is_hint_base && search_hint != hint {
            if let Some(vaddr) = self.areas.find_free_area(hint, size, limit, PAGE_SIZE_4K) {
                self.last_alloc_addr.store(vaddr.as_usize() + size, core::sync::atomic::Ordering::Release);
                return Some(vaddr);
            }
        }

        None
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
        self.map_area(area).map_err(mapping_err_to_ax_err)?;
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
        self.map_area(area).map_err(mapping_err_to_ax_err)?;
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
        self.map_area(area).map_err(mapping_err_to_ax_err)?;
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
        self.map_area(area).map_err(mapping_err_to_ax_err)?;
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
        self.map_area(area).map_err(mapping_err_to_ax_err)?;

        // Now manually map each physical page into the page table.
        let pages = PageIter4K::new(start, start + size).unwrap();
        for (vaddr, &frame) in pages.zip(phys_pages.iter()) {
            if let Ok(tlb) = self.pt.get_mut().map(vaddr, frame, PageSize::Size4K, flags) {
                tlb.ignore();
            }
        }
        Ok(())
    }

    /// Removes mappings within the specified virtual address range.
    ///
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn unmap(&mut self, start: VirtAddr, size: usize) -> AddrSpaceMutation<()> {
        let mut reclaim = DeferredReclaims::default();
        let mut attempted = false;
        let result = (|| -> AxResult {
            if !self.contains_range(start, size) {
                return ax_err!(InvalidInput, "address out of range");
            }
            if !start.is_aligned_4k() || !is_aligned_4k(size) {
                return ax_err!(InvalidInput, "address not aligned");
            }
            if !self.has_overlap(start, size) {
                return Ok(());
            }

            attempted = true;
            self.areas
                .unmap(start, size, &mut self.pt, &mut reclaim)
                .map_err(mapping_err_to_ax_err)
        })();
        let shootdown = if attempted {
            Some(TlbShootdown::new(self.asid, reclaim))
        } else {
            reclaim.reclaim();
            None
        };
        AddrSpaceMutation::new(result, shootdown)
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
            let (mut paddr, ..) = self.pt.lock_for_addr(vaddr).query(vaddr).map_err(|_| AxError::BadAddress)?;
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

        let end = start.checked_add(buf.len()).ok_or(AxError::BadAddress)?;
        let pages = PageIter4K::new(start.align_down_4k(), end.align_up_4k())
            .ok_or(AxError::BadAddress)?;
        for page in pages {
            let (paddr, flags, _) = self.query_vaddr(page).map_err(|_| AxError::BadAddress)?;
            if paddr.as_usize() == 0
                || !flags.contains(MappingFlags::WRITE | MappingFlags::USER)
            {
                // Let the caller fault in lazy pages or break COW before a
                // kernel write reaches the underlying physical frame.
                return Err(AxError::BadAddress);
            }
        }

        self.process_area_data(start, buf.len(), |dst, offset, write_size| unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr().add(offset), dst.as_mut_ptr(), write_size);
        })
    }

    /// Updates mapping within the specified virtual address range.
    ///
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn protect(&mut self, start: VirtAddr, size: usize, flags: MappingFlags) -> AddrSpaceMutation<()> {
        let mut attempted = false;
        let result = (|| -> AxResult {
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

            attempted = true;
            self.areas
                .protect(start, size, |_| Some(flags), &mut self.pt)
                .map_err(mapping_err_to_ax_err)
        })();
        AddrSpaceMutation::new(
            result,
            attempted.then(|| TlbShootdown::without_reclaims(self.asid)),
        )
    }

    /// Updates only page-table permissions within the specified range.
    ///
    /// Unlike [`Self::protect`], this does not change MemorySet area flags.
    pub fn protect_pte_only(
        &mut self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
    ) -> AddrSpaceMutation<()> {
        let mut attempted = false;
        let result = (|| -> AxResult {
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

            attempted = true;
            self.pt
                .get_mut()
                .protect_region(start, size, flags, false)
                .map_err(|_| AxError::BadState)?
                .ignore();
            Ok(())
        })();
        AddrSpaceMutation::new(
            result,
            attempted.then(|| TlbShootdown::without_reclaims(self.asid)),
        )
    }

    /// Remap a single 4K page to a specified physical frame.
    pub fn remap_page(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: MappingFlags,
    ) -> AddrSpaceMutation<()> {
        let mut reclaim = DeferredReclaims::default();
        let mut changed_existing = false;
        let result = (|| -> AxResult {
            if !self.contains_range(vaddr, PAGE_SIZE_4K) {
                return ax_err!(InvalidInput, "address out of range");
            }
            if !vaddr.is_aligned_4k() || !paddr.is_aligned_4k() {
                return ax_err!(InvalidInput, "address not aligned");
            }

            let pt = self.pt.get_mut();
            if let Ok((old_frame, old_flags, _)) = pt.query(vaddr) {
                pt.remap(vaddr, paddr, flags)
                    .map_err(|_| AxError::BadState)?
                    .1
                    .ignore();
                if old_frame.as_usize() != 0 {
                    changed_existing = old_frame != paddr || old_flags != flags;
                    if old_frame != paddr {
                        reclaim.defer_frame(old_frame);
                    }
                }
            } else {
                pt.map(vaddr, paddr, PageSize::Size4K, flags)
                    .map_err(|_| AxError::BadState)?
                    .ignore();
            }
            Ok(())
        })();
        let needs_shootdown = changed_existing || !reclaim.is_empty();
        let shootdown = if needs_shootdown {
            Some(TlbShootdown::new(self.asid, reclaim))
        } else {
            reclaim.reclaim();
            None
        };
        AddrSpaceMutation::new(result, shootdown)
    }

    /// Removes all mappings in the address space.
    pub fn clear(&mut self) -> AddrSpaceMutation<()> {
        let had_mappings = !self.areas.is_empty();
        let mut reclaim = DeferredReclaims::default();
        let result = self
            .areas
            .clear(&mut self.pt, &mut reclaim)
            .map_err(mapping_err_to_ax_err);
        let shootdown = if had_mappings {
            Some(TlbShootdown::new(self.asid, reclaim))
        } else {
            reclaim.reclaim();
            None
        };
        AddrSpaceMutation::new(result, shootdown)
    }

    fn clear_unpublished(&mut self) {
        let mut reclaim = DeferredReclaims::default();
        if let Err(error) = self.areas.clear(&mut self.pt, &mut reclaim) {
            error!("failed to clear unpublished address space: {error:?}");
        }
        reclaim.reclaim();
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
        let mut range = match VirtAddrRange::try_from_start_size(start, size) {
            Some(r) => r,
            None => return false,
        };
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
        let range = match VirtAddrRange::try_from_start_size(start, size) {
            Some(r) => r,
            None => return false,
        };
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
    pub fn handle_page_fault(&self, vaddr: VirtAddr, access_flags: PageFaultFlags) -> PageFaultResult {
        let page = vaddr.align_down_4k();
        let pte_before = self
            .pt
            .lock_for_addr(page)
            .query(page)
            .ok()
            .map(|(frame, flags, _)| (frame, flags));
        if !self.va_range.contains(vaddr) {
            error!(
                "handle_page_fault: reject=out_of_range vaddr={:#x} page={:#x} access={:?} \
                 aspace_range={:?} pte_before={:?}",
                vaddr, page, access_flags, self.va_range, pte_before
            );
            return PageFaultResult::Handled(false);
        }
        if let Some((frame, flags)) = pte_before {
            if access_flags.contains(PageFaultFlags::WRITE) && flags.contains(MappingFlags::WRITE) {
                let mut pt_guard = self.pt.lock_for_addr(page);
                if let Ok((_, tlb)) = pt_guard.remap(page, frame, flags) {
                    tlb.flush();
                    return PageFaultResult::Handled(true);
                }
            }
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
                let mut reclaim = DeferredReclaims::default();
                let handled = area.backend().handle_page_fault(
                    vaddr,
                    area.end(),
                    orig_flags,
                    &self.pt,
                    access_flags,
                    &mut reclaim,
                );
                let pte_after = self
                    .pt
                    .lock_for_addr(page)
                    .query(page)
                    .ok()
                    .map(|(frame, flags, _)| (frame, flags));
                if !handled {
                    error!(
                        "handle_page_fault: reject=backend_not_handled vaddr={:#x} page={:#x} \
                         access={:?} area_flags={:?} backend={} pte_before={:?} pte_after={:?}",
                        vaddr, page, access_flags, orig_flags, backend_kind, pte_before, pte_after
                    );
                }
                let had_resident_mapping = pte_before
                    .as_ref()
                    .map(|(frame, _)| frame.as_usize() != 0)
                    .unwrap_or(false);
                if (had_resident_mapping && pte_after != pte_before) || !reclaim.is_empty() {
                    // A COW remap can leave the old readable frame cached on
                    // CPUs where this address space ran previously. Waiting
                    // for those CPUs while holding the address-space lock can
                    // deadlock with a concurrent writer such as mprotect.
                    return PageFaultResult::HandledWithShootdown {
                        handled,
                        shootdown: TlbShootdown::new(self.asid, reclaim),
                    };
                }
                reclaim.reclaim();
                return PageFaultResult::Handled(handled);
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

            if growsdown_area_info.is_some() {
                return PageFaultResult::NeedWriteLock;
            }

            error!(
                "handle_page_fault: reject=no_area vaddr={:#x} page={:#x} access={:?} \
                 pte_before={:?}",
                vaddr, page, access_flags, pte_before
            );
        }
        PageFaultResult::Handled(false)
    }

    /// Handles a page fault that requires stack growth (write lock held).
    pub fn handle_page_fault_write(
        &mut self,
        vaddr: VirtAddr,
        access_flags: PageFaultFlags,
    ) -> PageFaultResult {
        let page = vaddr.align_down_4k();
        // Check for stack grows down auto-extension.
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
            // Linux stack_guard_gap check
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
                return PageFaultResult::Handled(false);
            }

            let backend = Backend::new_alloc_grows_down(false, true);
            if self.map_with_backend(page, PAGE_SIZE_4K, flags, backend).is_ok() {
                return self.handle_page_fault(vaddr, access_flags);
            }
        }
        PageFaultResult::Handled(false)
    }

    /// Attempts to clone the current address space into a new one.
    pub fn try_clone(&mut self) -> AddrSpaceCloneResult {
        let shootdown = TlbShootdown::without_reclaims(self.asid);
        let result = self.try_clone_inner();
        AddrSpaceCloneResult { result, shootdown }
    }

    fn try_clone_inner(&mut self) -> AxResult<Self> {
        let mut new_aspace = Self::new_empty(self.va_range.start, self.va_range.size())?;
        let last_alloc = self.last_alloc_addr.load(core::sync::atomic::Ordering::Acquire);
        new_aspace.last_alloc_addr.store(last_alloc, core::sync::atomic::Ordering::Release);

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
            if let Err(e) = new_aspace.map_area(new_area) {
                new_aspace.clear_unpublished();
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

            let should_copy = if is_cow {
                true
            } else if let Backend::File(mapping) = area.backend() {
                mapping.is_shared()
            } else {
                false
            };

            if should_copy {
                let inc_ref = |paddr| {
                    crate::cow_inc_frame_ref(paddr);
                };
                if new_aspace.pt.get_mut().copy_cow_range(
                    self.pt.get_mut(),
                    area.start(),
                    area.size(),
                    is_cow,
                    inc_ref,
                ).is_err() {
                    error!("try_clone: failed to copy user page table");
                    new_aspace.clear_unpublished();
                    return Err(AxError::NoMemory);
                }
            }
        }

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
            .field("page_table_root", &self.pt.lock().root_paddr())
            .field("areas", &self.areas)
            .finish()
    }
}

#[cfg(all(not(feature = "ipi"), target_arch = "riscv64"))]
unsafe fn flush_tlb_asid(asid: usize) {
    unsafe { core::arch::asm!("sfence.vma x0, {}", in(reg) asid) };
}

#[cfg(all(not(feature = "ipi"), target_arch = "loongarch64"))]
unsafe fn flush_tlb_asid(asid: usize) {
    unsafe { core::arch::asm!("dbar 0; invtlb 0x04, {}, $r0; dbar 0; ibar 0", in(reg) asid) };
}

#[cfg(all(
    not(feature = "ipi"),
    not(any(target_arch = "riscv64", target_arch = "loongarch64"))
))]
unsafe fn flush_tlb_asid(_asid: usize) {
    axhal::asm::flush_tlb(None);
}

struct AsidAllocator {
    used: [bool; 1024],
    next: usize,
}

impl AsidAllocator {
    const fn new() -> Self {
        let mut used = [false; 1024];
        used[0] = true; // reserve ASID 0 for kernel/special tasks
        Self { used, next: 1 }
    }

    fn alloc(&mut self) -> usize {
        let start = self.next;
        loop {
            if !self.used[self.next] {
                let asid = self.next;
                self.used[asid] = true;
                self.next = (self.next + 1) % 1024;
                if self.next == 0 {
                    self.next = 1;
                }
                return asid;
            }
            self.next = (self.next + 1) % 1024;
            if self.next == 0 {
                self.next = 1;
            }
            if self.next == start {
                panic!("Out of ASIDs!");
            }
        }
    }

    fn free(&mut self, asid: usize) {
        if asid > 0 && asid < 1024 {
            self.used[asid] = false;
        }
    }
}

static ASID_ALLOCATOR: spin::Mutex<AsidAllocator> = spin::Mutex::new(AsidAllocator::new());

impl Drop for AddrSpace {
    fn drop(&mut self) {
        let asid = self.asid;
        let (clear_result, shootdown) = self.clear().into_parts();
        if let Err(error) = clear_result {
            error!("failed to retire address-space mappings: {error:?}");
        }
        let shootdown_completed = shootdown
            .map(TlbShootdown::complete_after_unlock)
            .unwrap_or(Ok(()))
            .is_ok();
        if shootdown_completed {
            ASID_ALLOCATOR.lock().free(asid);
        } else {
            error!("failed to flush retired address space; ASID {asid} will not be reused");
        }
    }
}
