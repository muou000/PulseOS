use core::fmt;

use axalloc::frame_table;
use axerrno::{AxError, AxResult, ax_err};
use axfs::{CachedFile, FileFlags};
use axhal::{
    mem::{flush_dcache_range, phys_to_virt, PhysAddr},
    paging::{MappingFlags, PageSize, PageTable, PagingError, PagingResult, TlbFlush},
    trap::PageFaultFlags,
};
use memory_addr::{
    MemoryAddr, PAGE_SIZE_4K, PageIter4K, VirtAddr, VirtAddrRange, is_aligned_4k,
};
use memory_set::{MappingBackend, MappingMutation, MemoryArea, MemorySet};

use crate::{
    backend::{
        AnonPageLoad, AnonPagePrepared, Backend, DeferredReclaims, FilePageLoad,
        FilePagePrepared, FileWritebacks, TlbInvalidationTracker,
    },
    mapping_err_to_ax_err,
};

/// A TLB shootdown that must run after releasing the address-space lock.
#[must_use = "a TLB shootdown must be completed after releasing the address-space lock"]
pub struct TlbShootdown {
    primary: Option<(usize, TlbInvalidation)>,
    additional: alloc::vec::Vec<(usize, TlbInvalidation)>,
    reclaims: DeferredReclaims,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TlbInvalidation {
    Range {
        start: VirtAddr,
        end: VirtAddr,
        changed_pages: usize,
    },
    FullAsid,
}

impl TlbInvalidation {
    fn from_tracker(tracker: TlbInvalidationTracker) -> Option<Self> {
        Some(Self::Range {
            start: tracker.start()?,
            end: tracker.end()?,
            changed_pages: tracker.changed_pages(),
        })
    }

    fn merge(&mut self, other: Self) {
        match (*self, other) {
            (Self::FullAsid, _) | (_, Self::FullAsid) => *self = Self::FullAsid,
            (
                Self::Range {
                    start,
                    end,
                    changed_pages,
                },
                Self::Range {
                    start: other_start,
                    end: other_end,
                    changed_pages: other_changed_pages,
                },
            ) => {
                *self = Self::Range {
                    start: start.min(other_start),
                    end: end.max(other_end),
                    changed_pages: changed_pages.saturating_add(other_changed_pages),
                };
            }
        }
    }
}

impl TlbShootdown {
    fn new(asid: usize, reclaims: DeferredReclaims) -> Self {
        Self {
            primary: Some((asid, TlbInvalidation::FullAsid)),
            additional: alloc::vec::Vec::new(),
            reclaims,
        }
    }

    fn from_tracker(
        asid: usize,
        tracker: TlbInvalidationTracker,
        reclaims: DeferredReclaims,
    ) -> Self {
        Self {
            primary: TlbInvalidation::from_tracker(tracker).map(|invalidation| (asid, invalidation)),
            additional: alloc::vec::Vec::new(),
            reclaims,
        }
    }

    fn without_reclaims(asid: usize) -> Self {
        Self::new(asid, DeferredReclaims::default())
    }

    fn for_range(
        asid: usize,
        start: VirtAddr,
        size: usize,
        reclaims: DeferredReclaims,
    ) -> Self {
        let end = start
            .checked_add(size)
            .expect("TLB invalidation range overflow");
        Self {
            primary: Some((
                asid,
                TlbInvalidation::Range {
                    start,
                    end,
                    changed_pages: size.saturating_add(PAGE_SIZE_4K - 1) / PAGE_SIZE_4K,
                },
            )),
            additional: alloc::vec::Vec::new(),
            reclaims,
        }
    }

    /// Merges another deferred shootdown into this batch.
    pub fn merge(&mut self, other: Self) {
        let Self {
            primary,
            additional,
            reclaims,
        } = other;
        for (asid, invalidation) in primary.into_iter().chain(additional) {
            self.merge_invalidation(asid, invalidation);
        }
        self.reclaims.append(reclaims);
    }

    fn merge_invalidation(&mut self, asid: usize, invalidation: TlbInvalidation) {
        if let Some((primary_asid, primary_invalidation)) = self.primary.as_mut() {
            if *primary_asid == asid {
                primary_invalidation.merge(invalidation);
                return;
            }
        } else {
            self.primary = Some((asid, invalidation));
            return;
        }
        if let Some((_, existing)) = self
            .additional
            .iter_mut()
            .find(|(existing_asid, _)| *existing_asid == asid)
        {
            existing.merge(invalidation);
        } else {
            self.additional.push((asid, invalidation));
        }
    }

    /// Completes the shootdown without holding an address-space lock.
    pub fn complete_after_unlock(self) -> AxResult {
        let Self {
            primary,
            additional,
            reclaims,
        } = self;

        #[cfg(feature = "ipi")]
        {
            let mut merged_shootdown = Self {
                primary: None,
                additional: alloc::vec::Vec::new(),
                reclaims: DeferredReclaims::default(),
            };
            for (asid, invalidation) in primary.into_iter().chain(additional) {
                merged_shootdown.merge_invalidation(asid, invalidation);
            }
            let Self {
                primary: merged_primary,
                additional: merged_additional,
                ..
            } = merged_shootdown;

            for (asid, invalidation) in merged_primary.into_iter().chain(merged_additional) {
                let flush_result = match invalidation {
                    TlbInvalidation::Range {
                        start,
                        end,
                        changed_pages,
                    } => {
                        axipi::flush_tlb_asid_range_cpus(
                            asid,
                            start.as_usize(),
                            end - start,
                            changed_pages,
                        )
                    }
                    TlbInvalidation::FullAsid => axipi::flush_tlb_asid_cpus(asid),
                };
                if let Err(shootdown_error) = flush_result {
                    if shootdown_error.completion_guaranteed() {
                        warn!("{shootdown_error}");
                    } else {
                        error!("{shootdown_error}");
                        // DeferredReclaims intentionally leaks mapping references
                        // when dropped before a completion guarantee.
                        drop(reclaims);
                        return Err(AxError::BadState);
                    }
                }
            }
            reclaims.reclaim();
            Ok(())
        }

        #[cfg(not(feature = "ipi"))]
        {
            for (asid, invalidation) in primary.into_iter().chain(additional) {
                unsafe { flush_tlb_invalidation(asid, invalidation) };
            }
            reclaims.reclaim();
            Ok(())
        }
    }
}

impl fmt::Debug for TlbShootdown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlbShootdown")
            .field("primary", &self.primary)
            .field("additional", &self.additional)
            .field("has_reclaims", &!self.reclaims.is_empty())
            .finish()
    }
}

const MAX_PREALLOCATED_UNMAP_RECLAIMS: usize = 64;

/// Reclaim storage allocated before entering an address-space write section.
pub struct AddrSpaceUnmapPreparation {
    reclaims: DeferredReclaims,
}

impl AddrSpaceUnmapPreparation {
    /// Prepares bounded reclaim storage for an upcoming unmap operation.
    pub fn new(size: usize) -> Self {
        let pages = size.saturating_add(PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;
        let capacity = pages
            .saturating_add(1)
            .min(MAX_PREALLOCATED_UNMAP_RECLAIMS);
        Self {
            reclaims: DeferredReclaims::with_capacity(capacity),
        }
    }
}

impl Default for AddrSpaceUnmapPreparation {
    fn default() -> Self {
        Self {
            reclaims: DeferredReclaims::default(),
        }
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
    /// A file-backed page must be loaded after releasing the address-space lock.
    NeedFilePage(FilePageLoad),
    /// Anonymous frames must be allocated and zeroed after releasing the address-space lock.
    NeedAnonPage(AnonPageLoad),
}

#[derive(Debug)]
pub enum PageFaultOutcome {
    Handled(bool),
    RetryWithWriteLock,
    LoadFilePage(FilePageLoad),
    PrepareAnonPage(AnonPageLoad),
}

impl PageFaultResult {
    /// Resolves deferred work after the address-space lock has been released.
    pub fn complete_after_unlock(self) -> AxResult<PageFaultOutcome> {
        match self {
            Self::Handled(success) => Ok(PageFaultOutcome::Handled(success)),
            Self::HandledWithShootdown { handled, shootdown } => {
                shootdown.complete_after_unlock()?;
                Ok(PageFaultOutcome::Handled(handled))
            }
            Self::NeedWriteLock => Ok(PageFaultOutcome::RetryWithWriteLock),
            Self::NeedFilePage(load) => Ok(PageFaultOutcome::LoadFilePage(load)),
            Self::NeedAnonPage(load) => Ok(PageFaultOutcome::PrepareAnonPage(load)),
        }
    }
}

/// The result of cloning an address space, including the parent TLB update.
pub struct AddrSpaceCloneResult {
    result: AxResult<AddrSpace>,
    shootdown: Option<TlbShootdown>,
}

impl AddrSpaceCloneResult {
    /// Completes the parent TLB shootdown and returns the cloned address space.
    pub fn complete_after_unlock(self) -> AxResult<AddrSpace> {
        let Self { result, shootdown } = self;
        if let Some(shootdown) = shootdown {
            shootdown.complete_after_unlock()?;
        }
        result
    }
}

const PAGE_TABLE_SUBTREE_SHIFT: usize = 21;
const PAGE_TABLE_LOCK_SHARDS: usize = 64;

pub struct PageTableLockManager {
    /// Gates whole-table operations and upper-level page-table creation.
    pt: spin::RwLock<PageTable>,
    /// Serializes leaf-table creation and PTE updates within each 2 MiB subtree.
    subtrees: [spin::RwLock<()>; PAGE_TABLE_LOCK_SHARDS],
}

enum PageTableReadLock<'a> {
    Whole(spin::RwLockWriteGuard<'a, PageTable>),
    Subtree {
        pt: spin::RwLockReadGuard<'a, PageTable>,
        _subtree: spin::RwLockReadGuard<'a, ()>,
        subtree_id: usize,
    },
}

enum PageTableWriteLock<'a> {
    Whole(spin::RwLockWriteGuard<'a, PageTable>),
    Subtree {
        pt: spin::RwLockReadGuard<'a, PageTable>,
        _subtree: spin::RwLockWriteGuard<'a, ()>,
        subtree_id: usize,
    },
}

pub struct PageTableReadGuard<'a>(PageTableReadLock<'a>);
pub struct PageTableGuard<'a> {
    lock: PageTableWriteLock<'a>,
    probe: Option<(VirtAddr, PagingResult<(PhysAddr, MappingFlags, PageSize)>)>,
}

unsafe impl<'a> Send for PageTableReadGuard<'a> {}
unsafe impl<'a> Sync for PageTableReadGuard<'a> {}
unsafe impl<'a> Send for PageTableGuard<'a> {}
unsafe impl<'a> Sync for PageTableGuard<'a> {}

impl<'a> core::ops::Deref for PageTableReadGuard<'a> {
    type Target = PageTable;
    #[inline]
    fn deref(&self) -> &Self::Target {
        match &self.0 {
            PageTableReadLock::Whole(pt) => pt,
            PageTableReadLock::Subtree { pt, .. } => pt,
        }
    }
}

impl<'a> core::ops::Deref for PageTableGuard<'a> {
    type Target = PageTable;
    #[inline]
    fn deref(&self) -> &Self::Target {
        match &self.lock {
            PageTableWriteLock::Whole(pt) => pt,
            PageTableWriteLock::Subtree { pt, .. } => pt,
        }
    }
}

impl PageTableReadGuard<'_> {
    #[inline]
    pub(crate) fn covers(&self, vaddr: VirtAddr) -> bool {
        match &self.0 {
            PageTableReadLock::Whole(_) => true,
            PageTableReadLock::Subtree { subtree_id, .. } => {
                *subtree_id == vaddr.as_usize() >> PAGE_TABLE_SUBTREE_SHIFT
            }
        }
    }

    #[inline]
    fn assert_covers(&self, vaddr: VirtAddr) {
        debug_assert!(self.covers(vaddr));
    }

    pub fn query(&self, vaddr: VirtAddr) -> PagingResult<(PhysAddr, MappingFlags, PageSize)> {
        self.assert_covers(vaddr);
        core::ops::Deref::deref(self).query(vaddr)
    }
}

impl PageTableGuard<'_> {
    #[inline]
    pub(crate) fn covers(&self, vaddr: VirtAddr) -> bool {
        match &self.lock {
            PageTableWriteLock::Whole(_) => true,
            PageTableWriteLock::Subtree { subtree_id, .. } => {
                *subtree_id == vaddr.as_usize() >> PAGE_TABLE_SUBTREE_SHIFT
            }
        }
    }

    #[inline]
    fn assert_covers(&self, vaddr: VirtAddr) {
        debug_assert!(self.covers(vaddr));
    }

    pub fn query(&self, vaddr: VirtAddr) -> PagingResult<(PhysAddr, MappingFlags, PageSize)> {
        self.assert_covers(vaddr);
        if let Some((probe_vaddr, result)) = self.probe
            && probe_vaddr == vaddr
        {
            return result;
        }
        core::ops::Deref::deref(self).query(vaddr)
    }

    pub fn map(
        &mut self,
        vaddr: VirtAddr,
        target: PhysAddr,
        page_size: PageSize,
        flags: MappingFlags,
    ) -> PagingResult<TlbFlush> {
        self.assert_covers(vaddr);
        match &mut self.lock {
            PageTableWriteLock::Whole(pt) => pt.map(vaddr, target, page_size, flags),
            PageTableWriteLock::Subtree { pt, .. } => {
                debug_assert_ne!(page_size, PageSize::Size1G);
                // SAFETY: the gate keeps the table alive and the subtree lock
                // excludes every entry that this 4 KiB/2 MiB mapping can touch.
                unsafe { pt.map_with_external_lock(vaddr, target, page_size, flags) }
            }
        }
    }

    pub fn remap(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: MappingFlags,
    ) -> PagingResult<(PageSize, TlbFlush)> {
        self.assert_covers(vaddr);
        match &mut self.lock {
            PageTableWriteLock::Whole(pt) => pt.remap(vaddr, paddr, flags),
            PageTableWriteLock::Subtree { pt, .. } => {
                // SAFETY: the subtree lock excludes access to the leaf PTE.
                unsafe { pt.remap_with_external_lock(vaddr, paddr, flags) }
            }
        }
    }
}

impl PageTableLockManager {
    pub fn new(pt: PageTable) -> Self {
        Self {
            pt: spin::RwLock::new(pt),
            subtrees: core::array::from_fn(|_| spin::RwLock::new(())),
        }
    }

    #[inline]
    fn subtree_id(vaddr: VirtAddr) -> usize {
        vaddr.as_usize() >> PAGE_TABLE_SUBTREE_SHIFT
    }

    #[inline]
    fn subtree_lock(&self, vaddr: VirtAddr) -> &spin::RwLock<()> {
        &self.subtrees[Self::subtree_id(vaddr) & (PAGE_TABLE_LOCK_SHARDS - 1)]
    }

    #[inline]
    pub fn root_paddr(&self) -> PhysAddr {
        self.pt.read().root_paddr()
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut PageTable {
        self.pt.get_mut()
    }

    pub fn lock(&self) -> PageTableReadGuard {
        PageTableReadGuard(PageTableReadLock::Whole(self.pt.write()))
    }

    pub fn read_for_addr(&self, vaddr: VirtAddr) -> PageTableReadGuard {
        let pt = self.pt.read();
        let subtree = self.subtree_lock(vaddr).read();
        PageTableReadGuard(PageTableReadLock::Subtree {
            pt,
            _subtree: subtree,
            subtree_id: Self::subtree_id(vaddr),
        })
    }

    pub fn lock_for_addr(&self, vaddr: VirtAddr) -> PageTableGuard {
        let pt = self.pt.read();
        let subtree = self.subtree_lock(vaddr).write();
        let probe = pt.query_skip(vaddr);
        let needs_whole_lock = match probe {
            Ok((_, _, PageSize::Size1G)) => true,
            Err(skip) => skip >= PageSize::Size1G as usize,
            _ => false,
        };

        if needs_whole_lock {
            drop(subtree);
            drop(pt);
            PageTableGuard {
                lock: PageTableWriteLock::Whole(self.pt.write()),
                probe: None,
            }
        } else {
            PageTableGuard {
                lock: PageTableWriteLock::Subtree {
                    pt,
                    _subtree: subtree,
                    subtree_id: Self::subtree_id(vaddr),
                },
                probe: Some((vaddr, probe.map_err(|_| PagingError::NotMapped))),
            }
        }
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
        self.pt.read_for_addr(vaddr).query(vaddr)
    }

    /// Returns whether a user page is mapped or already resident in a file cache.
    pub fn page_is_resident(&self, vaddr: VirtAddr) -> bool {
        if let Ok((frame, ..)) = self.query_vaddr(vaddr)
            && frame.as_usize() != 0
        {
            return true;
        }

        self.areas
            .find(vaddr)
            .is_some_and(|area| area.backend().is_file_page_cached(vaddr))
    }

    /// Pins a mapped user frame while holding the leaf page-table read lock.
    pub fn pin_user_frame(
        &self,
        vaddr: VirtAddr,
        required_flags: MappingFlags,
    ) -> AxResult<PhysAddr> {
        let pt = self.pt.read_for_addr(vaddr);
        let (frame, flags, _) = pt.query(vaddr).map_err(|_| AxError::BadAddress)?;
        if frame.as_usize() == 0 || !flags.contains(required_flags | MappingFlags::USER) {
            return Err(AxError::BadAddress);
        }

        let frame_table = frame_table();
        if frame_table.contains(frame) {
            frame_table.inc_ref(frame);
        }
        Ok(frame)
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
        #[cfg(feature = "ipi")]
        axipi::reset_asid_active_cpu_mask(asid);
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
        write_access: Option<axfs::WriteAccessGuard>,
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
            Backend::new_file(
                start,
                file,
                file_flags,
                file_offset,
                file_bytes,
                shared,
                write_access,
            ),
        );
        self.map_area(area).map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// Write back all resident dirty pages in the given range to their
    /// underlying files. Only shared file-backed mappings are affected.
    pub fn prepare_file_writeback_range(
        &self,
        start: VirtAddr,
        size: usize,
        sync: bool,
    ) -> AxResult<FileWritebacks> {
        if size == 0 {
            return Ok(FileWritebacks::default());
        }
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }

        let range = VirtAddrRange::try_from_start_size(start, size)
            .ok_or(AxError::InvalidInput)?;
        let mut writebacks = FileWritebacks::default();
        for area in self.areas.iter_overlapping(range) {
            let overlap_start = area.start().max(range.start);
            let overlap_end = area.end().min(range.end);
            if overlap_start < overlap_end {
                if !area.backend().prepare_file_writeback_range(
                    overlap_start,
                    overlap_end - overlap_start,
                    sync,
                    &self.pt,
                    &mut writebacks,
                ) {
                    return ax_err!(Io, "writeback failed");
                }
            }
        }
        Ok(writebacks)
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
        self.unmap_prepared(start, size, AddrSpaceUnmapPreparation::default())
    }

    /// Discards resident anonymous pages within `[start, start + size)` while
    /// retaining the virtual memory areas that describe the range.
    ///
    /// File, shared, and linear mappings are left intact. A later access to a
    /// discarded anonymous page faults it back in as a fresh zeroed page.
    pub fn discard_range(&mut self, start: VirtAddr, size: usize) -> AddrSpaceMutation<()> {
        let mut reclaim = DeferredReclaims::default();
        let mut invalidation = TlbInvalidationTracker::default();
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

            let range = VirtAddrRange::try_from_start_size(start, size)
                .ok_or(AxError::InvalidInput)?;
            for area in self.areas.iter_overlapping(range) {
                if !area.backend().is_discardable() {
                    continue;
                }

                let overlap_start = area.start().max(range.start);
                let overlap_end = area.end().min(range.end);
                if overlap_start < overlap_end
                    && !area.backend().unmap_tracked(
                        overlap_start,
                        overlap_end - overlap_start,
                        &mut self.pt,
                        &mut reclaim,
                        &mut invalidation,
                    )
                {
                    return Err(AxError::BadState);
                }
            }
            Ok(())
        })();

        let needs_completion = !invalidation.is_empty() || !reclaim.is_empty();
        let shootdown = if needs_completion {
            Some(TlbShootdown::from_tracker(self.asid, invalidation, reclaim))
        } else {
            reclaim.reclaim();
            None
        };
        AddrSpaceMutation::new(result, shootdown)
    }

    /// Removes mappings using reclaim storage prepared before taking the
    /// address-space write lock.
    pub fn unmap_prepared(
        &mut self,
        start: VirtAddr,
        size: usize,
        preparation: AddrSpaceUnmapPreparation,
    ) -> AddrSpaceMutation<()> {
        let mut reclaim = preparation.reclaims;
        let mut invalidation = TlbInvalidationTracker::default();
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

            self.areas
                .unmap_tracked(start, size, &mut self.pt, &mut reclaim, &mut invalidation)
                .map_err(mapping_err_to_ax_err)
        })();
        let needs_completion = !invalidation.is_empty() || !reclaim.is_empty();
        let shootdown = if needs_completion {
            Some(TlbShootdown::from_tracker(self.asid, invalidation, reclaim))
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
        F: FnMut(PhysAddr, VirtAddr, usize, usize),
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
            let (mut paddr, ..) = self
                .pt
                .read_for_addr(vaddr)
                .query(vaddr)
                .map_err(|_| AxError::BadAddress)?;
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
            f(paddr, phys_to_virt(paddr), cnt, copy_size);
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
        self.process_area_data(start, buf.len(), |paddr, src, offset, read_size| unsafe {
            flush_dcache_range(paddr, read_size);
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

        self.process_area_data(start, buf.len(), |paddr, dst, offset, write_size| unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr().add(offset), dst.as_mut_ptr(), write_size);
            flush_dcache_range(paddr, write_size);
        })
    }

    /// Updates mapping within the specified virtual address range.
    ///
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn protect(&mut self, start: VirtAddr, size: usize, flags: MappingFlags) -> AddrSpaceMutation<()> {
        let mut invalidation = TlbInvalidationTracker::default();
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

            self.areas
                .protect_tracked(
                    start,
                    size,
                    |old_flags| (old_flags != flags).then_some(flags),
                    &mut self.pt,
                    &mut invalidation,
                )
                .map_err(mapping_err_to_ax_err)
        })();
        let shootdown = (!invalidation.is_empty()).then(|| {
            TlbShootdown::from_tracker(self.asid, invalidation, DeferredReclaims::default())
        });
        AddrSpaceMutation::new(result, shootdown)
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
        let mut invalidation = TlbInvalidationTracker::default();
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

            crate::backend::protect_populated_range(
                start,
                size,
                flags,
                self.pt.get_mut(),
                &mut invalidation,
            )
            .then_some(())
            .ok_or(AxError::BadState)
        })();
        let shootdown = (!invalidation.is_empty()).then(|| {
            TlbShootdown::from_tracker(self.asid, invalidation, DeferredReclaims::default())
        });
        AddrSpaceMutation::new(result, shootdown)
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
            Some(TlbShootdown::for_range(
                self.asid,
                vaddr,
                PAGE_SIZE_4K,
                reclaim,
            ))
        } else {
            reclaim.reclaim();
            None
        };
        AddrSpaceMutation::new(result, shootdown)
    }

    /// Removes all mappings in the address space.
    pub fn clear(&mut self) -> AddrSpaceMutation<()> {
        let mut reclaim = DeferredReclaims::default();
        let mut invalidation = TlbInvalidationTracker::default();
        let result = self
            .areas
            .clear_tracked(&mut self.pt, &mut reclaim, &mut invalidation)
            .map_err(mapping_err_to_ax_err);
        let needs_completion = !invalidation.is_empty() || !reclaim.is_empty();
        let shootdown = if needs_completion {
            Some(TlbShootdown::from_tracker(self.asid, invalidation, reclaim))
        } else {
            reclaim.reclaim();
            None
        };
        AddrSpaceMutation::new(result, shootdown)
    }

    fn clear_unpublished(&mut self) {
        let chunk_size = DeferredReclaims::retirement_capacity() * PAGE_SIZE_4K;
        'areas: while let Some(mut area) = self.areas.drain_first_area() {
            while !area.is_empty() {
                let mut reclaim = DeferredReclaims::for_retirement();
                let result = area.unmap_prefix(chunk_size, &mut self.pt, &mut reclaim);
                reclaim.reclaim();
                if let Err(error) = result {
                    error!("failed to clear unpublished address space: {error:?}");
                    break 'areas;
                }
            }
        }
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
        let range = match VirtAddrRange::try_from_start_size(start, size) {
            Some(r) => r,
            None => return false,
        };
        let mut covered_end = range.start;
        for area in self.areas.iter_overlapping(range) {
            if area.start() > covered_end {
                return false;
            }

            // This area overlaps with the memory region
            if !area.flags().contains(access_flags) {
                return false;
            }

            covered_end = area.end();
            if covered_end >= range.end {
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
        self.areas.overlaps(range)
    }

    /// Remap a virtual memory area, optionally moving it or resizing it.
    pub fn mremap(
        &mut self,
        old_addr: VirtAddr,
        old_size: usize,
        new_size: usize,
        flags: usize,
        new_addr: Option<VirtAddr>,
    ) -> AddrSpaceMutation<VirtAddr> {
        let mut reclaim = DeferredReclaims::default();
        let mut invalidation = TlbInvalidationTracker::default();
        let mut tlb_shootdown: Option<TlbShootdown> = None;

        const MREMAP_MAYMOVE: usize = 1;
        const MREMAP_FIXED: usize = 2;

        let result = (|| -> AxResult<VirtAddr> {
            if !old_addr.is_aligned_4k() || !is_aligned_4k(old_size) || !is_aligned_4k(new_size) {
                return Err(AxError::InvalidInput);
            }
            if old_size == 0 || new_size == 0 {
                return Err(AxError::InvalidInput);
            }

            let (old_area_start_val, old_area_end, old_flags, old_backend) = {
                let area = self
                    .areas
                    .find(old_addr)
                    .filter(|area| area.end() >= old_addr + old_size)
                    .ok_or(AxError::BadAddress)?;
                (area.start(), area.end(), area.flags(), area.backend().clone())
            };

            // Remove the old area to perform splitting and modifications
            self.areas.remove(old_area_start_val).unwrap();

            // Re-insert left split if any
            if old_addr > old_area_start_val {
                let left_size = old_addr.as_usize() - old_area_start_val.as_usize();
                let left_area = MemoryArea::new(old_area_start_val, left_size, old_flags, old_backend.clone());
                self.areas.insert(old_area_start_val, left_area);
            }

            // Re-insert right split if any
            if old_addr + old_size < old_area_end {
                let right_start = old_addr + old_size;
                let right_size = old_area_end.as_usize() - right_start.as_usize();
                let right_area = MemoryArea::new(right_start, right_size, old_flags, old_backend.clone());
                self.areas.insert(right_start, right_area);
            }

            // The target area for remapping
            let mut middle_area = MemoryArea::new(old_addr, old_size, old_flags, old_backend);

            // Check if we need to move
            let mut should_move = false;

            if let Some(fixed_addr) = new_addr {
                if (flags & MREMAP_FIXED) != 0 {
                    if fixed_addr != old_addr {
                        should_move = true;
                    }
                }
            }

            if new_size > old_size && !should_move {
                // Check if we can expand in-place
                let has_right_neighbor = old_addr + old_size < old_area_end;
                let has_overlap = self.has_overlap(old_addr + old_size, new_size - old_size);
                if has_right_neighbor || has_overlap {
                    if (flags & MREMAP_MAYMOVE) != 0 {
                        should_move = true;
                    } else {
                        // Re-insert middle_area before returning error
                        self.areas.insert(old_addr, middle_area);
                        return Err(AxError::NoMemory);
                    }
                }
            }

            if should_move {
                let target_addr = if (flags & MREMAP_FIXED) != 0 {
                    let dest_addr = new_addr.ok_or(AxError::InvalidInput)?;
                    if !dest_addr.is_aligned_4k() {
                        self.areas.insert(old_addr, middle_area);
                        return Err(AxError::InvalidInput);
                    }
                    if dest_addr == old_addr {
                        self.areas.insert(old_addr, middle_area);
                        return Err(AxError::InvalidInput);
                    }
                    // Unmap any overlapping regions at destination
                    let (unmap_res, shootdown) = self.unmap(dest_addr, new_size).into_parts();
                    if let Some(sd) = shootdown {
                        if let Some(existing) = &mut tlb_shootdown {
                            existing.merge(sd);
                        } else {
                            tlb_shootdown = Some(sd);
                        }
                    }
                    if let Err(e) = unmap_res {
                        self.areas.insert(old_addr, middle_area);
                        return Err(e);
                    }
                    dest_addr
                } else {
                    // MREMAP_MAYMOVE: find a free area
                    let limit = self.va_range;
                    match self.find_free_area(VirtAddr::from(old_addr), new_size, limit) {
                        Some(addr) => addr,
                        None => {
                            self.areas.insert(old_addr, middle_area);
                            return Err(AxError::NoMemory);
                        }
                    }
                };

                // Move physical pages: unmap from old address, but keep frames
                let mut phys_pages = alloc::vec::Vec::new();
                for page in PageIter4K::new(old_addr, old_addr + old_size).unwrap() {
                    let rel_offset = page.as_usize() - old_addr.as_usize();
                    if let Ok((frame, page_size, tlb)) = self.pt.get_mut().unmap(page) {
                        if frame.as_usize() != 0 {
                            invalidation.record(page, page_size as usize);
                        }
                        if page_size.is_huge() {
                            // Re-insert middle_area and rollback (though this shouldn't happen for user pages)
                            self.areas.insert(old_addr, middle_area);
                            return Err(AxError::InvalidInput);
                        }
                        if frame.as_usize() != 0 {
                            phys_pages.push((rel_offset, frame));
                        }
                        tlb.ignore(); // we will flush all together
                    }
                }

                // Update backend address
                let mut bk = middle_area.backend().clone();
                bk.update_address(old_addr, target_addr, old_size, new_size);

                // Create new MemoryArea at target
                let new_area = MemoryArea::new(target_addr, new_size, old_flags, bk);
                self.areas.insert(target_addr, new_area);

                // Map physical pages at new address
                for (rel_offset, frame) in phys_pages {
                    let new_page = target_addr + rel_offset;
                    if let Err(_) = self.pt.get_mut().map(new_page, frame, PageSize::Size4K, old_flags) {
                        return Err(AxError::NoMemory);
                    }
                }

                // Map any expanded space
                if new_size > old_size {
                    let expand_size = new_size - old_size;
                    let new_area_ref = self.areas.find(target_addr).unwrap();
                    new_area_ref.backend().map(target_addr + old_size, expand_size, old_flags, &mut self.pt);
                }

                Ok(target_addr)
            } else {
                // In-place changes
                if new_size < old_size {
                    // In-place shrink: unmap tail
                    let cut_start = old_addr + new_size;
                    let cut_size = old_size - new_size;
                    middle_area.backend().unmap_tracked(
                        cut_start,
                        cut_size,
                        &mut self.pt,
                        &mut reclaim,
                        &mut invalidation,
                    );
                    middle_area.set_end(old_addr + new_size);
                    self.areas.insert(old_addr, middle_area);
                    Ok(old_addr)
                } else if new_size > old_size {
                    // In-place expand
                    let mut bk = middle_area.backend().clone();
                    bk.update_address(old_addr, old_addr, old_size, new_size);
                    middle_area.set_backend(bk);
                    middle_area.set_end(old_addr + new_size);

                    let expand_size = new_size - old_size;
                    middle_area.backend().map(old_addr + old_size, expand_size, old_flags, &mut self.pt);
                    self.areas.insert(old_addr, middle_area);
                    Ok(old_addr)
                } else {
                    // Size unchanged, just return old_addr
                    self.areas.insert(old_addr, middle_area);
                    Ok(old_addr)
                }
            }
        })();

        let local_needs_completion = !invalidation.is_empty() || !reclaim.is_empty();
        if local_needs_completion {
            let local = TlbShootdown::from_tracker(self.asid, invalidation, reclaim);
            if let Some(existing) = &mut tlb_shootdown {
                existing.merge(local);
            } else {
                tlb_shootdown = Some(local);
            }
        } else {
            reclaim.reclaim();
        }

        AddrSpaceMutation::new(result, tlb_shootdown)
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
            .read_for_addr(page)
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
            if frame.as_usize() != 0 && flags.contains(access_flags) {
                #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
                axhal::asm::flush_tlb_asid_vaddr(self.asid, page);
                #[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
                axhal::asm::flush_tlb(Some(page));
                return PageFaultResult::Handled(true);
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
                if let Some(load) = area.backend().page_fault_load_request(
                    vaddr,
                    area.end(),
                    orig_flags,
                    &self.pt,
                ) {
                    return PageFaultResult::NeedFilePage(load);
                }
                if let Some(load) =
                    area.backend()
                        .page_fault_anon_request(vaddr, area.end(), &self.pt)
                {
                    return PageFaultResult::NeedAnonPage(load);
                }
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
                    .read_for_addr(page)
                    .query(page)
                    .ok()
                    .map(|(frame, flags, _)| (frame, flags));
                if !handled {
                    if let Some(load) = area.backend().page_fault_load_request(
                        vaddr,
                        area.end(),
                        orig_flags,
                        &self.pt,
                    ) {
                        reclaim.reclaim();
                        return PageFaultResult::NeedFilePage(load);
                    }
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
                        shootdown: TlbShootdown::for_range(
                            self.asid,
                            page,
                            PAGE_SIZE_4K,
                            reclaim,
                        ),
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

    /// Installs a file page that was loaded and pinned without holding the
    /// address-space lock.
    pub fn handle_prepared_file_page(
        &self,
        vaddr: VirtAddr,
        access_flags: PageFaultFlags,
        prepared: &mut FilePagePrepared,
    ) -> PageFaultResult {
        let page = vaddr.align_down_4k();
        if !self.va_range.contains(vaddr) {
            return PageFaultResult::Handled(false);
        }

        if self
            .pt
            .read_for_addr(page)
            .query(page)
            .is_ok_and(|(frame, _, _)| frame.as_usize() != 0)
        {
            return self.handle_page_fault(vaddr, access_flags);
        }

        let Some(area) = self.areas.find(vaddr) else {
            return self.handle_page_fault(vaddr, access_flags);
        };
        let orig_flags = area.flags();
        if !orig_flags.contains(access_flags) {
            return PageFaultResult::Handled(false);
        }

        if area.backend().handle_prepared_file_page(
            vaddr,
            area.end(),
            orig_flags,
            &self.pt,
            access_flags,
            prepared,
        ) {
            PageFaultResult::Handled(true)
        } else {
            self.handle_page_fault(vaddr, access_flags)
        }
    }

    /// Installs anonymous frames allocated and zeroed without the address-space lock.
    pub fn handle_prepared_anon_page(
        &self,
        vaddr: VirtAddr,
        access_flags: PageFaultFlags,
        prepared: &mut AnonPagePrepared,
    ) -> PageFaultResult {
        if !self.va_range.contains(vaddr) {
            return PageFaultResult::Handled(false);
        }

        let Some(area) = self.areas.find(vaddr) else {
            return self.handle_page_fault(vaddr, access_flags);
        };
        let orig_flags = area.flags();
        if !orig_flags.contains(access_flags) {
            return PageFaultResult::Handled(false);
        }

        if area.backend().handle_prepared_anon_page(
            vaddr,
            area.end(),
            orig_flags,
            &self.pt,
            prepared,
        ) {
            PageFaultResult::Handled(true)
        } else {
            self.handle_page_fault(vaddr, access_flags)
        }
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
        let mut invalidation = TlbInvalidationTracker::default();
        let result = self.try_clone_inner(&mut invalidation);
        let shootdown = (!invalidation.is_empty()).then(|| {
            TlbShootdown::from_tracker(self.asid, invalidation, DeferredReclaims::default())
        });
        AddrSpaceCloneResult { result, shootdown }
    }

    fn try_clone_inner(&mut self, invalidation: &mut TlbInvalidationTracker) -> AxResult<Self> {
        let mut new_aspace = Self::new_empty(self.va_range.start, self.va_range.size())?;
        let frame_table = frame_table();
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
                    if frame_table.contains(paddr) {
                        frame_table.inc_ref(paddr);
                    }
                };
                let record_src_change = |start, size| invalidation.record(start, size);
                if new_aspace.pt.get_mut().copy_cow_range(
                    self.pt.get_mut(),
                    area.start(),
                    area.size(),
                    is_cow,
                    inc_ref,
                    record_src_change,
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

#[cfg(not(feature = "ipi"))]
unsafe fn flush_tlb_invalidation(asid: usize, invalidation: TlbInvalidation) {
    const RANGE_PAGE_LIMIT: usize = 32;

    match invalidation {
        TlbInvalidation::FullAsid => axhal::asm::flush_tlb_asid(asid),
        TlbInvalidation::Range { start, end, .. }
            if (end - start) / PAGE_SIZE_4K <= RANGE_PAGE_LIMIT =>
        {
            for page in PageIter4K::new(start, end).unwrap() {
                #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
                axhal::asm::flush_tlb_asid_vaddr(asid, page);
                #[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
                {
                    let _ = asid;
                    axhal::asm::flush_tlb(Some(page));
                }
            }
        }
        TlbInvalidation::Range { .. } => axhal::asm::flush_tlb_asid(asid),
    }
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
        let chunk_size = DeferredReclaims::retirement_capacity() * PAGE_SIZE_4K;
        // Drop has unique ownership and every caller switches away from this
        // page table before releasing its final handle. Retire the ASID before
        // taking a CPU-local reclaim buffer so its lease is never held while
        // waiting for a remote TLB IPI.
        let mut retirement_completed = self.areas.is_empty()
            || TlbShootdown::without_reclaims(asid)
                .complete_after_unlock()
                .is_ok();

        'areas: while retirement_completed {
            let Some(mut area) = self.areas.drain_first_area() else {
                break;
            };
            while !area.is_empty() {
                let mut reclaim = DeferredReclaims::for_retirement();
                let result = area.unmap_prefix(chunk_size, &mut self.pt, &mut reclaim);
                reclaim.reclaim();
                if let Err(error) = result {
                    error!("failed to retire address-space mappings: {error:?}");
                    retirement_completed = false;
                    break 'areas;
                }
            }
        }

        if retirement_completed {
            ASID_ALLOCATOR.lock().free(asid);
        } else {
            error!("failed to retire address space; ASID {asid} will not be reused");
        }
    }
}
