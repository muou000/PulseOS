//! Page table manipulation.

use axalloc::global_allocator;
use memory_addr::{PAGE_SIZE_4K, PhysAddr, VirtAddr};
use page_table_multiarch::PagingHandler;
#[doc(no_inline)]
pub use page_table_multiarch::{MappingFlags, PageSize, PagingError, PagingResult};

use crate::mem::{phys_to_virt, virt_to_phys};

pub struct PagingHandlerImpl;

impl PagingHandler for PagingHandlerImpl {
    fn alloc_frame() -> Option<PhysAddr> {
        global_allocator()
            .alloc_pages(1, PAGE_SIZE_4K)
            .ok()
            .map(|v| virt_to_phys(VirtAddr::from(v)))
    }

    fn dealloc_frame(paddr: PhysAddr) {
        global_allocator().dealloc_pages(phys_to_virt(paddr).as_usize(), 1);
    }

    #[inline]
    fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
        phys_to_virt(paddr)
    }
}

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        type InnerPageTable = page_table_multiarch::x86_64::X64PageTable<PagingHandlerImpl>;
        pub type TlbFlush = page_table_multiarch::TlbFlush<page_table_multiarch::x86_64::X64PagingMetaData>;
        pub type TlbFlushAll = page_table_multiarch::TlbFlushAll<page_table_multiarch::x86_64::X64PagingMetaData>;
    } else if #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))] {
        type InnerPageTable = page_table_multiarch::riscv::Sv39PageTable<PagingHandlerImpl>;
        pub type TlbFlush = page_table_multiarch::TlbFlush<page_table_multiarch::riscv::Sv39MetaData<memory_addr::VirtAddr>>;
        pub type TlbFlushAll = page_table_multiarch::TlbFlushAll<page_table_multiarch::riscv::Sv39MetaData<memory_addr::VirtAddr>>;
    } else if #[cfg(target_arch = "aarch64")] {
        type InnerPageTable = page_table_multiarch::aarch64::A64PageTable<PagingHandlerImpl>;
        pub type TlbFlush = page_table_multiarch::TlbFlush<page_table_multiarch::aarch64::A64PagingMetaData>;
        pub type TlbFlushAll = page_table_multiarch::TlbFlushAll<page_table_multiarch::aarch64::A64PagingMetaData>;
    } else if #[cfg(target_arch = "loongarch64")] {
        type InnerPageTable = page_table_multiarch::loongarch64::LA64PageTable<PagingHandlerImpl>;
        pub type TlbFlush = page_table_multiarch::TlbFlush<page_table_multiarch::loongarch64::LA64MetaData>;
        pub type TlbFlushAll = page_table_multiarch::TlbFlushAll<page_table_multiarch::loongarch64::LA64MetaData>;
    }
}

pub struct PageTable {
    inner: InnerPageTable,
}

impl PageTable {
    pub fn try_new() -> PagingResult<Self> {
        Ok(Self {
            inner: InnerPageTable::try_new()?,
        })
    }

    pub const fn root_paddr(&self) -> PhysAddr {
        self.inner.root_paddr()
    }

    pub fn copy_from(&mut self, other: &Self, start: VirtAddr, size: usize) {
        self.inner.copy_from(&other.inner, start, size)
    }

    pub fn copy_cow_range(
        &mut self,
        other: &mut Self,
        start: VirtAddr,
        size: usize,
        is_cow: bool,
        inc_ref: impl FnMut(PhysAddr),
        record_src_change: impl FnMut(VirtAddr, usize),
    ) -> PagingResult {
        self.inner.copy_cow_range(
            &mut other.inner,
            start,
            size,
            is_cow,
            inc_ref,
            record_src_change,
        )
    }

    pub fn query(&self, vaddr: VirtAddr) -> PagingResult<(PhysAddr, MappingFlags, PageSize)> {
        self.inner.query(vaddr)
    }

    pub fn query_skip(&self, vaddr: VirtAddr) -> Result<(PhysAddr, MappingFlags, PageSize), usize> {
        self.inner.query_skip(vaddr)
    }

    pub fn unmap(&mut self, vaddr: VirtAddr) -> PagingResult<(PhysAddr, PageSize, TlbFlush)> {
        self.inner.unmap(vaddr)
    }

    /// Unmaps one page while synchronization is provided by the caller.
    ///
    /// # Safety
    ///
    /// The caller must exclude all accesses to the affected page-table entry.
    pub unsafe fn unmap_with_external_lock(
        &self,
        vaddr: VirtAddr,
    ) -> PagingResult<(PhysAddr, PageSize, TlbFlush)> {
        unsafe { self.inner.unmap_with_external_lock(vaddr) }
    }

    pub fn unmap_region(
        &mut self,
        vaddr: VirtAddr,
        size: usize,
        flush_tlb_by_page: bool,
    ) -> PagingResult<TlbFlushAll> {
        self.inner.unmap_region(vaddr, size, flush_tlb_by_page)
    }

    pub fn unmap_present_range(
        &mut self,
        vaddr: VirtAddr,
        size: usize,
        allow_huge: bool,
        on_unmapped: impl FnMut(VirtAddr, PhysAddr, MappingFlags, PageSize),
    ) -> PagingResult {
        self.inner
            .unmap_present_range(vaddr, size, allow_huge, on_unmapped)
    }

    pub fn map(
        &mut self,
        vaddr: VirtAddr,
        target: PhysAddr,
        page_size: PageSize,
        flags: MappingFlags,
    ) -> PagingResult<TlbFlush> {
        let flags = Self::adjust_flags(flags);
        self.inner.map(vaddr, target, page_size, flags)
    }

    /// Maps one page while synchronization is provided by the caller.
    ///
    /// # Safety
    ///
    /// The caller must exclude all accesses to the affected page-table entries,
    /// including creation of shared intermediate tables.
    pub unsafe fn map_with_external_lock(
        &self,
        vaddr: VirtAddr,
        target: PhysAddr,
        page_size: PageSize,
        flags: MappingFlags,
    ) -> PagingResult<TlbFlush> {
        let flags = Self::adjust_flags(flags);
        unsafe {
            self.inner
                .map_with_external_lock(vaddr, target, page_size, flags)
        }
    }

    pub fn remap(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: MappingFlags,
    ) -> PagingResult<(PageSize, TlbFlush)> {
        let flags = Self::adjust_flags(flags);
        self.inner.remap(vaddr, paddr, flags)
    }

    /// Remaps one page while synchronization is provided by the caller.
    ///
    /// # Safety
    ///
    /// The caller must exclude all accesses to the affected page-table entry.
    pub unsafe fn remap_with_external_lock(
        &self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: MappingFlags,
    ) -> PagingResult<(PageSize, TlbFlush)> {
        let flags = Self::adjust_flags(flags);
        unsafe { self.inner.remap_with_external_lock(vaddr, paddr, flags) }
    }

    pub fn protect(
        &mut self,
        vaddr: VirtAddr,
        flags: MappingFlags,
    ) -> PagingResult<(PageSize, TlbFlush)> {
        let flags = Self::adjust_flags(flags);
        self.inner.protect(vaddr, flags)
    }

    /// Protects one page while synchronization is provided by the caller.
    ///
    /// # Safety
    ///
    /// The caller must exclude all accesses to the affected page-table entry.
    pub unsafe fn protect_with_external_lock(
        &self,
        vaddr: VirtAddr,
        flags: MappingFlags,
    ) -> PagingResult<(PageSize, TlbFlush)> {
        let flags = Self::adjust_flags(flags);
        unsafe { self.inner.protect_with_external_lock(vaddr, flags) }
    }

    pub fn map_region(
        &mut self,
        vaddr: VirtAddr,
        get_paddr: impl Fn(VirtAddr) -> PhysAddr,
        size: usize,
        flags: MappingFlags,
        allow_huge: bool,
        flush_tlb_by_page: bool,
    ) -> PagingResult<TlbFlushAll> {
        let flags = Self::adjust_flags(flags);
        self.inner
            .map_region(vaddr, get_paddr, size, flags, allow_huge, flush_tlb_by_page)
    }

    pub fn protect_region(
        &mut self,
        vaddr: VirtAddr,
        size: usize,
        flags: MappingFlags,
        flush_tlb_by_page: bool,
    ) -> PagingResult<TlbFlushAll> {
        let flags = Self::adjust_flags(flags);
        self.inner
            .protect_region(vaddr, size, flags, flush_tlb_by_page)
    }

    fn adjust_flags(flags: MappingFlags) -> MappingFlags {
        #[allow(unused_mut)]
        let mut flags = flags;
        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
        {
            if flags.contains(MappingFlags::WRITE) {
                flags |= MappingFlags::READ;
            }
        }
        flags
    }
}
