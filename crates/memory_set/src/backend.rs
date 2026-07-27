use memory_addr::MemoryAddr;

/// Accumulates page-table entries changed by a mapping operation.
///
/// Backends that can partially mutate a mapping before returning failure should
/// record each completed change as it happens.
pub trait MappingMutation<A: MemoryAddr> {
    /// Records a changed virtual-address range.
    fn record(&mut self, start: A, size: usize);
}

impl<A: MemoryAddr> MappingMutation<A> for () {
    fn record(&mut self, _start: A, _size: usize) {}
}

/// Underlying operations to do when manipulating mappings within the specific
/// [`MemoryArea`](crate::MemoryArea).
///
/// The backend can be different for different memory areas. e.g., for linear
/// mappings, the target physical address is known when it is added to the page
/// table. For lazy mappings, an empty mapping needs to be added to the page
/// table to trigger a page fault.
pub trait MappingBackend: Clone {
    /// The address type used in the memory area.
    type Addr: MemoryAddr;
    /// The flags type used in the memory area.
    type Flags: Copy;
    /// The page table type used in the memory area.
    type PageTable;
    /// Resources whose reclamation must be deferred by the caller after unmap.
    type Reclaim;

    /// What to do when mapping a region within the area with the given flags.
    fn map(
        &self,
        start: Self::Addr,
        size: usize,
        flags: Self::Flags,
        page_table: &mut Self::PageTable,
    ) -> bool;

    /// What to do when unmaping a memory region within the area.
    ///
    /// Resources detached from the page table must be added to `reclaim`,
    /// including when the operation returns `false` after a partial unmap.
    fn unmap(
        &self,
        start: Self::Addr,
        size: usize,
        page_table: &mut Self::PageTable,
        reclaim: &mut Self::Reclaim,
    ) -> bool;

    /// What to do when unmapping while reporting changed page-table entries.
    ///
    /// The default implementation conservatively reports the full range after
    /// a successful unmap. Backends that support sparse mappings or partial
    /// failure should override this method.
    fn unmap_tracked<M: MappingMutation<Self::Addr>>(
        &self,
        start: Self::Addr,
        size: usize,
        page_table: &mut Self::PageTable,
        reclaim: &mut Self::Reclaim,
        mutation: &mut M,
    ) -> bool {
        let success = self.unmap(start, size, page_table, reclaim);
        if success {
            mutation.record(start, size);
        }
        success
    }

    /// What to do when changing access flags.
    fn protect(
        &self,
        start: Self::Addr,
        size: usize,
        new_flags: Self::Flags,
        page_table: &mut Self::PageTable,
    ) -> bool;

    /// What to do when changing access flags while reporting changed entries.
    ///
    /// The default implementation conservatively reports the full range after
    /// a successful protection change. Sparse backends should override it.
    fn protect_tracked<M: MappingMutation<Self::Addr>>(
        &self,
        start: Self::Addr,
        size: usize,
        new_flags: Self::Flags,
        page_table: &mut Self::PageTable,
        mutation: &mut M,
    ) -> bool {
        let success = self.protect(start, size, new_flags, page_table);
        if success {
            mutation.record(start, size);
        }
        success
    }
}
