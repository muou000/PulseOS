use memory_addr::MemoryAddr;

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

    /// What to do when changing access flags.
    fn protect(
        &self,
        start: Self::Addr,
        size: usize,
        new_flags: Self::Flags,
        page_table: &mut Self::PageTable,
    ) -> bool;
}
