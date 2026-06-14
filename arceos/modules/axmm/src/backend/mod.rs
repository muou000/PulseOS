//! Memory mapping backends.

use axhal::paging::{MappingFlags, PageSize, PageTable};
use memory_addr::VirtAddr;
use memory_set::MappingBackend;
use ::alloc::sync::Arc;

mod alloc;
mod cow;
mod file;
mod linear;
mod shared;

pub use self::shared::SharedFrame;
pub(crate) use alloc::{cow_dec_frame_ref, cow_inc_frame_ref};
pub use self::cow::CowMapping;

/// A unified enum type for different memory mapping backends.
///
/// Currently, two backends are implemented:
///
/// - **Linear**: used for linear mappings. The target physical frames are
///   contiguous and their addresses should be known when creating the mapping.
/// - **Allocation**: used in general, or for lazy mappings. The target physical
///   frames are obtained from the global allocator.
#[derive(Clone)]
pub enum Backend {
    /// Shared memory mapping backend.
    Shared {
        shared_frame: Arc<SharedFrame>,
        align: PageSize,
    },
    /// Linear mapping backend.
    ///
    /// The offset between the virtual address and the physical address is
    /// constant, which is specified by `pa_va_offset`. For example, the virtual
    /// address `vaddr` is mapped to the physical address `vaddr - pa_va_offset`.
    Linear {
        /// `vaddr - paddr`.
        pa_va_offset: usize,
    },
    /// Allocation mapping backend.
    ///
    /// If `populate` is `true`, all physical frames are allocated when the
    /// mapping is created, and no page faults are triggered during the memory
    /// access. Otherwise, the physical frames are allocated on demand (by
    /// handling page faults).
    Alloc {
        /// Whether to populate the physical frames when creating the mapping.
        populate: bool,
        /// Whether the memory grows down (stack).
        grows_down: bool,
    },
    /// File-backed demand mapping backend.
    File(file::FileMapping),
    /// Copy-on-write mapping backend.
    Cow(CowMapping),
}

impl MappingBackend for Backend {
    type Addr = VirtAddr;
    type Flags = MappingFlags;
    type PageTable = spin::Mutex<PageTable>;
    fn map(&self, start: VirtAddr, size: usize, flags: MappingFlags, pt: &mut Self::PageTable) -> bool {
        let pt = pt.get_mut();
        match self {
            Self::Shared { shared_frame, .. } => {
                Self::map_shared(start, size, flags, pt, VirtAddr::from(shared_frame.vaddr))
            }
            Self::Linear { pa_va_offset } => self.map_linear(start, size, flags, pt, *pa_va_offset),
            Self::Alloc { populate, .. } => self.map_alloc(start, size, flags, pt, *populate),
            Self::File(mapping) => self.map_file(start, size, flags, pt, mapping),
            Self::Cow(_cow) => {
                // COW mappings are generally lazy. However, we should still delegate to the
                // inner backend if it's NOT an Alloc/File backend (though currently all
                // COW-able backends are Alloc/File).
                // For now, we keep it simple: initial map is lazy.
                // We must ensure the area is properly registered.
                true
            }
        }
    }

    fn unmap(&self, start: VirtAddr, size: usize, pt: &mut Self::PageTable) -> bool {
        let pt_mut = pt.get_mut();
        match self {
            Self::Shared { .. } => Self::unmap_shared(start, size, pt_mut),
            Self::Linear { pa_va_offset } => self.unmap_linear(start, size, pt_mut, *pa_va_offset),
            Self::Alloc { populate, .. } => self.unmap_alloc(start, size, pt_mut, *populate),
            Self::File(_) => self.unmap_file(start, size, pt_mut),
            Self::Cow(cow) => cow.inner.unmap(start, size, pt),
        }
    }

    fn protect(
        &self,
        start: Self::Addr,
        size: usize,
        new_flags: Self::Flags,
        page_table: &mut Self::PageTable,
    ) -> bool {
        let pt_mut = page_table.get_mut();
        match self {
            Self::Shared { .. } | Self::Linear { .. } => pt_mut
                .protect_region(start, size, new_flags, true)
                .map(|tlb| tlb.ignore())
                .is_ok(),
            Self::Alloc { populate, .. } => {
                self.protect_alloc(start, size, new_flags, pt_mut, *populate)
            }
            Self::File(mapping) => {
                self.protect_file(start, size, new_flags, pt_mut, mapping)
            }
            Self::Cow(cow) => cow.inner.protect(start, size, new_flags, page_table),
        }
    }
}

impl Backend {
    pub fn is_grows_down(&self) -> bool {
        match self {
            Self::Alloc { grows_down, .. } => *grows_down,
            Self::Cow(cow) => cow.inner.is_grows_down(),
            _ => false,
        }
    }

    pub(crate) fn handle_page_fault(
        &self,
        vaddr: VirtAddr,
        area_end: VirtAddr,
        orig_flags: MappingFlags,
        page_table: &spin::Mutex<PageTable>,
    ) -> bool {
        match self {
            Self::Shared { .. } => false,
            Self::Linear { .. } => false, // Linear mappings should not trigger page faults.
            Self::Alloc { populate, .. } => {
                self.handle_page_fault_alloc(vaddr, area_end, orig_flags, page_table, *populate)
            }
            Self::File(mapping) => {
                self.handle_page_fault_file(vaddr, area_end, orig_flags, page_table, mapping)
            }
            Self::Cow(cow) => cow.handle_page_fault(vaddr, area_end, orig_flags, page_table),
        }
    }

    /// Write back all resident dirty pages in the given range to the
    /// underlying file. Only meaningful for shared file mappings.
    pub(crate) fn writeback_file_range(
        &self,
        start: VirtAddr,
        size: usize,
        sync: bool,
        pt: &spin::Mutex<PageTable>,
    ) -> bool {
        match self {
            Self::File(_) => self.writeback_file_range_impl(start, size, sync, pt),
            Self::Cow(cow) => cow.inner.writeback_file_range(start, size, sync, pt),
            _ => true, // Non-file backends have nothing to write back.
        }
    }
}
