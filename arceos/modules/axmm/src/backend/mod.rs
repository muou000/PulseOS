//! Memory mapping backends.

use axhal::paging::{MappingFlags, PageSize};
use memory_addr::{PhysAddr, VirtAddr};
use memory_set::MappingBackend;
use ::alloc::{sync::Arc, vec::Vec};

mod alloc;
mod cow;
mod file;
mod linear;
mod shared;

pub use self::shared::SharedFrame;
pub(crate) use alloc::{cow_dec_frame_ref, cow_inc_frame_ref};
pub use self::cow::CowMapping;
pub use self::file::{FilePageLoad, FilePagePrepared};

#[derive(Default)]
pub struct FileWritebacks(Vec<file::FileWriteback>);

impl FileWritebacks {
    pub fn complete(self) -> axerrno::AxResult {
        for writeback in self.0 {
            writeback.complete()?;
        }
        Ok(())
    }
}

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

enum DeferredReclaim {
    Frame(PhysAddr),
    Backend(Backend),
}

/// Mapping references kept alive until a remote TLB shootdown has completed.
pub struct DeferredReclaims {
    actions: Option<Vec<DeferredReclaim>>,
}

impl Default for DeferredReclaims {
    fn default() -> Self {
        Self {
            actions: Some(Vec::new()),
        }
    }
}

impl DeferredReclaims {
    pub(crate) fn defer_frame(&mut self, frame: PhysAddr) {
        if frame.as_usize() != 0 {
            self.actions
                .as_mut()
                .unwrap()
                .push(DeferredReclaim::Frame(frame));
        }
    }

    fn defer_backend(&mut self, backend: Backend) {
        self.actions
            .as_mut()
            .unwrap()
            .push(DeferredReclaim::Backend(backend));
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.actions.as_ref().unwrap().is_empty()
    }

    pub(crate) fn append(&mut self, other: Self) {
        let mut actions = other.into_actions();
        self.actions.as_mut().unwrap().append(&mut actions);
    }

    pub(crate) fn reclaim(self) {
        for action in self.into_actions() {
            match action {
                DeferredReclaim::Frame(frame) => self::alloc::dealloc_frame(frame),
                DeferredReclaim::Backend(backend) => drop(backend),
            }
        }
    }

    fn into_actions(mut self) -> Vec<DeferredReclaim> {
        self.actions.take().unwrap()
    }
}

impl Drop for DeferredReclaims {
    fn drop(&mut self) {
        let Some(actions) = self.actions.take() else {
            return;
        };
        if !actions.is_empty() {
            error!(
                "leaking {} deferred mapping references after incomplete TLB shootdown",
                actions.len()
            );
            core::mem::forget(actions);
        }
    }
}

impl MappingBackend for Backend {
    type Addr = VirtAddr;
    type Flags = MappingFlags;
    type PageTable = crate::PageTableLockManager;
    type Reclaim = DeferredReclaims;
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

    fn unmap(
        &self,
        start: VirtAddr,
        size: usize,
        pt: &mut Self::PageTable,
        reclaim: &mut Self::Reclaim,
    ) -> bool {
        let pt_mut = pt.get_mut();
        match self {
            Self::Shared { .. } => {
                reclaim.defer_backend(self.clone());
                Self::unmap_shared(start, size, pt_mut)
            }
            Self::Linear { pa_va_offset } => self.unmap_linear(start, size, pt_mut, *pa_va_offset),
            Self::Alloc { populate, .. } => {
                self.unmap_alloc(start, size, pt_mut, *populate, reclaim)
            }
            Self::File(_) => {
                // Keep the CachedFile alive until after the address-space lock
                // is released; dropping its final reference may perform I/O.
                reclaim.defer_backend(self.clone());
                self.unmap_file(start, size, pt_mut, reclaim)
            }
            Self::Cow(cow) => cow.inner.unmap(start, size, pt, reclaim),
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
    pub(crate) fn update_address(
        &mut self,
        old_start: VirtAddr,
        new_start: VirtAddr,
        old_size: usize,
        new_size: usize,
    ) {
        match self {
            Self::File(mapping) => {
                mapping.update_address(new_start, new_size);
            }
            Self::Cow(cow) => {
                cow.inner.update_address(old_start, new_start, old_size, new_size);
            }
            Self::Linear { pa_va_offset } => {
                let diff = new_start.as_usize() as isize - old_start.as_usize() as isize;
                *pa_va_offset = (*pa_va_offset as isize + diff) as usize;
            }
            _ => {}
        }
    }

    pub fn is_grows_down(&self) -> bool {
        match self {
            Self::Alloc { grows_down, .. } => *grows_down,
            Self::Cow(cow) => cow.inner.is_grows_down(),
            _ => false,
        }
    }

    pub(crate) fn page_fault_load_request(
        &self,
        vaddr: VirtAddr,
        orig_flags: MappingFlags,
        page_table: &crate::PageTableLockManager,
    ) -> Option<FilePageLoad> {
        match self {
            Self::File(mapping) => mapping.page_load_request(vaddr, orig_flags, page_table),
            Self::Cow(cow) => {
                cow.inner()
                    .page_fault_load_request(vaddr, orig_flags, page_table)
            }
            _ => None,
        }
    }

    pub(crate) fn handle_page_fault(
        &self,
        vaddr: VirtAddr,
        area_end: VirtAddr,
        orig_flags: MappingFlags,
        page_table: &crate::PageTableLockManager,
        access_flags: MappingFlags,
        reclaim: &mut DeferredReclaims,
    ) -> bool {
        match self {
            Self::Shared { .. } => false,
            Self::Linear { .. } => false, // Linear mappings should not trigger page faults.
            Self::Alloc { populate, .. } => {
                self.handle_page_fault_alloc(vaddr, area_end, orig_flags, page_table, *populate)
            }
            Self::File(mapping) => self.handle_page_fault_file(
                vaddr,
                area_end,
                orig_flags,
                page_table,
                mapping,
                access_flags,
                reclaim,
            ),
            Self::Cow(cow) => cow.handle_page_fault(
                vaddr,
                area_end,
                orig_flags,
                page_table,
                access_flags,
                reclaim,
            ),
        }
    }

    pub(crate) fn handle_prepared_file_page(
        &self,
        vaddr: VirtAddr,
        orig_flags: MappingFlags,
        page_table: &crate::PageTableLockManager,
        access_flags: MappingFlags,
        prepared: &mut FilePagePrepared,
    ) -> bool {
        match self {
            Self::File(mapping) => self.handle_prepared_page_fault_file(
                vaddr,
                orig_flags,
                page_table,
                mapping,
                access_flags,
                prepared,
            ),
            Self::Cow(cow) => cow.inner().handle_prepared_file_page(
                vaddr,
                orig_flags,
                page_table,
                access_flags,
                prepared,
            ),
            _ => false,
        }
    }

    /// Write back all resident dirty pages in the given range to the
    /// underlying file. Only meaningful for shared file mappings.
    pub(crate) fn prepare_file_writeback_range(
        &self,
        start: VirtAddr,
        size: usize,
        sync: bool,
        pt: &crate::PageTableLockManager,
        writebacks: &mut FileWritebacks,
    ) -> bool {
        match self {
            Self::File(_) => match self.prepare_file_writeback_range_impl(start, size, sync, pt) {
                Ok(Some(writeback)) => {
                    writebacks.0.push(writeback);
                    true
                }
                Ok(None) => true,
                Err(()) => false,
            },
            Self::Cow(cow) => cow
                .inner
                .prepare_file_writeback_range(start, size, sync, pt, writebacks),
            _ => true, // Non-file backends have nothing to write back.
        }
    }
}
