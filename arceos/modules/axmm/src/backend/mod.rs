//! Memory mapping backends.

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

use axhal::paging::{MappingFlags, PageSize};
use memory_addr::{MemoryAddr, PhysAddr, VirtAddr, PAGE_SIZE_4K};
use memory_set::{MappingBackend, MappingMutation as MappingMutationTracker};
use ::alloc::{sync::Arc, vec::Vec};

mod alloc;
mod cow;
mod file;
mod linear;
mod shared;

pub use self::shared::SharedFrame;
pub(crate) use alloc::{cow_dec_frame_ref, cow_inc_frame_ref};
pub use alloc::{AnonPageLoad, AnonPagePrepared};
pub use self::cow::CowMapping;
pub use self::file::{FilePageLoad, FilePagePrepared};

/// The resident page-table entries changed by one address-space operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TlbInvalidationTracker {
    start: Option<VirtAddr>,
    end: Option<VirtAddr>,
    changed_pages: usize,
}

impl TlbInvalidationTracker {
    pub(crate) const fn is_empty(&self) -> bool {
        self.changed_pages == 0
    }

    pub(crate) const fn start(&self) -> Option<VirtAddr> {
        self.start
    }

    pub(crate) const fn end(&self) -> Option<VirtAddr> {
        self.end
    }

    pub(crate) const fn changed_pages(&self) -> usize {
        self.changed_pages
    }
}

impl MappingMutationTracker<VirtAddr> for TlbInvalidationTracker {
    fn record(&mut self, start: VirtAddr, size: usize) {
        if size == 0 {
            return;
        }
        let Some(end) = start.checked_add(size) else {
            return;
        };
        self.start = Some(self.start.map_or(start, |current| current.min(start)));
        self.end = Some(self.end.map_or(end, |current| current.max(end)));
        self.changed_pages = self
            .changed_pages
            .saturating_add(size.saturating_add(PAGE_SIZE_4K - 1) / PAGE_SIZE_4K);
    }
}

pub(super) fn effective_pte_flags(flags: MappingFlags) -> MappingFlags {
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        let mut flags = flags;
        if flags.contains(MappingFlags::WRITE) {
            flags |= MappingFlags::READ;
        }
        flags
    }
    #[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
    {
        flags
    }
}

pub(super) fn unmap_populated_range<M: MappingMutationTracker<VirtAddr>>(
    start: VirtAddr,
    size: usize,
    pt: &mut axhal::paging::PageTable,
    mutation: &mut M,
) -> bool {
    let Some(end) = start.checked_add(size) else {
        return false;
    };
    let mut page = start;
    while page < end {
        let Ok((_, _, page_size)) = pt.query(page) else {
            return false;
        };
        let mapped_size = page_size as usize;
        if mapped_size > end - page {
            return false;
        }
        let Ok((frame, page_size, tlb)) = pt.unmap(page) else {
            return false;
        };
        debug_assert_eq!(page_size as usize, mapped_size);
        tlb.ignore();
        if frame.as_usize() != 0 {
            mutation.record(page, mapped_size);
        }
        page += mapped_size;
    }
    true
}

pub(crate) fn protect_populated_range<M: MappingMutationTracker<VirtAddr>>(
    start: VirtAddr,
    size: usize,
    new_flags: MappingFlags,
    pt: &mut axhal::paging::PageTable,
    mutation: &mut M,
) -> bool {
    let Some(end) = start.checked_add(size) else {
        return false;
    };
    let effective_flags = effective_pte_flags(new_flags);
    let mut page = start;
    while page < end {
        let Ok((frame, old_flags, page_size)) = pt.query(page) else {
            return false;
        };
        let mapped_size = page_size as usize;
        if mapped_size > end - page {
            return false;
        }
        if frame.as_usize() != 0 && old_flags != effective_flags {
            let Ok((protected_size, tlb)) = pt.protect(page, new_flags) else {
                return false;
            };
            tlb.ignore();
            mutation.record(page, protected_size as usize);
        }
        page += mapped_size;
    }
    true
}

#[derive(Default)]
pub struct FileWritebacks(Vec<file::FileWriteback>);

impl FileWritebacks {
    fn push(&mut self, writeback: file::FileWriteback) {
        self.0.push(writeback);
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn append(&mut self, mut other: Self) {
        self.0.append(&mut other.0);
    }

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

impl Backend {
    pub(crate) fn is_file_page_cached(&self, page_addr: VirtAddr) -> bool {
        match self {
            Self::File(mapping) => mapping.is_page_cached(page_addr),
            Self::Cow(mapping) => mapping.inner().is_file_page_cached(page_addr),
            _ => false,
        }
    }
}

const RETIREMENT_RECLAIM_CAPACITY: usize = 4096;

#[repr(align(64))]
struct RetirementFrameBuffer {
    in_use: AtomicBool,
    frames: UnsafeCell<[usize; RETIREMENT_RECLAIM_CAPACITY]>,
}

impl RetirementFrameBuffer {
    const fn new() -> Self {
        Self {
            in_use: AtomicBool::new(false),
            frames: UnsafeCell::new([0; RETIREMENT_RECLAIM_CAPACITY]),
        }
    }
}

// Access to each CPU slot is serialized by its in_use lease.
unsafe impl Sync for RetirementFrameBuffer {}

static RETIREMENT_RECLAIM_BUFFERS: [RetirementFrameBuffer; axconfig::plat::MAX_CPU_NUM] =
    [const { RetirementFrameBuffer::new() }; axconfig::plat::MAX_CPU_NUM];

enum DeferredFrames {
    Dynamic(Vec<PhysAddr>),
    Retirement { cpu_id: usize, len: usize },
}

/// Mapping references kept alive until a remote TLB shootdown has completed.
pub struct DeferredReclaims {
    frames: Option<DeferredFrames>,
    backend: Option<Backend>,
    additional_backends: Option<Vec<Backend>>,
    file_writebacks: FileWritebacks,
}

impl Default for DeferredReclaims {
    fn default() -> Self {
        Self {
            frames: Some(DeferredFrames::Dynamic(Vec::new())),
            backend: None,
            additional_backends: Some(Vec::new()),
            file_writebacks: FileWritebacks::default(),
        }
    }
}

impl DeferredReclaims {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            frames: Some(DeferredFrames::Dynamic(Vec::with_capacity(capacity))),
            backend: None,
            additional_backends: Some(Vec::new()),
            file_writebacks: FileWritebacks::default(),
        }
    }

    pub(crate) fn for_retirement() -> Self {
        let cpu_id = axhal::percpu::this_cpu_id();
        let buffer = &RETIREMENT_RECLAIM_BUFFERS[cpu_id];
        while buffer
            .in_use
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            #[cfg(feature = "ipi")]
            axipi::service_tlb_shootdown();
            core::hint::spin_loop();
        }
        Self {
            frames: Some(DeferredFrames::Retirement { cpu_id, len: 0 }),
            backend: None,
            additional_backends: Some(Vec::new()),
            file_writebacks: FileWritebacks::default(),
        }
    }

    pub(crate) const fn retirement_capacity() -> usize {
        RETIREMENT_RECLAIM_CAPACITY
    }

    pub(crate) fn defer_frame(&mut self, frame: PhysAddr) {
        if frame.as_usize() == 0 {
            return;
        }
        match self.frames.as_mut().unwrap() {
            DeferredFrames::Dynamic(frames) => frames.push(frame),
            DeferredFrames::Retirement { cpu_id, len } => {
                assert!(*len < RETIREMENT_RECLAIM_CAPACITY);
                // SAFETY: this object holds the selected CPU buffer's lease.
                unsafe {
                    (*RETIREMENT_RECLAIM_BUFFERS[*cpu_id].frames.get())[*len] = frame.as_usize();
                }
                *len += 1;
            }
        }
    }

    fn defer_backend(&mut self, backend: Backend) {
        if self.backend.is_none() {
            self.backend = Some(backend);
        } else {
            self.additional_backends.as_mut().unwrap().push(backend);
        }
    }

    fn defer_file_writeback(&mut self, writeback: file::FileWriteback) {
        self.file_writebacks.push(writeback);
    }

    pub(crate) fn is_empty(&self) -> bool {
        let frames_empty = match self.frames.as_ref().unwrap() {
            DeferredFrames::Dynamic(frames) => frames.is_empty(),
            DeferredFrames::Retirement { len, .. } => *len == 0,
        };
        frames_empty
            && self.backend.is_none()
            && self.additional_backends.as_ref().unwrap().is_empty()
            && self.file_writebacks.is_empty()
    }

    pub(crate) fn append(&mut self, other: Self) {
        let (other_frames, backend, additional_backends, file_writebacks) = other.into_parts();
        match other_frames {
            DeferredFrames::Dynamic(mut frames) => match self.frames.as_mut().unwrap() {
                DeferredFrames::Dynamic(own_frames) => own_frames.append(&mut frames),
                DeferredFrames::Retirement { .. } => {
                    for frame in frames {
                        self.defer_frame(frame);
                    }
                }
            },
            DeferredFrames::Retirement { cpu_id, len } => {
                for index in 0..len {
                    self.defer_frame(retirement_frame(cpu_id, index));
                }
                release_retirement_buffer(cpu_id);
            }
        }
        if let Some(backend) = backend {
            self.defer_backend(backend);
        }
        for backend in additional_backends {
            self.defer_backend(backend);
        }
        self.file_writebacks.append(file_writebacks);
    }

    pub(crate) fn reclaim(self) {
        let (frames, backend, additional_backends, file_writebacks) = self.into_parts();
        // File-backed MAP_SHARED pages must be marked dirty only after the
        // PTE invalidation is visible to every CPU. `reclaim()` is reached
        // after that completion for published address spaces.
        let _ = file_writebacks.complete();
        match frames {
            DeferredFrames::Dynamic(frames) => {
                self::alloc::dealloc_frames(frames);
            }
            DeferredFrames::Retirement { cpu_id, len } => {
                // SAFETY: this reclaim owns the CPU buffer lease until it is
                // released below, so the initialized prefix is exclusive.
                let frames = unsafe {
                    &mut (*RETIREMENT_RECLAIM_BUFFERS[cpu_id].frames.get())[..len]
                };
                self::alloc::dealloc_frame_values(frames);
                release_retirement_buffer(cpu_id);
            }
        }
        drop(backend);
        drop(additional_backends);
    }

    fn into_parts(mut self) -> (DeferredFrames, Option<Backend>, Vec<Backend>, FileWritebacks) {
        (
            self.frames.take().unwrap(),
            self.backend.take(),
            self.additional_backends.take().unwrap(),
            core::mem::take(&mut self.file_writebacks),
        )
    }
}

fn retirement_frame(cpu_id: usize, index: usize) -> PhysAddr {
    // SAFETY: a live Retirement DeferredFrames owns this CPU slot's lease,
    // and callers only read initialized indices below its recorded length.
    PhysAddr::from(unsafe { (*RETIREMENT_RECLAIM_BUFFERS[cpu_id].frames.get())[index] })
}

fn release_retirement_buffer(cpu_id: usize) {
    RETIREMENT_RECLAIM_BUFFERS[cpu_id]
        .in_use
        .store(false, Ordering::Release);
}

impl Drop for DeferredReclaims {
    fn drop(&mut self) {
        let Some(frames) = self.frames.take() else {
            return;
        };
        let frame_count = match &frames {
            DeferredFrames::Dynamic(frames) => frames.len(),
            DeferredFrames::Retirement { len, .. } => *len,
        };
        let backend_count = usize::from(self.backend.is_some())
            + self.additional_backends.as_ref().unwrap().len();
        let writeback_count = usize::from(!self.file_writebacks.is_empty());
        if frame_count + backend_count + writeback_count > 0 {
            error!(
                "leaking {} deferred mapping references after incomplete TLB shootdown",
                frame_count + backend_count + writeback_count
            );
        }
        match frames {
            DeferredFrames::Dynamic(frames) if !frames.is_empty() => core::mem::forget(frames),
            DeferredFrames::Dynamic(_) => {}
            DeferredFrames::Retirement { cpu_id, .. } => release_retirement_buffer(cpu_id),
        }
        if let Some(backend) = self.backend.take() {
            core::mem::forget(backend);
        }
        if let Some(backends) = self.additional_backends.take() {
            if !backends.is_empty() {
                core::mem::forget(backends);
            }
        }
        if !self.file_writebacks.is_empty() {
            core::mem::forget(core::mem::take(&mut self.file_writebacks));
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
        self.unmap_tracked(start, size, pt, reclaim, &mut ())
    }

    fn unmap_tracked<M: MappingMutationTracker<Self::Addr>>(
        &self,
        start: VirtAddr,
        size: usize,
        pt: &mut Self::PageTable,
        reclaim: &mut Self::Reclaim,
        mutation: &mut M,
    ) -> bool {
        let pt_mut = pt.get_mut();
        match self {
            Self::Shared { .. } => {
                reclaim.defer_backend(self.clone());
                Self::unmap_shared(start, size, pt_mut, mutation)
            }
            Self::Linear { pa_va_offset } => {
                self.unmap_linear(start, size, pt_mut, *pa_va_offset, mutation)
            }
            Self::Alloc { populate, .. } => {
                self.unmap_alloc(start, size, pt_mut, *populate, reclaim, mutation)
            }
            Self::File(_) => {
                // Keep the CachedFile alive until after the address-space lock
                // is released; dropping its final reference may perform I/O.
                reclaim.defer_backend(self.clone());
                self.unmap_file(start, size, pt_mut, reclaim, mutation)
            }
            Self::Cow(cow) => cow
                .inner
                .unmap_tracked(start, size, pt, reclaim, mutation),
        }
    }

    fn protect(
        &self,
        start: Self::Addr,
        size: usize,
        new_flags: Self::Flags,
        page_table: &mut Self::PageTable,
    ) -> bool {
        self.protect_tracked(start, size, new_flags, page_table, &mut ())
    }

    fn protect_tracked<M: MappingMutationTracker<Self::Addr>>(
        &self,
        start: Self::Addr,
        size: usize,
        new_flags: Self::Flags,
        page_table: &mut Self::PageTable,
        mutation: &mut M,
    ) -> bool {
        let pt_mut = page_table.get_mut();
        match self {
            Self::Shared { .. } | Self::Linear { .. } => {
                protect_populated_range(start, size, new_flags, pt_mut, mutation)
            }
            Self::Alloc { populate, .. } => {
                self.protect_alloc(start, size, new_flags, pt_mut, *populate, mutation)
            }
            Self::File(mapping) => {
                self.protect_file(start, size, new_flags, pt_mut, mapping, mutation)
            }
            Self::Cow(cow) => cow
                .inner
                .protect_tracked(start, size, new_flags, page_table, mutation),
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

    /// Returns whether resident pages can be discarded and later faulted back
    /// as zero-filled anonymous pages.
    pub fn is_discardable(&self) -> bool {
        match self {
            Self::Alloc { .. } => true,
            Self::Cow(cow) => cow.inner.is_discardable(),
            _ => false,
        }
    }

    pub(crate) fn page_fault_load_request(
        &self,
        vaddr: VirtAddr,
        area_end: VirtAddr,
        orig_flags: MappingFlags,
        page_table: &crate::PageTableLockManager,
    ) -> Option<FilePageLoad> {
        match self {
            Self::File(mapping) => {
                mapping.page_load_request(vaddr, area_end, orig_flags, page_table)
            }
            Self::Cow(cow) => {
                cow.inner()
                    .page_fault_load_request(vaddr, area_end, orig_flags, page_table)
            }
            _ => None,
        }
    }

    pub(crate) fn page_fault_anon_request(
        &self,
        vaddr: VirtAddr,
        area_end: VirtAddr,
        page_table: &crate::PageTableLockManager,
    ) -> Option<AnonPageLoad> {
        self.page_fault_alloc_request(vaddr, area_end, page_table)
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
        area_end: VirtAddr,
        orig_flags: MappingFlags,
        page_table: &crate::PageTableLockManager,
        access_flags: MappingFlags,
        prepared: &mut FilePagePrepared,
    ) -> bool {
        match self {
            Self::File(mapping) => self.handle_prepared_page_fault_file(
                vaddr,
                area_end,
                orig_flags,
                page_table,
                mapping,
                access_flags,
                prepared,
            ),
            Self::Cow(cow) => cow.inner().handle_prepared_file_page(
                vaddr,
                area_end,
                orig_flags,
                page_table,
                access_flags,
                prepared,
            ),
            _ => false,
        }
    }

    pub(crate) fn handle_prepared_anon_page(
        &self,
        vaddr: VirtAddr,
        area_end: VirtAddr,
        orig_flags: MappingFlags,
        page_table: &crate::PageTableLockManager,
        prepared: &mut AnonPagePrepared,
    ) -> bool {
        match self {
            Self::Alloc { populate: false, .. } => self.handle_prepared_page_fault_alloc(
                vaddr,
                area_end,
                orig_flags,
                page_table,
                prepared,
            ),
            Self::Cow(cow) => cow.inner().handle_prepared_anon_page(
                vaddr,
                area_end,
                orig_flags,
                page_table,
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

#[cfg(test)]
mod tests {
    use ::alloc::boxed::Box;

    use super::{Backend, CowMapping};

    #[test]
    fn only_anonymous_backends_are_discardable() {
        assert!(Backend::new_alloc(false).is_discardable());
        assert!(Backend::new_alloc(true).is_discardable());
        assert!(Backend::Cow(CowMapping::new(Box::new(Backend::new_alloc(false)))).is_discardable());
        assert!(!Backend::Linear { pa_va_offset: 0 }.is_discardable());
    }
}
