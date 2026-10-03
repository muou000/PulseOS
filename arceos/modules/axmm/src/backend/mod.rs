//! Memory mapping backends.

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

use ::alloc::{sync::Arc, vec::Vec};
use axhal::paging::{MappingFlags, PageSize};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, PhysAddr, VirtAddr};
use memory_set::{MappingBackend, MappingMutation as MappingMutationTracker};

mod alloc;
mod cow;
mod file;
mod linear;
mod shared;

pub use alloc::{AnonPageLoad, AnonPagePrepared};
pub(crate) use alloc::{alloc_frame, cow_dec_frame_ref, cow_inc_frame_ref, dealloc_frame};

pub use self::{
    cow::CowMapping,
    file::{FilePageLoad, FilePagePrepared},
    shared::SharedFrame,
};

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
pub struct FileWritebacks {
    pages: Vec<file::DirtyFilePage>,
    files: Vec<axfs::CachedFile>,
}

// Failed publications retain both the cache and the extra physical-frame pin.
// Take the queue before doing cache work so no queue lock is held across I/O.
static FAILED_FILE_PAGES: spin::Mutex<Vec<file::DirtyFilePage>> = spin::Mutex::new(Vec::new());

fn range_page_capacity(size: usize) -> usize {
    size / PAGE_SIZE_4K + usize::from(size % PAGE_SIZE_4K != 0)
}

/// Publish every record, retaining only failures, then sync every requested file
/// if all publications succeeded. The closures also provide a test seam for
/// ownership and error handling without a physical allocator or filesystem.
fn complete_writeback_records<Page, File>(
    pages: &mut Vec<Page>,
    files: &[File],
    mut publish: impl FnMut(&Page) -> axerrno::AxResult,
    mut sync: impl FnMut(&File) -> axerrno::AxResult,
) -> axerrno::AxResult {
    let mut first_error = None;
    pages.retain(|page| match publish(page) {
        Ok(()) => false,
        Err(error) => {
            first_error.get_or_insert(error);
            true
        }
    });
    if let Some(error) = first_error {
        return Err(error);
    }
    for file in files {
        if let Err(error) = sync(file) {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

impl FileWritebacks {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            pages: Vec::with_capacity(capacity),
            files: Vec::new(),
        }
    }

    /// Reserve the maximum page records and, when requested, sync-file records
    /// for a byte range before acquiring the address-space lock.
    pub fn try_prepare(size: usize, sync: bool) -> axerrno::AxResult<Self> {
        let capacity = range_page_capacity(size);
        let mut writebacks = Self::default();
        writebacks
            .pages
            .try_reserve_exact(capacity)
            .map_err(|_| axerrno::AxError::NoMemory)?;
        if sync {
            writebacks
                .files
                .try_reserve_exact(capacity)
                .map_err(|_| axerrno::AxError::NoMemory)?;
        }
        Ok(writebacks)
    }

    /// Pin a live mapping frame while its PTE guard or mapping reference is
    /// still held. Legacy callers may grow the vector; prepared batches have
    /// enough capacity for the full operation.
    pub(crate) fn record_page(
        &mut self,
        file: &axfs::CachedFile,
        page_number: u32,
        frame: PhysAddr,
    ) -> axerrno::AxResult {
        self.pages
            .push(file::DirtyFilePage::new(file, page_number, frame)?);
        Ok(())
    }

    /// Request a sync even if a shared mapping has no resident or writable PTEs.
    pub(crate) fn record_file(&mut self, file: &axfs::CachedFile) {
        if !self
            .files
            .iter()
            .any(|recorded| recorded.shares_page_cache_with(file))
        {
            self.files.push(file.clone());
        }
    }

    fn is_empty(&self) -> bool {
        self.pages.is_empty() && self.files.is_empty()
    }

    fn append(&mut self, mut other: Self) {
        self.pages.append(&mut other.pages);
        for file in &other.files {
            self.record_file(file);
        }
    }

    /// Retry previously failed publications once, publish the entire new batch,
    /// and release every successful record's extra pin. Storage errors leave
    /// dirty ownership in axfs rather than retaining physical-frame pins here.
    pub fn complete(mut self) -> axerrno::AxResult {
        let mut pages = core::mem::take(&mut *FAILED_FILE_PAGES.lock());
        pages.append(&mut self.pages);
        let result = complete_writeback_records(
            &mut pages,
            &self.files,
            file::DirtyFilePage::publish,
            |file| file.sync(false).map_err(|_| axerrno::AxError::Io),
        );
        if !pages.is_empty() {
            FAILED_FILE_PAGES.lock().append(&mut pages);
        }
        result
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
    pub(crate) fn requires_private_copy(&self) -> bool {
        match self {
            Self::Cow(_) => true,
            Self::File(mapping) => !mapping.is_shared(),
            _ => false,
        }
    }

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
            file_writebacks: FileWritebacks::with_capacity(capacity),
        }
    }

    /// Reserve all retirement records for a byte range outside the mapping lock.
    pub fn try_prepare(size: usize) -> axerrno::AxResult<Self> {
        let capacity = range_page_capacity(size);
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(capacity)
            .map_err(|_| axerrno::AxError::NoMemory)?;
        let mut backends = Vec::new();
        backends
            .try_reserve_exact(capacity)
            .map_err(|_| axerrno::AxError::NoMemory)?;
        Ok(Self {
            frames: Some(DeferredFrames::Dynamic(frames)),
            backend: None,
            additional_backends: Some(backends),
            file_writebacks: FileWritebacks::try_prepare(size, false)?,
        })
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

    pub(crate) fn defer_file_page(
        &mut self,
        file: &axfs::CachedFile,
        page_number: u32,
        frame: PhysAddr,
    ) -> axerrno::AxResult {
        self.file_writebacks.record_page(file, page_number, frame)
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

    pub(crate) fn reclaim(self) -> axerrno::AxResult {
        let (frames, backend, additional_backends, file_writebacks) = self.into_parts();
        // File-backed MAP_SHARED pages must be marked dirty only after the
        // PTE invalidation is visible to every CPU. `reclaim()` is reached
        // after that completion for published address spaces.
        let writeback_result = file_writebacks.complete();
        // Failed publications now own independent pins in FAILED_FILE_PAGES.
        // Mapping references and retirement leases can always be released once
        // the TLB shootdown has completed, regardless of publication or I/O errors.
        match frames {
            DeferredFrames::Dynamic(frames) => {
                self::alloc::dealloc_frames(frames);
            }
            DeferredFrames::Retirement { cpu_id, len } => {
                // SAFETY: this reclaim owns the CPU buffer lease until it is
                // released below, so the initialized prefix is exclusive.
                let frames =
                    unsafe { &mut (&mut *RETIREMENT_RECLAIM_BUFFERS[cpu_id].frames.get())[..len] };
                self::alloc::dealloc_frame_values(frames);
                release_retirement_buffer(cpu_id);
            }
        }
        drop(backend);
        drop(additional_backends);
        writeback_result
    }

    fn into_parts(
        mut self,
    ) -> (
        DeferredFrames,
        Option<Backend>,
        Vec<Backend>,
        FileWritebacks,
    ) {
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
        let backend_count =
            usize::from(self.backend.is_some()) + self.additional_backends.as_ref().unwrap().len();
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
    fn map(
        &self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        pt: &mut Self::PageTable,
    ) -> bool {
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
            Self::Cow(cow) => cow.inner.unmap_tracked(start, size, pt, reclaim, mutation),
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
    /// Place a prepared mapping without expanding its original file byte window.
    pub(crate) fn relocate_prepared(&mut self, start: VirtAddr) {
        match self {
            Self::File(mapping) => mapping.relocate(start),
            Self::Cow(cow) => cow.inner.relocate_prepared(start),
            _ => {}
        }
    }

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
                cow.inner
                    .update_address(old_start, new_start, old_size, new_size);
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
            Self::Cow(cow) => cow
                .inner()
                .page_fault_load_request(vaddr, area_end, orig_flags, page_table),
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
            Self::Alloc {
                populate: false, ..
            } => self.handle_prepared_page_fault_alloc(
                vaddr, area_end, orig_flags, page_table, prepared,
            ),
            Self::Cow(cow) => cow
                .inner()
                .handle_prepared_anon_page(vaddr, area_end, orig_flags, page_table, prepared),
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
            Self::File(_) => self
                .prepare_file_writeback_range_impl(start, size, sync, pt, writebacks)
                .is_ok(),
            Self::Cow(cow) => cow
                .inner
                .prepare_file_writeback_range(start, size, sync, pt, writebacks),
            _ => true, // Non-file backends have nothing to write back.
        }
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use ::alloc::{boxed::Box, rc::Rc, vec, vec::Vec};
    use axerrno::AxError;

    use super::{Backend, CowMapping, complete_writeback_records, range_page_capacity};

    struct TestDirtyPage {
        page_number: usize,
        file: Rc<()>,
        frame_pin: Rc<()>,
        drops: Rc<Cell<usize>>,
    }

    impl TestDirtyPage {
        fn new(page_number: usize, drops: &Rc<Cell<usize>>) -> Self {
            Self {
                page_number,
                file: Rc::new(()),
                frame_pin: Rc::new(()),
                drops: drops.clone(),
            }
        }
    }

    impl Drop for TestDirtyPage {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    #[test]
    fn publication_error_processes_the_entire_batch_and_retains_only_failures() {
        let drops = Rc::new(Cell::new(0));
        let mut pages: Vec<_> = (0..4).map(|pn| TestDirtyPage::new(pn, &drops)).collect();
        let mut visited = Vec::new();
        let mut syncs = 0;
        let result = complete_writeback_records(
            &mut pages,
            &[0, 1],
            |page| {
                visited.push(page.page_number);
                match page.page_number {
                    0 => Err(AxError::Io),
                    2 => Err(AxError::BadState),
                    _ => Ok(()),
                }
            },
            |_| {
                syncs += 1;
                Ok(())
            },
        );
        assert_eq!(result, Err(AxError::Io));
        assert_eq!(visited, vec![0, 1, 2, 3]);
        assert_eq!(
            pages
                .iter()
                .map(|page| page.page_number)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
        assert_eq!(drops.get(), 2);
        assert_eq!(syncs, 0);
    }

    #[test]
    fn failed_publication_owns_file_and_pin_until_the_next_completion() {
        let drops = Rc::new(Cell::new(0));
        let failed_page = TestDirtyPage::new(7, &drops);
        let file = Rc::downgrade(&failed_page.file);
        let pin = Rc::downgrade(&failed_page.frame_pin);
        let mut pages = vec![failed_page];
        assert_eq!(
            complete_writeback_records(
                &mut pages,
                &[] as &[usize],
                |_| Err(AxError::Io),
                |_| Ok(())
            ),
            Err(AxError::Io)
        );
        assert_eq!(drops.get(), 0);
        assert_eq!(file.strong_count(), 1);
        assert_eq!(pin.strong_count(), 1);

        // Moving into the retry queue keeps the complete failed record alive.
        let mut retry_queue = Vec::new();
        retry_queue.append(&mut pages);
        let mut next_batch = core::mem::take(&mut retry_queue);
        next_batch.push(TestDirtyPage::new(8, &drops));
        let mut visited = Vec::new();
        assert_eq!(
            complete_writeback_records(
                &mut next_batch,
                &[] as &[usize],
                |page| {
                    visited.push(page.page_number);
                    Ok(())
                },
                |_| Ok(())
            ),
            Ok(())
        );
        assert_eq!(visited, vec![7, 8]);
        assert!(next_batch.is_empty());
        assert_eq!(drops.get(), 2);
        assert!(file.upgrade().is_none());
        assert!(pin.upgrade().is_none());
    }

    #[test]
    fn repeated_publication_failure_retries_each_record_only_once_per_completion() {
        let drops = Rc::new(Cell::new(0));
        let mut pages = vec![TestDirtyPage::new(0, &drops), TestDirtyPage::new(1, &drops)];
        for _ in 0..2 {
            let mut visited = Vec::new();
            assert_eq!(
                complete_writeback_records(
                    &mut pages,
                    &[] as &[usize],
                    |page| {
                        visited.push(page.page_number);
                        Err(AxError::Io)
                    },
                    |_| Ok(())
                ),
                Err(AxError::Io)
            );
            assert_eq!(visited, vec![0, 1]);
            assert_eq!(pages.len(), 2);
            assert_eq!(drops.get(), 0);
        }
    }

    #[test]
    fn storage_failure_syncs_every_file_without_retaining_physical_pins() {
        let drops = Rc::new(Cell::new(0));
        let mut pages = vec![TestDirtyPage::new(0, &drops)];
        let mut synced = Vec::new();
        assert_eq!(
            complete_writeback_records(
                &mut pages,
                &[10, 11, 12],
                |_| Ok(()),
                |file| {
                    synced.push(*file);
                    if *file == 10 {
                        Err(AxError::Io)
                    } else if *file == 12 {
                        Err(AxError::BadState)
                    } else {
                        Ok(())
                    }
                }
            ),
            Err(AxError::Io)
        );
        assert_eq!(synced, vec![10, 11, 12]);
        assert!(pages.is_empty());
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn sync_without_resident_pages_still_processes_all_requested_files() {
        let mut pages = Vec::<TestDirtyPage>::new();
        let mut synced = Vec::new();
        assert_eq!(
            complete_writeback_records(
                &mut pages,
                &[10, 11],
                |_| panic!("an empty batch must not publish a page"),
                |file| {
                    synced.push(*file);
                    Ok(())
                }
            ),
            Ok(())
        );
        assert_eq!(synced, vec![10, 11]);
    }

    #[test]
    fn range_capacity_rounds_up_without_overflow() {
        assert_eq!(range_page_capacity(0), 0);
        assert_eq!(range_page_capacity(1), 1);
        assert_eq!(range_page_capacity(memory_addr::PAGE_SIZE_4K), 1);
        assert_eq!(range_page_capacity(memory_addr::PAGE_SIZE_4K + 1), 2);
        assert_eq!(
            range_page_capacity(usize::MAX),
            usize::MAX / memory_addr::PAGE_SIZE_4K + 1
        );
    }

    #[test]
    fn only_anonymous_backends_are_discardable() {
        assert!(Backend::new_alloc(false).is_discardable());
        assert!(Backend::new_alloc(true).is_discardable());
        assert!(
            Backend::Cow(CowMapping::new(Box::new(Backend::new_alloc(false)))).is_discardable()
        );
        assert!(!Backend::Linear { pa_va_offset: 0 }.is_discardable());
    }
}
