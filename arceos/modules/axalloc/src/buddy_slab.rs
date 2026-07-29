use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::NonNull,
    slice,
};

use allocator::{AllocError, AllocResult};
use buddy_slab_allocator::{
    AllocError as SlubAllocError, GlobalAllocator as InnerAllocator, SizeClass, SlabAllocResult,
    SlabAllocator, SlabDeallocResult, SlabPoolTrait, SlabTrait, eii::AllocatorIf,
};
use kernel_guard::NoPreemptIrqSave;
use kspin::SpinRaw;

use crate::{MIN_PAGE_RECLAIM_BATCH, PAGE_SIZE, try_page_reclaim};

#[percpu::def_percpu]
static PERCPU_SLAB: PerCpuSlab<PAGE_SIZE> = PerCpuSlab::new_uninit();

static SLAB_POOL: SlabPool = SlabPool;

struct PerCpuSlab<const PAGE_SIZE: usize> {
    cpu_id: Option<u16>,
    inner: SpinRaw<SlabAllocator<PAGE_SIZE>>,
}

impl<const PAGE_SIZE: usize> PerCpuSlab<PAGE_SIZE> {
    const fn new_uninit() -> Self {
        Self {
            cpu_id: None,
            inner: SpinRaw::new(SlabAllocator::new()),
        }
    }

    fn init_during_cpu_bringup(&mut self, cpu_id: usize) {
        let cpu_id = u16::try_from(cpu_id).expect("CPU id exceeds SLUB owner range");
        assert!(self.cpu_id.is_none(), "per-CPU SLUB is already initialized");
        self.cpu_id = Some(cpu_id);
        *self.inner.get_mut() = SlabAllocator::new();
    }

    fn cpu_id_checked(&self) -> u16 {
        self.cpu_id
            .expect("per-CPU SLUB is not initialized on this CPU")
    }
}

impl<const PAGE_SIZE: usize> SlabTrait for PerCpuSlab<PAGE_SIZE> {
    fn cpu_id(&self) -> usize {
        self.cpu_id_checked() as usize
    }

    fn page_size(&self) -> usize {
        PAGE_SIZE
    }

    fn alloc(&self, layout: Layout) -> buddy_slab_allocator::AllocResult<SlabAllocResult> {
        self.inner.lock().alloc(layout)
    }

    fn add_slab(&self, size_class: SizeClass, base: usize, bytes: usize) {
        self.inner
            .lock()
            .add_slab(size_class, base, bytes, self.cpu_id_checked());
    }

    fn dealloc_local(&self, ptr: NonNull<u8>, layout: Layout) -> SlabDeallocResult {
        self.inner.lock().dealloc(ptr, layout)
    }
}

struct SlabPool;

impl SlabPoolTrait for SlabPool {
    fn current_slab(&self) -> &dyn SlabTrait {
        // SAFETY: every allocator entry pins the current CPU and disables local
        // interrupts before the upstream allocator reaches this hook.
        unsafe { PERCPU_SLAB.current_ref_raw() }
    }

    fn owner_slab(&self, cpu_idx: usize) -> &dyn SlabTrait {
        // SAFETY: a slab header can only name a CPU whose permanent per-CPU
        // area was initialized. Remote deallocation touches only atomic header
        // state and the immutable owner id.
        unsafe { PERCPU_SLAB.remote_ref_raw(cpu_idx) }
    }
}

struct AllocatorIfImpl;

#[crate_interface::impl_interface]
impl AllocatorIf for AllocatorIfImpl {
    fn virt_to_phys(vaddr: usize) -> usize {
        axplat::mem::virt_to_phys(vaddr.into()).as_usize()
    }

    fn slab_pool() -> &'static dyn SlabPoolTrait {
        &SLAB_POOL
    }
}

fn map_error(error: SlubAllocError) -> AllocError {
    match error {
        SlubAllocError::MemoryOverlap => AllocError::MemoryOverlap,
        SlubAllocError::NoMemory => AllocError::NoMemory,
        SlubAllocError::NotAllocated => AllocError::NotAllocated,
        SlubAllocError::InvalidParam
        | SlubAllocError::AlreadyInitialized
        | SlubAllocError::NotInitialized
        | SlubAllocError::NotFound => AllocError::InvalidParam,
    }
}

/// PulseOS global allocator backed by per-CPU SLUB and a multi-region Buddy.
pub struct GlobalAllocator {
    inner: InnerAllocator<PAGE_SIZE>,
}

impl GlobalAllocator {
    /// Creates an empty allocator.
    pub const fn new() -> Self {
        Self {
            inner: InnerAllocator::new(),
        }
    }

    /// Returns the allocator name printed during boot.
    pub const fn name(&self) -> &'static str {
        "SLUB+Buddy"
    }

    /// Initializes the allocator with the first free physical-memory region.
    pub fn init(&self, start_vaddr: usize, size: usize) {
        let region = unsafe { slice::from_raw_parts_mut(start_vaddr as *mut u8, size) };
        let _guard = NoPreemptIrqSave::new();
        unsafe { self.inner.init(region) }.expect("initialize SLUB+Buddy allocator failed");
    }

    /// Adds another, possibly discontiguous, physical-memory region.
    pub fn add_memory(&self, start_vaddr: usize, size: usize) -> AllocResult {
        let region = unsafe { slice::from_raw_parts_mut(start_vaddr as *mut u8, size) };
        let _guard = NoPreemptIrqSave::new();
        unsafe { self.inner.add_region(region) }.map_err(map_error)
    }

    fn alloc_once(&self, layout: Layout) -> buddy_slab_allocator::AllocResult<NonNull<u8>> {
        let _guard = NoPreemptIrqSave::new();
        self.inner.alloc(layout)
    }

    /// Allocates arbitrary bytes through the local SLUB or Buddy slow path.
    pub fn alloc(&self, layout: Layout) -> AllocResult<NonNull<u8>> {
        let mut result = self.alloc_once(layout);
        if matches!(result, Err(SlubAllocError::NoMemory)) {
            let reclaim_pages = layout
                .size()
                .div_ceil(PAGE_SIZE)
                .max(MIN_PAGE_RECLAIM_BATCH);
            for _ in 0..4 {
                let reclaimed = try_page_reclaim(reclaim_pages);
                result = self.alloc_once(layout);
                if result.is_ok() || reclaimed == 0 {
                    break;
                }
            }
        }
        result.map_err(map_error)
    }

    /// Deallocates a prior byte allocation.
    pub fn dealloc(&self, pos: NonNull<u8>, layout: Layout) {
        let _guard = NoPreemptIrqSave::new();
        unsafe { self.inner.dealloc(pos, layout) };
    }

    fn alloc_pages_once(
        &self,
        num_pages: usize,
        align_pow2: usize,
    ) -> buddy_slab_allocator::AllocResult<usize> {
        let _guard = NoPreemptIrqSave::new();
        self.inner.alloc_pages(num_pages, align_pow2)
    }

    /// Allocates contiguous pages, invoking the registered reclaim hook on OOM.
    pub fn alloc_pages(&self, num_pages: usize, align_pow2: usize) -> AllocResult<usize> {
        let mut result = self.alloc_pages_once(num_pages, align_pow2);
        if matches!(result, Err(SlubAllocError::NoMemory)) {
            for _ in 0..4 {
                let reclaimed = try_page_reclaim(num_pages.max(MIN_PAGE_RECLAIM_BATCH));
                result = self.alloc_pages_once(num_pages, align_pow2);
                if result.is_ok() || reclaimed == 0 {
                    break;
                }
            }
        }
        result.map_err(map_error)
    }

    /// Allocates independent pages while acquiring the Buddy lock once.
    pub fn alloc_page_batch(&self, pages: &mut [usize]) -> usize {
        if pages.is_empty() {
            return 0;
        }
        let mut allocated = {
            let _guard = NoPreemptIrqSave::new();
            self.inner.alloc_page_batch(pages)
        };
        if allocated == 0 {
            let Ok(first) = self.alloc_pages(1, PAGE_SIZE) else {
                return 0;
            };
            pages[0] = first;
            allocated = 1;
            let _guard = NoPreemptIrqSave::new();
            allocated += self.inner.alloc_page_batch(&mut pages[1..]);
        }
        allocated
    }

    fn alloc_pages_at_once(
        &self,
        start: usize,
        num_pages: usize,
        align_pow2: usize,
    ) -> buddy_slab_allocator::AllocResult<usize> {
        let _guard = NoPreemptIrqSave::new();
        self.inner.alloc_pages_at(start, num_pages, align_pow2)
    }

    /// Allocates an exact contiguous page range at `start`.
    pub fn alloc_pages_at(
        &self,
        start: usize,
        num_pages: usize,
        align_pow2: usize,
    ) -> AllocResult<usize> {
        let mut result = self.alloc_pages_at_once(start, num_pages, align_pow2);
        if matches!(result, Err(SlubAllocError::NoMemory)) {
            for _ in 0..4 {
                let reclaimed = try_page_reclaim(num_pages.max(MIN_PAGE_RECLAIM_BATCH));
                result = self.alloc_pages_at_once(start, num_pages, align_pow2);
                if result.is_ok() || reclaimed == 0 {
                    break;
                }
            }
        }
        result.map_err(map_error)
    }

    /// Returns pages to Buddy. Non-power-of-two ranges are freed exactly.
    pub fn dealloc_pages(&self, pos: usize, num_pages: usize) {
        let _guard = NoPreemptIrqSave::new();
        self.inner.dealloc_pages(pos, num_pages);
    }

    /// Returns backend page occupancy in bytes, including cached slab pages.
    pub fn used_bytes(&self) -> usize {
        let _guard = NoPreemptIrqSave::new();
        self.inner.allocated_bytes()
    }

    /// Free memory is reported through [`available_pages`](Self::available_pages).
    pub const fn available_bytes(&self) -> usize {
        0
    }

    /// Returns backend page occupancy.
    pub fn used_pages(&self) -> usize {
        self.used_bytes() / PAGE_SIZE
    }

    /// Returns free Buddy pages across all managed regions.
    pub fn available_pages(&self) -> usize {
        let _guard = NoPreemptIrqSave::new();
        let managed = self.inner.managed_bytes();
        let allocated = self.inner.allocated_bytes();
        managed.saturating_sub(allocated) / PAGE_SIZE
    }
}

unsafe impl GlobalAlloc for GlobalAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match GlobalAllocator::alloc(self, layout) {
            Ok(ptr) => ptr.as_ptr(),
            Err(_) => alloc::alloc::handle_alloc_error(layout),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        GlobalAllocator::dealloc(
            self,
            NonNull::new(ptr).expect("dealloc null pointer"),
            layout,
        )
    }
}

#[cfg_attr(all(target_os = "none", not(test)), global_allocator)]
static GLOBAL_ALLOCATOR: GlobalAllocator = GlobalAllocator::new();

/// Returns the global SLUB+Buddy allocator.
pub fn global_allocator() -> &'static GlobalAllocator {
    &GLOBAL_ALLOCATOR
}

/// Initializes the current CPU's SLUB during CPU bring-up.
pub fn init_percpu_slab(cpu_id: usize) {
    let _guard = NoPreemptIrqSave::new();
    PERCPU_SLAB.with_current(|slab| slab.init_during_cpu_bringup(cpu_id));
}

/// Initializes the global allocator with the first memory region.
pub fn global_init(start_vaddr: usize, size: usize) {
    debug!(
        "initialize SLUB+Buddy allocator at: [{:#x}, {:#x})",
        start_vaddr,
        start_vaddr + size
    );
    GLOBAL_ALLOCATOR.init(start_vaddr, size);
}

/// Adds a discontiguous memory region to the global Buddy allocator.
pub fn global_add_memory(start_vaddr: usize, size: usize) -> AllocResult {
    debug!(
        "add a memory region to SLUB+Buddy: [{:#x}, {:#x})",
        start_vaddr,
        start_vaddr + size
    );
    GLOBAL_ALLOCATOR.add_memory(start_vaddr, size)
}
