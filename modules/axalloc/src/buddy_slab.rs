use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::NonNull,
    slice,
    sync::atomic::{AtomicUsize, Ordering},
};

use allocator::{AllocError, AllocResult};
use buddy_slab_allocator::{
    AllocError as SlubAllocError, GlobalAllocator as InnerAllocator, SizeClass, SlabAllocResult,
    SlabAllocator, SlabDeallocResult, SlabFreeBatch, SlabPoolTrait, SlabTrait, eii::AllocatorIf,
};
use kernel_guard::NoPreemptIrqSave;
use kspin::SpinRaw;

use crate::{
    MIN_PAGE_RECLAIM_BATCH, PAGE_SIZE,
    pcp::{PCP_BATCH_SIZE, PCP_CAPACITY, PerCpuPcp},
    try_page_reclaim,
};

#[percpu::def_percpu]
static PERCPU_SLAB: PerCpuSlab<PAGE_SIZE> = PerCpuSlab::new_uninit();

#[percpu::def_percpu]
static PERCPU_PCP: PerCpuPcp = PerCpuPcp::new_uninit();

static ACTIVE_CPU_COUNT: AtomicUsize = AtomicUsize::new(0);

static SLAB_POOL: SlabPool = SlabPool;

const MAGAZINE_CAP: usize = 32;
const BATCH_SIZE: usize = SlabFreeBatch::CAPACITY;
const NUM_SIZE_CLASSES: usize = SizeClass::COUNT;
// A normal kernel allocation should never approach this size in the hot path.
// Keep a caller-PC diagnostic above this threshold so an on-board allocation
// failure can be tied back to its source without logging or adding work to
// ordinary allocations.
const LARGE_ALLOCATION_DIAGNOSTIC_THRESHOLD: usize = 64 * 1024 * 1024;

/// Returns the caller PC inherited from Rust's `__rust_alloc` shim.
///
/// The shim tail-calls `GlobalAlloc::alloc`, so on the supported kernel
/// architectures the return-address register still identifies the allocation
/// site rather than the shim. This is intentionally used only for anomalously
/// large requests before the allocator performs any calls which could clobber
/// that register.
#[inline(always)]
fn allocation_callsite() -> usize {
    #[cfg(target_arch = "riscv64")]
    {
        let callsite: usize;
        // SAFETY: reading the architectural return-address register has no
        // memory effect and does not change machine state.
        unsafe {
            core::arch::asm!(
                "mv {callsite}, ra",
                callsite = out(reg) callsite,
                options(nomem, nostack, preserves_flags),
            );
        }
        callsite
    }

    #[cfg(target_arch = "loongarch64")]
    {
        let callsite: usize;
        // SAFETY: see the RISC-V branch above.
        unsafe {
            core::arch::asm!(
                "move {callsite}, $ra",
                callsite = out(reg) callsite,
                options(nomem, nostack, preserves_flags),
            );
        }
        callsite
    }

    #[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
    {
        0
    }
}

#[derive(Copy, Clone)]
struct SizeClassMagazine {
    objects: [usize; MAGAZINE_CAP],
    count: usize,
}

impl SizeClassMagazine {
    const fn new() -> Self {
        Self {
            objects: [0; MAGAZINE_CAP],
            count: 0,
        }
    }
}

struct PerCpuSlab<const PAGE_SIZE: usize> {
    cpu_id: Option<u16>,
    magazines: core::cell::UnsafeCell<[SizeClassMagazine; NUM_SIZE_CLASSES]>,
    inner: SpinRaw<SlabAllocator<PAGE_SIZE>>,
}

// SAFETY: PerCpuSlab is per-CPU and protected against re-entrancy by NoPreemptIrqSave.
unsafe impl<const PAGE_SIZE: usize> Sync for PerCpuSlab<PAGE_SIZE> {}

fn collect_slab_reclaim(reclaims: &mut SlabFreeBatch, result: SlabDeallocResult) {
    match result {
        SlabDeallocResult::Done => {}
        SlabDeallocResult::FreeSlab { base, pages } => reclaims.push(base, pages),
        SlabDeallocResult::FreeSlabs(batch) => reclaims.extend_from(&batch),
    }
}

fn finish_slab_reclaims(reclaims: SlabFreeBatch) -> SlabDeallocResult {
    match reclaims.as_slice() {
        [] => SlabDeallocResult::Done,
        [(base, pages)] => SlabDeallocResult::FreeSlab {
            base: *base,
            pages: *pages,
        },
        _ => SlabDeallocResult::FreeSlabs(reclaims),
    }
}

impl<const PAGE_SIZE: usize> PerCpuSlab<PAGE_SIZE> {
    const fn new_uninit() -> Self {
        Self {
            cpu_id: None,
            magazines: core::cell::UnsafeCell::new([SizeClassMagazine::new(); NUM_SIZE_CLASSES]),
            inner: SpinRaw::new(SlabAllocator::new()),
        }
    }

    fn init_during_cpu_bringup(&mut self, cpu_id: usize) {
        let cpu_id = u16::try_from(cpu_id).expect("CPU id exceeds SLUB owner range");
        assert!(self.cpu_id.is_none(), "per-CPU SLUB is already initialized");
        self.cpu_id = Some(cpu_id);
        self.magazines = core::cell::UnsafeCell::new([SizeClassMagazine::new(); NUM_SIZE_CLASSES]);
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
        let Some(sc) = SizeClass::from_layout(layout) else {
            return Err(buddy_slab_allocator::AllocError::InvalidParam);
        };
        let sc_idx = sc.index();
        // SAFETY: NoPreemptIrqSave protects this per-CPU access against concurrent execution on the same core.
        let mag = unsafe { &mut (*self.magazines.get())[sc_idx] };

        if mag.count > 0 {
            mag.count -= 1;
            let addr = mag.objects[mag.count];
            let ptr = unsafe { NonNull::new_unchecked(addr as *mut u8) };
            return Ok(SlabAllocResult::Allocated(ptr));
        }

        let mut inner = self.inner.lock();
        let mut first_ptr = None;
        for i in 0..BATCH_SIZE {
            match inner.alloc(layout)? {
                SlabAllocResult::Allocated(ptr) => {
                    if i == 0 {
                        first_ptr = Some(ptr);
                    } else {
                        mag.objects[mag.count] = ptr.as_ptr() as usize;
                        mag.count += 1;
                    }
                }
                SlabAllocResult::NeedsSlab { size_class, pages } => {
                    if first_ptr.is_none() {
                        return Ok(SlabAllocResult::NeedsSlab { size_class, pages });
                    }
                    break;
                }
            }
        }
        Ok(SlabAllocResult::Allocated(first_ptr.unwrap()))
    }

    fn add_slab(&self, size_class: SizeClass, base: usize, bytes: usize) {
        self.inner
            .lock()
            .add_slab(size_class, base, bytes, self.cpu_id_checked());
    }

    fn dealloc_local(&self, ptr: NonNull<u8>, layout: Layout) -> SlabDeallocResult {
        let Some(sc) = SizeClass::from_layout(layout) else {
            return SlabDeallocResult::Done;
        };
        let sc_idx = sc.index();
        // SAFETY: NoPreemptIrqSave protects this per-CPU access against concurrent execution on the same core.
        let mag = unsafe { &mut (*self.magazines.get())[sc_idx] };

        if mag.count < MAGAZINE_CAP {
            mag.objects[mag.count] = ptr.as_ptr() as usize;
            mag.count += 1;
            return SlabDeallocResult::Done;
        }

        let mut inner = self.inner.lock();
        let mut reclaims = SlabFreeBatch::new();
        for _ in 0..BATCH_SIZE {
            mag.count -= 1;
            let p = unsafe { NonNull::new_unchecked(mag.objects[mag.count] as *mut u8) };
            collect_slab_reclaim(&mut reclaims, inner.dealloc(p, layout));
        }
        mag.objects[mag.count] = ptr.as_ptr() as usize;
        mag.count += 1;
        finish_slab_reclaims(reclaims)
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
        ACTIVE_CPU_COUNT.fetch_max(1, Ordering::Release);
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
            self.drain_all_pcp();
            result = self.alloc_once(layout);
            if matches!(result, Err(SlubAllocError::NoMemory)) {
                let reclaim_pages = layout
                    .size()
                    .div_ceil(PAGE_SIZE)
                    .max(MIN_PAGE_RECLAIM_BATCH);
                for _ in 0..4 {
                    let reclaimed = try_page_reclaim(reclaim_pages);
                    self.drain_all_pcp();
                    result = self.alloc_once(layout);
                    if result.is_ok() || reclaimed == 0 {
                        break;
                    }
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

    fn dealloc_batch_pages(&self, pages: &[usize]) {
        if pages.is_empty() {
            return;
        }
        let mut runs = [(0usize, 1usize); PCP_CAPACITY];
        for (i, &page) in pages.iter().enumerate() {
            runs[i] = (page, 1);
        }
        let _guard = NoPreemptIrqSave::new();
        self.inner.dealloc_pages_batch(&runs[..pages.len()]);
    }

    /// Drains all cached Order-0 pages across all initialized CPU PCP caches
    /// back into Buddy using batched deallocation.
    ///
    /// Never holds a PCP lock while acquiring Buddy locks, ensuring no deadlocks.
    pub fn drain_all_pcp(&self) -> usize {
        let active_cpus = ACTIVE_CPU_COUNT.load(Ordering::Acquire).max(1);
        let mut total_drained = 0;
        for cpu in 0..active_cpus {
            let mut drain_buf = [0usize; PCP_CAPACITY];
            let n = {
                let _guard = NoPreemptIrqSave::new();
                let pcp = unsafe { PERCPU_PCP.remote_ref_raw(cpu) };
                pcp.drain_all(&mut drain_buf)
            };
            if n > 0 {
                total_drained += n;
                self.dealloc_batch_pages(&drain_buf[..n]);
            }
        }
        total_drained
    }

    /// Returns the total number of free Order-0 pages currently cached
    /// across all initialized CPU PCP pools.
    pub fn total_pcp_cached_pages(&self) -> usize {
        let active_cpus = ACTIVE_CPU_COUNT.load(Ordering::Acquire).max(1);
        let mut total = 0;
        for cpu in 0..active_cpus {
            let _guard = NoPreemptIrqSave::new();
            let pcp = unsafe { PERCPU_PCP.remote_ref_raw(cpu) };
            total += pcp.count();
        }
        total
    }

    fn cache_refill_pages(&self, extra_pages: &[usize]) {
        if !extra_pages.is_empty() {
            let _guard = NoPreemptIrqSave::new();
            PERCPU_PCP.with_current(|pcp| {
                pcp.push_batch(extra_pages);
            });
        }
    }

    fn alloc_order0_pcp(&self) -> AllocResult<usize> {
        // 1. Fast path: try popping from current CPU's local PCP
        {
            let _guard = NoPreemptIrqSave::new();
            let popped = PERCPU_PCP.with_current(|pcp| pcp.pop());
            if let Some(page) = popped {
                return Ok(page);
            }
        }

        // 2. Cache miss: refill a batch under one Buddy lock acquisition
        let mut batch = [0usize; PCP_BATCH_SIZE];
        let mut allocated = {
            let _guard = NoPreemptIrqSave::new();
            self.inner.alloc_page_batch(&mut batch)
        };

        if allocated > 0 {
            let first_page = batch[0];
            self.cache_refill_pages(&batch[1..allocated]);
            return Ok(first_page);
        }

        // 3. Buddy was empty: drain all CPU caches and retry batch refill
        self.drain_all_pcp();
        allocated = {
            let _guard = NoPreemptIrqSave::new();
            self.inner.alloc_page_batch(&mut batch)
        };
        if allocated > 0 {
            let first_page = batch[0];
            self.cache_refill_pages(&batch[1..allocated]);
            return Ok(first_page);
        }

        // 4. Memory pressure: invoke reclaim callbacks and drain PCP before each retry
        for _ in 0..4 {
            let reclaimed = try_page_reclaim(MIN_PAGE_RECLAIM_BATCH);
            self.drain_all_pcp();
            allocated = {
                let _guard = NoPreemptIrqSave::new();
                self.inner.alloc_page_batch(&mut batch)
            };
            if allocated > 0 {
                let first_page = batch[0];
                self.cache_refill_pages(&batch[1..allocated]);
                return Ok(first_page);
            }
            if reclaimed == 0 {
                break;
            }
        }

        Err(AllocError::NoMemory)
    }

    fn alloc_pages_once(
        &self,
        num_pages: usize,
        align_pow2: usize,
    ) -> buddy_slab_allocator::AllocResult<usize> {
        let _guard = NoPreemptIrqSave::new();
        self.inner.alloc_pages(num_pages, align_pow2)
    }

    /// Allocates contiguous pages, routing ordinary Order-0 requests through
    /// the local PCP cache, and invoking global drain / registered reclaim on OOM.
    pub fn alloc_pages(&self, num_pages: usize, align_pow2: usize) -> AllocResult<usize> {
        if num_pages == 0 {
            return Err(AllocError::InvalidParam);
        }

        // Eligible single-page unconstrained allocation
        if num_pages == 1 && align_pow2 <= PAGE_SIZE {
            return self.alloc_order0_pcp();
        }

        // Higher-order or stricter alignment: bypass PCP directly to Buddy
        let mut result = self.alloc_pages_once(num_pages, align_pow2);
        if matches!(result, Err(SlubAllocError::NoMemory)) {
            self.drain_all_pcp();
            result = self.alloc_pages_once(num_pages, align_pow2);
            if matches!(result, Err(SlubAllocError::NoMemory)) {
                for _ in 0..4 {
                    let reclaimed = try_page_reclaim(num_pages.max(MIN_PAGE_RECLAIM_BATCH));
                    self.drain_all_pcp();
                    result = self.alloc_pages_once(num_pages, align_pow2);
                    if result.is_ok() || reclaimed == 0 {
                        break;
                    }
                }
            }
        }
        result.map_err(map_error)
    }

    /// Allocates contiguous pages whose physical address range stays below
    /// the 4 GiB DMA32 limit.
    pub fn alloc_pages_lowmem(&self, num_pages: usize, align_pow2: usize) -> AllocResult<usize> {
        let mut result = {
            let _guard = NoPreemptIrqSave::new();
            self.inner.alloc_pages_lowmem(num_pages, align_pow2)
        };
        if matches!(result, Err(SlubAllocError::NoMemory)) {
            self.drain_all_pcp();
            result = {
                let _guard = NoPreemptIrqSave::new();
                self.inner.alloc_pages_lowmem(num_pages, align_pow2)
            };
            if matches!(result, Err(SlubAllocError::NoMemory)) {
                for _ in 0..4 {
                    let reclaimed = try_page_reclaim(num_pages.max(MIN_PAGE_RECLAIM_BATCH));
                    self.drain_all_pcp();
                    result = {
                        let _guard = NoPreemptIrqSave::new();
                        self.inner.alloc_pages_lowmem(num_pages, align_pow2)
                    };
                    if result.is_ok() || reclaimed == 0 {
                        break;
                    }
                }
            }
        }
        result.map_err(map_error)
    }

    /// Allocates independent pages while acquiring the Buddy lock once.
    ///
    /// Preserves single-page Order-0 PCP caches for latency-critical paths.
    pub fn alloc_page_batch(&self, pages: &mut [usize]) -> usize {
        if pages.is_empty() {
            return 0;
        }

        let mut allocated = {
            let _guard = NoPreemptIrqSave::new();
            self.inner.alloc_page_batch(pages)
        };
        if allocated == 0 {
            self.drain_all_pcp();
            let _guard = NoPreemptIrqSave::new();
            allocated = self.inner.alloc_page_batch(pages);
        }
        if allocated == 0 {
            for _ in 0..4 {
                let reclaimed =
                    try_page_reclaim(pages.len().max(MIN_PAGE_RECLAIM_BATCH));
                self.drain_all_pcp();
                let _guard = NoPreemptIrqSave::new();
                allocated = self.inner.alloc_page_batch(pages);
                if allocated > 0 || reclaimed == 0 {
                    break;
                }
            }
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
            self.drain_all_pcp();
            result = self.alloc_pages_at_once(start, num_pages, align_pow2);
            if matches!(result, Err(SlubAllocError::NoMemory)) {
                for _ in 0..4 {
                    let reclaimed = try_page_reclaim(num_pages.max(MIN_PAGE_RECLAIM_BATCH));
                    self.drain_all_pcp();
                    result = self.alloc_pages_at_once(start, num_pages, align_pow2);
                    if result.is_ok() || reclaimed == 0 {
                        break;
                    }
                }
            }
        }
        result.map_err(map_error)
    }

    /// Returns pages to Buddy. Non-power-of-two ranges are freed exactly.
    pub fn dealloc_pages(&self, pos: usize, num_pages: usize) {
        if num_pages == 0 {
            return;
        }

        if num_pages == 1 && pos % PAGE_SIZE == 0 {
            let mut drain_buf = [0usize; PCP_BATCH_SIZE];
            let push_res = {
                let _guard = NoPreemptIrqSave::new();
                PERCPU_PCP.with_current(|pcp| pcp.push_or_drain(pos, &mut drain_buf))
            };

            match push_res {
                Ok(Some(n)) => {
                    self.dealloc_batch_pages(&drain_buf[..n]);
                    return;
                }
                Ok(None) => return,
                Err(unpushed) => {
                    let _guard = NoPreemptIrqSave::new();
                    self.inner.dealloc_pages(unpushed, 1);
                    return;
                }
            }
        }

        let _guard = NoPreemptIrqSave::new();
        self.inner.dealloc_pages(pos, num_pages);
    }

    /// Returns multiple page ranges to Buddy under a single preemption/interrupt
    /// guard and allocator lock acquisition.
    pub fn dealloc_pages_batch(&self, runs: &[(usize, usize)]) {
        if runs.is_empty() {
            return;
        }
        let _guard = NoPreemptIrqSave::new();
        self.inner.dealloc_pages_batch(runs);
    }

    /// Splits a contiguous allocation into independently releasable pages.
    pub fn split_allocated_pages(&self, pos: usize, num_pages: usize) -> AllocResult {
        let _guard = NoPreemptIrqSave::new();
        self.inner
            .split_allocated_pages(pos, num_pages)
            .map_err(map_error)
    }

    /// Returns backend page occupancy in bytes, excluding free pages cached in PCP.
    pub fn used_bytes(&self) -> usize {
        let allocated = {
            let _guard = NoPreemptIrqSave::new();
            self.inner.allocated_bytes()
        };
        let pcp_cached = self.total_pcp_cached_pages() * PAGE_SIZE;
        allocated.saturating_sub(pcp_cached)
    }

    /// Free memory is reported through [`available_pages`](Self::available_pages).
    pub const fn available_bytes(&self) -> usize {
        0
    }

    /// Returns backend page occupancy, excluding free frames held in CPU-local caches.
    pub fn used_pages(&self) -> usize {
        self.used_bytes() / PAGE_SIZE
    }

    /// Returns free Buddy pages plus all free Order-0 pages held in CPU-local caches.
    pub fn available_pages(&self) -> usize {
        let (managed, allocated) = {
            let _guard = NoPreemptIrqSave::new();
            (self.inner.managed_bytes(), self.inner.allocated_bytes())
        };
        let buddy_free = managed.saturating_sub(allocated) / PAGE_SIZE;
        buddy_free + self.total_pcp_cached_pages()
    }
}

unsafe impl GlobalAlloc for GlobalAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() >= LARGE_ALLOCATION_DIAGNOSTIC_THRESHOLD {
            // Capture and emit the return address before `GlobalAllocator::alloc`
            // can enter reclaim or take any locks. `addr2line` against the
            // matching kernel ELF resolves this address to the allocation site.
            warn!(
                "large_kernel_allocation_request: size={} align={} caller_ra={:#x}",
                layout.size(),
                layout.align(),
                allocation_callsite(),
            );
        }
        match GlobalAllocator::alloc(self, layout) {
            Ok(ptr) => ptr.as_ptr(),
            Err(_) => {
                // This path is reached only after the registered page-cache
                // reclaim hook has already run. Keep the allocator state in
                // the message so an on-board OOM can distinguish a genuinely
                // exhausted Buddy from an unexpectedly large transient
                // allocation.
                error!(
                    "SLUB+Buddy allocation failed after reclaim: size={} align={} \
                     requested_pages={} free_pages={} used_bytes={}",
                    layout.size(),
                    layout.align(),
                    layout.size().div_ceil(PAGE_SIZE),
                    self.available_pages(),
                    self.used_bytes(),
                );

                // GlobalAlloc is required to return null on allocation
                // failure. Infallible callers still invoke
                // `handle_alloc_error`, while fallible users such as
                // `Vec::try_reserve_exact` can return an error instead of
                // turning a recoverable I/O allocation failure into a kernel
                // panic.
                core::ptr::null_mut()
            }
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // This must be captured before Layout validation (or any other call):
        // `ra` is caller-saved on both supported architectures, so reading it
        // after a helper call would report that helper's return site instead of
        // the Vec/String growth site that entered `__rust_realloc`.
        let caller_ra = if new_size >= LARGE_ALLOCATION_DIAGNOSTIC_THRESHOLD {
            allocation_callsite()
        } else {
            0
        };
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return core::ptr::null_mut();
        };

        if caller_ra != 0 {
            // Implementing this trait method explicitly makes Rust's
            // `__rust_realloc` shim tail-call it. Consequently `ra` remains
            // the original Vec/String growth caller, rather than an address
            // inside the compiler-generated realloc shim.
            warn!(
                "large_kernel_reallocation_request: old_size={} new_size={} align={} \
                 caller_ra={:#x}",
                layout.size(),
                new_size,
                layout.align(),
                caller_ra,
            );
        }

        match GlobalAllocator::alloc(self, new_layout) {
            Ok(new_ptr) => {
                let new_ptr = new_ptr.as_ptr();
                let copy_size = layout.size().min(new_size);
                if copy_size != 0 {
                    // SAFETY: GlobalAlloc::realloc receives a valid old block;
                    // the replacement is allocated before the old block is
                    // released, so the two ranges cannot overlap.
                    unsafe { core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size) };
                }
                if let Some(old_ptr) = NonNull::new(ptr) {
                    GlobalAllocator::dealloc(self, old_ptr, layout);
                }
                new_ptr
            }
            Err(_) => {
                error!(
                    "SLUB+Buddy reallocation failed after reclaim: old_size={} new_size={} \
                     align={} requested_pages={} free_pages={} used_bytes={}",
                    layout.size(),
                    new_size,
                    layout.align(),
                    new_size.div_ceil(PAGE_SIZE),
                    self.available_pages(),
                    self.used_bytes(),
                );
                // realloc must leave the old allocation live on failure.
                core::ptr::null_mut()
            }
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

/// Initializes the current CPU's SLUB and Order-0 PCP cache during CPU bring-up.
pub fn init_percpu_slab(cpu_id: usize) {
    let _guard = NoPreemptIrqSave::new();
    PERCPU_SLAB.with_current(|slab| slab.init_during_cpu_bringup(cpu_id));
    PERCPU_PCP.with_current(|pcp| pcp.init_during_cpu_bringup());
    ACTIVE_CPU_COUNT.fetch_max(cpu_id + 1, Ordering::Release);
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

/// Runs in-kernel verification of the Per-CPU Order-0 page cache (PCP).
pub fn run_pcp_guest_checks() -> Result<(), &'static str> {
    info!("[PCP_GUEST] Starting Per-CPU Order-0 PCP cache & watermark checks...");

    let alloc = global_allocator();

    // 0. Initial baseline drain to start with a clean known PCP state
    alloc.drain_all_pcp();
    assert_eq!(alloc.total_pcp_cached_pages(), 0);

    let avail_init = alloc.available_pages();
    let used_init = alloc.used_pages();

    // 1. Order-0 empty-cache refill:
    // Allocating 1 page from an empty PCP should trigger a batch refill of PCP_BATCH_SIZE (16).
    // 1 page is returned to caller, 15 remain cached in the current CPU's PCP.
    let p1 = alloc.alloc_pages(1, PAGE_SIZE).map_err(|_| "alloc p1 failed")?;
    assert_eq!(alloc.used_pages(), used_init + 1);
    assert_eq!(alloc.available_pages(), avail_init - 1);
    assert_eq!(alloc.total_pcp_cached_pages(), PCP_BATCH_SIZE - 1);
    info!("[PCP_GUEST] Order-0 empty-cache refill & accounting: PASS");

    // 2. Local PCP cache hits:
    // The next 15 single-page allocations must come directly from local PCP without Buddy refill.
    let mut pages = [0usize; PCP_BATCH_SIZE - 1];
    for i in 0..pages.len() {
        pages[i] = alloc.alloc_pages(1, PAGE_SIZE).map_err(|_| "alloc page failed")?;
    }
    assert_eq!(alloc.total_pcp_cached_pages(), 0);
    assert_eq!(alloc.used_pages(), used_init + PCP_BATCH_SIZE);
    assert_eq!(alloc.available_pages(), avail_init - PCP_BATCH_SIZE);
    info!("[PCP_GUEST] Single-page cache hits: PASS");

    // 3. Free back to local PCP:
    // Freeing single pages pushes them onto the local PCP until the high watermark.
    alloc.dealloc_pages(p1, 1);
    assert_eq!(alloc.total_pcp_cached_pages(), 1);
    assert_eq!(alloc.used_pages(), used_init + PCP_BATCH_SIZE - 1);
    assert_eq!(alloc.available_pages(), avail_init - PCP_BATCH_SIZE + 1);

    for &p in &pages {
        alloc.dealloc_pages(p, 1);
    }
    assert_eq!(alloc.total_pcp_cached_pages(), PCP_BATCH_SIZE);
    assert_eq!(alloc.used_pages(), used_init);
    assert_eq!(alloc.available_pages(), avail_init);

    // Now allocate up to 50 pages and free them to trigger the high watermark drain (48).
    let mut fill_pages = [0usize; 50];
    for i in 0..50 {
        fill_pages[i] = alloc.alloc_pages(1, PAGE_SIZE).map_err(|_| "fill alloc failed")?;
    }
    assert_eq!(alloc.used_pages(), used_init + 50);

    // Free 50 pages sequentially.
    // When count reaches 48, freeing one more page drains a batch of 16 to Buddy.
    for &p in &fill_pages {
        alloc.dealloc_pages(p, 1);
    }
    assert_eq!(alloc.used_pages(), used_init);
    assert_eq!(alloc.available_pages(), avail_init);
    // 50 pages freed into PCP: at watermark 48, 16 was drained, leaving 32 + remaining 2 = 34 cached pages.
    assert!(alloc.total_pcp_cached_pages() > 0 && alloc.total_pcp_cached_pages() < PCP_CAPACITY);
    info!("[PCP_GUEST] Free to local PCP & high-watermark batch drain: PASS");

    // 4. Higher-order and lowmem requests bypass PCP
    let h1 = alloc.alloc_pages(2, PAGE_SIZE).map_err(|_| "higher order alloc failed")?;
    assert_eq!(alloc.used_pages(), used_init + 2);
    alloc.dealloc_pages(h1, 2);
    assert_eq!(alloc.used_pages(), used_init);

    let lm = alloc.alloc_pages_lowmem(1, PAGE_SIZE).map_err(|_| "lowmem alloc failed")?;
    assert_eq!(alloc.used_pages(), used_init + 1);
    // Physical address must be under 4 GiB
    let paddr = axplat::mem::virt_to_phys(lm.into()).as_usize();
    assert!(paddr < 0x1_0000_0000, "lowmem paddr must be below 4 GiB");
    alloc.dealloc_pages(lm, 1);
    assert_eq!(alloc.used_pages(), used_init);
    info!("[PCP_GUEST] Higher-order and lowmem bypass: PASS");

    // 5. Cross-CPU global drain
    let active_cpus = ACTIVE_CPU_COUNT.load(Ordering::Acquire);
    info!("[PCP_GUEST] Active CPU count: {}", active_cpus);
    if active_cpus > 1 {
        // Prime remote CPU cache (CPU 1) and verify remote drain
        let test_page = alloc
            .alloc_pages(1, PAGE_SIZE)
            .map_err(|_| "alloc remote test page failed")?;
        let _guard = NoPreemptIrqSave::new();
        let remote_pcp = unsafe { PERCPU_PCP.remote_ref_raw(1) };
        let pushed = remote_pcp.push_batch(&[test_page]);
        assert_eq!(pushed, 1, "remote pcp push_batch must succeed");
    }
    let cached_before = alloc.total_pcp_cached_pages();
    assert!(cached_before > 0);
    let drained = alloc.drain_all_pcp();
    assert_eq!(drained, cached_before);
    assert_eq!(alloc.total_pcp_cached_pages(), 0);
    assert_eq!(alloc.used_pages(), used_init);
    assert_eq!(alloc.available_pages(), avail_init);
    info!("[PCP_GUEST] Cross-CPU global drain: PASS");

    // 6. Batch API: alloc_page_batch & dealloc_pages_batch
    let mut batch = [0usize; 8];
    let allocated = alloc.alloc_page_batch(&mut batch);
    assert_eq!(allocated, 8);
    assert_eq!(alloc.used_pages(), used_init + 8);

    let mut runs = [(0usize, 1usize); 8];
    for i in 0..8 {
        runs[i] = (batch[i], 1);
    }
    alloc.dealloc_pages_batch(&runs);
    assert_eq!(alloc.used_pages(), used_init);
    assert_eq!(alloc.available_pages(), avail_init);
    info!("[PCP_GUEST] Batch allocation & deallocation: PASS");

    info!("[PCP_GUEST] All PCP cache & watermark checks PASSED!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SlabDeallocResult, SlabFreeBatch, collect_slab_reclaim, finish_slab_reclaims};

    #[test]
    fn batch_flush_preserves_every_reclaimed_slab() {
        let mut reclaims = SlabFreeBatch::new();
        collect_slab_reclaim(
            &mut reclaims,
            SlabDeallocResult::FreeSlab {
                base: 0x1000,
                pages: 1,
            },
        );
        collect_slab_reclaim(
            &mut reclaims,
            SlabDeallocResult::FreeSlab {
                base: 0x4000,
                pages: 2,
            },
        );

        match finish_slab_reclaims(reclaims) {
            SlabDeallocResult::FreeSlabs(batch) => {
                assert_eq!(batch.as_slice(), &[(0x1000, 1), (0x4000, 2)]);
            }
            _ => panic!("multiple reclaimed slabs must not be collapsed to one"),
        }
    }
}
