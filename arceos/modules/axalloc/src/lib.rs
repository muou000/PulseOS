//! [ArceOS](https://github.com/arceos-org/arceos) global memory allocator.
//!
//! It provides [`GlobalAllocator`], which implements the trait
//! [`core::alloc::GlobalAlloc`]. A static global variable of type
//! [`GlobalAllocator`] is defined with the `#[global_allocator]` attribute, to
//! be registered as the standard library’s default allocator.

#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;

#[cfg(feature = "slab")]
mod buddy_slab;
mod frameinfo;
mod page;
#[cfg(not(feature = "slab"))]
pub mod percpu_cache;

#[cfg(not(feature = "slab"))]
use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::NonNull,
};

#[cfg(not(feature = "slab"))]
use allocator::{AllocResult, BaseAllocator, BitmapPageAllocator, ByteAllocator, PageAllocator};
#[cfg(feature = "slab")]
pub use buddy_slab::{
    GlobalAllocator, global_add_memory, global_allocator, global_init, init_percpu_slab,
};
pub use frameinfo::{FrameTable, frame_table, init_frame_table};
use kspin::SpinNoIrq;

pub(crate) const PAGE_SIZE: usize = 0x1000;
#[cfg(not(feature = "slab"))]
const MIN_HEAP_SIZE: usize = 0x200000; // 2 MB
pub(crate) const MIN_PAGE_RECLAIM_BATCH: usize = 256;

pub use page::GlobalPage;

/// A function that tries to reclaim physical pages (e.g. by evicting
/// clean file-backed page cache pages). Returns the number of pages freed.
pub type PageReclaimFn = fn(num_pages: usize) -> usize;

static PAGE_RECLAIM_FN: SpinNoIrq<Option<PageReclaimFn>> = SpinNoIrq::new(None);

/// Register a callback that the allocator will invoke when a page allocation
/// cannot be satisfied.
pub fn register_page_reclaim_fn(f: PageReclaimFn) {
    *PAGE_RECLAIM_FN.lock() = Some(f);
}

/// Try to reclaim physical pages by invoking the registered callback.
/// Returns the number of pages actually freed.
pub fn try_page_reclaim(num_pages: usize) -> usize {
    let reclaim_fn = { *PAGE_RECLAIM_FN.lock() };
    reclaim_fn.map_or(0, |f| f(num_pages))
}

#[cfg(not(feature = "slab"))]
cfg_if::cfg_if! {
    if #[cfg(feature = "buddy")] {
        /// The default byte allocator.
        pub type DefaultByteAllocator = allocator::BuddyByteAllocator;
    } else if #[cfg(feature = "tlsf")] {
        /// The default byte allocator.
        pub type DefaultByteAllocator = allocator::TlsfByteAllocator;
    }
}

/// The global allocator used by ArceOS.
///
/// It combines a [`ByteAllocator`] and a [`PageAllocator`] into a simple
/// two-level allocator: firstly tries allocate from the byte allocator, if
/// there is no memory, asks the page allocator for more memory and adds it to
/// the byte allocator.
///
/// The concrete byte and page backends are selected through Cargo features.
#[cfg(not(feature = "slab"))]
pub struct GlobalAllocator {
    balloc: SpinNoIrq<DefaultByteAllocator>,
    palloc: SpinNoIrq<BitmapPageAllocator<PAGE_SIZE>>,
}

#[cfg(not(feature = "slab"))]
impl GlobalAllocator {
    /// Creates an empty [`GlobalAllocator`].
    pub const fn new() -> Self {
        Self {
            balloc: SpinNoIrq::new(DefaultByteAllocator::new()),
            palloc: SpinNoIrq::new(BitmapPageAllocator::new()),
        }
    }

    /// Returns the name of the allocator.
    pub const fn name(&self) -> &'static str {
        cfg_if::cfg_if! {
            if #[cfg(feature = "buddy")] {
                "buddy"
            } else if #[cfg(feature = "tlsf")] {
                "TLSF"
            }
        }
    }

    /// Initializes the allocator with the given region.
    ///
    /// It firstly adds the whole region to the page allocator, then allocates
    /// a small region (32 KB) to initialize the byte allocator. Therefore,
    /// the given region must be larger than 32 KB.
    pub fn init(&self, start_vaddr: usize, size: usize) {
        assert!(size > MIN_HEAP_SIZE);
        let init_heap_size = MIN_HEAP_SIZE;
        self.palloc.lock().init(start_vaddr, size);
        let heap_ptr = self
            .alloc_pages(init_heap_size / PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        self.balloc.lock().init(heap_ptr, init_heap_size);
        percpu_cache::enable_percpu_cache();
    }

    /// Add the given region to the allocator.
    ///
    /// It will add the whole region to the byte allocator.
    pub fn add_memory(&self, start_vaddr: usize, size: usize) -> AllocResult {
        self.balloc.lock().add_memory(start_vaddr, size)
    }

    fn expand_heap(&self, layout: Layout) -> AllocResult {
        let old_size = self.balloc.lock().total_bytes();
        let mut target_expand_size = old_size
            .max(layout.size())
            .next_power_of_two()
            .max(PAGE_SIZE);

        const MAX_EXPAND_SIZE: usize = 8 * 1024 * 1024; // 8 MB
        if target_expand_size > MAX_EXPAND_SIZE {
            let required_size = layout.size().saturating_mul(2).next_power_of_two();
            target_expand_size = required_size.max(MAX_EXPAND_SIZE);
        }

        let min_expand_size = layout.size().next_power_of_two().max(PAGE_SIZE);
        let mut expand_size = target_expand_size;
        let mut heap_ptr_res = Err(allocator::AllocError::NoMemory);

        while expand_size >= min_expand_size {
            match self.alloc_pages(expand_size / PAGE_SIZE, PAGE_SIZE) {
                Ok(ptr) => {
                    heap_ptr_res = Ok((ptr, expand_size));
                    break;
                }
                Err(_) => {
                    if expand_size == min_expand_size {
                        break;
                    }
                    expand_size = (expand_size / 2).max(min_expand_size);
                }
            }
        }

        let (heap_ptr, actual_expand_size) = heap_ptr_res?;
        debug!(
            "expand heap memory: [{:#x}, {:#x})",
            heap_ptr,
            heap_ptr + actual_expand_size
        );
        let result = self.balloc.lock().add_memory(heap_ptr, actual_expand_size);
        if result.is_err() {
            self.dealloc_pages(heap_ptr, actual_expand_size / PAGE_SIZE);
        }
        result
    }

    /// Allocate arbitrary number of bytes. Returns the left bound of the
    /// allocated region.
    ///
    /// It firstly tries to allocate from the per-CPU magazine cache (if eligible),
    /// then from the byte allocator. If there is no memory, it asks the page
    /// allocator for more memory and adds it to the byte allocator.
    pub fn alloc(&self, layout: Layout) -> AllocResult<NonNull<u8>> {
        // Keep heap expansion outside the IRQ-disabled magazine critical
        // section so reclaim callbacks can never re-enter the same cache.
        loop {
            match percpu_cache::try_alloc(&layout, |sc_idx, mag| {
                let sc_bytes = percpu_cache::size_class_bytes(sc_idx);
                let fill_layout = Layout::from_size_align(sc_bytes, sc_bytes).unwrap();
                let mut balloc = self.balloc.lock();
                let first_ptr = balloc.alloc(fill_layout)?;
                for _ in 1..percpu_cache::BATCH_SIZE {
                    if let Ok(extra_ptr) = balloc.alloc(fill_layout) {
                        if !mag.push(extra_ptr) {
                            balloc.dealloc(extra_ptr, fill_layout);
                            break;
                        }
                    } else {
                        break;
                    }
                }
                Ok(first_ptr)
            }) {
                Ok(Some(ptr)) => return Ok(ptr),
                Ok(None) => break,
                Err(err) => {
                    let Some(sc_idx) = percpu_cache::get_size_class_index(&layout) else {
                        return Err(err);
                    };
                    let sc_bytes = percpu_cache::size_class_bytes(sc_idx);
                    let fill_layout = Layout::from_size_align(sc_bytes, sc_bytes).unwrap();
                    self.expand_heap(fill_layout)?;
                }
            }
        }

        // Slow-path: allocate directly from the byte allocator
        loop {
            if let Ok(ptr) = self.balloc.lock().alloc(layout) {
                return Ok(ptr);
            }
            self.expand_heap(layout)?;
        }
    }

    /// Gives back the allocated region to the byte allocator.
    ///
    /// The region should be allocated by [`alloc`], and `align_pow2` should be
    /// the same as the one used in [`alloc`]. Otherwise, the behavior is
    /// undefined.
    ///
    /// [`alloc`]: GlobalAllocator::alloc
    pub fn dealloc(&self, pos: NonNull<u8>, layout: Layout) {
        // Fast-path: try per-CPU local magazine cache
        if percpu_cache::try_dealloc(pos, &layout, |sc_idx, mag| {
            let sc_bytes = percpu_cache::size_class_bytes(sc_idx);
            let drain_layout = Layout::from_size_align(sc_bytes, sc_bytes).unwrap();
            let mut balloc = self.balloc.lock();

            for _ in 0..percpu_cache::BATCH_SIZE {
                if let Some(obj_ptr) = mag.pop() {
                    balloc.dealloc(obj_ptr, drain_layout);
                } else {
                    break;
                }
            }
        }) {
            return;
        }

        self.balloc.lock().dealloc(pos, layout);
    }

    /// Allocates contiguous pages.
    ///
    /// It allocates `num_pages` pages from the page allocator.
    ///
    /// `align_pow2` must be a power of 2, and the returned region bound will be
    /// aligned to it.
    pub fn alloc_pages(&self, num_pages: usize, align_pow2: usize) -> AllocResult<usize> {
        let mut result = self.palloc.lock().alloc_pages(num_pages, align_pow2);
        if result.is_err() {
            for _ in 0..4 {
                try_page_reclaim(num_pages.max(MIN_PAGE_RECLAIM_BATCH));
                result = self.palloc.lock().alloc_pages(num_pages, align_pow2);
                if result.is_ok() {
                    break;
                }
            }
        }
        result
    }

    /// Allocates contiguous pages for a DMA32 device.
    ///
    /// The bitmap/page allocator configuration has no low-memory zone. The
    /// DMA API still validates the returned physical range against the
    /// device mask and releases an out-of-mask allocation, so this fallback
    /// remains memory-safe for configurations with <=4 GiB RAM.
    pub fn alloc_pages_lowmem(&self, num_pages: usize, align_pow2: usize) -> AllocResult<usize> {
        self.alloc_pages(num_pages, align_pow2)
    }

    /// Allocates independent 4K pages while holding the page allocator lock once.
    ///
    /// Returns the number of initialized entries in `pages`. A short allocation
    /// indicates that the allocator ran out of pages.
    pub fn alloc_page_batch(&self, pages: &mut [usize]) -> usize {
        if pages.is_empty() {
            return 0;
        }

        let mut allocated = {
            let mut palloc = self.palloc.lock();
            let mut allocated = 0;
            for page in pages.iter_mut() {
                let Ok(pos) = palloc.alloc_pages(1, PAGE_SIZE) else {
                    break;
                };
                *page = pos;
                allocated += 1;
            }
            allocated
        };

        // The batched fast path must not bypass the allocator's reclaim hook.
        // Allocate one page through alloc_pages() to trigger reclaim, then fill
        // the rest while holding the page-allocator lock only once again.
        if allocated == 0 {
            let Ok(pos) = self.alloc_pages(1, PAGE_SIZE) else {
                return 0;
            };
            pages[0] = pos;
            allocated = 1;

            let mut palloc = self.palloc.lock();
            for page in &mut pages[1..] {
                let Ok(pos) = palloc.alloc_pages(1, PAGE_SIZE) else {
                    break;
                };
                *page = pos;
                allocated += 1;
            }
        }
        allocated
    }

    /// Allocates contiguous pages starting from the given address.
    ///
    /// It allocates `num_pages` pages from the page allocator starting from the
    /// given address.
    ///
    /// `align_pow2` must be a power of 2, and the returned region bound will be
    /// aligned to it.
    pub fn alloc_pages_at(
        &self,
        start: usize,
        num_pages: usize,
        align_pow2: usize,
    ) -> AllocResult<usize> {
        let mut result = self
            .palloc
            .lock()
            .alloc_pages_at(start, num_pages, align_pow2);
        if result.is_err() {
            for _ in 0..4 {
                let reclaimed = try_page_reclaim(num_pages.max(16));
                result = self
                    .palloc
                    .lock()
                    .alloc_pages_at(start, num_pages, align_pow2);
                if result.is_ok() || reclaimed == 0 {
                    break;
                }
            }
        }
        result
    }

    /// Gives back the allocated pages starts from `pos` to the page allocator.
    ///
    /// The pages should be allocated by [`alloc_pages`], and `align_pow2`
    /// should be the same as the one used in [`alloc_pages`]. Otherwise, the
    /// behavior is undefined.
    ///
    /// [`alloc_pages`]: GlobalAllocator::alloc_pages
    pub fn dealloc_pages(&self, pos: usize, num_pages: usize) {
        self.palloc.lock().dealloc_pages(pos, num_pages)
    }

    /// Bitmap allocations already track each page independently, so converting
    /// a contiguous range requires no metadata update.
    pub fn split_allocated_pages(&self, pos: usize, num_pages: usize) -> AllocResult {
        if num_pages == 0 || pos % PAGE_SIZE != 0 {
            Err(allocator::AllocError::InvalidParam)
        } else {
            Ok(())
        }
    }

    /// Returns the number of allocated bytes in the byte allocator.
    pub fn used_bytes(&self) -> usize {
        self.balloc.lock().used_bytes()
    }

    /// Returns the number of available bytes in the byte allocator.
    pub fn available_bytes(&self) -> usize {
        self.balloc.lock().available_bytes()
    }

    /// Returns the number of allocated pages in the page allocator.
    pub fn used_pages(&self) -> usize {
        self.palloc.lock().used_pages()
    }

    /// Returns the number of available pages in the page allocator.
    pub fn available_pages(&self) -> usize {
        self.palloc.lock().available_pages()
    }
}

#[cfg(not(feature = "slab"))]
unsafe impl GlobalAlloc for GlobalAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if let Ok(ptr) = GlobalAllocator::alloc(self, layout) {
            ptr.as_ptr()
        } else {
            alloc::alloc::handle_alloc_error(layout)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        GlobalAllocator::dealloc(self, NonNull::new(ptr).expect("dealloc null ptr"), layout)
    }
}

#[cfg_attr(all(target_os = "none", not(test)), global_allocator)]
#[cfg(not(feature = "slab"))]
static GLOBAL_ALLOCATOR: GlobalAllocator = GlobalAllocator::new();

/// Returns the reference to the global allocator.
#[cfg(not(feature = "slab"))]
pub fn global_allocator() -> &'static GlobalAllocator {
    &GLOBAL_ALLOCATOR
}

/// Initializes the global allocator with the given memory region.
///
/// The page allocator may store intrusive metadata in free pages. The region
/// must therefore be mapped, writable, and unused by any other subsystem.
///
/// This function should be called only once, and before any allocation.
#[cfg(not(feature = "slab"))]
pub fn global_init(start_vaddr: usize, size: usize) {
    debug!(
        "initialize global allocator at: [{:#x}, {:#x})",
        start_vaddr,
        start_vaddr + size
    );
    GLOBAL_ALLOCATOR.init(start_vaddr, size);
}

/// Add the given memory region to the global allocator.
///
/// Users should ensure that the region is valid and not being used by others,
/// so that the allocated memory is also valid.
///
/// It's similar to [`global_init`], but can be called multiple times.
#[cfg(not(feature = "slab"))]
pub fn global_add_memory(start_vaddr: usize, size: usize) -> AllocResult {
    debug!(
        "add a memory region to global allocator: [{:#x}, {:#x})",
        start_vaddr,
        start_vaddr + size
    );
    GLOBAL_ALLOCATOR.add_memory(start_vaddr, size)
}

/// No per-CPU allocator state is required by legacy byte allocators.
#[cfg(not(feature = "slab"))]
pub fn init_percpu_slab(_cpu_id: usize) {}
