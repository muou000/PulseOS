//! Per-CPU local magazine caches for small-object heap allocations.
//!
//! This module provides lock-free per-CPU caches (magazines) for small objects
//! (size <= 2048 bytes). It significantly reduces global spinlock contention
//! on `GlobalAllocator::balloc` during high-concurrency workloads on SMP systems.

use core::{
    alloc::Layout,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

use allocator::AllocResult;
use kernel_guard::NoPreemptIrqSave;

/// Flag indicating whether per-CPU caches are initialized and ready to use.
static PERCPU_CACHE_READY: AtomicBool = AtomicBool::new(false);

/// Enables per-CPU local caches.
pub(crate) fn enable_percpu_cache() {
    PERCPU_CACHE_READY.store(true, Ordering::Release);
    info!("Per-CPU local magazine memory cache enabled for small objects (<= 2048 B).");
}

/// Returns whether per-CPU caches are currently enabled and ready.
#[inline]
pub fn is_percpu_cache_enabled() -> bool {
    PERCPU_CACHE_READY.load(Ordering::Acquire)
}

/// Maximum object size supported by per-CPU local caches.
pub const MAX_SLAB_OBJECT_SIZE: usize = 2048;

/// Number of size classes (8, 16, 32, 64, 128, 256, 512, 1024, 2048 bytes).
pub const NUM_SIZE_CLASSES: usize = 9;

/// Maximum capacity of a per-CPU magazine for a size class.
pub const MAGAZINE_CAPACITY: usize = 32;

/// Number of objects transferred in a single batch refill/drain.
pub const BATCH_SIZE: usize = 16;

/// Returns the size class index for a given requested layout, or `None` if ineligible.
#[inline]
pub const fn get_size_class_index(layout: &Layout) -> Option<usize> {
    let size = layout.size();
    if size == 0 || size > MAX_SLAB_OBJECT_SIZE {
        return None;
    }
    let idx = if size <= 8 {
        0
    } else if size <= 16 {
        1
    } else if size <= 32 {
        2
    } else if size <= 64 {
        3
    } else if size <= 128 {
        4
    } else if size <= 256 {
        5
    } else if size <= 512 {
        6
    } else if size <= 1024 {
        7
    } else {
        8
    };

    let sc_bytes = 8 << idx;
    if layout.align() <= sc_bytes {
        Some(idx)
    } else {
        None
    }
}

/// Returns the object byte size for the given size class index.
#[inline]
pub const fn size_class_bytes(idx: usize) -> usize {
    8 << idx
}

/// A fixed-capacity magazine for storing pre-allocated object pointers of a single size class.
pub struct SizeClassMagazine {
    objects: [usize; MAGAZINE_CAPACITY],
    count: usize,
}

impl SizeClassMagazine {
    pub const fn new() -> Self {
        Self {
            objects: [0; MAGAZINE_CAPACITY],
            count: 0,
        }
    }

    /// Pops an object pointer from the magazine, if available.
    #[inline]
    pub fn pop(&mut self) -> Option<NonNull<u8>> {
        if self.count > 0 {
            self.count -= 1;
            NonNull::new(self.objects[self.count] as *mut u8)
        } else {
            None
        }
    }

    /// Pushes an object pointer into the magazine if space is available.
    /// Returns `true` on success, or `false` if the magazine is full.
    #[inline]
    pub fn push(&mut self, ptr: NonNull<u8>) -> bool {
        if self.count < MAGAZINE_CAPACITY {
            self.objects[self.count] = ptr.as_ptr() as usize;
            self.count += 1;
            true
        } else {
            false
        }
    }

    /// Returns the number of objects currently in the magazine.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }
}

/// Per-CPU array of magazines, one for each size class.
pub struct PerCpuCaches {
    magazines: [SizeClassMagazine; NUM_SIZE_CLASSES],
}

impl PerCpuCaches {
    pub const fn new() -> Self {
        const INIT_MAGAZINE: SizeClassMagazine = SizeClassMagazine::new();
        Self {
            magazines: [INIT_MAGAZINE; NUM_SIZE_CLASSES],
        }
    }

    /// Attempts to allocate an object of the given size class from the local magazine.
    /// If empty, calls `refill_fn` to fetch a batch of objects from the global allocator.
    pub fn alloc<F>(&mut self, sc_idx: usize, refill_fn: F) -> AllocResult<NonNull<u8>>
    where
        F: FnOnce(&mut SizeClassMagazine) -> AllocResult<NonNull<u8>>,
    {
        let mag = &mut self.magazines[sc_idx];
        if let Some(ptr) = mag.pop() {
            Ok(ptr)
        } else {
            refill_fn(mag)
        }
    }

    /// Attempts to deallocate an object of the given size class back into the local magazine.
    /// If full, calls `drain_fn` to return a batch of objects to the global allocator.
    pub fn dealloc<F>(&mut self, sc_idx: usize, ptr: NonNull<u8>, drain_fn: F)
    where
        F: FnOnce(&mut SizeClassMagazine),
    {
        let mag = &mut self.magazines[sc_idx];
        if !mag.push(ptr) {
            drain_fn(mag);
            let pushed = mag.push(ptr);
            debug_assert!(pushed, "push after drain must succeed");
        }
    }
}

#[percpu::def_percpu]
static PERCPU_CACHES: PerCpuCaches = PerCpuCaches::new();

/// Allocates an object using the Per-CPU magazine cache if eligible and enabled.
///
/// Returns `Ok(Some(ptr))` if handled by local magazine or batch refill,
/// or `Ok(None)` if ineligible / cache disabled.
pub fn try_alloc<F>(layout: &Layout, refill_batch_fn: F) -> AllocResult<Option<NonNull<u8>>>
where
    F: FnOnce(usize, &mut SizeClassMagazine) -> AllocResult<NonNull<u8>>,
{
    if !is_percpu_cache_enabled() {
        return Ok(None);
    }

    let Some(sc_idx) = get_size_class_index(layout) else {
        return Ok(None);
    };

    // `with_current` prevents migration but does not prevent an interrupt from
    // re-entering the allocator and mutating the same magazine.
    let _guard = NoPreemptIrqSave::new();
    let res = PERCPU_CACHES
        .with_current(|caches| caches.alloc(sc_idx, |mag| refill_batch_fn(sc_idx, mag)));

    res.map(Some)
}

/// Deallocates an object back to the Per-CPU magazine cache if eligible and enabled.
///
/// Returns `true` if handled by local magazine or batch drain, `false` otherwise.
pub fn try_dealloc<F>(ptr: NonNull<u8>, layout: &Layout, drain_batch_fn: F) -> bool
where
    F: FnOnce(usize, &mut SizeClassMagazine),
{
    if !is_percpu_cache_enabled() {
        return false;
    }

    let Some(sc_idx) = get_size_class_index(layout) else {
        return false;
    };

    let _guard = NoPreemptIrqSave::new();
    PERCPU_CACHES.with_current(|caches| {
        caches.dealloc(sc_idx, ptr, |mag| drain_batch_fn(sc_idx, mag));
    });

    true
}
