//! # buddy-slab-allocator
//!
//! A `#![no_std]` memory allocator featuring:
//!
//! - **Buddy page allocator** — page-metadata-based with intrusive free lists
//! - **Slab allocator** — bitmap-based with lock-free cross-CPU freeing (Linux SLUB inspired)
//! - **Global allocator** — composes buddy + per-CPU slab, implements [`core::alloc::GlobalAlloc`]
//!
//! Both buddy and slab allocators can be used standalone.

#![no_std]

mod error;
pub use error::{AllocError, AllocResult};

pub mod buddy;
pub use buddy::{BuddyAllocator, ManagedSection};

pub mod slab;
pub use slab::{
    PerCpuSlab, SizeClass, SlabAllocResult, SlabAllocator, SlabDeallocResult, SlabFreeBatch,
    SlabPoolDeallocResult, SlabPoolTrait, SlabTrait, StaticSlabPool,
};

pub mod global;
#[doc(hidden)]
pub use global::__reset_global_allocator_singleton_for_tests;
pub use global::GlobalAllocator;

/// External interface items supplied by the platform / allocator integrator.
pub mod eii {
    /// Platform callbacks required by the combined allocator.
    #[crate_interface::def_interface]
    pub trait AllocatorIf {
        /// Translate a direct-mapped virtual address to a physical address.
        fn virt_to_phys(vaddr: usize) -> usize;

        /// Return the system-global per-CPU slab pool.
        fn slab_pool() -> &'static dyn crate::SlabPoolTrait;
    }

    /// Translate a virtual address to a physical address.
    pub fn virt_to_phys(vaddr: usize) -> usize {
        crate_interface::call_interface!(AllocatorIf::virt_to_phys, vaddr)
    }

    /// Return the system-global slab pool.
    pub fn slab_pool() -> &'static dyn crate::SlabPoolTrait {
        crate_interface::call_interface!(AllocatorIf::slab_pool)
    }
}

// ---------------------------------------------------------------------------
// Utility helpers (crate-internal)
// ---------------------------------------------------------------------------

#[inline]
pub(crate) const fn align_up(pos: usize, align: usize) -> usize {
    (pos + align - 1) & !(align - 1)
}

#[inline]
pub(crate) const fn is_aligned(addr: usize, align: usize) -> bool {
    addr & (align - 1) == 0
}

#[cfg(test)]
mod test_eii_impls {
    use core::{alloc::Layout, ptr::NonNull};

    use super::{
        AllocError, AllocResult, SizeClass, SlabAllocResult, SlabPoolTrait, SlabTrait,
        eii::AllocatorIf,
    };

    struct NullSlabPool;
    struct NullSlab;

    impl SlabTrait for NullSlab {
        fn cpu_id(&self) -> usize {
            0
        }

        fn page_size(&self) -> usize {
            0x1000
        }

        fn alloc(&self, _layout: Layout) -> AllocResult<SlabAllocResult> {
            Err(AllocError::NotInitialized)
        }

        fn add_slab(&self, _size_class: SizeClass, _base: usize, _bytes: usize) {}

        fn dealloc_local(&self, _ptr: NonNull<u8>, _layout: Layout) -> super::SlabDeallocResult {
            super::SlabDeallocResult::Done
        }
    }

    static NULL_SLAB: NullSlab = NullSlab;

    impl SlabPoolTrait for NullSlabPool {
        fn current_slab(&self) -> &dyn SlabTrait {
            &NULL_SLAB
        }

        fn owner_slab(&self, _cpu_idx: usize) -> &dyn SlabTrait {
            &NULL_SLAB
        }
    }

    static NULL_SLAB_POOL: NullSlabPool = NullSlabPool;

    struct AllocatorIfImpl;

    #[crate_interface::impl_interface]
    impl AllocatorIf for AllocatorIfImpl {
        fn virt_to_phys(vaddr: usize) -> usize {
            vaddr
        }

        fn slab_pool() -> &'static dyn SlabPoolTrait {
            &NULL_SLAB_POOL
        }
    }
}
