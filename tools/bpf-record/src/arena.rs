//! Bounded reusable storage for the guest recorder's process-lifetime arena.
//!
//! The intentionally selected `buddy_system_allocator` 0.10.0 owns free-list
//! operations and disjoint block splitting/coalescing. This wrapper restricts
//! its initialization and layout arithmetic and makes deallocation's ownership
//! obligation explicit; its upstream safe `dealloc` cannot be exposed safely.

use core::{alloc::Layout, mem::size_of, ptr::NonNull};

use buddy_system_allocator::Heap;

/// One reservation covers the bounded 128 MiB ELF input and 64 MiB retention,
/// including transient copies and buddy rounding. Exhaustion never grows it.
pub const MAX_ARENA_BYTES: usize = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeapStats {
    pub reserved_bytes: usize,
    pub used_bytes: usize,
    pub allocated_bytes: usize,
    pub peak_allocated_bytes: usize,
}

pub struct ArenaHeap {
    // Safety invariant: free lists refer only to disjoint free blocks in the
    // single exclusively owned live region; allocated blocks are excluded.
    // Only checked initialization/allocation and exact-layout deallocation may
    // alter these lists.
    // Heap's opted-in Send transfers metadata, never a borrowed reference.
    heap: Heap<32>,
    // Safety invariant: word-aligned region length is nonzero and <=2^29,
    // bounding every allocation/free-list order below Heap<32>'s array length.
    // Its start+reserved+word was checked not to wrap before initialization.
    reserved: usize,
    peak: usize,
}

impl ArenaHeap {
    /// Take exclusive allocator access to one externally owned storage region.
    /// Dropping this value does not unmap or free that region.
    ///
    /// # Safety
    /// `base..base+len` must be one live, exclusively owned writable allocation.
    /// Its owner must keep it allocated while this allocator or any returned
    /// block remains live, including if allocator ownership moves across threads.
    /// There must be no overlapping allocator or references accessing its free
    /// storage. While a returned block is allocated, only pointers derived from
    /// that block may access it. The original owner may reclaim the region only
    /// after every block and this allocator have been retired.
    pub unsafe fn from_region(base: *mut u8, len: usize) -> Option<Self> {
        let word = size_of::<usize>();
        let start = base as usize;
        let end = start.checked_add(len)?;
        if start == 0
            || start % word != 0
            || len % word != 0
            || !(word..=MAX_ARENA_BYTES).contains(&len)
            || end.checked_add(word).is_none()
        {
            return None;
        }
        let mut heap = Heap::empty();
        // SAFETY: caller grants one live exclusive region. Checked alignment
        // avoids the dependency's boundary rounding, and checked nonzero start
        // and end+word prevent all init-loop integer overflow. len<=2^29 keeps
        // every free block's order below Heap<32>'s free-list array bound. This
        // empty private heap has no existing region or outstanding allocation.
        unsafe { heap.init(start, len) };
        Some(Self {
            heap,
            reserved: len,
            peak: 0,
        })
    }

    /// Return a fresh disjoint block, or None for zero/unsupported/exhausted
    /// layouts. This method never requests more storage from the backing owner.
    pub fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        if layout.size() == 0 {
            return None;
        }
        let rounded = layout
            .size()
            .checked_next_power_of_two()?
            .max(layout.align())
            .max(size_of::<usize>());
        if rounded > self.reserved {
            return None;
        }
        // The opted-in buddy heap receives nonzero, nonoverflowing layouts with
        // order<=29. Its exclusive borrow serializes metadata changes; its
        // initialized-region invariant guarantees returned blocks are disjoint.
        let allocation = self.heap.alloc(layout).ok()?;
        self.peak = self.peak.max(self.heap.stats_alloc_actual());
        Some(allocation)
    }

    /// Return a block to the same arena without releasing backing storage.
    ///
    /// # Safety
    /// `pointer` must be a currently live block returned by this exact arena,
    /// and `layout` must equal the layout used for that successful allocation.
    /// All references/accesses to the block must end before this call; it must
    /// not be accessed or deallocated again until a new allocation returns it.
    pub unsafe fn deallocate(&mut self, pointer: NonNull<u8>, layout: Layout) {
        // The caller's exact ownership/layout obligation supplies the contract
        // missing from the dependency's safe dealloc signature. allocate checked
        // its size/order already, and exclusive &mut self serializes free lists.
        self.heap.dealloc(pointer, layout);
    }

    pub fn stats(&self) -> HeapStats {
        HeapStats {
            reserved_bytes: self.reserved,
            used_bytes: self.heap.stats_alloc_user(),
            allocated_bytes: self.heap.stats_alloc_actual(),
            peak_allocated_bytes: self.peak,
        }
    }
}
