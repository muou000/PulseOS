//! Fixed-capacity range preparation and one-time publication.
//!
//! Local proofs below use the core contracts checked in the installed rust-src
//! for rustc 1.101.0-nightly (c1070d693, 2026-09-28):
//! - [Sync] requires shared references to be free of UB, including data races.
//! - [UnsafeCell] permits interior mutation, but shared references into its
//!   contents require those contents to "remain immutable" for their lifetime.
//! - [Atomics]: swap returns the previous value; Relaxed provides "only atomic
//!   operations". A Release store makes preceding writes visible to an Acquire
//!   load observing it. These are separate writer-exclusion and visibility rules.
//! - [Copy] requires aligned, valid, disjoint regions and preserves initialization.
//! - [Slice] requires "consecutive properly initialized values", one allocation,
//!   alignment, non-nullness, bounded size, lifetime and immutability.
//!
//! These are source-level arguments for this container, independent of BSP
//! scheduling, SMP/IRQ features and the configured physical addresses. Kernel
//! boot, compiler code generation and hardware execution are outside this scope.
//!
//! [Sync]: https://github.com/rust-lang/rust/blob/c1070d69382b8d2f2eb65119c738a77d9e324c9e/library/core/src/marker.rs#L511-L526
//! [UnsafeCell]: https://github.com/rust-lang/rust/blob/c1070d69382b8d2f2eb65119c738a77d9e324c9e/library/core/src/cell.rs#L2145-L2213
//! [Atomics]: https://github.com/rust-lang/rust/blob/c1070d69382b8d2f2eb65119c738a77d9e324c9e/library/core/src/sync/atomic.rs
//! [Copy]: https://github.com/rust-lang/rust/blob/c1070d69382b8d2f2eb65119c738a77d9e324c9e/library/core/src/ptr/mod.rs#L462-L501
//! [Slice]: https://github.com/rust-lang/rust/blob/c1070d69382b8d2f2eb65119c738a77d9e324c9e/library/core/src/slice/raw.rs#L5-L41

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use super::RawRange;

/// One-time publication of an immutable range list.
///
/// Publication invariant (owned by this module's private fields): `claimed`
/// changes from false to true at most once, selecting the only writer. `count`
/// stays zero until that writer has copied all entries, then a Release store
/// publishes a value in `0..=N`. Neither the entries nor count change afterward.
/// A zero count never grants access to the array; a nonzero Acquire load grants
/// read-only access to its initialized prefix for the borrow of this storage.
pub(super) struct RangeStorage<const N: usize> {
    ranges: UnsafeCell<[RawRange; N]>,
    claimed: AtomicBool,
    count: AtomicUsize,
}

// SAFETY: Sharing &RangeStorage only exposes publish/get. The atomic claim
// admits one writer, including for an empty publication, and is never reset.
// Until count is published, get returns an unrelated empty slice and creates
// no reference into ranges. The Release store follows every payload write;
// get's Acquire load of that store makes those writes visible before reading.
// Thereafter the claim rejects all writes and only shared slices of RawRange
// (two usize values, both Sync) escape. Their lifetimes are tied to &self, so
// the allocation cannot move or be dropped while they are used. Thus neither
// concurrent publishers nor readers can race on the UnsafeCell payload.
unsafe impl<const N: usize> Sync for RangeStorage<N> {}

impl<const N: usize> RangeStorage<N> {
    pub(super) const fn new() -> Self {
        Self {
            ranges: UnsafeCell::new([(0, 0); N]),
            claimed: AtomicBool::new(false),
            count: AtomicUsize::new(0),
        }
    }

    /// Publish the first list; later or concurrent attempts leave it unchanged.
    /// A losing caller need not wait for the winning publication to finish.
    pub(super) fn publish(&self, ranges: &RangeList<N>) {
        // This flag only arbitrates writers. Payload visibility is supplied by
        // count's Release/Acquire pair, not by observing the claim.
        if self.claimed.swap(true, Ordering::Relaxed) {
            return;
        }
        let source = ranges.as_slice();
        let count = ranges.len();
        // SAFETY: source is a shared, initialized slice of Copy (usize, usize)
        // values. RangeList's bounds invariant gives source.len() <= N. The
        // destination comes directly from this live UnsafeCell<[RawRange; N]>,
        // with the array's alignment, provenance and room for N entries. Source
        // and destination are distinct objects: this module never exposes a
        // RangeList backed by the storage. Both pointers stay aligned even for
        // N == 0, when no bytes are copied. The winning claim excludes all other
        // writers, and count is still zero so get cannot alias the destination.
        // Copying preserves initialization; RawRange has no ownership to move.
        unsafe {
            core::ptr::copy_nonoverlapping(
                source.as_ptr(),
                self.ranges.get().cast::<RawRange>(),
                count,
            )
        };
        // No fallible work or callbacks separate the completed copy and its
        // publication. An earlier panic would leave count zero and hide data.
        self.count.store(count, Ordering::Release);
    }

    /// Return the published entries, or an empty slice before publication.
    pub(super) fn get(&self) -> &[RawRange] {
        let count = self.count.load(Ordering::Acquire);
        if count == 0 {
            return &[];
        }
        // SAFETY: A nonzero count can only come from publish's Release store,
        // so this Acquire observes every preceding copy into the first count
        // entries. The invariant gives count <= N and no subsequent mutation.
        // UnsafeCell::get returns the live array's non-null, aligned pointer;
        // casting it to its element pointer preserves address and provenance
        // without making an intermediate array reference. This prefix lies in
        // one allocation, and its byte size is bounded by the live array's size
        // (<= isize::MAX), so its end cannot wrap the address space. The returned
        // slice borrows self, keeping that allocation alive and immovable for
        // all reads; the one-time claim keeps its initialized values immutable.
        unsafe { core::slice::from_raw_parts(self.ranges.get().cast::<RawRange>(), count) }
    }
}

/// A bounded, owned list: count is always in 0..=N, and all entries are initialized.
/// new starts at zero; push checks capacity before incrementing; normalize only
/// retains or merges entries and therefore cannot increase count.
#[derive(Clone, Copy)]
pub(super) struct RangeList<const N: usize> {
    ranges: [RawRange; N],
    count: usize,
}

impl<const N: usize> RangeList<N> {
    pub(super) const fn new() -> Self {
        Self {
            ranges: [(0, 0); N],
            count: 0,
        }
    }

    pub(super) fn push(&mut self, range: RawRange) -> bool {
        if range.1 == 0 {
            return true;
        }
        if self.count < N {
            self.ranges[self.count] = range;
            self.count += 1;
            true
        } else {
            false
        }
    }

    pub(super) fn normalize(&mut self) {
        self.ranges[..self.count].sort_unstable_by_key(|range| range.0);
        let mut output = 0usize;
        for input in 0..self.count {
            let (start, size) = self.ranges[input];
            let Some(end) = start.checked_add(size) else {
                continue;
            };
            if output > 0 {
                let (previous_start, previous_size) = self.ranges[output - 1];
                let previous_end = previous_start.saturating_add(previous_size);
                if start <= previous_end {
                    self.ranges[output - 1].1 = previous_end.max(end) - previous_start;
                    continue;
                }
            }
            self.ranges[output] = (start, end - start);
            output += 1;
        }
        self.count = output;
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub(super) const fn len(&self) -> usize {
        self.count
    }

    pub(super) fn as_slice(&self) -> &[RawRange] {
        &self.ranges[..self.count]
    }
}
