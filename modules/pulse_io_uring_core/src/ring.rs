//! Shared-memory Acquire/Release SPSC ring protocol and `IORING_FEAT_NODROP` state machine.

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU32, Ordering};

use pulse_user_abi::io_uring::{IoUringCqe, IoUringSqe};

use crate::capacity::{PAGE_SIZE_4K, RingRegionLayout};

/// Result of publishing one CQE into the completion ring state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostCqeOutcome {
    /// Written directly into the shared CQ ring and published via `cq.tail` (`Release`).
    RingWritten,
    /// Shared CQ ring was full or overflow FIFO was non-empty; pushed into `cq_overflow_list`.
    QueuedOverflow,
    /// Bounded overflow capacity exhausted or allocation failed; incremented `cq.overflow`.
    DroppedWithOverflow,
}

/// Non-owning view over the dual shared `io_uring` memory regions (`rings` and `sqes`).
///
/// # Invariants
/// - Never creates shared (`&`) or mutable (`&mut`) Rust references to any SQE,
///   CQE, or non-atomic byte slice inside the mapped shared pages.
/// - Every `u32` control word uses `AtomicU32::from_ptr` within a single method call.
/// - Every `IoUringSqe` read uses `core::ptr::read_volatile` (single copy into kernel stack).
/// - Every `IoUringCqe` write uses `core::ptr::write_volatile` strictly before `Release` on `cq.tail`.
pub struct SharedRingMemory {
    // Safety invariant: `rings_ptr` is page-aligned (`PAGE_SIZE_4K`), non-null, and
    // backed by at least `rings_len >= layout.rings_alloc_bytes` zero-initialized bytes
    // for the entire lifetime of `SharedRingMemory`. Concurrent userspace access uses
    // only single-copy atomic/volatile reads/writes.
    rings_ptr: *mut u8,
    rings_len: usize,
    // Safety invariant: `sqes_ptr` is page-aligned (`PAGE_SIZE_4K`), non-null, and
    // backed by at least `sqes_len >= layout.sqes_alloc_bytes` zero-initialized bytes
    // for the entire lifetime of `SharedRingMemory`.
    sqes_ptr: *mut u8,
    sqes_len: usize,
    layout: RingRegionLayout,
}

// SAFETY: `SharedRingMemory` does not grant unsynchronized `&`/`&mut` aliasing to
// shared pages; callers synchronize SQ consumer operations and CQ producer operations
// separately, and owner keeps the backing page allocations pinned for its lifetime.
unsafe impl Send for SharedRingMemory {}
// SAFETY: `SharedRingMemory` does not grant unsynchronized `&`/`&mut` aliasing to
// shared pages; external `Mutex`/`SpinNoIrq` locks serialize kernel-side SQ consumer
// and CQ producer methods (`SubmitRingState`/`CompletionRingState`), while `SharedRingMemory`'s
// raw mutation primitives stay crate-private. Only read-only atomic header queries (`load_cq_flags`)
// and `&self` atomic loads are exposed across shared references.
unsafe impl Sync for SharedRingMemory {}

impl SharedRingMemory {
    /// Creates a new non-owning view over initialized `rings` and `sqes` buffers.
    ///
    /// # Safety
    /// - `rings_ptr` must be non-null, valid for reads/writes for `rings_len` bytes, aligned
    ///   to at least `PAGE_SIZE_4K`, with `layout.rings_alloc_bytes <= rings_len <= isize::MAX`.
    /// - `sqes_ptr` must be non-null, valid for reads/writes for `sqes_len` bytes, aligned
    ///   to at least `PAGE_SIZE_4K`, with `layout.sqes_alloc_bytes <= sqes_len <= isize::MAX`.
    /// - `[rings_ptr, rings_ptr + rings_len)` and `[sqes_ptr, sqes_ptr + sqes_len)` must be
    ///   strictly non-overlapping, have no live non-atomic Rust references anywhere, and stay
    ///   pinned and un-freed until `self` is dropped.
    /// - Concurrent accesses by userspace or other threads must use only single-copy atomic/volatile
    ///   accesses matching the `io_uring` SPSC protocol (`SubmitRingState` serialized vs `CompletionRingState`).
    pub unsafe fn new(
        rings_ptr: *mut u8,
        rings_len: usize,
        sqes_ptr: *mut u8,
        sqes_len: usize,
        layout: RingRegionLayout,
    ) -> Self {
        assert!(!rings_ptr.is_null() && (rings_ptr as usize) % PAGE_SIZE_4K == 0);
        assert!(rings_len >= layout.rings_alloc_bytes && rings_len <= isize::MAX as usize);
        assert!(!sqes_ptr.is_null() && (sqes_ptr as usize) % PAGE_SIZE_4K == 0);
        assert!(sqes_len >= layout.sqes_alloc_bytes && sqes_len <= isize::MAX as usize);
        let r_start = rings_ptr as usize;
        let r_end = r_start.checked_add(rings_len).expect("rings address range overflow");
        let s_start = sqes_ptr as usize;
        let s_end = s_start.checked_add(sqes_len).expect("sqes address range overflow");
        assert!(r_end <= s_start || s_end <= r_start, "rings and sqes buffers must not overlap");

        assert!(layout.sq_entries > 0 && layout.sq_entries.is_power_of_two());
        assert!(layout.cq_entries > 0 && layout.cq_entries.is_power_of_two());
        for off in [
            layout.sq_head_off,
            layout.sq_tail_off,
            layout.cq_head_off,
            layout.cq_tail_off,
            layout.sq_mask_off,
            layout.sq_entries_off,
            layout.sq_flags_off,
            layout.sq_dropped_off,
            layout.cq_mask_off,
            layout.cq_entries_off,
            layout.cq_overflow_off,
            layout.cq_flags_off,
        ] {
            assert!(off % core::mem::align_of::<u32>() == 0);
            assert!(off.checked_add(4).is_some_and(|e| e <= layout.cqes_off));
        }
        assert!(layout.cqes_off % core::mem::align_of::<IoUringCqe>() == 0);
        let cqe_bytes = (layout.cq_entries as usize) * core::mem::size_of::<IoUringCqe>();
        let cqes_end = layout.cqes_off.checked_add(cqe_bytes).unwrap();
        assert!(cqes_end <= layout.sq_array_off);
        assert!(layout.sq_array_off % core::mem::align_of::<u32>() == 0);
        let sq_arr_bytes = (layout.sq_entries as usize) * core::mem::size_of::<u32>();
        let raw_end = layout.sq_array_off.checked_add(sq_arr_bytes).unwrap();
        assert!(raw_end <= layout.rings_raw_bytes && layout.rings_raw_bytes <= layout.rings_alloc_bytes);
        assert!(
            (layout.sq_entries as usize) * core::mem::size_of::<IoUringSqe>()
                <= layout.sqes_alloc_bytes
        );

        Self {
            rings_ptr,
            rings_len,
            sqes_ptr,
            sqes_len,
            layout,
        }
    }

    #[inline]
    pub fn layout(&self) -> &RingRegionLayout {
        &self.layout
    }

    #[inline]
    pub fn load_cq_flags(&self) -> u32 {
        self.load_u32(self.layout.cq_flags_off, Ordering::Acquire)
    }

    /// Initializes the immutable mask/entries fields and zeroed head/tail/flags/counters
    /// in the shared rings page before userspace can map the FD.
    pub fn init_headers(&mut self) {
        let l = &self.layout;
        self.store_u32(l.sq_head_off, 0, Ordering::Relaxed);
        self.store_u32(l.sq_tail_off, 0, Ordering::Relaxed);
        self.store_u32(l.cq_head_off, 0, Ordering::Relaxed);
        self.store_u32(l.cq_tail_off, 0, Ordering::Relaxed);
        self.store_u32(l.sq_mask_off, l.sq_entries - 1, Ordering::Relaxed);
        self.store_u32(l.sq_entries_off, l.sq_entries, Ordering::Relaxed);
        self.store_u32(l.sq_flags_off, 0, Ordering::Relaxed);
        self.store_u32(l.sq_dropped_off, 0, Ordering::Relaxed);
        self.store_u32(l.cq_mask_off, l.cq_entries - 1, Ordering::Relaxed);
        self.store_u32(l.cq_entries_off, l.cq_entries, Ordering::Relaxed);
        self.store_u32(l.cq_overflow_off, 0, Ordering::Relaxed);
        self.store_u32(l.cq_flags_off, 0, Ordering::Relaxed);
    }

    #[inline]
    fn u32_ptr(&self, byte_offset: usize) -> *mut u32 {
        assert!(byte_offset % core::mem::align_of::<u32>() == 0);
        assert!(
            byte_offset
                .checked_add(core::mem::size_of::<u32>())
                .is_some_and(|e| e <= self.rings_len)
        );
        // SAFETY: `byte_offset` is 4-byte aligned and in bounds of `rings_ptr..rings_ptr+rings_len`.
        unsafe { self.rings_ptr.add(byte_offset).cast::<u32>() }
    }

    #[inline]
    pub(crate) fn load_u32(&self, byte_offset: usize, order: Ordering) -> u32 {
        let ptr = self.u32_ptr(byte_offset);
        // SAFETY: `ptr` is 4-byte aligned, in bounds of the pinned shared rings allocation,
        // and only accessed via atomic/volatile operations across threads and userspace.
        unsafe { AtomicU32::from_ptr(ptr).load(order) }
    }

    #[inline]
    pub(crate) fn store_u32(&self, byte_offset: usize, val: u32, order: Ordering) {
        let ptr = self.u32_ptr(byte_offset);
        // SAFETY: Same alignment, bounds, and lifetime guarantees as `load_u32`, while
        // callers enforce external SPSC mutual exclusion across kernel SQ/CQ writers.
        unsafe { AtomicU32::from_ptr(ptr).store(val, order) }
    }

    #[inline]
    pub(crate) fn fetch_or_u32(&self, byte_offset: usize, bits: u32, order: Ordering) -> u32 {
        let ptr = self.u32_ptr(byte_offset);
        // SAFETY: Same alignment, bounds, and lifetime guarantees as `load_u32`.
        unsafe { AtomicU32::from_ptr(ptr).fetch_or(bits, order) }
    }

    #[inline]
    pub(crate) fn fetch_and_u32(&self, byte_offset: usize, mask: u32, order: Ordering) -> u32 {
        let ptr = self.u32_ptr(byte_offset);
        // SAFETY: Same alignment, bounds, and lifetime guarantees as `load_u32`.
        unsafe { AtomicU32::from_ptr(ptr).fetch_and(mask, order) }
    }

    /// Reads one `IoUringSqe` slot via a single volatile copy into stack-local memory.
    pub(crate) fn read_sqe_volatile(&self, sqe_index: u32) -> IoUringSqe {
        assert!(sqe_index < self.layout.sq_entries);
        let offset = (sqe_index as usize)
            .checked_mul(core::mem::size_of::<IoUringSqe>())
            .expect("SQE offset overflow");
        assert!(
            offset
                .checked_add(core::mem::size_of::<IoUringSqe>())
                .is_some_and(|e| e <= self.sqes_len)
        );
        // SAFETY: `offset + size_of::<IoUringSqe>() <= sqes_len`, and `sqes_ptr` is
        // page-aligned so `ptr` is 64-byte aligned (>= `align_of::<IoUringSqe>()`).
        let ptr = unsafe { self.sqes_ptr.add(offset).cast::<IoUringSqe>() };
        // SAFETY: `ptr` points into the pinned shared SQEs region, `IoUringSqe` is
        // `#[repr(C)]` with zero padding and all integer fields (every bit pattern valid),
        // and a single volatile copy avoids creating `&IoUringSqe` or suffering TOCTOU.
        unsafe { ptr.read_volatile() }
    }

    /// Writes one `IoUringCqe` into the shared CQ ring via `write_volatile`.
    pub(crate) fn write_cqe_volatile(&self, cq_slot: u32, cqe: IoUringCqe) {
        assert!(cq_slot < self.layout.cq_entries);
        let slot_bytes = (cq_slot as usize)
            .checked_mul(core::mem::size_of::<IoUringCqe>())
            .expect("CQE slot offset overflow");
        let offset = self
            .layout
            .cqes_off
            .checked_add(slot_bytes)
            .expect("CQE byte offset overflow");
        assert!(offset % core::mem::align_of::<IoUringCqe>() == 0);
        assert!(
            offset
                .checked_add(core::mem::size_of::<IoUringCqe>())
                .is_some_and(|e| e <= self.rings_len)
        );
        // SAFETY: `offset + size_of::<IoUringCqe>() <= rings_len`, `offset` is verified
        // 16-byte aligned and `rings_ptr` is page-aligned, so `ptr` is naturally aligned.
        let ptr = unsafe { self.rings_ptr.add(offset).cast::<IoUringCqe>() };
        // SAFETY: `ptr` is valid, aligned, in bounds, and the caller owns the slot under
        // the kernel CQ producer lock prior to publishing `cq.tail` with `Ordering::Release`.
        unsafe { ptr.write_volatile(cqe) }
    }
}

/// Authoritative kernel-side SQ consumer state.
pub struct SubmitRingState {
    kernel_sq_head: u32,
    kernel_sq_dropped: u32,
    sq_entries: u32,
    sq_mask: u32,
    submit_all: bool,
}

impl SubmitRingState {
    pub fn new(sq_entries: u32, submit_all: bool) -> Self {
        assert!(sq_entries > 0 && sq_entries.is_power_of_two());
        Self {
            kernel_sq_head: 0,
            kernel_sq_dropped: 0,
            sq_entries,
            sq_mask: sq_entries - 1,
            submit_all,
        }
    }

    #[inline]
    pub fn kernel_sq_head(&self) -> u32 {
        self.kernel_sq_head
    }

    #[inline]
    pub fn kernel_sq_dropped(&self) -> u32 {
        self.kernel_sq_dropped
    }

    #[inline]
    pub const fn is_submit_all(&self) -> bool {
        self.submit_all
    }

    /// Consumes up to `to_submit` SQEs using kernel-private `kernel_sq_head`.
    ///
    /// The callback receives one snapshot `IoUringSqe` and returns `Ok(())` on success
    /// or `Err(())` when an inline failure CQE was produced so `!submit_all` stops the loop.
    /// Out-of-bounds `sq_array` indices increment `sq.dropped`, update `sq.head`, and
    /// stop the loop without invoking `on_sqe` or emitting a CQE.
    pub fn submit_batch(
        &mut self,
        shared: &SharedRingMemory,
        to_submit: u32,
        mut on_sqe: impl FnMut(&IoUringSqe) -> Result<(), ()>,
    ) -> u32 {
        if to_submit == 0 {
            return 0;
        }
        let l = shared.layout();
        let sq_tail = shared.load_u32(l.sq_tail_off, Ordering::Acquire);
        let avail = sq_tail.wrapping_sub(self.kernel_sq_head);
        let actual = to_submit.min(avail).min(self.sq_entries);
        if actual == 0 {
            return 0;
        }

        let mut submitted = 0u32;
        for _ in 0..actual {
            let ring_slot = self.kernel_sq_head & self.sq_mask;
            let sq_array_off =
                l.sq_array_off + (ring_slot as usize) * core::mem::size_of::<u32>();
            let sqe_idx = shared.load_u32(sq_array_off, Ordering::Relaxed);
            self.kernel_sq_head = self.kernel_sq_head.wrapping_add(1);

            if sqe_idx >= self.sq_entries {
                self.kernel_sq_dropped = self.kernel_sq_dropped.wrapping_add(1);
                shared.store_u32(l.sq_dropped_off, self.kernel_sq_dropped, Ordering::Relaxed);
                break;
            }

            let sqe = shared.read_sqe_volatile(sqe_idx);
            submitted += 1;
            if on_sqe(&sqe).is_err() && !self.submit_all {
                break;
            }
        }
        shared.store_u32(l.sq_head_off, self.kernel_sq_head, Ordering::Release);
        submitted
    }
}

/// Authoritative kernel-side CQ producer state with bounded `IORING_FEAT_NODROP` FIFO.
pub struct CompletionRingState {
    kernel_cq_tail: u32,
    kernel_cq_overflow: u32,
    cq_entries: u32,
    cq_mask: u32,
    cq_overflow_list: VecDeque<IoUringCqe>,
    max_overflow_entries: usize,
    pending_ebadr: bool,
}

impl CompletionRingState {
    pub fn new(cq_entries: u32) -> Self {
        assert!(cq_entries > 0 && cq_entries.is_power_of_two());
        let max_overflow_entries = (cq_entries as usize).saturating_mul(4).max(65_536);
        Self {
            kernel_cq_tail: 0,
            kernel_cq_overflow: 0,
            cq_entries,
            cq_mask: cq_entries - 1,
            cq_overflow_list: VecDeque::new(),
            max_overflow_entries,
            pending_ebadr: false,
        }
    }

    #[cfg(test)]
    pub fn with_max_overflow_for_test(mut self, cap: usize) -> Self {
        self.max_overflow_entries = cap;
        self
    }

    #[inline]
    pub fn kernel_cq_tail(&self) -> u32 {
        self.kernel_cq_tail
    }

    #[inline]
    pub fn kernel_cq_overflow(&self) -> u32 {
        self.kernel_cq_overflow
    }

    #[inline]
    pub fn overflow_len(&self) -> usize {
        self.cq_overflow_list.len()
    }

    #[inline]
    pub fn ring_ready_count(&self, shared: &SharedRingMemory) -> u32 {
        let head = shared.load_u32(shared.layout().cq_head_off, Ordering::Acquire);
        self.kernel_cq_tail.wrapping_sub(head)
    }

    pub fn flush_cq_overflow(&mut self, shared: &SharedRingMemory) -> usize {
        use linux_raw_sys::io_uring::IORING_SQ_CQ_OVERFLOW;

        let l = shared.layout();
        if self.cq_overflow_list.is_empty() {
            if shared.load_u32(l.sq_flags_off, Ordering::Relaxed) & IORING_SQ_CQ_OVERFLOW != 0 {
                shared.fetch_and_u32(l.sq_flags_off, !IORING_SQ_CQ_OVERFLOW, Ordering::AcqRel);
            }
            return 0;
        }

        let mut cq_head = shared.load_u32(l.cq_head_off, Ordering::Acquire);
        let mut flushed = 0usize;
        while self.kernel_cq_tail.wrapping_sub(cq_head) < self.cq_entries {
            let Some(cqe) = self.cq_overflow_list.pop_front() else {
                break;
            };
            let cq_slot = self.kernel_cq_tail & self.cq_mask;
            shared.write_cqe_volatile(cq_slot, cqe);
            self.kernel_cq_tail = self.kernel_cq_tail.wrapping_add(1);
            flushed += 1;
            if self.kernel_cq_tail.wrapping_sub(cq_head) >= self.cq_entries {
                cq_head = shared.load_u32(l.cq_head_off, Ordering::Acquire);
            }
        }
        if flushed > 0 {
            shared.store_u32(l.cq_tail_off, self.kernel_cq_tail, Ordering::Release);
        }
        if self.cq_overflow_list.is_empty() {
            shared.fetch_and_u32(l.sq_flags_off, !IORING_SQ_CQ_OVERFLOW, Ordering::AcqRel);
        }
        flushed
    }

    pub fn post_cqe(&mut self, shared: &SharedRingMemory, cqe: IoUringCqe) -> PostCqeOutcome {
        if !self.cq_overflow_list.is_empty() {
            let _ = self.flush_cq_overflow(shared);
        }
        if !self.cq_overflow_list.is_empty() {
            return self.enqueue_overflow(shared, cqe);
        }
        let l = shared.layout();
        let cq_head = shared.load_u32(l.cq_head_off, Ordering::Acquire);
        if self.kernel_cq_tail.wrapping_sub(cq_head) < self.cq_entries {
            let cq_slot = self.kernel_cq_tail & self.cq_mask;
            shared.write_cqe_volatile(cq_slot, cqe);
            self.kernel_cq_tail = self.kernel_cq_tail.wrapping_add(1);
            shared.store_u32(l.cq_tail_off, self.kernel_cq_tail, Ordering::Release);
            PostCqeOutcome::RingWritten
        } else {
            self.enqueue_overflow(shared, cqe)
        }
    }

    fn enqueue_overflow(&mut self, shared: &SharedRingMemory, cqe: IoUringCqe) -> PostCqeOutcome {
        use linux_raw_sys::io_uring::IORING_SQ_CQ_OVERFLOW;

        let l = shared.layout();
        if self.cq_overflow_list.len() >= self.max_overflow_entries
            || self.cq_overflow_list.try_reserve(1).is_err()
        {
            self.kernel_cq_overflow = self.kernel_cq_overflow.wrapping_add(1);
            shared.store_u32(l.cq_overflow_off, self.kernel_cq_overflow, Ordering::Relaxed);
            self.pending_ebadr = true;
            return PostCqeOutcome::DroppedWithOverflow;
        }
        let was_empty = self.cq_overflow_list.is_empty();
        self.cq_overflow_list.push_back(cqe);
        if was_empty {
            shared.fetch_or_u32(l.sq_flags_off, IORING_SQ_CQ_OVERFLOW, Ordering::AcqRel);
        }
        PostCqeOutcome::QueuedOverflow
    }

    /// Consumes and clears `pending_ebadr` once when both the CQ ring and overflow FIFO are empty.
    pub fn take_pending_ebadr_if_empty(&mut self, shared: &SharedRingMemory) -> bool {
        if self.pending_ebadr && self.cq_overflow_list.is_empty() && self.ring_ready_count(shared) == 0 {
            self.pending_ebadr = false;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::alloc::{Layout, alloc_zeroed, dealloc};
    use core::sync::atomic::Ordering;

    use linux_raw_sys::io_uring::{IORING_SETUP_SUBMIT_ALL, IORING_SQ_CQ_OVERFLOW, io_cqring_offsets, io_sqring_offsets, io_uring_params};
    use pulse_user_abi::io_uring::{IoUringCqe, IoUringSqe};

    use super::*;
    use crate::capacity::validate_and_compute_ring_geometry;

    struct AlignedTestBuffers {
        rings_ptr: *mut u8,
        rings_layout: Layout,
        sqes_ptr: *mut u8,
        sqes_layout: Layout,
        shared: SharedRingMemory,
    }

    impl AlignedTestBuffers {
        fn new(entries: u32, flags: u32) -> Self {
            let mut params = zero_params();
            params.flags = flags;
            let layout = validate_and_compute_ring_geometry(entries, &mut params).unwrap();
            let rings_layout =
                Layout::from_size_align(layout.rings_alloc_bytes, PAGE_SIZE_4K).unwrap();
            let sqes_layout =
                Layout::from_size_align(layout.sqes_alloc_bytes, PAGE_SIZE_4K).unwrap();
            // SAFETY: Non-zero sizes, page-aligned layouts.
            let rings_ptr = unsafe { alloc_zeroed(rings_layout) };
            let sqes_ptr = unsafe { alloc_zeroed(sqes_layout) };
            assert!(!rings_ptr.is_null() && !sqes_ptr.is_null());
            // SAFETY: Pointers remain pinned in `self` and dropped after `shared` if dropped explicitly.
            let mut shared = unsafe {
                SharedRingMemory::new(
                    rings_ptr,
                    layout.rings_alloc_bytes,
                    sqes_ptr,
                    layout.sqes_alloc_bytes,
                    layout,
                )
            };
            shared.init_headers();
            Self {
                rings_ptr,
                rings_layout,
                sqes_ptr,
                sqes_layout,
                shared,
            }
        }

        fn write_sqe(&self, idx: u32, sqe: IoUringSqe) {
            let off = (idx as usize) * core::mem::size_of::<IoUringSqe>();
            assert!(off + core::mem::size_of::<IoUringSqe>() <= self.shared.sqes_len);
            // SAFETY: `off` is 64-byte aligned within `sqes_ptr..sqes_ptr+sqes_len`.
            unsafe {
                self.sqes_ptr.add(off).cast::<IoUringSqe>().write_volatile(sqe);
            }
        }

        fn write_sq_array(&self, slot: u32, sqe_idx: u32) {
            let off = self.shared.layout().sq_array_off + (slot as usize) * 4;
            self.shared.store_u32(off, sqe_idx, Ordering::Relaxed);
        }

        fn read_cqe(&self, idx: u32) -> IoUringCqe {
            let mask = self.shared.layout().cq_entries - 1;
            let slot = idx & mask;
            let off = self.shared.layout().cqes_off + (slot as usize) * core::mem::size_of::<IoUringCqe>();
            // SAFETY: `off` is 16-byte aligned within `rings_ptr..rings_ptr+rings_len`.
            unsafe { self.rings_ptr.add(off).cast::<IoUringCqe>().read_volatile() }
        }
    }

    impl Drop for AlignedTestBuffers {
        fn drop(&mut self) {
            // SAFETY: Allocated with `alloc_zeroed` using the same layouts.
            unsafe {
                dealloc(self.rings_ptr, self.rings_layout);
                dealloc(self.sqes_ptr, self.sqes_layout);
            }
        }
    }

    fn zero_params() -> io_uring_params {
        io_uring_params {
            sq_entries: 0,
            cq_entries: 0,
            flags: 0,
            sq_thread_cpu: 0,
            sq_thread_idle: 0,
            features: 0,
            wq_fd: 0,
            resv: [0; 3],
            sq_off: io_sqring_offsets {
                head: 0,
                tail: 0,
                ring_mask: 0,
                ring_entries: 0,
                flags: 0,
                dropped: 0,
                array: 0,
                resv1: 0,
                user_addr: 0,
            },
            cq_off: io_cqring_offsets {
                head: 0,
                tail: 0,
                ring_mask: 0,
                ring_entries: 0,
                overflow: 0,
                cqes: 0,
                flags: 0,
                resv1: 0,
                user_addr: 0,
            },
        }
    }

    #[test]
    fn submit_ignores_tampered_sq_head_mask_and_handles_u32_wrap_and_oob_drop() {
        let buf = AlignedTestBuffers::new(4, 0);
        let l = *buf.shared.layout();
        assert_eq!(buf.shared.load_u32(l.sq_mask_off, Ordering::Relaxed), 3);
        assert_eq!(buf.shared.load_u32(l.sq_entries_off, Ordering::Relaxed), 4);
        assert_eq!(buf.shared.load_u32(l.cq_mask_off, Ordering::Relaxed), 7);
        assert_eq!(buf.shared.load_u32(l.cq_entries_off, Ordering::Relaxed), 8);

        let mut sq = SubmitRingState::new(4, false);
        // Simulate userspace tampering with shared sq.head, sq_mask, sq_entries.
        buf.shared.store_u32(l.sq_head_off, 999, Ordering::Relaxed);
        buf.shared.store_u32(l.sq_mask_off, 0, Ordering::Relaxed);
        buf.shared.store_u32(l.sq_entries_off, 1, Ordering::Relaxed);

        // First slot valid, second slot out-of-bounds (`4 >= 4`), third slot valid.
        buf.write_sqe(
            1,
            IoUringSqe {
                user_data: 0x1111,
                ..Default::default()
            },
        );
        buf.write_sq_array(0, 1);
        buf.write_sq_array(1, 4);
        buf.write_sq_array(2, 0);
        buf.shared.store_u32(l.sq_tail_off, 3, Ordering::Release);

        let mut seen = alloc::vec::Vec::new();
        let submitted = sq.submit_batch(&buf.shared, 3, |sqe| {
            seen.push(sqe.user_data);
            Ok(())
        });
        assert_eq!(submitted, 1);
        assert_eq!(seen, alloc::vec![0x1111]);
        assert_eq!(sq.kernel_sq_head(), 2);
        assert_eq!(sq.kernel_sq_dropped(), 1);
        assert_eq!(buf.shared.load_u32(l.sq_head_off, Ordering::Acquire), 2);
        assert_eq!(buf.shared.load_u32(l.sq_dropped_off, Ordering::Relaxed), 1);

        // Advance near u32::MAX to test wrap-around.
        sq.kernel_sq_head = u32::MAX - 1;
        buf.shared.store_u32(l.sq_head_off, u32::MAX - 1, Ordering::Release);
        for (idx, tag) in [(u32::MAX - 1, 0xa1u64), (u32::MAX, 0xa2), (0u32, 0xa3)] {
            let slot = idx & 3;
            buf.write_sqe(
                slot,
                IoUringSqe {
                    user_data: tag,
                    ..Default::default()
                },
            );
            buf.write_sq_array(slot, slot);
        }
        // Tail wraps cleanly across u32::MAX -> 1 (`delta = 3`, clamped cleanly).
        buf.shared.store_u32(l.sq_tail_off, 1, Ordering::Release);
        let mut wrap_seen = alloc::vec::Vec::new();
        let wrap_sub = sq.submit_batch(&buf.shared, 10, |sqe| {
            wrap_seen.push(sqe.user_data);
            Ok(())
        });
        assert_eq!(wrap_sub, 3);
        assert_eq!(wrap_seen, alloc::vec![0xa1, 0xa2, 0xa3]);
        assert_eq!(sq.kernel_sq_head(), 1);
    }

    #[test]
    fn submit_stops_on_error_unless_submit_all_is_set() {
        let buf = AlignedTestBuffers::new(4, 0);
        let l = *buf.shared.layout();
        for i in 0..3u32 {
            buf.write_sqe(
                i,
                IoUringSqe {
                    user_data: u64::from(i + 1),
                    ..Default::default()
                },
            );
            buf.write_sq_array(i, i);
        }
        buf.shared.store_u32(l.sq_tail_off, 3, Ordering::Release);

        let mut sq = SubmitRingState::new(4, false);
        let mut count = 0u32;
        let sub = sq.submit_batch(&buf.shared, 3, |_| {
            count += 1;
            Err(())
        });
        assert_eq!(sub, 1);
        assert_eq!(count, 1);
        assert_eq!(sq.kernel_sq_head(), 1);

        let mut sq_all = SubmitRingState::new(4, true);
        let buf2 = AlignedTestBuffers::new(4, IORING_SETUP_SUBMIT_ALL);
        let l2 = *buf2.shared.layout();
        for i in 0..3u32 {
            buf2.write_sqe(i, IoUringSqe::default());
            buf2.write_sq_array(i, i);
        }
        buf2.shared.store_u32(l2.sq_tail_off, 3, Ordering::Release);
        let sub_all = sq_all.submit_batch(&buf2.shared, 3, |_| Err(()));
        assert_eq!(sub_all, 3);
        assert_eq!(sq_all.kernel_sq_head(), 3);
    }

    #[test]
    fn cq_nodrop_preserves_fifo_no_jumping_and_bounded_overflow_triggers_single_ebadr() {
        let buf = AlignedTestBuffers::new(2, 0);
        let l = *buf.shared.layout();
        // `cq_entries == 4`
        assert_eq!(l.cq_entries, 4);
        let mut cq = CompletionRingState::new(4).with_max_overflow_for_test(2);

        // Fill all 4 ring slots -> 4 RingWritten, overflow flag still clear.
        for i in 0..4u64 {
            assert_eq!(
                cq.post_cqe(
                    &buf.shared,
                    IoUringCqe {
                        user_data: i + 1,
                        res: 0,
                        flags: 0,
                    },
                ),
                PostCqeOutcome::RingWritten
            );
        }
        assert_eq!(
            buf.shared.load_u32(l.sq_flags_off, Ordering::Relaxed) & IORING_SQ_CQ_OVERFLOW,
            0
        );

        // Next 2 enter overflow FIFO (`max = 2`), setting IORING_SQ_CQ_OVERFLOW.
        for i in 5..=6u64 {
            assert_eq!(
                cq.post_cqe(
                    &buf.shared,
                    IoUringCqe {
                        user_data: i,
                        res: 0,
                        flags: 0,
                    },
                ),
                PostCqeOutcome::QueuedOverflow
            );
        }
        assert_eq!(cq.overflow_len(), 2);
        assert_ne!(
            buf.shared.load_u32(l.sq_flags_off, Ordering::Relaxed) & IORING_SQ_CQ_OVERFLOW,
            0
        );

        // 7th overflows cap -> DroppedWithOverflow increments cq.overflow and arms single EBADR.
        assert_eq!(
            cq.post_cqe(
                &buf.shared,
                IoUringCqe {
                    user_data: 7,
                    res: 0,
                    flags: 0,
                },
            ),
            PostCqeOutcome::DroppedWithOverflow
        );
        assert_eq!(cq.kernel_cq_overflow(), 1);
        assert_eq!(buf.shared.load_u32(l.cq_overflow_off, Ordering::Relaxed), 1);

        // Consume ONLY 1 slot (cq.head = 1). Posting #8 must flush 1 from FIFO (slot 5) and
        // push #8 to the back of FIFO so #6 stays ahead of #8 (no queue jumping!).
        buf.shared.store_u32(l.cq_head_off, 1, Ordering::Release);
        assert_eq!(
            cq.post_cqe(
                &buf.shared,
                IoUringCqe {
                    user_data: 8,
                    res: 0,
                    flags: 0,
                },
            ),
            PostCqeOutcome::QueuedOverflow
        );
        assert_eq!(buf.read_cqe(4).user_data, 5);
        assert_ne!(
            buf.shared.load_u32(l.sq_flags_off, Ordering::Relaxed) & IORING_SQ_CQ_OVERFLOW,
            0
        );

        // Consume all 4 remaining CQEs (head becomes 5), then flush 2 from overflow (#6, #8).
        buf.shared.store_u32(l.cq_head_off, 5, Ordering::Release);
        assert!(!cq.take_pending_ebadr_if_empty(&buf.shared));
        assert_eq!(cq.flush_cq_overflow(&buf.shared), 2);
        assert_eq!(cq.overflow_len(), 0);
        assert_eq!(
            buf.shared.load_u32(l.sq_flags_off, Ordering::Relaxed) & IORING_SQ_CQ_OVERFLOW,
            0
        );
        assert_eq!(buf.read_cqe(5).user_data, 6);
        assert_eq!(buf.read_cqe(6).user_data, 8);

        // Consume final 2 (`head = 7`), now empty -> take_pending_ebadr_if_empty succeeds once!
        buf.shared.store_u32(l.cq_head_off, 7, Ordering::Release);
        assert!(cq.take_pending_ebadr_if_empty(&buf.shared));
        assert!(!cq.take_pending_ebadr_if_empty(&buf.shared));
    }

    #[test]
    fn cq_ignores_tampered_tail_masks_and_handles_u32_wrap_and_sqe_snapshot() {
        let buf = AlignedTestBuffers::new(2, 0);
        let l = *buf.shared.layout();
        let mut cq = CompletionRingState::new(4);

        // Simulate userspace tampering cq.tail, cq_mask, cq_entries.
        buf.shared.store_u32(l.cq_tail_off, 999, Ordering::Relaxed);
        buf.shared.store_u32(l.cq_mask_off, 0, Ordering::Relaxed);
        buf.shared.store_u32(l.cq_entries_off, 1, Ordering::Relaxed);

        // Advance both CQ pointers near u32::MAX to test wrap-around.
        cq.kernel_cq_tail = u32::MAX;
        buf.shared.store_u32(l.cq_head_off, u32::MAX, Ordering::Release);
        for i in 0..3u64 {
            assert_eq!(
                cq.post_cqe(
                    &buf.shared,
                    IoUringCqe {
                        user_data: 100 + i,
                        res: i as i32,
                        flags: 0,
                    },
                ),
                PostCqeOutcome::RingWritten
            );
        }
        assert_eq!(cq.kernel_cq_tail(), 2);
        assert_eq!(buf.shared.load_u32(l.cq_tail_off, Ordering::Acquire), 2);
        assert_eq!(cq.ring_ready_count(&buf.shared), 3);
        assert_eq!(buf.read_cqe(u32::MAX).user_data, 100);
        assert_eq!(buf.read_cqe(0).user_data, 101);
        assert_eq!(buf.read_cqe(1).user_data, 102);

        // Verify read_sqe_volatile takes an independent snapshot immune to post-read mutation.
        let mut sq = SubmitRingState::new(2, false);
        buf.write_sqe(
            0,
            IoUringSqe {
                opcode: 0,
                user_data: 0xbeef_cafe,
                ..Default::default()
            },
        );
        buf.write_sq_array(0, 0);
        buf.shared.store_u32(l.sq_tail_off, 1, Ordering::Release);
        let mut observed_tag = 0u64;
        let sub = sq.submit_batch(&buf.shared, 1, |sqe| {
            // Mutate underlying shared SQE after snapshot copy; snapshot must remain intact.
            buf.write_sqe(
                0,
                IoUringSqe {
                    opcode: 99,
                    user_data: 0xdead_dead,
                    ..Default::default()
                },
            );
            observed_tag = sqe.user_data;
            assert_eq!(sqe.opcode, 0);
            Ok(())
        });
        assert_eq!(sub, 1);
        assert_eq!(observed_tag, 0xbeef_cafe);
    }
}
