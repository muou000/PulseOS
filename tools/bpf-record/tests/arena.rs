use std::{
    alloc::{Layout, alloc, dealloc},
    ptr::NonNull,
};

use bpf_record::arena::ArenaHeap;

#[test]
fn allocation_cycles_reuse_one_bounded_region_with_disjoint_aligned_blocks() {
    let backing_layout = Layout::from_size_align(1024 * 1024, 1024 * 1024).unwrap();
    // SAFETY: the layout is nonzero; ownership stays here until all arena blocks
    // are freed and the arena metadata is dropped, then the original layout frees it.
    let backing = unsafe { alloc(backing_layout) };
    assert!(!backing.is_null());
    // SAFETY: backing uniquely owns this complete live allocation and grants the
    // arena exclusive access. No other pointer accesses it while the arena lives.
    let mut arena = unsafe { ArenaHeap::from_region(backing, backing_layout.size()) }.unwrap();
    for _ in 0..2000 {
        let mut blocks: Vec<(NonNull<u8>, Layout)> = Vec::new();
        for (size, alignment) in [(1, 1), (37, 64), (8193, 4096), (65536, 65536)] {
            let layout = Layout::from_size_align(size, alignment).unwrap();
            let pointer = arena
                .allocate(layout)
                .expect("freed backing must be reusable");
            let address = pointer.as_ptr() as usize;
            assert_eq!(address % alignment, 0);
            assert!(
                (backing as usize..backing as usize + backing_layout.size()).contains(&address)
            );
            assert!(address + size <= backing as usize + backing_layout.size());
            for (other, previous) in &blocks {
                let other = other.as_ptr() as usize;
                assert!(address + size <= other || other + previous.size() <= address);
            }
            // SAFETY: allocate grants this block exclusively for exactly layout's
            // readable/writable extent; no other live block overlaps it.
            unsafe { pointer.as_ptr().write_bytes(0xa5, size) };
            blocks.push((pointer, layout));
        }
        for (pointer, layout) in blocks.into_iter().rev() {
            // SAFETY: each pointer is live from this arena with its unchanged
            // allocation layout, is freed exactly once, and has no live references.
            unsafe { arena.deallocate(pointer, layout) };
        }
        assert_eq!(arena.stats().used_bytes, 0);
        assert_eq!(arena.stats().allocated_bytes, 0);
        assert_eq!(arena.stats().reserved_bytes, backing_layout.size());
    }
    let whole = arena
        .allocate(backing_layout)
        .expect("free buddies must coalesce");
    assert_eq!(arena.stats().peak_allocated_bytes, backing_layout.size());
    assert!(
        arena
            .allocate(Layout::from_size_align(8, 8).unwrap())
            .is_none()
    );
    // SAFETY: whole is the sole live allocation with its original exact layout.
    unsafe { arena.deallocate(whole, backing_layout) };
    drop(arena);
    // SAFETY: the arena and every suballocation have been retired; this is the
    // original std allocation and Layout, with no remaining access through aliases.
    unsafe { dealloc(backing, backing_layout) };
}

#[test]
fn unsupported_layouts_leave_the_single_arena_available() {
    let backing_layout = Layout::from_size_align(65536, 65536).unwrap();
    // SAFETY: nonzero valid layout; this test retains exclusive ownership until
    // every block is retired and the allocator is dropped below.
    let backing = unsafe { alloc(backing_layout) };
    assert!(!backing.is_null());
    // SAFETY: the complete owned writable region stays live without competing
    // accesses until the allocator and returned whole-region block are retired.
    let mut arena = unsafe { ArenaHeap::from_region(backing, backing_layout.size()) }.unwrap();
    for layout in [
        Layout::from_size_align(0, 8).unwrap(),
        Layout::from_size_align(65537, 1).unwrap(),
        Layout::from_size_align(1, 131072).unwrap(),
        Layout::from_size_align(isize::MAX as usize, 1).unwrap(),
    ] {
        assert!(arena.allocate(layout).is_none());
        assert_eq!(arena.stats().used_bytes, 0);
        assert_eq!(arena.stats().allocated_bytes, 0);
        assert_eq!(arena.stats().reserved_bytes, backing_layout.size());
    }
    let whole = arena.allocate(backing_layout).unwrap();
    // SAFETY: whole is the sole live block, returned for exactly backing_layout.
    unsafe { arena.deallocate(whole, backing_layout) };
    drop(arena);
    // SAFETY: all arena ownership is retired; backing and layout are exactly
    // those returned/used by the original std allocation.
    unsafe { dealloc(backing, backing_layout) };
}
