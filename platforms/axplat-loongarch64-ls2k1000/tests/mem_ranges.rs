//! Host tests for the production range container, without board dependencies.
//! Run with `rustc --edition=2024 --test tests/mem_ranges.rs -o /tmp/ls2k1000-ranges`
//! from this platform directory, then `/tmp/ls2k1000-ranges`.

// Matches the alias in platforms/axplat/src/mem.rs.
type RawRange = (usize, usize);

#[path = "../src/mem/ranges.rs"]
mod ranges;

use ranges::{RangeList, RangeStorage};

#[test]
fn first_publication_wins() {
    let storage = RangeStorage::<2>::new();
    let before = storage.get();
    assert!(before.is_empty());
    let mut first = RangeList::new();
    assert!(first.push((0x1000, 0x2000)));
    storage.publish(&first);
    let published = storage.get();

    let mut second = RangeList::new();
    assert!(second.push((0x9000, 0x1000)));
    storage.publish(&second);

    assert!(before.is_empty());
    assert_eq!(published, &[(0x1000, 0x2000)]);
    assert_eq!(storage.get(), published);
}

#[test]
fn empty_publication_also_consumes_the_only_write() {
    let storage = RangeStorage::<1>::new();
    let mut ranges = RangeList::new();
    assert!(ranges.is_empty());
    storage.publish(&ranges);
    assert!(ranges.push((0x1000, 0x1000)));
    storage.publish(&ranges);
    assert!(storage.get().is_empty());
}

#[test]
fn zero_capacity_accepts_empty_ranges_and_rejects_entries() {
    let storage = RangeStorage::<0>::new();
    let mut ranges = RangeList::new();
    assert!(ranges.push((0x1000, 0)));
    assert!(!ranges.push((0x1000, 0x1000)));
    ranges.normalize();
    assert_eq!(ranges.len(), 0);
    storage.publish(&ranges);
    assert!(storage.get().is_empty());
}

#[test]
fn maximum_platform_capacities_preserve_every_entry_in_order() {
    fn check<const N: usize>() {
        let storage = RangeStorage::<N>::new();
        let mut ranges = RangeList::new();
        let expected: [RawRange; N] = core::array::from_fn(|i| (i * 0x2000, 0x1000));
        for range in expected {
            assert!(ranges.push(range));
        }
        assert!(!ranges.push((0xffff_0000, 0x1000)));
        assert_eq!(ranges.len(), N);
        storage.publish(&ranges);
        assert_eq!(storage.get(), expected);
    }

    check::<8>();
    check::<32>();
}

#[test]
fn normalization_sorts_and_merges_overlapping_adjacent_and_nested_ranges() {
    let mut ranges = RangeList::<8>::new();
    for range in [
        (0x9000, 0x1000),
        (0x3000, 0x3000),
        (0x2000, 0x1000),
        (0x1000, 0x3000),
        (0x6000, 0x1000),
        (0x3000, 0x3000),
        (usize::MAX - 0x1000, 0x2000),
        (0x8000, 0),
    ] {
        assert!(ranges.push(range));
    }
    ranges.normalize();
    assert_eq!(ranges.as_slice(), &[(0x1000, 0x6000), (0x9000, 0x1000)]);
    ranges.normalize();
    assert_eq!(ranges.as_slice(), &[(0x1000, 0x6000), (0x9000, 0x1000)]);

    let storage = RangeStorage::new();
    storage.publish(&ranges);
    assert_eq!(storage.get(), &[(0x1000, 0x6000), (0x9000, 0x1000)]);
}

#[test]
fn preserves_discontiguous_ls2k1000_ranges() {
    let mut ranges = RangeList::<4>::new();
    assert!(ranges.push((0x0020_0000, 0x0fe0_0000)));
    assert!(ranges.push((0x9000_0000, 0x3000_0000)));
    ranges.normalize();
    assert_eq!(
        ranges.as_slice(),
        &[(0x0020_0000, 0x0fe0_0000), (0x9000_0000, 0x3000_0000)]
    );
}

#[test]
fn racing_publishers_and_readers_observe_one_complete_immutable_list() {
    use std::{sync::Barrier, thread};

    for _ in 0..8 {
        let storage = RangeStorage::<32>::new();
        let start = Barrier::new(4);
        let mut first = RangeList::new();
        let mut second = RangeList::new();
        for _ in 0..32 {
            assert!(first.push((0x1000, 0x2000)));
        }
        for _ in 0..16 {
            assert!(second.push((0x9000, 0x1000)));
        }
        thread::scope(|scope| {
            for candidate in [&first, &second] {
                scope.spawn(|| {
                    start.wait();
                    storage.publish(candidate);
                });
            }
            for _ in 0..2 {
                scope.spawn(|| {
                    start.wait();
                    let published = loop {
                        let observed = storage.get();
                        if !observed.is_empty() {
                            break observed;
                        }
                        thread::yield_now();
                    };
                    assert!(published == first.as_slice() || published == second.as_slice());
                    for _ in 0..8 {
                        thread::yield_now();
                        assert_eq!(storage.get(), published);
                    }
                });
            }
        });
        let published = storage.get();
        assert!(published == first.as_slice() || published == second.as_slice());
    }
}
