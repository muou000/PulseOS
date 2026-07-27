use core::{
    cmp::Ordering,
    sync::atomic::{AtomicUsize, Ordering as AtomicOrdering},
};

use memory_addr::{MemoryAddr, VirtAddr, va_range};

use crate::{MappingBackend, MappingError, MappingMutation, MemoryArea, MemorySet};

const MAX_ADDR: usize = 0x10000;

type MockFlags = u8;
type MockPageTable = [MockFlags; MAX_ADDR];

#[derive(Clone)]
struct MockBackend;

type MockMemorySet = MemorySet<MockBackend>;

impl MappingBackend for MockBackend {
    type Addr = VirtAddr;
    type Flags = MockFlags;
    type PageTable = MockPageTable;
    type Reclaim = Vec<(usize, usize)>;

    fn map(&self, start: VirtAddr, size: usize, flags: MockFlags, pt: &mut MockPageTable) -> bool {
        for entry in pt.iter_mut().skip(start.as_usize()).take(size) {
            if *entry != 0 {
                return false;
            }
            *entry = flags;
        }
        true
    }

    fn unmap(
        &self,
        start: VirtAddr,
        size: usize,
        pt: &mut MockPageTable,
        reclaim: &mut Self::Reclaim,
    ) -> bool {
        reclaim.push((start.as_usize(), size));
        for entry in pt.iter_mut().skip(start.as_usize()).take(size) {
            if *entry == 0 {
                return false;
            }
            *entry = 0;
        }
        true
    }

    fn protect(
        &self,
        start: VirtAddr,
        size: usize,
        new_flags: MockFlags,
        pt: &mut MockPageTable,
    ) -> bool {
        for entry in pt.iter_mut().skip(start.as_usize()).take(size) {
            if *entry == 0 {
                return false;
            }
            *entry = new_flags;
        }
        true
    }
}

#[derive(Clone)]
struct RejectProtectBackend;

impl MappingBackend for RejectProtectBackend {
    type Addr = VirtAddr;
    type Flags = MockFlags;
    type PageTable = MockPageTable;
    type Reclaim = Vec<(usize, usize)>;

    fn map(&self, start: VirtAddr, size: usize, flags: MockFlags, pt: &mut MockPageTable) -> bool {
        MockBackend.map(start, size, flags, pt)
    }

    fn unmap(
        &self,
        start: VirtAddr,
        size: usize,
        pt: &mut MockPageTable,
        reclaim: &mut Self::Reclaim,
    ) -> bool {
        MockBackend.unmap(start, size, pt, reclaim)
    }

    fn protect(
        &self,
        _start: VirtAddr,
        _size: usize,
        _new_flags: MockFlags,
        _pt: &mut MockPageTable,
    ) -> bool {
        false
    }
}

#[derive(Clone)]
struct RejectUnmapBackend;

impl MappingBackend for RejectUnmapBackend {
    type Addr = VirtAddr;
    type Flags = MockFlags;
    type PageTable = MockPageTable;
    type Reclaim = Vec<(usize, usize)>;

    fn map(&self, start: VirtAddr, size: usize, flags: MockFlags, pt: &mut MockPageTable) -> bool {
        MockBackend.map(start, size, flags, pt)
    }

    fn unmap(
        &self,
        start: VirtAddr,
        size: usize,
        pt: &mut MockPageTable,
        reclaim: &mut Self::Reclaim,
    ) -> bool {
        let _ = MockBackend.unmap(start, size, pt, reclaim);
        false
    }

    fn protect(
        &self,
        start: VirtAddr,
        size: usize,
        new_flags: MockFlags,
        pt: &mut MockPageTable,
    ) -> bool {
        MockBackend.protect(start, size, new_flags, pt)
    }
}

#[derive(Clone)]
struct ConditionalUnmapBackend {
    reject: bool,
}

impl MappingBackend for ConditionalUnmapBackend {
    type Addr = VirtAddr;
    type Flags = MockFlags;
    type PageTable = MockPageTable;
    type Reclaim = Vec<(usize, usize)>;

    fn map(&self, start: VirtAddr, size: usize, flags: MockFlags, pt: &mut MockPageTable) -> bool {
        MockBackend.map(start, size, flags, pt)
    }

    fn unmap(
        &self,
        start: VirtAddr,
        size: usize,
        pt: &mut MockPageTable,
        reclaim: &mut Self::Reclaim,
    ) -> bool {
        let success = MockBackend.unmap(start, size, pt, reclaim);
        success && !self.reject
    }

    fn protect(
        &self,
        start: VirtAddr,
        size: usize,
        new_flags: MockFlags,
        pt: &mut MockPageTable,
    ) -> bool {
        MockBackend.protect(start, size, new_flags, pt)
    }
}

static ADDRESS_COMPARISONS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CountingAddr(usize);

impl From<usize> for CountingAddr {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

impl From<CountingAddr> for usize {
    fn from(value: CountingAddr) -> Self {
        value.0
    }
}

impl Ord for CountingAddr {
    fn cmp(&self, other: &Self) -> Ordering {
        ADDRESS_COMPARISONS.fetch_add(1, AtomicOrdering::Relaxed);
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for CountingAddr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone)]
struct CountingBackend;

impl MappingBackend for CountingBackend {
    type Addr = CountingAddr;
    type Flags = MockFlags;
    type PageTable = MockPageTable;
    type Reclaim = Vec<(usize, usize)>;

    fn map(
        &self,
        start: CountingAddr,
        size: usize,
        flags: MockFlags,
        pt: &mut MockPageTable,
    ) -> bool {
        for entry in pt.iter_mut().skip(start.into()).take(size) {
            if *entry != 0 {
                return false;
            }
            *entry = flags;
        }
        true
    }

    fn unmap(
        &self,
        start: CountingAddr,
        size: usize,
        pt: &mut MockPageTable,
        reclaim: &mut Self::Reclaim,
    ) -> bool {
        let start = usize::from(start);
        reclaim.push((start, size));
        for entry in pt.iter_mut().skip(start).take(size) {
            if *entry == 0 {
                return false;
            }
            *entry = 0;
        }
        true
    }

    fn protect(
        &self,
        start: CountingAddr,
        size: usize,
        new_flags: MockFlags,
        pt: &mut MockPageTable,
    ) -> bool {
        for entry in pt.iter_mut().skip(start.into()).take(size) {
            if *entry == 0 {
                return false;
            }
            *entry = new_flags;
        }
        true
    }
}

#[derive(Clone)]
struct ConditionalProtectBackend {
    reject: bool,
}

#[derive(Clone)]
struct PartialTrackingBackend {
    fail_at: usize,
}

impl MappingBackend for PartialTrackingBackend {
    type Addr = VirtAddr;
    type Flags = MockFlags;
    type PageTable = MockPageTable;
    type Reclaim = Vec<(usize, usize)>;

    fn map(&self, start: VirtAddr, size: usize, flags: MockFlags, pt: &mut MockPageTable) -> bool {
        MockBackend.map(start, size, flags, pt)
    }

    fn unmap(
        &self,
        start: VirtAddr,
        size: usize,
        pt: &mut MockPageTable,
        reclaim: &mut Self::Reclaim,
    ) -> bool {
        MockBackend.unmap(start, size, pt, reclaim)
    }

    fn protect(
        &self,
        start: VirtAddr,
        size: usize,
        new_flags: MockFlags,
        pt: &mut MockPageTable,
    ) -> bool {
        MockBackend.protect(start, size, new_flags, pt)
    }

    fn protect_tracked<M: MappingMutation<VirtAddr>>(
        &self,
        start: VirtAddr,
        size: usize,
        new_flags: MockFlags,
        pt: &mut MockPageTable,
        mutation: &mut M,
    ) -> bool {
        for addr in start.as_usize()..start.as_usize() + size {
            if addr == self.fail_at || pt[addr] == 0 {
                return false;
            }
            if pt[addr] != new_flags {
                pt[addr] = new_flags;
                mutation.record(addr.into(), 1);
            }
        }
        true
    }
}

#[derive(Default)]
struct RecordedMutations(Vec<(usize, usize)>);

impl MappingMutation<VirtAddr> for RecordedMutations {
    fn record(&mut self, start: VirtAddr, size: usize) {
        self.0.push((start.as_usize(), size));
    }
}

impl MappingBackend for ConditionalProtectBackend {
    type Addr = VirtAddr;
    type Flags = MockFlags;
    type PageTable = MockPageTable;
    type Reclaim = Vec<(usize, usize)>;

    fn map(&self, start: VirtAddr, size: usize, flags: MockFlags, pt: &mut MockPageTable) -> bool {
        MockBackend.map(start, size, flags, pt)
    }

    fn unmap(
        &self,
        start: VirtAddr,
        size: usize,
        pt: &mut MockPageTable,
        reclaim: &mut Self::Reclaim,
    ) -> bool {
        MockBackend.unmap(start, size, pt, reclaim)
    }

    fn protect(
        &self,
        start: VirtAddr,
        size: usize,
        new_flags: MockFlags,
        pt: &mut MockPageTable,
    ) -> bool {
        !self.reject && MockBackend.protect(start, size, new_flags, pt)
    }
}

macro_rules! assert_ok {
    ($expr:expr) => {
        assert!(($expr).is_ok())
    };
}

macro_rules! assert_err {
    ($expr:expr) => {
        assert!(($expr).is_err())
    };
    ($expr:expr, $err:ident) => {
        assert_eq!(($expr).err(), Some(MappingError::$err))
    };
}

fn dump_memory_set(set: &MockMemorySet) {
    use std::sync::Mutex;
    static DUMP_LOCK: Mutex<()> = Mutex::new(());

    let _lock = DUMP_LOCK.lock().unwrap();
    println!("Number of areas: {}", set.len());
    for area in set.iter() {
        println!("{:?}", area);
    }
}

fn mapped_ranges<B: MappingBackend>(set: &MemorySet<B>) -> Vec<(usize, usize)> {
    set.iter()
        .map(|area| (area.start().into(), area.end().into()))
        .collect()
}

#[test]
fn test_map_unmap() {
    let mut set = MockMemorySet::new();
    let mut pt = [0; MAX_ADDR];
    let mut reclaim = Vec::new();

    // Map [0, 0x1000), [0x2000, 0x3000), [0x4000, 0x5000), ...
    for start in (0..MAX_ADDR).step_by(0x2000) {
        assert_ok!(set.map(
            MemoryArea::new(start.into(), 0x1000, 1, MockBackend),
            &mut pt,
            false,
            &mut reclaim,
        ));
    }
    // Map [0x1000, 0x2000), [0x3000, 0x4000), [0x5000, 0x6000), ...
    for start in (0x1000..MAX_ADDR).step_by(0x2000) {
        assert_ok!(set.map(
            MemoryArea::new(start.into(), 0x1000, 2, MockBackend),
            &mut pt,
            false,
            &mut reclaim,
        ));
    }
    dump_memory_set(&set);
    assert_eq!(set.len(), 16);
    for &e in &pt[0..MAX_ADDR] {
        assert!(e == 1 || e == 2);
    }

    // Found [0x4000, 0x5000), flags = 1.
    let area = set.find(0x4100.into()).unwrap();
    assert_eq!(area.start(), 0x4000.into());
    assert_eq!(area.end(), 0x5000.into());
    assert_eq!(area.flags(), 1);
    assert_eq!(pt[0x4200], 1);

    // The area [0x4000, 0x8000) is already mapped, map returns an error.
    assert_err!(
        set.map(
            MemoryArea::new(0x4000.into(), 0x4000, 3, MockBackend),
            &mut pt,
            false,
            &mut reclaim,
        ),
        AlreadyExists
    );
    // Unmap overlapped areas before adding the new mapping [0x4000, 0x8000).
    assert_ok!(set.map(
        MemoryArea::new(0x4000.into(), 0x4000, 3, MockBackend),
        &mut pt,
        true,
        &mut reclaim,
    ));
    assert!(!reclaim.is_empty());
    reclaim.clear();
    dump_memory_set(&set);
    assert_eq!(set.len(), 13);

    // Found [0x4000, 0x8000), flags = 3.
    let area = set.find(0x4100.into()).unwrap();
    assert_eq!(area.start(), 0x4000.into());
    assert_eq!(area.end(), 0x8000.into());
    assert_eq!(area.flags(), 3);
    for &e in &pt[0x4000..0x8000] {
        assert_eq!(e, 3);
    }

    // Unmap areas in the middle.
    assert_ok!(set.unmap(0x4000.into(), 0x8000, &mut pt, &mut reclaim));
    assert!(!reclaim.is_empty());
    assert_eq!(set.len(), 8);
    // Unmap the remaining areas, including the unmapped ranges.
    assert_ok!(set.unmap(0.into(), MAX_ADDR * 2, &mut pt, &mut reclaim));
    assert_eq!(set.len(), 0);
    for &e in &pt[0..MAX_ADDR] {
        assert_eq!(e, 0);
    }
}

#[test]
fn test_unmap_split() {
    let mut set = MockMemorySet::new();
    let mut pt = [0; MAX_ADDR];
    let mut reclaim = Vec::new();

    // Map [0, 0x1000), [0x2000, 0x3000), [0x4000, 0x5000), ...
    for start in (0..MAX_ADDR).step_by(0x2000) {
        assert_ok!(set.map(
            MemoryArea::new(start.into(), 0x1000, 1, MockBackend),
            &mut pt,
            false,
            &mut reclaim,
        ));
    }
    assert_eq!(set.len(), 8);

    // Unmap [0xc00, 0x2400), [0x2c00, 0x4400), [0x4c00, 0x6400), ...
    // The areas are shrinked at the left and right boundaries.
    for start in (0..MAX_ADDR).step_by(0x2000) {
        assert_ok!(set.unmap((start + 0xc00).into(), 0x1800, &mut pt, &mut reclaim));
    }
    dump_memory_set(&set);
    assert_eq!(set.len(), 8);

    for area in set.iter() {
        if area.start().as_usize() == 0 {
            assert_eq!(area.size(), 0xc00);
        } else {
            assert_eq!(area.start().align_offset_4k(), 0x400);
            assert_eq!(area.end().align_offset_4k(), 0xc00);
            assert_eq!(area.size(), 0x800);
        }
        for &e in &pt[area.start().as_usize()..area.end().as_usize()] {
            assert_eq!(e, 1);
        }
    }

    // Unmap [0x800, 0x900), [0x2800, 0x2900), [0x4800, 0x4900), ...
    // The areas are split into two areas.
    for start in (0..MAX_ADDR).step_by(0x2000) {
        assert_ok!(set.unmap((start + 0x800).into(), 0x100, &mut pt, &mut reclaim));
    }
    dump_memory_set(&set);
    assert_eq!(set.len(), 16);

    for area in set.iter() {
        let off = area.start().align_offset_4k();
        if off == 0 {
            assert_eq!(area.size(), 0x800);
        } else if off == 0x400 {
            assert_eq!(area.size(), 0x400);
        } else if off == 0x900 {
            assert_eq!(area.size(), 0x300);
        } else {
            unreachable!();
        }
        for &e in &pt[area.start().as_usize()..area.end().as_usize()] {
            assert_eq!(e, 1);
        }
    }
    let mut iter = set.iter();
    while let Some(area) = iter.next() {
        if let Some(next) = iter.next() {
            for &e in &pt[area.end().as_usize()..next.start().as_usize()] {
                assert_eq!(e, 0);
            }
        }
    }
    drop(iter);

    // Unmap all areas.
    assert_ok!(set.unmap(0.into(), MAX_ADDR, &mut pt, &mut reclaim));
    assert_eq!(set.len(), 0);
    for &e in &pt[0..MAX_ADDR] {
        assert_eq!(e, 0);
    }
}

#[test]
fn test_unmap_boundary_shapes_holes_and_full_removal() {
    let mut set = MockMemorySet::new();
    let mut pt = [0; MAX_ADDR];
    let mut reclaim = Vec::new();
    for start in [0x1000, 0x3000, 0x5000] {
        assert_ok!(set.map(
            MemoryArea::new(start.into(), 0x1000, 1, MockBackend),
            &mut pt,
            false,
            &mut reclaim,
        ));
    }

    // Right trim crossing the following hole.
    assert_ok!(set.unmap(0x1800.into(), 0x1000, &mut pt, &mut reclaim));
    // Left trim starting in the preceding hole.
    assert_ok!(set.unmap(0x4800.into(), 0x1000, &mut pt, &mut reclaim));
    // Split the middle area without touching either neighbor.
    assert_ok!(set.unmap(0x3400.into(), 0x400, &mut pt, &mut reclaim));

    assert_eq!(
        mapped_ranges(&set),
        [
            (0x1000, 0x1800),
            (0x3000, 0x3400),
            (0x3800, 0x4000),
            (0x5800, 0x6000),
        ]
    );
    assert_eq!(reclaim, [(0x1800, 0x800), (0x5000, 0x800), (0x3400, 0x400)]);

    assert_ok!(set.unmap(0.into(), MAX_ADDR, &mut pt, &mut reclaim));
    assert!(set.is_empty());
    assert!(pt.iter().all(|&entry| entry == 0));
}

#[test]
fn test_unmap_continues_contained_areas_before_returning_failure() {
    let mut set = MemorySet::<ConditionalUnmapBackend>::new();
    let mut pt = [0; MAX_ADDR];
    let mut reclaim = Vec::new();
    for (start, size, reject) in [
        (0x0800, 0x1000, false),
        (0x2000, 0x0800, false),
        (0x3000, 0x0800, true),
        (0x4000, 0x0800, false),
        (0x5000, 0x1000, false),
    ] {
        assert_ok!(set.map(
            MemoryArea::new(start.into(), size, 1, ConditionalUnmapBackend { reject }),
            &mut pt,
            false,
            &mut reclaim,
        ));
    }

    assert_err!(
        set.unmap(0x1000.into(), 0x4800, &mut pt, &mut reclaim),
        BadState
    );

    assert_eq!(
        reclaim,
        [(0x2000, 0x0800), (0x3000, 0x0800), (0x4000, 0x0800)]
    );
    assert_eq!(
        mapped_ranges(&set),
        [(0x0800, 0x1800), (0x3000, 0x3800), (0x5000, 0x6000),]
    );
    assert!(pt[0x1000..0x1800].iter().all(|&entry| entry == 1));
    assert!(pt[0x5000..0x5800].iter().all(|&entry| entry == 1));
}

#[test]
fn test_narrow_unmap_is_bounded_with_many_unrelated_areas() {
    const AREA_COUNT: usize = 512;
    const AREA_SIZE: usize = 0x10;
    const AREA_STRIDE: usize = 0x20;

    let mut set = MemorySet::<CountingBackend>::new();
    let mut pt = [0; MAX_ADDR];
    let mut reclaim = Vec::new();
    for index in 0..AREA_COUNT {
        let start = 0x1000 + index * AREA_STRIDE;
        assert_ok!(set.map(
            MemoryArea::new(start.into(), AREA_SIZE, 1, CountingBackend),
            &mut pt,
            false,
            &mut reclaim,
        ));
    }

    let area_start = 0x1000 + 377 * AREA_STRIDE;
    let unmap_start = area_start + 4;
    ADDRESS_COMPARISONS.store(0, AtomicOrdering::Relaxed);
    assert_ok!(set.unmap(unmap_start.into(), 4, &mut pt, &mut reclaim));
    let comparisons = ADDRESS_COMPARISONS.load(AtomicOrdering::Relaxed);

    assert!(
        comparisons < AREA_COUNT / 2,
        "narrow unmap made {comparisons} address comparisons"
    );
    assert_eq!(set.len(), AREA_COUNT + 1);
    assert_eq!(reclaim, [(unmap_start, 4)]);
    assert_eq!(
        mapped_ranges(&set)[377..379],
        [
            (area_start, unmap_start),
            (unmap_start + 4, area_start + AREA_SIZE)
        ]
    );
}

#[test]
fn test_protect() {
    let mut set = MockMemorySet::new();
    let mut pt = [0; MAX_ADDR];
    let mut reclaim = Vec::new();
    let update_flags = |new_flags: MockFlags| {
        move |old_flags: MockFlags| -> Option<MockFlags> {
            if (old_flags & 0x7) == (new_flags & 0x7) {
                return None;
            }
            let flags = (new_flags & 0x7) | (old_flags & !0x7);
            Some(flags)
        }
    };

    // Map [0, 0x1000), [0x2000, 0x3000), [0x4000, 0x5000), ...
    for start in (0..MAX_ADDR).step_by(0x2000) {
        assert_ok!(set.map(
            MemoryArea::new(start.into(), 0x1000, 0x7, MockBackend),
            &mut pt,
            false,
            &mut reclaim,
        ));
    }
    assert_eq!(set.len(), 8);

    // Protect [0xc00, 0x2400), [0x2c00, 0x4400), [0x4c00, 0x6400), ...
    // The areas are split into two areas.
    for start in (0..MAX_ADDR).step_by(0x2000) {
        assert_ok!(set.protect((start + 0xc00).into(), 0x1800, update_flags(0x1), &mut pt));
    }
    dump_memory_set(&set);
    assert_eq!(set.len(), 23);

    for area in set.iter() {
        let off = area.start().align_offset_4k();
        if area.start().as_usize() == 0 {
            assert_eq!(area.size(), 0xc00);
            assert_eq!(area.flags(), 0x7);
        } else if off == 0 {
            assert_eq!(area.size(), 0x400);
            assert_eq!(area.flags(), 0x1);
        } else if off == 0x400 {
            assert_eq!(area.size(), 0x800);
            assert_eq!(area.flags(), 0x7);
        } else if off == 0xc00 {
            assert_eq!(area.size(), 0x400);
            assert_eq!(area.flags(), 0x1);
        }
    }

    // Protect [0x800, 0x900), [0x2800, 0x2900), [0x4800, 0x4900), ...
    // The areas are split into three areas.
    for start in (0..MAX_ADDR).step_by(0x2000) {
        assert_ok!(set.protect((start + 0x800).into(), 0x100, update_flags(0x13), &mut pt));
    }
    dump_memory_set(&set);
    assert_eq!(set.len(), 39);

    for area in set.iter() {
        let off = area.start().align_offset_4k();
        if area.start().as_usize() == 0 {
            assert_eq!(area.size(), 0x800);
            assert_eq!(area.flags(), 0x7);
        } else if off == 0 {
            assert_eq!(area.size(), 0x400);
            assert_eq!(area.flags(), 0x1);
        } else if off == 0x400 {
            assert_eq!(area.size(), 0x400);
            assert_eq!(area.flags(), 0x7);
        } else if off == 0x800 {
            assert_eq!(area.size(), 0x100);
            assert_eq!(area.flags(), 0x3);
        } else if off == 0x900 {
            assert_eq!(area.size(), 0x300);
            assert_eq!(area.flags(), 0x7);
        } else if off == 0xc00 {
            assert_eq!(area.size(), 0x400);
            assert_eq!(area.flags(), 0x1);
        }
    }

    // Test skip [0x880, 0x900), [0x2880, 0x2900), [0x4880, 0x4900), ...
    for start in (0..MAX_ADDR).step_by(0x2000) {
        assert_ok!(set.protect((start + 0x880).into(), 0x80, update_flags(0x3), &mut pt));
    }
    assert_eq!(set.len(), 39);

    // Unmap all areas.
    assert_ok!(set.unmap(0.into(), MAX_ADDR, &mut pt, &mut reclaim));
    assert_eq!(set.len(), 0);
    for &e in &pt[0..MAX_ADDR] {
        assert_eq!(e, 0);
    }
}

#[test]
fn test_protect_failure_is_propagated() {
    let mut set = MemorySet::<RejectProtectBackend>::new();
    let mut pt = [0; MAX_ADDR];
    let mut reclaim = Vec::new();
    assert_ok!(set.map(
        MemoryArea::new(0x1000.into(), 0x3000, 0x7, RejectProtectBackend),
        &mut pt,
        false,
        &mut reclaim,
    ));

    assert_err!(
        set.protect(0x2000.into(), 0x1000, |_| Some(0x1), &mut pt),
        BadState
    );
    assert_eq!(set.len(), 1);
    assert_eq!(
        set.find(0x1000.into()).unwrap().va_range(),
        va_range!(0x1000..0x4000)
    );
    assert!(pt[0x1000..0x4000].iter().all(|&flags| flags == 0x7));
}

#[test]
fn test_unmap_failure_preserves_area_layout() {
    let mut set = MemorySet::<RejectUnmapBackend>::new();
    let mut pt = [0; MAX_ADDR];
    let mut reclaim = Vec::new();
    assert_ok!(set.map(
        MemoryArea::new(0x1000.into(), 0x3000, 0x7, RejectUnmapBackend),
        &mut pt,
        false,
        &mut reclaim,
    ));

    assert_err!(
        set.unmap(0x2000.into(), 0x1000, &mut pt, &mut reclaim),
        BadState
    );
    assert_eq!(set.len(), 1);
    assert_eq!(
        set.find(0x1000.into()).unwrap().va_range(),
        va_range!(0x1000..0x4000)
    );
    assert_eq!(reclaim, [(0x2000, 0x1000)]);
}

#[test]
fn test_protect_commits_prior_splits_before_later_failure() {
    let mut set = MemorySet::<ConditionalProtectBackend>::new();
    let mut pt = [0; MAX_ADDR];
    let mut reclaim = Vec::new();
    for (start, reject) in [(0x1000, false), (0x4000, true)] {
        assert_ok!(set.map(
            MemoryArea::new(
                start.into(),
                0x2000,
                0x7,
                ConditionalProtectBackend { reject },
            ),
            &mut pt,
            false,
            &mut reclaim,
        ));
    }

    assert_err!(
        set.protect(0x2000.into(), 0x3000, |_| Some(0x1), &mut pt),
        BadState
    );
    let areas = set.iter().collect::<Vec<_>>();
    assert_eq!(areas.len(), 3);
    assert_eq!(areas[0].va_range(), va_range!(0x1000..0x2000));
    assert_eq!(areas[0].flags(), 0x7);
    assert_eq!(areas[1].va_range(), va_range!(0x2000..0x3000));
    assert_eq!(areas[1].flags(), 0x1);
    assert_eq!(areas[2].va_range(), va_range!(0x4000..0x6000));
    assert_eq!(areas[2].flags(), 0x7);
}

#[test]
fn test_tracked_protect_skips_unchanged_entries() {
    let mut set = MemorySet::<PartialTrackingBackend>::new();
    let mut pt = [0; MAX_ADDR];
    let mut reclaim = Vec::new();
    assert_ok!(set.map(
        MemoryArea::new(
            0x1000.into(),
            4,
            0x7,
            PartialTrackingBackend {
                fail_at: usize::MAX
            },
        ),
        &mut pt,
        false,
        &mut reclaim,
    ));

    let mut mutation = RecordedMutations::default();
    assert_ok!(set.protect_tracked(0x1000.into(), 4, |_| Some(0x7), &mut pt, &mut mutation,));
    assert!(mutation.0.is_empty());
}

#[test]
fn test_tracked_protect_keeps_changes_before_failure() {
    let mut set = MemorySet::<PartialTrackingBackend>::new();
    let mut pt = [0; MAX_ADDR];
    let mut reclaim = Vec::new();
    assert_ok!(set.map(
        MemoryArea::new(
            0x2000.into(),
            4,
            0x7,
            PartialTrackingBackend { fail_at: 0x2002 },
        ),
        &mut pt,
        false,
        &mut reclaim,
    ));

    let mut mutation = RecordedMutations::default();
    assert_err!(
        set.protect_tracked(0x2000.into(), 4, |_| Some(0x1), &mut pt, &mut mutation,),
        BadState
    );
    assert_eq!(mutation.0, [(0x2000, 1), (0x2001, 1)]);
    assert_eq!(&pt[0x2000..0x2004], &[0x1, 0x1, 0x7, 0x7]);
}

#[test]
fn test_clear_collects_all_reclaims_after_unmap_failure() {
    let mut set = MemorySet::<RejectUnmapBackend>::new();
    let mut pt = [0; MAX_ADDR];
    let mut reclaim = Vec::new();
    for start in [0x1000, 0x3000] {
        assert_ok!(set.map(
            MemoryArea::new(start.into(), 0x1000, 0x7, RejectUnmapBackend),
            &mut pt,
            false,
            &mut reclaim,
        ));
    }

    assert_err!(set.clear(&mut pt, &mut reclaim), BadState);
    assert!(set.is_empty());
    assert_eq!(reclaim, [(0x1000, 0x1000), (0x3000, 0x1000)]);
}

#[test]
fn test_find_free_area() {
    let mut set = MockMemorySet::new();
    let mut pt = [0; MAX_ADDR];
    let mut reclaim = Vec::new();

    // Map [0, 0x1000), [0x2000, 0x3000), ..., [0xe000, 0xf000)
    for start in (0..MAX_ADDR).step_by(0x2000) {
        assert_ok!(set.map(
            MemoryArea::new(start.into(), 0x1000, 1, MockBackend),
            &mut pt,
            false,
            &mut reclaim,
        ));
    }

    let addr = set.find_free_area(0.into(), 0x1000, va_range!(0..MAX_ADDR), 1);
    assert_eq!(addr, Some(0x1000.into()));

    let addr = set.find_free_area(0x800.into(), 0x800, va_range!(0..MAX_ADDR), 0x800);
    assert_eq!(addr, Some(0x1000.into()));

    let addr = set.find_free_area(0x1800.into(), 0x800, va_range!(0..MAX_ADDR), 0x800);
    assert_eq!(addr, Some(0x1800.into()));

    let addr = set.find_free_area(0x1800.into(), 0x1000, va_range!(0..MAX_ADDR), 0x1000);
    assert_eq!(addr, Some(0x3000.into()));

    let addr = set.find_free_area(0x2000.into(), 0x1000, va_range!(0..MAX_ADDR), 0x1000);
    assert_eq!(addr, Some(0x3000.into()));

    let addr = set.find_free_area(0xf000.into(), 0x1000, va_range!(0..MAX_ADDR), 0x1000);
    assert_eq!(addr, Some(0xf000.into()));

    let addr = set.find_free_area(0xf001.into(), 0x1000, va_range!(0..MAX_ADDR), 0x1000);
    assert_eq!(addr, None);
}

#[test]
fn test_iter_overlapping() {
    let mut set = MockMemorySet::new();
    let mut pt = [0; MAX_ADDR];
    let mut reclaim = Vec::new();

    for (start, size) in [(0x1000, 0x2000), (0x4000, 0x1000), (0x5000, 0x1000)] {
        assert_ok!(set.map(
            MemoryArea::new(start.into(), size, 1, MockBackend),
            &mut pt,
            false,
            &mut reclaim,
        ));
    }

    let ranges = |range| {
        set.iter_overlapping(range)
            .map(|area| area.va_range())
            .collect::<Vec<_>>()
    };

    assert_eq!(
        ranges(va_range!(0x1800..0x4800)),
        [va_range!(0x1000..0x3000), va_range!(0x4000..0x5000)]
    );
    assert_eq!(ranges(va_range!(0x3000..0x4000)), []);
    assert_eq!(
        ranges(va_range!(0x3000..0x5000)),
        [va_range!(0x4000..0x5000)]
    );
    assert_eq!(
        ranges(va_range!(0x5000..0x6000)),
        [va_range!(0x5000..0x6000)]
    );
    assert_eq!(ranges(va_range!(0x6000..0x6000)), []);

    for area in set.iter_overlapping_mut(va_range!(0x2800..0x5800)) {
        area.set_flags(2);
    }
    assert_eq!(set.find(0x1800.into()).unwrap().flags(), 2);
    assert_eq!(set.find(0x4800.into()).unwrap().flags(), 2);
    assert_eq!(set.find(0x5800.into()).unwrap().flags(), 2);
}
