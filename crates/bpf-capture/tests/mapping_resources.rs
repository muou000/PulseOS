//! Mapping validation runs inside the guest recorder after source quiescence.
//! Heap allocation there is observable kernel mapping work, so validation must
//! not allocate an owned copy of every journal row just to discard it.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    time::Instant,
};

use bpf_capture::mapping::{Artifact, MappingMetadata};

thread_local! {
    static MEASURE: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
struct CountAllocations;
fn count() {
    let _ = MEASURE.try_with(|enabled| {
        if enabled.get() {
            ALLOCATIONS.with(|count| count.set(count.get() + 1));
        }
    });
}
// SAFETY: all allocation/deallocation requests are forwarded unchanged to
// System. The const-initialized thread-local counters allocate no memory,
// never inspect allocation contents and preserve System's ownership contract.
unsafe impl GlobalAlloc for CountAllocations {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: GlobalAlloc's caller supplies a valid Layout; forwarding it
        // unchanged delegates allocation and its ownership to System.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: every successful allocation came unchanged from System;
        // GlobalAlloc's caller supplies that live allocation and original layout.
        unsafe { System.dealloc(pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count();
        // SAFETY: caller guarantees the original allocation/layout and valid
        // nonzero new size; all are forwarded unchanged to their System owner.
        unsafe { System.realloc(pointer, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: CountAllocations = CountAllocations;

fn fixture() -> MappingMetadata {
    let mut rows = String::new();
    for index in 0..2000 {
        let first = index * 2 + 1;
        let second = first + 1;
        rows.push_str(&format!(
            "SPACE seq={first} ts={first} space=1 revision={index} begin_ns={first} count=4\nMAP \
             start=4096 len=4096 pgoff=0 perms=5 object=1\nMAP start=8192 len=4096 pgoff=4096 \
             perms=5 object=1\nMAP start=12288 len=4096 pgoff=8192 perms=3 object=1\nMAP \
             start=16384 len=4096 pgoff=0 perms=3 object=0\nENDSPACE\nTASK seq={second} \
             ts={second} task=1 pid=7 tid=8 space=1 exec=1 kind=rename begin_ns={second} parent=0 \
             class=user comm_hex=776f726b6572\n"
        ));
    }
    MappingMetadata {
        journal: format!(
            "PULSE_BPF_MAPPINGS version=2 available=1 started_ns=0 snapshot_ns=5000 dropped=0 \
             records=4000\n{rows}END records=4000 dropped=0 snapshot_ns=5000\n"
        ),
        artifacts: vec![Artifact {
            sha256: "ab".repeat(32),
            gnu_build_id: None,
            path: format!("artifacts/{}.elf", "ab".repeat(32)),
            debug_sha256: None,
            debug_build_id: None,
        }],
        kernel: None,
    }
}

#[test]
fn validating_bounded_mapping_evidence_does_not_allocate_guest_mappings() {
    let metadata = fixture();
    let started = Instant::now();
    ALLOCATIONS.with(|count| count.set(0));
    MEASURE.with(|enabled| enabled.set(true));
    let result = metadata.validate();
    MEASURE.with(|enabled| enabled.set(false));
    let elapsed = started.elapsed();
    let allocations = ALLOCATIONS.with(Cell::get);
    eprintln!(
        "MAPPING_VALIDATION bytes={} allocations={allocations} elapsed_ns={}",
        metadata.journal.len(),
        elapsed.as_nanos()
    );
    result.unwrap();
    assert_eq!(
        allocations, 0,
        "validation must not create guest mapping observation work"
    );
}
