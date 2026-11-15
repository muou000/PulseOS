//! Repeatable demand-fault workload for the freestanding sampling guest.
//!
//! The deployment is the parent guest's RV64/LA64 Linux-shaped syscall ABI.
//! Each call owns three fresh anonymous pages until munmap. The middle page
//! is made inaccessible before the end pages are touched, separating their VMAs. The syscall/OS mapping contract is the external premise for the
//! raw accesses; this module neither borrows nor exposes the mapped bytes.
use super::*;

/// Exercise read-first and write-first VMAs separated by an inaccessible page.
///
/// The returned addresses identify the two first-touch instructions' targets
/// for capture validation. The mapping has already been removed on return;
/// these numeric addresses are evidence only, not pointers a caller may read.
/// Every phase calls this same paced workload, including the 1 ms sleep after
/// munmap that allows the sampling worker to consume completed observations.
pub fn iteration() -> (usize, usize) {
    const LENGTH: usize = 3 * PAGE;
    const PROT_READ_WRITE: usize = 3;
    const MAP_PRIVATE_ANONYMOUS: usize = 0x22;
    let base = ok(
        "fault workload mmap",
        syscall(
            222,
            0,
            LENGTH,
            PROT_READ_WRITE,
            MAP_PRIVATE_ANONYMOUS,
            usize::MAX,
            0,
        ),
    );
    check!(
        base != 0 && base % PAGE == 0,
        "fault workload mapping alignment"
    );
    check!(
        base.checked_add(LENGTH).is_some(),
        "fault workload mapping overflows address space"
    );

    // Anonymous fault allocation can populate a bounded batch through the
    // current VMA. Splitting at a PROT_NONE guard stops the read fault from
    // pre-populating the later write-first page without changing that policy.
    check!(
        syscall(226, base + PAGE, PAGE, 0, 0, 0, 0) == 0,
        "fault workload guard mprotect"
    );

    // SAFETY: successful mmap supplies an exclusively owned, initialized
    // three-page range under the guest syscall/OS contract. mprotect changes
    // only [base + PAGE, base + 2*PAGE) to inaccessible; neither load nor store
    // below touches that guard. The two end pages retain read/write permission
    // and are live through all accesses. The checked nonnull aligned base and
    // nonoverflowing extent cover each end-page u8 offset (< 3 * PAGE).
    // u8 has alignment one and every bit pattern is valid. No Rust reference,
    // aliasing thread or BPF program is given the allocation; no unmap occurs
    // until after all accesses, and no access follows munmap. Demand paging is
    // serviced by the OS while preserving this ordinary mapped-memory contract.
    // read_volatile/write_volatile retain these actual accesses; they do not
    // provide synchronization and none is required for this private allocation.
    // See core::ptr::{read_volatile,write_volatile}'s allocation safety rules.
    unsafe {
        let read_first = base as *mut u8;
        let write_first = read_first.add(2 * PAGE);

        // A load must be the first access to page 0; reading both pages first
        // could leave no first-write fault to observe on a writable mapping.
        for offset in 0..PAGE {
            check!(
                core::ptr::read_volatile(read_first.add(offset)) == 0,
                "read-first anonymous page was not zero-filled"
            );
        }
        core::ptr::write_volatile(read_first, 0xa5);
        core::ptr::write_volatile(read_first.add(PAGE - 1), 0xc3);
        check!(
            core::ptr::read_volatile(read_first) == 0xa5
                && core::ptr::read_volatile(read_first.add(PAGE - 1)) == 0xc3,
            "read-first page did not retain writes"
        );

        // A store is the first access to page 2; page 1 is never touched. Check the rest of the new page
        // for zero fill after that store, then verify both written locations.
        core::ptr::write_volatile(write_first, 0x5a);
        for offset in 1..PAGE {
            check!(
                core::ptr::read_volatile(write_first.add(offset)) == 0,
                "write-first anonymous page was not zero-filled"
            );
        }
        core::ptr::write_volatile(write_first.add(PAGE - 1), 0x3c);
        check!(
            core::ptr::read_volatile(write_first) == 0x5a
                && core::ptr::read_volatile(write_first.add(PAGE - 1)) == 0x3c,
            "write-first page did not retain writes"
        );
    }

    check!(
        syscall(215, base, LENGTH, 0, 0, 0, 0) == 0,
        "fault workload munmap"
    );
    sleep_ms(1);
    (base, base + 2 * PAGE)
}
