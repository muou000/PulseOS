//! Bounded mapping-lifecycle checks executed in the initialized guest init task.
//! These use real page tables, cache frames, and fork; they do not test durability.

use axerrno::{AxError, AxResult};
use axfs::{CachedFile, File, OpenOptions, ROOT_FS_CONTEXT};
use axhal::{paging::MappingFlags, trap::PageFaultFlags};
use axmm::{FilePageLoad, MappingPlacement, PageFaultOutcome, PageFaultResult, PreparedMapping};
use axtask::future::block_on;
use memory_addr::{PhysAddr, VirtAddr, PAGE_SIZE_4K};

use crate::{
    config::{USER_SPACE_BASE, USER_SPACE_SIZE},
    task::AddressSpaceLock,
};

const TEST_VA: usize = 0x1000000;
const FILE_SIZE: usize = 3 * PAGE_SIZE_4K;
const TEST_PATH: &str = "/.pulse-mapping-lifecycle-check";
const CONTENTS: [[u8; 16]; 3] = [[0x31; 16], [0x52; 16], [0x73; 16]];

fn failure(case: &str, assertion: &str) -> AxError {
    axlog::ax_println!("MLC_KERNEL ASSERT FAIL {case} {assertion}");
    AxError::BadState
}

fn check(case: &str, assertion: &str, condition: bool) -> AxResult<()> {
    if condition {
        Ok(())
    } else {
        Err(failure(case, assertion))
    }
}

fn checked<T, E: core::fmt::Debug>(
    case: &str,
    operation: &str,
    result: Result<T, E>,
) -> AxResult<T> {
    result.map_err(|error| {
        axlog::ax_println!("MLC_KERNEL ASSERT FAIL {case} {operation}: {error:?}");
        AxError::BadState
    })
}

fn frame_refs(case: &str, frame: PhysAddr) -> AxResult<usize> {
    axalloc::frame_table().try_get_ref(frame).ok_or_else(|| {
        axlog::ax_println!("MLC_KERNEL ASSERT FAIL {case} frame {frame:#x} outside frame table");
        AxError::BadState
    })
}

fn expect_refs(case: &str, frame: PhysAddr, expected: usize) -> AxResult<()> {
    let actual = frame_refs(case, frame)?;
    if actual != expected {
        axlog::ax_println!(
            "MLC_KERNEL ASSERT FAIL {case} frame {frame:#x} refs={actual} expected={expected}"
        );
        return Err(AxError::BadState);
    }
    Ok(())
}

fn cache_frame(fixture: &Fixture, page: u32, case: &str) -> AxResult<PhysAddr> {
    checked(case, "resident cache frame", fixture.cached.shared_page_paddr(page))
}

fn mapped_frame(aspace: &AddressSpaceLock, address: VirtAddr, case: &str) -> AxResult<PhysAddr> {
    let (frame, flags, _) = checked(case, "query mapped PTE", aspace.read().query_vaddr(address))?;
    check(
        case,
        "PTE owns a readable user frame",
        frame.as_usize() != 0 && flags.contains(MappingFlags::READ | MappingFlags::USER),
    )?;
    Ok(frame)
}

fn absent(aspace: &AddressSpaceLock, address: VirtAddr, case: &str) -> AxResult<()> {
    // page_is_resident also consults the cache and cannot prove PTE absence.
    check(
        case,
        "PTE remains absent",
        !aspace.read().query_vaddr(address).is_ok_and(|(frame, _, _)| frame.as_usize() != 0),
    )
}

fn read_equals(
    aspace: &AddressSpaceLock,
    address: VirtAddr,
    expected: &[u8; 16],
    case: &str,
    assertion: &str,
) -> AxResult<()> {
    let mut bytes = [0; 16];
    checked(case, "read mapped bytes", aspace.read().read(address, &mut bytes))?;
    check(case, assertion, &bytes == expected)
}

fn resolve(aspace: &AddressSpaceLock, address: VirtAddr, flags: PageFaultFlags, case: &str) -> AxResult<()> {
    let handled = checked(case, "resolve guest page fault", aspace.resolve_page_fault(address, flags))?;
    check(case, "page fault handled", handled)
}

fn file_request(case: &str, result: PageFaultResult) -> AxResult<FilePageLoad> {
    match result {
        PageFaultResult::NeedFilePage(load) => Ok(load),
        other => {
            axlog::ax_println!("MLC_KERNEL ASSERT FAIL {case} expected NeedFilePage, got {other:?}");
            // Even an unexpected result can own a shootdown; complete it unlocked.
            checked(case, "complete unexpected fault", other.complete_after_unlock())?;
            Err(AxError::BadState)
        }
    }
}

fn new_aspace(case: &str) -> AxResult<AddressSpaceLock> {
    let end = USER_SPACE_BASE.checked_add(USER_SPACE_SIZE)
        .ok_or_else(|| failure(case, "configured user range does not overflow"))?;
    check(
        case,
        "low aligned test VA lies inside configured USER range",
        TEST_VA % PAGE_SIZE_4K == 0
            && TEST_VA >= USER_SPACE_BASE
            && TEST_VA.checked_add(4 * PAGE_SIZE_4K).is_some_and(|limit| limit <= end),
    )?;
    checked(
        case,
        "create guest user address space",
        axmm::new_user_aspace(VirtAddr::from(USER_SPACE_BASE), USER_SPACE_SIZE),
    ).map(AddressSpaceLock::new)
}

fn publish(
    aspace: &AddressSpaceLock,
    prepared: PreparedMapping,
    address: VirtAddr,
    replace: bool,
    case: &str,
) -> AxResult<()> {
    let placement = if replace {
        MappingPlacement::Fixed(address)
    } else {
        MappingPlacement::FixedNoReplace(address)
    };
    let actual = checked(case, "publish mapping", aspace.map(prepared, placement))?;
    check(case, "fixed mapping returns requested VA", actual == address)
}

struct Fixture {
    file: File,
    cached: CachedFile,
}

impl Fixture {
    fn new() -> AxResult<Self> {
        const CASE: &str = "setup";
        let context = ROOT_FS_CONTEXT.get()
            .ok_or_else(|| failure(CASE, "root filesystem context initialized"))?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(true);
        let opened = checked(CASE, "open read/write fixture with create/truncate", block_on(options.open(context, TEST_PATH)))?;
        let file = checked(CASE, "fixture is a regular file", opened.into_file())?;
        let cached = checked(CASE, "get actual shared file cache", CachedFile::get_or_create(file.location().clone()))?;
        checked(CASE, "set three-page fixture length", cached.set_len(FILE_SIZE as u64))?;
        for (page, bytes) in CONTENTS.iter().enumerate() {
            let written = checked(
                CASE,
                "initialize cached fixture page",
                block_on(cached.write_at_slice_async(bytes, (page * PAGE_SIZE_4K) as u64)),
            )?;
            check(CASE, "fixture write is complete", written == bytes.len())?;
        }
        Ok(Self { file, cached })
    }

    fn mapping(&self, case: &str, size: usize, offset: usize, shared: bool, writable: bool) -> AxResult<PreparedMapping> {
        let mut flags = MappingFlags::READ | MappingFlags::USER;
        if writable {
            flags |= MappingFlags::WRITE;
        }
        checked(
            case,
            "prepare file mapping",
            PreparedMapping::file(
                size,
                flags,
                self.cached.clone(),
                self.file.flags(),
                offset,
                size,
                shared,
                if shared && writable { self.file.write_access_guard() } else { None },
            ),
        )
    }
}

fn prepared_pin_drop(fixture: &Fixture) -> AxResult<()> {
    const CASE: &str = "prepared_pin_drop";
    let aspace = new_aspace(CASE)?;
    let address = VirtAddr::from(TEST_VA);
    publish(&aspace, fixture.mapping(CASE, FILE_SIZE, 0, true, false)?, address, false, CASE)?;

    // A cache-only frame can start at refcount zero. The first real preparation
    // establishes its cache owner; dropping it gives a stable ownership baseline.
    let initial = file_request(CASE, aspace.read().handle_page_fault(address, PageFaultFlags::READ))?;
    let primed = checked(CASE, "prime cache ownership through preparation", initial.prepare())?;
    drop(primed);
    let mut frames = [PhysAddr::from(0); 3];
    let mut baseline = [0; 3];
    for page in 0..3 {
        frames[page] = cache_frame(fixture, page as u32, CASE)?;
        baseline[page] = frame_refs(CASE, frames[page])?;
        check(CASE, "only the cache owns the primed frame", baseline[page] == 1)?;
    }
    let request = file_request(CASE, aspace.read().handle_page_fault(address, PageFaultFlags::READ))?;
    let prepared = checked(CASE, "prepare pinned file batch", request.prepare())?;
    for page in 0..3 {
        expect_refs(CASE, frames[page], baseline[page] + 1)?;
        absent(&aspace, address + page * PAGE_SIZE_4K, CASE)?;
    }
    drop(prepared);
    for page in 0..3 {
        expect_refs(CASE, frames[page], baseline[page])?;
    }
    checked(CASE, "unmap unused file batch", aspace.unmap(address, FILE_SIZE))
}

fn stale_file_replace(fixture: &Fixture) -> AxResult<()> {
    const CASE: &str = "stale_file_replace";
    let aspace = new_aspace(CASE)?;
    let address = VirtAddr::from(TEST_VA);
    let frame = cache_frame(fixture, 0, CASE)?;
    let baseline = frame_refs(CASE, frame)?;
    publish(&aspace, fixture.mapping(CASE, PAGE_SIZE_4K, 0, true, false)?, address, false, CASE)?;
    let request = file_request(CASE, aspace.read().handle_page_fault(address, PageFaultFlags::READ))?;
    let mut old = checked(CASE, "prepare original mapping page", request.prepare())?;
    expect_refs(CASE, frame, baseline + 1)?;

    // Same file, offset, flags, and VA: identity/generation must reject the old
    // preparation even though the underlying cache frame is still identical.
    publish(&aspace, fixture.mapping(CASE, PAGE_SIZE_4K, 0, true, false)?, address, true, CASE)?;
    absent(&aspace, address, CASE)?;
    let result = aspace.read().handle_prepared_file_page(address, PageFaultFlags::READ, &mut old);
    let fresh_request = file_request(CASE, result)?;
    absent(&aspace, address, CASE)?;
    expect_refs(CASE, frame, baseline + 1)?;
    drop(old);
    expect_refs(CASE, frame, baseline)?;

    let mut fresh = checked(CASE, "prepare replacement request", fresh_request.prepare())?;
    let committed = aspace.read().handle_prepared_file_page(address, PageFaultFlags::READ, &mut fresh);
    let outcome = checked(CASE, "complete fresh file commit", committed.complete_after_unlock())?;
    check(CASE, "fresh replacement commits", matches!(outcome, PageFaultOutcome::Handled(true)))?;
    drop(fresh);
    check(CASE, "replacement PTE owns actual cache frame", mapped_frame(&aspace, address, CASE)? == frame)?;
    expect_refs(CASE, frame, baseline + 1)?;
    read_equals(&aspace, address, &CONTENTS[0], CASE, "replacement reads initialized file bytes")?;
    checked(CASE, "unmap committed replacement", aspace.unmap(address, PAGE_SIZE_4K))?;
    expect_refs(CASE, frame, baseline)
}

fn deferred_file_unmap(fixture: &Fixture) -> AxResult<()> {
    const CASE: &str = "deferred_file_unmap";
    let aspace = new_aspace(CASE)?;
    let address = VirtAddr::from(TEST_VA);
    let frame = cache_frame(fixture, 0, CASE)?;
    let baseline = frame_refs(CASE, frame)?;
    publish(&aspace, fixture.mapping(CASE, PAGE_SIZE_4K, 0, true, false)?, address, false, CASE)?;
    resolve(&aspace, address, PageFaultFlags::READ, CASE)?;
    check(CASE, "committed file PTE owns cache frame", mapped_frame(&aspace, address, CASE)? == frame)?;
    read_equals(&aspace, address, &CONTENTS[0], CASE, "committed file bytes are intact")?;
    expect_refs(CASE, frame, baseline + 1)?;

    let mutation = { aspace.write().unmap(address, PAGE_SIZE_4K) };
    let (result, shootdown) = mutation.into_parts();
    let before_completion = (|| {
        checked(CASE, "unmap mutation", result)?;
        absent(&aspace, address, CASE)?;
        // Both the removed PTE owner and the dirty-publication pin stay alive.
        expect_refs(CASE, frame, baseline + 2)
    })();
    // Complete even when an observation fails, so a failed assertion does not
    // itself abandon the deferred references under test.
    let completion = match shootdown {
        Some(shootdown) => checked(CASE, "complete unlocked TLB shootdown", shootdown.complete_after_unlock()),
        None => Err(failure(CASE, "resident unmap returns deferred shootdown")),
    };
    before_completion?;
    completion?;
    expect_refs(CASE, frame, baseline)
}

fn partial_file_unmap(fixture: &Fixture) -> AxResult<()> {
    const CASE: &str = "partial_file_unmap";
    let aspace = new_aspace(CASE)?;
    let address = VirtAddr::from(TEST_VA);
    let left = cache_frame(fixture, 0, CASE)?;
    let middle = cache_frame(fixture, 1, CASE)?;
    let right = cache_frame(fixture, 2, CASE)?;
    let baseline = [frame_refs(CASE, left)?, frame_refs(CASE, middle)?, frame_refs(CASE, right)?];
    publish(&aspace, fixture.mapping(CASE, FILE_SIZE, 0, true, false)?, address, false, CASE)?;
    // Split while still lazy, then fault both survivors to test their file offsets.
    checked(CASE, "remove middle file page", aspace.unmap(address + PAGE_SIZE_4K, PAGE_SIZE_4K))?;
    check(CASE, "removed middle has no VMA", !aspace.read().has_overlap(address + PAGE_SIZE_4K, PAGE_SIZE_4K))?;
    absent(&aspace, address + PAGE_SIZE_4K, CASE)?;
    resolve(&aspace, address, PageFaultFlags::READ, CASE)?;
    resolve(&aspace, address + 2 * PAGE_SIZE_4K, PageFaultFlags::READ, CASE)?;
    check(CASE, "left survivor uses file page zero", mapped_frame(&aspace, address, CASE)? == left)?;
    check(CASE, "right survivor uses file page two", mapped_frame(&aspace, address + 2 * PAGE_SIZE_4K, CASE)? == right)?;
    read_equals(&aspace, address, &CONTENTS[0], CASE, "left file survivor bytes")?;
    read_equals(&aspace, address + 2 * PAGE_SIZE_4K, &CONTENTS[2], CASE, "right file survivor bytes")?;
    expect_refs(CASE, left, baseline[0] + 1)?;
    expect_refs(CASE, middle, baseline[1])?;
    expect_refs(CASE, right, baseline[2] + 1)?;
    checked(CASE, "remove both file survivors across hole", aspace.unmap(address, FILE_SIZE))?;
    expect_refs(CASE, left, baseline[0])?;
    expect_refs(CASE, middle, baseline[1])?;
    expect_refs(CASE, right, baseline[2])
}

fn partial_anonymous_unmap(_: &Fixture) -> AxResult<()> {
    const CASE: &str = "partial_anonymous_unmap";
    let aspace = new_aspace(CASE)?;
    let address = VirtAddr::from(TEST_VA);
    let flags = MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER;
    let prepared = checked(CASE, "prepare anonymous range", PreparedMapping::anonymous(FILE_SIZE, flags, false, false))?;
    publish(&aspace, prepared, address, false, CASE)?;
    let mut frames = [PhysAddr::from(0); 3];
    for page in 0..3 {
        let page_address = address + page * PAGE_SIZE_4K;
        resolve(&aspace, page_address, PageFaultFlags::WRITE, CASE)?;
        checked(CASE, "write anonymous page", aspace.read().write(page_address, &CONTENTS[page]))?;
        frames[page] = mapped_frame(&aspace, page_address, CASE)?;
    }
    checked(CASE, "remove middle resident anonymous page", aspace.unmap(address + PAGE_SIZE_4K, PAGE_SIZE_4K))?;
    absent(&aspace, address + PAGE_SIZE_4K, CASE)?;
    check(CASE, "anonymous hole has no VMA", !aspace.read().has_overlap(address + PAGE_SIZE_4K, PAGE_SIZE_4K))?;
    check(CASE, "left anonymous frame survives", mapped_frame(&aspace, address, CASE)? == frames[0])?;
    check(CASE, "right anonymous frame survives", mapped_frame(&aspace, address + 2 * PAGE_SIZE_4K, CASE)? == frames[2])?;
    read_equals(&aspace, address, &CONTENTS[0], CASE, "left anonymous survivor bytes")?;
    read_equals(&aspace, address + 2 * PAGE_SIZE_4K, &CONTENTS[2], CASE, "right anonymous survivor bytes")?;
    checked(CASE, "remove anonymous survivors across hole", aspace.unmap(address, FILE_SIZE))
}

fn unused_file_mapping_drop(fixture: &Fixture) -> AxResult<()> {
    const CASE: &str = "unused_file_mapping_drop";
    let frame = cache_frame(fixture, 0, CASE)?;
    let baseline = frame_refs(CASE, frame)?;
    let aspace = new_aspace(CASE)?;
    let address = VirtAddr::from(TEST_VA);
    publish(&aspace, fixture.mapping(CASE, PAGE_SIZE_4K, 0, true, false)?, address, false, CASE)?;
    absent(&aspace, address, CASE)?;
    expect_refs(CASE, frame, baseline)?;
    // Exercise destruction of a published, unused file area without explicit unmap.
    drop(aspace);
    expect_refs(CASE, frame, baseline)
}

fn file_fork_cow(fixture: &Fixture) -> AxResult<()> {
    const CASE: &str = "file_fork_cow";
    let parent = new_aspace(CASE)?;
    let private_address = VirtAddr::from(TEST_VA);
    let shared_address = private_address + 2 * PAGE_SIZE_4K;
    let private_cache = cache_frame(fixture, 0, CASE)?;
    let shared_cache = cache_frame(fixture, 1, CASE)?;
    let private_baseline = frame_refs(CASE, private_cache)?;
    let shared_baseline = frame_refs(CASE, shared_cache)?;
    publish(&parent, fixture.mapping(CASE, PAGE_SIZE_4K, 0, false, true)?, private_address, false, CASE)?;
    publish(&parent, fixture.mapping(CASE, PAGE_SIZE_4K, PAGE_SIZE_4K, true, true)?, shared_address, false, CASE)?;
    resolve(&parent, private_address, PageFaultFlags::READ, CASE)?;
    resolve(&parent, shared_address, PageFaultFlags::READ, CASE)?;
    read_equals(&parent, private_address, &CONTENTS[0], CASE, "parent private bytes before fork")?;
    check(CASE, "private read initially uses cache frame", mapped_frame(&parent, private_address, CASE)? == private_cache)?;

    let clone_result = { parent.write().try_clone() };
    let child = AddressSpaceLock::new(checked(CASE, "fork and complete parent shootdown unlocked", clone_result.complete_after_unlock())?);
    check(CASE, "fork initially shares private frame", mapped_frame(&child, private_address, CASE)? == private_cache)?;
    check(CASE, "parent private PTE stays read-only", !checked(CASE, "query parent fork flags", parent.read().query_vaddr(private_address))?.1.contains(MappingFlags::WRITE))?;
    check(CASE, "child private PTE stays read-only", !checked(CASE, "query child fork flags", child.read().query_vaddr(private_address))?.1.contains(MappingFlags::WRITE))?;
    expect_refs(CASE, private_cache, private_baseline + 2)?;
    expect_refs(CASE, shared_cache, shared_baseline + 2)?;
    check(CASE, "shared parent and child PTEs own common cache frame", mapped_frame(&parent, shared_address, CASE)? == shared_cache && mapped_frame(&child, shared_address, CASE)? == shared_cache)?;

    resolve(&child, private_address, PageFaultFlags::WRITE, CASE)?;
    let copied = mapped_frame(&child, private_address, CASE)?;
    check(CASE, "child write fault creates an owned private frame", copied != private_cache)?;
    expect_refs(CASE, copied, 1)?;
    expect_refs(CASE, private_cache, private_baseline + 1)?;
    let private_write = [0xa4; 16];
    checked(CASE, "write child private page after COW", child.read().write(private_address, &private_write))?;
    read_equals(&child, private_address, &private_write, CASE, "child private write is visible")?;
    read_equals(&parent, private_address, &CONTENTS[0], CASE, "parent private bytes unchanged after child write")?;

    let shared_write = [0xb5; 16];
    resolve(&child, shared_address, PageFaultFlags::WRITE, CASE)?;
    checked(CASE, "write child shared file page", child.read().write(shared_address, &shared_write))?;
    checked(CASE, "publish shared dirty mapping without claiming durability", child.sync_mappings(shared_address, PAGE_SIZE_4K, false))?;
    read_equals(&parent, shared_address, &shared_write, CASE, "shared write visible through parent mapping")?;
    read_equals(&child, shared_address, &shared_write, CASE, "shared write visible through child mapping")?;
    read_equals(&parent, private_address, &CONTENTS[0], CASE, "parent private bytes remain isolated")?;
    drop(child);
    expect_refs(CASE, private_cache, private_baseline + 1)?;
    expect_refs(CASE, shared_cache, shared_baseline + 1)?;
    drop(parent);
    expect_refs(CASE, private_cache, private_baseline)?;
    expect_refs(CASE, shared_cache, shared_baseline)
}

/// Run after filesystem/trap initialization, before loading the guest shell.
/// Each failed kernel assertion is logged and returned as `BadState`.
pub fn run() -> AxResult<()> {
    let fixture = match Fixture::new() {
        Ok(fixture) => fixture,
        Err(error) => {
            axlog::ax_println!("MLC_KERNEL RESULT FAIL setup");
            return Err(error);
        }
    };
    let cases: [(&str, fn(&Fixture) -> AxResult<()>); 7] = [
        ("prepared_pin_drop", prepared_pin_drop),
        ("stale_file_replace", stale_file_replace),
        ("deferred_file_unmap", deferred_file_unmap),
        ("partial_file_unmap", partial_file_unmap),
        ("partial_anonymous_unmap", partial_anonymous_unmap),
        ("unused_file_mapping_drop", unused_file_mapping_drop),
        ("file_fork_cow", file_fork_cow),
    ];
    for (case, run_case) in cases {
        if let Err(error) = run_case(&fixture) {
            axlog::ax_println!("MLC_KERNEL RESULT FAIL {case}");
            return Err(error);
        }
        axlog::ax_println!("MLC_KERNEL PASS {case}");
    }
    axlog::ax_println!("MLC_KERNEL RESULT PASS");
    Ok(())
}
