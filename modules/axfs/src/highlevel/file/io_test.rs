//! Test-only counters for one explicitly selected task's I/O operation.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static TASK: AtomicU64 = AtomicU64::new(0);
static POSITION: AtomicU64 = AtomicU64::new(0);
static OPERATIONS: AtomicU64 = AtomicU64::new(0);
static PIN_PEAK: AtomicU64 = AtomicU64::new(0);
static STAGED: AtomicU64 = AtomicU64::new(0);
static PIN_ACQUIRED: AtomicU64 = AtomicU64::new(0);
static PIN_RELEASED: AtomicU64 = AtomicU64::new(0);
static PIN_ACTIVE: AtomicU64 = AtomicU64::new(0);
static PIN_UNBALANCED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Default)]
pub struct FileIoTestSnapshot {
    pub position_acquisitions: u64,
    pub operations: u64,
    pub pin_peak_pages: u64,
    /// Bytes copied into an intermediate buffer, once per staging layer.
    /// This is copied payload, not allocated capacity or committed file bytes:
    /// a short write can consume staged bytes that were not committed.
    pub staged_bytes: u64,
}

/// Selects one task and clears its counters. Test controllers serialize their
/// sessions; unrelated tasks, including background writeback, are excluded.
/// A session brackets synchronous syscalls in this task. Windows must be
/// dropped before snapshot/reset/disable and cannot move to another task.
pub fn file_io_test_begin(task_id: u64) {
    TASK.store(0, Ordering::Release);
    POSITION.store(0, Ordering::Relaxed);
    OPERATIONS.store(0, Ordering::Relaxed);
    PIN_PEAK.store(0, Ordering::Relaxed);
    STAGED.store(0, Ordering::Relaxed);
    PIN_ACQUIRED.store(0, Ordering::Relaxed);
    PIN_RELEASED.store(0, Ordering::Relaxed);
    PIN_ACTIVE.store(0, Ordering::Relaxed);
    PIN_UNBALANCED.store(false, Ordering::Relaxed);
    TASK.store(task_id, Ordering::Release);
}

pub fn file_io_test_disable() {
    TASK.store(0, Ordering::Release);
}

pub fn file_io_test_snapshot() -> FileIoTestSnapshot {
    FileIoTestSnapshot {
        position_acquisitions: POSITION.load(Ordering::Relaxed),
        operations: OPERATIONS.load(Ordering::Relaxed),
        pin_peak_pages: PIN_PEAK.load(Ordering::Relaxed),
        staged_bytes: STAGED.load(Ordering::Relaxed),
    }
}

fn selected() -> bool {
    let selected = TASK.load(Ordering::Acquire);
    selected != 0 && task::current_may_uninit().is_some_and(|task| task.id().as_u64() == selected)
}

pub(super) fn position_acquired() {
    if selected() {
        POSITION.fetch_add(1, Ordering::Relaxed);
    }
}

pub(super) fn operation_started() {
    if selected() {
        OPERATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

pub(super) fn staged_bytes(bytes: usize) {
    if selected() {
        STAGED.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

pub fn file_io_test_pinned_pages(pages: usize) {
    if selected() {
        PIN_PEAK.fetch_max(pages as u64, Ordering::Relaxed);
    }
}

/// Records one successful frame-reference increment in the selected task.
pub fn file_io_test_pin_acquired() {
    if selected() {
        PIN_ACQUIRED.fetch_add(1, Ordering::Relaxed);
        let active = PIN_ACTIVE.fetch_add(1, Ordering::Relaxed) + 1;
        PIN_PEAK.fetch_max(active, Ordering::Relaxed);
    }
}

/// Records one frame-reference decrement after it has actually completed.
pub fn file_io_test_pin_released() {
    if selected() {
        PIN_RELEASED.fetch_add(1, Ordering::Relaxed);
        if PIN_ACTIVE.fetch_sub(1, Ordering::Relaxed) == 0 {
            PIN_UNBALANCED.store(true, Ordering::Relaxed);
        }
    }
}

/// Checks that the selected task released every acquired reference. The guest
/// controller calls this after the observed syscall returns, before exposing
/// the existing fixed-size snapshot. It deliberately adds no snapshot fields.
/// This observes pin ownership, not the allocator's separate frame-reuse policy.
pub fn file_io_test_pins_balanced() -> bool {
    selected()
        && !PIN_UNBALANCED.load(Ordering::Relaxed)
        && PIN_ACTIVE.load(Ordering::Relaxed) == 0
        && PIN_ACQUIRED.load(Ordering::Relaxed) == PIN_RELEASED.load(Ordering::Relaxed)
}
