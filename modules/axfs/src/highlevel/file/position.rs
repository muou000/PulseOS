use core::sync::atomic::{AtomicUsize, Ordering};

/// A file position lock that leaves queued async operations ahead of the
/// resident-read fast path. The async mutex alone cannot expose its waiter
/// state to `try_lock` callers.
pub(super) struct FilePosition {
    value: async_lock::Mutex<u64>,
    waiters: AtomicUsize,
}

struct PositionWaiter<'a>(&'a AtomicUsize);

impl Drop for PositionWaiter<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl FilePosition {
    pub(super) fn new(value: u64) -> Self {
        Self {
            value: async_lock::Mutex::new(value),
            waiters: AtomicUsize::new(0),
        }
    }

    pub(super) fn try_lock(&self) -> Option<async_lock::MutexGuard<'_, u64>> {
        if self.waiters.load(Ordering::Acquire) != 0 {
            return None;
        }
        let guard = self.value.try_lock()?;
        // Count the actual acquisition, even if the fairness recheck below
        // immediately gives it back to an already queued operation.
        #[cfg(feature = "file-io-test")]
        super::io_test::position_acquired();
        if self.waiters.load(Ordering::Acquire) != 0 {
            drop(guard);
            return None;
        }
        Some(guard)
    }

    pub(super) async fn lock(&self) -> async_lock::MutexGuard<'_, u64> {
        self.waiters.fetch_add(1, Ordering::AcqRel);
        // The RAII token also decrements the count if an enclosing file future
        // is cancelled while this mutex acquisition is pending.
        let waiter = PositionWaiter(&self.waiters);
        let guard = self.value.lock().await;
        #[cfg(feature = "file-io-test")]
        super::io_test::position_acquired();
        drop(waiter);
        guard
    }
}

/// The position portion of one I/O operation, including all of its windows.
/// A positioned operation never borrows the shared-position mutex. Append can
/// select a different starting offset without publishing it before progress.
pub(super) struct IoPosition<'a> {
    shared: Option<async_lock::MutexGuard<'a, u64>>,
    offset: u64,
    validation_offset: u64,
}

impl<'a> IoPosition<'a> {
    pub(super) async fn begin(position: Option<&'a FilePosition>, offset: Option<u64>) -> Self {
        let shared = if offset.is_none() {
            match position {
                Some(position) => Some(position.lock().await),
                None => None,
            }
        } else {
            None
        };
        let offset = offset.unwrap_or_else(|| shared.as_deref().copied().unwrap_or(0));
        Self {
            shared,
            offset,
            validation_offset: offset,
        }
    }

    pub(super) fn offset(&self) -> u64 {
        self.offset
    }

    pub(super) fn validation_offset(&self) -> u64 {
        self.validation_offset
    }

    pub(super) fn select_append(&mut self, end: u64) {
        self.offset = end;
    }

    /// Publishes only completed bytes. A zero-length result leaves the shared
    /// position unchanged, including when append selected a different EOF.
    pub(super) fn advance(&mut self, completed: usize) -> Option<()> {
        if completed != 0 {
            self.offset = self.offset.checked_add(completed as u64)?;
            if let Some(shared) = &mut self.shared {
                **shared = self.offset;
            }
        }
        Some(())
    }
}
