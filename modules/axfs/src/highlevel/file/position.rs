use alloc::{
    collections::{BTreeSet, VecDeque},
    sync::Arc,
};
use core::{
    cell::UnsafeCell,
    future::poll_fn,
    ops::{Deref, DerefMut},
    task::{Poll, Waker},
};

use kspin::SpinNoIrq;

struct FilePositionState {
    locked: bool,
    next_ticket: u64,
    serving_ticket: u64,
    cancelled: BTreeSet<u64>,
    waiters: VecDeque<(u64, Waker)>,
}

/// Fair FIFO file-position coordinator shared across Path 1 (`try_lock`),
/// Path 2 (async future), and Path 3 (worker-pool pre-reserved ticket).
pub(super) struct FilePosition {
    value: UnsafeCell<u64>,
    state: SpinNoIrq<FilePositionState>,
}

// SAFETY: `value` is only read or mutated under a live `FilePositionGuard`,
// whose exclusivity is enforced by `state.locked` under `SpinNoIrq`.
unsafe impl Sync for FilePosition {}

/// Submission-time ticket reserving one future turn on [`FilePosition`].
///
/// Reserving on submission ensures a Path 3 worker request still acquires
/// `FilePosition` strictly ahead of subsequent Path 1/Path 2 requests.
pub struct FilePositionTicket {
    pos: Arc<FilePosition>,
    ticket: u64,
    consumed: bool,
}

pub(super) struct FilePositionGuard<'a> {
    pos: &'a FilePosition,
}

impl Deref for FilePositionGuard<'_> {
    type Target = u64;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: `self` guarantees exclusive ownership while `state.locked` is true.
        unsafe { &*self.pos.value.get() }
    }
}

impl DerefMut for FilePositionGuard<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: `&mut self` + `state.locked` guarantees unique mutable access.
        unsafe { &mut *self.pos.value.get() }
    }
}

fn take_waiter(waiters: &mut VecDeque<(u64, Waker)>, ticket: u64) -> Option<Waker> {
    let idx = waiters.iter().position(|(t, _)| *t == ticket)?;
    waiters.remove(idx).map(|(_, w)| w)
}

fn remove_waiter(waiters: &mut VecDeque<(u64, Waker)>, ticket: u64) {
    if let Some(idx) = waiters.iter().position(|(t, _)| *t == ticket) {
        waiters.remove(idx);
    }
}

fn advance_cancelled_and_take_waker(state: &mut FilePositionState) -> Option<Waker> {
    while state.cancelled.remove(&state.serving_ticket) {
        state.serving_ticket += 1;
    }
    take_waiter(&mut state.waiters, state.serving_ticket)
}

impl Drop for FilePositionGuard<'_> {
    fn drop(&mut self) {
        let waker = {
            let mut state = self.pos.state.lock();
            state.locked = false;
            state.serving_ticket += 1;
            advance_cancelled_and_take_waker(&mut state)
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Drop for FilePositionTicket {
    fn drop(&mut self) {
        if self.consumed {
            return;
        }
        let waker = {
            let mut state = self.pos.state.lock();
            remove_waiter(&mut state.waiters, self.ticket);
            state.cancelled.insert(self.ticket);
            if state.locked {
                None
            } else {
                advance_cancelled_and_take_waker(&mut state)
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl FilePosition {
    pub(super) fn new(value: u64) -> Arc<Self> {
        Arc::new(Self {
            value: UnsafeCell::new(value),
            state: SpinNoIrq::new(FilePositionState {
                locked: false,
                next_ticket: 0,
                serving_ticket: 0,
                cancelled: BTreeSet::new(),
                waiters: VecDeque::new(),
            }),
        })
    }

    fn try_acquire_fast(&self) -> Option<FilePositionGuard<'_>> {
        {
            let mut state = self.state.lock();
            if state.locked || state.serving_ticket != state.next_ticket {
                return None;
            }
            state.locked = true;
            state.next_ticket += 1;
        }
        #[cfg(feature = "file-io-test")]
        super::io_test::position_acquired();
        Some(FilePositionGuard { pos: self })
    }

    pub(super) fn try_lock(&self) -> Option<FilePositionGuard<'_>> {
        self.try_acquire_fast()
    }

    /// Acquires `FilePosition` without waiting behind an existing holder or
    /// any queued ticket, keeping `self` locked across cache misses.
    fn try_lock_for_operation(&self) -> Option<FilePositionGuard<'_>> {
        self.try_acquire_fast()
    }

    pub(super) fn reserve(self: &Arc<Self>) -> FilePositionTicket {
        self.reserve_with(|ticket| ticket)
    }

    pub(super) fn reserve_with<R>(
        self: &Arc<Self>,
        publish: impl FnOnce(FilePositionTicket) -> R,
    ) -> R {
        let mut state = self.state.lock();
        let ticket = state.next_ticket;
        state.next_ticket += 1;
        let result = publish(FilePositionTicket {
            pos: Arc::clone(self),
            ticket,
            consumed: false,
        });
        drop(state);
        result
    }

    pub(super) async fn lock(self: &Arc<Self>) -> FilePositionGuard<'_> {
        let ticket = self.reserve();
        self.lock_with_ticket(ticket).await
    }

    pub(super) async fn lock_with_ticket(
        &self,
        mut ticket: FilePositionTicket,
    ) -> FilePositionGuard<'_> {
        debug_assert!(Arc::as_ptr(&ticket.pos) as *const () == self as *const Self as *const ());
        poll_fn(|cx| {
            let acquired = {
                let mut state = self.state.lock();
                if !state.locked && state.serving_ticket == ticket.ticket {
                    state.locked = true;
                    ticket.consumed = true;
                    true
                } else {
                    if let Some((_, existing)) =
                        state.waiters.iter_mut().find(|(t, _)| *t == ticket.ticket)
                    {
                        if !existing.will_wake(cx.waker()) {
                            *existing = cx.waker().clone();
                        }
                    } else {
                        state.waiters.push_back((ticket.ticket, cx.waker().clone()));
                    }
                    false
                }
            };
            if acquired {
                #[cfg(feature = "file-io-test")]
                super::io_test::position_acquired();
                Poll::Ready(FilePositionGuard { pos: self })
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

/// The position portion of one I/O operation, including all of its windows.
/// A positioned operation never borrows the shared-position lock. Append can
/// select a different starting offset without publishing it before progress.
pub(super) struct IoPosition<'a> {
    shared: Option<FilePositionGuard<'a>>,
    offset: u64,
    validation_offset: u64,
}

impl<'a> IoPosition<'a> {
    pub(super) fn try_begin(
        position: Option<&'a Arc<FilePosition>>,
        offset: Option<u64>,
    ) -> Option<Self> {
        let shared = if offset.is_none() {
            match position {
                Some(position) => Some(position.try_lock_for_operation()?),
                None => None,
            }
        } else {
            None
        };
        Some(Self::new(shared, offset))
    }

    pub(super) async fn begin_with_ticket(
        position: Option<&'a Arc<FilePosition>>,
        ticket: Option<FilePositionTicket>,
        offset: Option<u64>,
    ) -> Self {
        let shared = if offset.is_none() {
            match (position, ticket) {
                (Some(position), Some(ticket)) => Some(position.lock_with_ticket(ticket).await),
                (Some(position), None) => Some(position.lock().await),
                (None, _) => None,
            }
        } else {
            None
        };
        Self::new(shared, offset)
    }

    fn new(shared: Option<FilePositionGuard<'a>>, offset: Option<u64>) -> Self {
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
