use alloc::sync::Arc;
use core::future::{Future, IntoFuture};
use core::pin::pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use kspin::SpinNoIrq;

use crate::{AxTaskRef, AxTaskWeak, current};

mod poll;
mod time;

pub use self::poll::*;
pub use self::time::*;

/// A waker that wakes up the associated task.
pub struct AxWaker {
    task: AxTaskWeak,
    active: AtomicBool,
    woke: SpinNoIrq<bool>,
}

impl AxWaker {
    /// Creates a new [`AxWaker`] from a task reference.
    pub fn new(task: &AxTaskRef) -> Arc<Self> {
        Arc::new(Self {
            task: Arc::downgrade(task),
            active: AtomicBool::new(true),
            woke: SpinNoIrq::new(false),
        })
    }

    /// Returns the task associated with this waker.
    pub fn task(&self) -> AxTaskWeak {
        self.task.clone()
    }

    /// Prevents registrations retained by an already completed `block_on`
    /// invocation from waking the task during an unrelated later wait.
    fn deactivate(&self) {
        // Serialize with wake_by_ref and let an already-started wake finish
        // before block_on returns to synchronous task code.
        let _woke = self.woke.lock();
        self.active.store(false, Ordering::Release);
    }
}

impl alloc::task::Wake for AxWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(task) = self.task.upgrade() {
            let mut rq =
                crate::api::select_wake_run_queue::<kernel_guard::NoPreemptIrqSave>(&task);
            // Keep this guard until unblock_task has completed. This pairs
            // with deactivate so a wake either finishes within this
            // block_on lifetime or observes the inactive state.
            let mut woke = self.woke.lock();
            if !self.active.load(Ordering::Acquire) {
                return;
            }
            *woke = true;
            rq.unblock_task(task, true);
        }
    }
}

/// Runs a future to completion on the current task.
///
/// This function will block the current task until the future is ready.
pub fn block_on<F: IntoFuture>(f: F) -> F::Output {
    let mut fut = pin!(f.into_future());

    let curr = current();
    // It's necessary to keep a strong reference to the current task
    // to prevent it from being dropped while blocking.
    let task = curr.as_task_ref().clone();

    let waker_arc = AxWaker::new(&task);
    let waker = Waker::from(waker_arc.clone());
    let mut cx = Context::from_waker(&waker);

    let output = loop {
        *waker_arc.woke.lock() = false;
        match fut.as_mut().poll(&mut cx) {
            Poll::Pending => {
                let mut rq = crate::api::current_run_queue::<kernel_guard::NoPreemptIrqSave>();
                let woke_guard = waker_arc.woke.lock();
                if !*woke_guard {
                    rq.blocked_resched_woke(woke_guard);
                } else {
                    drop(woke_guard);
                }
            }
            Poll::Ready(output) => break output,
        }
    };
    waker_arc.deactivate();
    output
}

/// Yields the current task until the future is ready.
pub fn yield_now() -> YieldNow {
    YieldNow(false)
}

/// A future that yields the current task.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct YieldNow(bool);

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// A future that waits for a [`WaitQueue`](crate::wait_queue::WaitQueue).
///
/// The future registers itself with the queue on the first poll and captures
/// a shared notification flag. It only completes when a matching
/// `notify_one` / `notify_all` has observed and consumed that registration
/// (i.e. set the flag), not merely when the future was once registered. This
/// honors the `Future` contract, which permits being polled again after
/// returning `Pending` even when the awaited event has not occurred.
pub struct WaitFuture<'a> {
    wq: &'a crate::wait_queue::WaitQueue,
    notified: Option<Arc<AtomicBool>>,
    registration_id: Option<u64>,
}

impl<'a> WaitFuture<'a> {
    /// Creates a new [`WaitFuture`].
    pub fn new(wq: &'a crate::wait_queue::WaitQueue) -> Self {
        Self {
            wq,
            notified: None,
            registration_id: None,
        }
    }
}

impl<'a> Future for WaitFuture<'a> {
    type Output = ();

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Lazy registration: capture the notification flag on the first poll
        // and reuse it on subsequent polls so that spurious or unrelated
        // wakes do not cause premature completion.
        let flag = if let Some(f) = self.notified.as_ref() {
            // We only registered one waker; the executor may have reused
            // the same waker across polls, so re-registering isn't strictly
            // required here. Keep the original entry so its flag stays in
            // sync with the wait queue's storage.
            f.clone()
        } else {
            let (registration_id, f) = self.wq.register_wait_future_waker(cx.waker());
            self.registration_id = Some(registration_id);
            self.notified = Some(f.clone());
            f
        };

        // Only complete when an actual notify_* has set the flag. If the
        // notification raced in between registering and checking, the load
        // below will observe `true` since both the store in `notify_*` and
        // our register_waker/load sequence are ordered by the wait queue's
        // internal locks and the Release/Acquire pair on the flag itself.
        if flag.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for WaitFuture<'_> {
    fn drop(&mut self) {
        if let Some(registration_id) = self.registration_id.take() {
            self.wq.unregister_waker(registration_id);
        }
    }
}
