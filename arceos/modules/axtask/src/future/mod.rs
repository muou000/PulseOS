use alloc::sync::Arc;
use core::{
    fmt,
    future::{Future, IntoFuture, poll_fn},
    pin::pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, Waker},
};

use kspin::SpinNoIrq;

#[cfg(feature = "qperf-trace")]
use crate::current_may_uninit;
use crate::{AxTaskRef, AxTaskWeak, WaitContext, WaitReason, WakeContext, WakeSource, current};

mod poll;
mod time;

pub use self::{poll::*, time::*};

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
            let mut rq = crate::api::select_wake_run_queue::<kernel_guard::NoPreemptIrqSave>(&task);
            // Keep this guard until unblock_task has completed. This pairs
            // with deactivate so a wake either finishes within this
            // block_on lifetime or observes the inactive state.
            let mut woke = self.woke.lock();
            if !self.active.load(Ordering::Acquire) {
                return;
            }
            *woke = true;
            rq.unblock_task_with_context(task, true, WakeContext::new(|| (WakeSource::Future, 0)));
        }
    }
}

/// Overrides the qperf reason for the next suspension of the current `block_on` poll.
///
/// Nested futures should call this only when they are about to return `Pending`.
/// The context is cleared before every poll, so a completed or cancelled future
/// cannot leak its reason into a later suspension.
#[inline(always)]
pub fn set_current_wait_context(_context: WaitContext) {
    #[cfg(feature = "qperf-trace")]
    if let Some(task) = current_may_uninit() {
        task.set_qperf_pending_wait_context(_context);
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
        #[cfg(feature = "qperf-trace")]
        curr.clear_qperf_pending_wait_context();
        match fut.as_mut().poll(&mut cx) {
            Poll::Pending => {
                let context = {
                    #[cfg(feature = "qperf-trace")]
                    {
                        curr.take_qperf_pending_wait_context().unwrap_or_else(|| {
                            WaitContext::new(|| {
                                (
                                    WaitReason::Future,
                                    Arc::as_ptr(&waker_arc) as usize as u64,
                                    0,
                                )
                            })
                        })
                    }
                    #[cfg(not(feature = "qperf-trace"))]
                    {
                        WaitContext::new(|| (WaitReason::Future, 0, 0))
                    }
                };
                let mut rq = crate::api::current_run_queue::<kernel_guard::NoPreemptIrqSave>();
                let woke_guard = waker_arc.woke.lock();
                if !*woke_guard {
                    rq.blocked_resched_woke(woke_guard, context);
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

/// Error returned when an interruptible future observes a task interruption.
#[derive(Debug, PartialEq, Eq)]
pub struct Interrupted;

impl fmt::Display for Interrupted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "interrupted")
    }
}

impl From<Interrupted> for axerrno::AxError {
    fn from(_: Interrupted) -> Self {
        axerrno::AxError::Interrupted
    }
}

/// Runs a future until it completes or the current task is interrupted.
pub async fn interruptible<F: IntoFuture>(f: F) -> Result<F::Output, Interrupted> {
    let mut f = pin!(f.into_future());
    let curr = current();
    poll_fn(|cx| {
        if curr.poll_interrupt(cx).is_ready() {
            Poll::Ready(Err(Interrupted))
        } else {
            f.as_mut().poll(cx).map(Ok)
        }
    })
    .await
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
    registration: Option<crate::wait_queue::WakerRegistration>,
}

impl<'a> WaitFuture<'a> {
    /// Creates a new [`WaitFuture`].
    pub fn new(wq: &'a crate::wait_queue::WaitQueue) -> Self {
        Self {
            wq,
            notified: None,
            registration: None,
        }
    }
}

impl<'a> Future for WaitFuture<'a> {
    type Output = ();

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let flag = if let Some(flag) = self.notified.as_ref() {
            flag.clone()
        } else {
            let (registration, flag) = self.wq.register_wait_future_waker(cx.waker());
            self.registration = Some(registration);
            self.notified = Some(flag.clone());
            flag
        };

        if let Some(registration) = self.registration.as_ref() {
            // A Future may be moved between executors or tasks while Pending.
            // Always retain the waker supplied by the latest poll.
            self.wq.update_registered_waker(registration, cx.waker());
        }

        if flag.load(Ordering::Acquire) {
            // The notifier may already have dequeued this registration; in
            // that case unregistering is a harmless no-op.
            if let Some(registration) = self.registration.take() {
                self.wq.unregister_waker(registration);
            }
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for WaitFuture<'_> {
    fn drop(&mut self) {
        if let Some(registration) = self.registration.take() {
            self.wq.unregister_waker(registration);
        }
    }
}
