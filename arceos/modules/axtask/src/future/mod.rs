use alloc::sync::Arc;
use core::future::{Future, IntoFuture};
use core::pin::pin;
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
    woke: Arc<SpinNoIrq<bool>>,
}

impl AxWaker {
    /// Creates a new [`AxWaker`] from a task reference.
    pub fn new(task: &AxTaskRef) -> Arc<Self> {
        Arc::new(Self {
            task: Arc::downgrade(task),
            woke: Arc::new(SpinNoIrq::new(false)),
        })
    }

    /// Returns the task associated with this waker.
    pub fn task(&self) -> AxTaskWeak {
        self.task.clone()
    }
}

impl alloc::task::Wake for AxWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(task) = self.task.upgrade() {
            let mut rq = crate::api::select_run_queue::<kernel_guard::NoPreemptIrqSave>(&task);
            *self.woke.lock() = true;
            rq.unblock_task(task, false);
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
    let woke = waker_arc.woke.clone();
    let waker = Waker::from(waker_arc);
    let mut cx = Context::from_waker(&waker);

    loop {
        *woke.lock() = false;
        match fut.as_mut().poll(&mut cx) {
            Poll::Pending => {
                let mut rq = crate::api::current_run_queue::<kernel_guard::NoPreemptIrqSave>();
                let woke_guard = woke.lock();
                if !*woke_guard {
                    rq.blocked_resched_woke(woke_guard);
                } else {
                    // Immediately woken
                    drop(woke_guard);
                    crate::api::yield_now();
                }
            }
            Poll::Ready(output) => break output,
        }
    }
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
pub struct WaitFuture<'a> {
    wq: &'a crate::wait_queue::WaitQueue,
    registered: bool,
}

impl<'a> WaitFuture<'a> {
    /// Creates a new [`WaitFuture`].
    pub fn new(wq: &'a crate::wait_queue::WaitQueue) -> Self {
        Self {
            wq,
            registered: false,
        }
    }
}

impl<'a> Future for WaitFuture<'a> {
    type Output = ();

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.registered {
            Poll::Ready(())
        } else {
            self.wq.register_waker(cx.waker());
            self.registered = true;
            Poll::Pending
        }
    }
}
