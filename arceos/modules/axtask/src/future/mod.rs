use alloc::sync::Arc;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use crate::AxTaskRef;
use crate::task::TaskState;
use alloc::task::Wake;

/// A waker that wakes up the associated task.
pub struct AxWaker(AxTaskRef);

impl AxWaker {
    /// Creates a new [`AxWaker`] from a task reference.
    pub fn new(task: AxTaskRef) -> Self {
        Self(task)
    }

    /// Returns the task associated with this waker.
    pub fn task(&self) -> &AxTaskRef {
        &self.0
    }
}

impl Wake for AxWaker {
    fn wake(self: Arc<Self>) {
        crate::wake_task(self.0.clone(), true);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        crate::wake_task(self.0.clone(), true);
    }
}

/// Runs a future to completion on the current task.
///
/// This function will block the current task until the future is ready.
pub fn block_on<F: Future>(mut f: F) -> F::Output {
    let curr = crate::current();
    let waker = Waker::from(Arc::new(AxWaker::new(curr.as_task_ref().clone())));
    let mut cx = Context::from_waker(&waker);

    // SAFETY: The future is pinned on the stack.
    let mut f = unsafe { Pin::new_unchecked(&mut f) };

    loop {
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(res) => return res,
            Poll::Pending => {
                let mut rq = crate::api::current_run_queue::<kernel_guard::NoPreemptIrqSave>();
                curr.set_state(TaskState::Blocked);
                rq.resched_blocked();
            }
        }
    }
}

/// Yields the current task until the future is ready.
pub async fn yield_now() {
    struct YieldFuture(bool);
    impl Future for YieldFuture {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    YieldFuture(false).await;
}

/// A future that waits for a [`WaitQueue`].
pub struct WaitFuture<'a> {
    wq: &'a crate::wait_queue::WaitQueue,
    registered: bool,
}

impl<'a> WaitFuture<'a> {
    /// Creates a new [`WaitFuture`].
    pub fn new(wq: &'a crate::wait_queue::WaitQueue) -> Self {
        Self { wq, registered: false }
    }
}

impl<'a> Future for WaitFuture<'a> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.registered {
            Poll::Ready(())
        } else {
            self.wq.register_waker(cx.waker());
            self.registered = true;
            Poll::Pending
        }
    }
}

/// A future that polls for I/O events.
pub struct IoFuture<'a, P, F, T>
where
    P: axpoll::Pollable,
    F: FnMut() -> axio::Result<T>,
{
    pollable: &'a P,
    events: axpoll::IoEvents,
    f: F,
}

impl<'a, P, F, T> Future for IoFuture<'a, P, F, T>
where
    P: axpoll::Pollable,
    F: FnMut() -> axio::Result<T>,
{
    type Output = axio::Result<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        match (this.f)() {
            Ok(res) => Poll::Ready(Ok(res)),
            Err(e) if e == axio::Error::WouldBlock => {
                this.pollable.register(cx, this.events);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// Polls for I/O events.
pub fn poll_io<'a, P, F, T>(
    pollable: &'a P,
    events: axpoll::IoEvents,
    nonblocking: bool,
    f: F,
) -> impl Future<Output = axio::Result<T>> + 'a
where
    P: axpoll::Pollable,
    F: FnMut() -> axio::Result<T> + 'a,
    T: 'a,
{
    async move {
        let mut f = f;
        if nonblocking {
            return f();
        }
        IoFuture {
            pollable,
            events,
            f,
        }
        .await
    }
}
