use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    fmt,
    future::{Future, IntoFuture},
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

use axerrno::AxError;
use axhal::time::{TimeValue, monotonic_time};
use futures_util::{FutureExt, select_biased};

macro_rules! percpu_static {
    ($(
        $(#[$comment:meta])*
        $name:ident: $ty:ty = $init:expr
    ),* $(,)?) => {
        $(
            $(#[$comment])*
            #[percpu::def_percpu]
            static $name: $ty = $init;
        )*
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TimerKey {
    deadline: TimeValue,
    key: u64,
}

struct TimerRuntime {
    key: u64,
    wheel: BTreeMap<TimerKey, Waker>,
}

impl TimerRuntime {
    const fn new() -> Self {
        TimerRuntime {
            key: 0,
            wheel: BTreeMap::new(),
        }
    }

    fn add(&mut self, deadline: TimeValue) -> Option<TimerKey> {
        if deadline <= monotonic_time() {
            return None;
        }

        let key = TimerKey {
            deadline,
            key: self.key,
        };
        self.wheel.insert(key, Waker::noop().clone());
        self.key += 1;

        Some(key)
    }

    fn poll(&mut self, key: &TimerKey, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(w) = self.wheel.get_mut(key) {
            *w = cx.waker().clone();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }

    fn cancel(&mut self, key: &TimerKey) {
        self.wheel.remove(key);
    }

    #[cfg(feature = "irq")]
    fn next_deadline(&self) -> Option<TimeValue> {
        self.wheel.keys().next().map(|key| key.deadline)
    }

    /// Removes all expired timers and returns their wakers without invoking
    /// them while `self` is mutably borrowed.
    ///
    /// A timer waker may unblock a task and reprogram the hardware timer. That
    /// path queries this same per-CPU runtime again, so calling `wake()` from
    /// inside this method would create a re-entrant mutable reference to
    /// `TIMER_RUNTIME`.
    fn drain_expired(&mut self) -> Vec<Waker> {
        if self.wheel.is_empty() {
            return Vec::new();
        }

        let now = monotonic_time();

        let pending = self.wheel.split_off(&TimerKey {
            deadline: now,
            key: u64::MAX,
        });

        core::mem::replace(&mut self.wheel, pending)
            .into_values()
            .collect()
    }
}

percpu_static! {
    TIMER_RUNTIME: TimerRuntime = TimerRuntime::new(),
}

#[allow(dead_code)]
pub(crate) fn check_timer_events() {
    // SAFETY: only called in the local CPU's timer hook or an equivalent
    // IRQ-disabled context. End the per-CPU mutable borrow before invoking any
    // waker because waking a task may re-enter timer reprogramming.
    let expired = unsafe { TIMER_RUNTIME.current_ref_mut_raw() }.drain_expired();
    for waker in expired {
        waker.wake();
    }
}

#[cfg(feature = "irq")]
pub(crate) fn next_timer_deadline() -> Option<TimeValue> {
    with_current(|runtime| runtime.next_deadline())
}

fn with_current<R>(f: impl FnOnce(&mut TimerRuntime) -> R) -> R {
    let _g = kernel_guard::NoPreemptIrqSave::new();
    f(unsafe { TIMER_RUNTIME.current_ref_mut_raw() })
}

/// Future returned by `sleep` and `sleep_until`.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct TimerFuture(TimerKey);

impl Future for TimerFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        with_current(|r| r.poll(&self.0, cx))
    }
}

impl Drop for TimerFuture {
    fn drop(&mut self) {
        with_current(|r| r.cancel(&self.0));
    }
}

/// Waits until `duration` has elapsed.
pub async fn sleep(duration: Duration) {
    sleep_until(monotonic_time() + duration).await
}

/// Waits until `deadline` is reached.
pub async fn sleep_until(deadline: TimeValue) {
    let key = with_current(|r| r.add(deadline));
    if let Some(key) = key {
        #[cfg(feature = "irq")]
        crate::timers::reprogram_timer();
        TimerFuture(key).await;
    }
}

/// Error returned by [`timeout`] and [`timeout_at`].
#[derive(Debug, PartialEq, Eq)]
pub struct Elapsed(());

impl fmt::Display for Elapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "deadline elapsed")
    }
}

impl From<Elapsed> for AxError {
    fn from(_: Elapsed) -> Self {
        AxError::TimedOut
    }
}

/// Requires a `Future` to complete before the specified duration has elapsed.
pub async fn timeout<F: IntoFuture>(
    duration: Option<Duration>,
    f: F,
) -> Result<F::Output, Elapsed> {
    timeout_at(
        duration.and_then(|x| x.checked_add(axhal::time::monotonic_time())),
        f,
    )
    .await
}

/// Requires a `Future` to complete before the specified deadline.
pub async fn timeout_at<F: IntoFuture>(
    deadline: Option<TimeValue>,
    f: F,
) -> Result<F::Output, Elapsed> {
    if let Some(deadline) = deadline {
        select_biased! {
            res = f.into_future().fuse() => Ok(res),
            _ = sleep_until(deadline).fuse() => Err(Elapsed(())),
        }
    } else {
        Ok(f.into_future().await)
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Wake, Waker},
    };

    use super::{TimeValue, TimerKey, TimerRuntime};

    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn draining_expired_timers_does_not_invoke_wakers() {
        let counter = Arc::new(CountWake(AtomicUsize::new(0)));
        let mut runtime = TimerRuntime::new();
        runtime.wheel.insert(
            TimerKey {
                deadline: TimeValue::from_nanos(0),
                key: 0,
            },
            Waker::from(counter.clone()),
        );

        let expired = runtime.drain_expired();
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        assert_eq!(expired.len(), 1);

        for waker in expired {
            waker.wake();
        }
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    }
}
