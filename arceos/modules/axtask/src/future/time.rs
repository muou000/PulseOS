use alloc::collections::BTreeMap;
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

    /// Removes the earliest expired timer and returns its waker without
    /// invoking it while `self` is mutably borrowed.
    ///
    /// A timer waker may unblock a task and reprogram the hardware timer. That
    /// path queries this same per-CPU runtime again, so calling `wake()` from
    /// inside this method would create a re-entrant mutable reference to
    /// `TIMER_RUNTIME`.
    fn pop_expired(&mut self, now: TimeValue) -> Option<Waker> {
        match self.wheel.first_key_value() {
            Some((key, _)) if key.deadline <= now => self.wheel.pop_first().map(|(_, waker)| waker),
            _ => None,
        }
    }
}

percpu_static! {
    TIMER_RUNTIME: TimerRuntime = TimerRuntime::new(),
}

#[allow(dead_code)]
pub(crate) fn check_timer_events() {
    let now = monotonic_time();
    loop {
        let waker = {
            // SAFETY: only called in the local CPU's timer hook or an
            // equivalent IRQ-disabled context. This borrow ends before the
            // waker is invoked below.
            unsafe { TIMER_RUNTIME.current_ref_mut_raw() }.pop_expired(now)
        };
        match waker {
            Some(waker) => waker.wake(),
            None => break,
        }
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

    fn timer_key(deadline_ns: u64, key: u64) -> TimerKey {
        TimerKey {
            deadline: TimeValue::from_nanos(deadline_ns),
            key,
        }
    }

    #[test]
    fn popping_expired_timers_defers_wake_and_preserves_order() {
        let first = Arc::new(CountWake(AtomicUsize::new(0)));
        let second = Arc::new(CountWake(AtomicUsize::new(0)));
        let future = Arc::new(CountWake(AtomicUsize::new(0)));
        let mut runtime = TimerRuntime::new();
        runtime
            .wheel
            .insert(timer_key(10, 1), Waker::from(second.clone()));
        runtime
            .wheel
            .insert(timer_key(10, 0), Waker::from(first.clone()));
        runtime
            .wheel
            .insert(timer_key(11, 0), Waker::from(future.clone()));

        let waker = runtime.pop_expired(TimeValue::from_nanos(10)).unwrap();
        assert_eq!(first.0.load(Ordering::Relaxed), 0);
        assert_eq!(second.0.load(Ordering::Relaxed), 0);
        waker.wake();
        assert_eq!(first.0.load(Ordering::Relaxed), 1);
        assert_eq!(second.0.load(Ordering::Relaxed), 0);

        let waker = runtime.pop_expired(TimeValue::from_nanos(10)).unwrap();
        assert_eq!(second.0.load(Ordering::Relaxed), 0);
        waker.wake();
        assert_eq!(second.0.load(Ordering::Relaxed), 1);

        assert!(runtime.pop_expired(TimeValue::from_nanos(10)).is_none());
        assert_eq!(runtime.wheel.len(), 1);
        assert_eq!(
            runtime.wheel.first_key_value().unwrap().0.deadline,
            TimeValue::from_nanos(11)
        );
        assert_eq!(future.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn pop_expired_leaves_empty_and_future_queues_untouched() {
        let mut runtime = TimerRuntime::new();
        assert!(runtime.pop_expired(TimeValue::from_nanos(10)).is_none());

        let future = Arc::new(CountWake(AtomicUsize::new(0)));
        runtime
            .wheel
            .insert(timer_key(11, 0), Waker::from(future.clone()));

        assert!(runtime.pop_expired(TimeValue::from_nanos(10)).is_none());
        assert_eq!(runtime.wheel.len(), 1);
        assert_eq!(future.0.load(Ordering::Relaxed), 0);
    }
}
