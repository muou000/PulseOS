use core::{future::poll_fn, task::Poll};

use axerrno::{AxError, AxResult};
use axpoll::{IoEvents, Pollable};

/// A helper to wrap a synchronous non-blocking I/O function into an
/// asynchronous function.
///
/// # Arguments
///
/// * `pollable`: The pollable object to register for I/O events.
/// * `events`: The I/O events to wait for.
/// * `non_blocking`: If true, the function will return `AxError::WouldBlock`
///   immediately when the I/O operation would block.
/// * `f`: The synchronous non-blocking I/O function to be wrapped. It should
///   return `AxError::WouldBlock` when the operation would block.
pub async fn poll_io<P: Pollable, F: FnMut() -> AxResult<T>, T>(
    pollable: &P,
    events: IoEvents,
    non_blocking: bool,
    mut f: F,
) -> AxResult<T> {
    poll_fn(move |cx| match f() {
        Ok(value) => Poll::Ready(Ok(value)),
        Err(AxError::WouldBlock) => {
            if non_blocking {
                return Poll::Ready(Err(AxError::WouldBlock));
            }
            pollable.register(cx, events);
            match f() {
                Ok(value) => Poll::Ready(Ok(value)),
                Err(AxError::WouldBlock) => Poll::Pending,
                Err(e) => Poll::Ready(Err(e)),
            }
        }
        Err(e) => Poll::Ready(Err(e)),
    })
    .await
}

#[cfg(feature = "irq")]
/// Registers a waker for the given IRQ number.
pub fn register_irq_waker(irq: usize, waker: &core::task::Waker) {
    use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
    use core::sync::atomic::{AtomicBool, Ordering};

    use axpoll::PollSet;
    use kspin::SpinNoIrq;

    struct IrqPollState {
        pending: bool,
        poll: Arc<PollSet>,
    }

    static POLL_IRQ: SpinNoIrq<BTreeMap<usize, IrqPollState>> =
        SpinNoIrq::new(BTreeMap::new());
    static DRAIN_WAIT: crate::WaitQueue = crate::WaitQueue::new();
    static DRAIN_SPAWNED: AtomicBool = AtomicBool::new(false);

    fn irq_hook(irq: usize) {
        let registered = {
            let mut states = POLL_IRQ.lock();
            if let Some(state) = states.get_mut(&irq) {
                state.pending = true;
                true
            } else {
                false
            }
        };
        if registered {
            DRAIN_WAIT.notify_one(false);
        }
    }

    fn ensure_drain_task() {
        if DRAIN_SPAWNED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        crate::spawn_raw(
            || loop {
                DRAIN_WAIT.wait_until(|| POLL_IRQ.lock().values().any(|state| state.pending));

                let pending: Vec<Arc<PollSet>> = {
                    let mut states = POLL_IRQ.lock();
                    states
                        .values_mut()
                        .filter_map(|state| {
                            if state.pending {
                                state.pending = false;
                                Some(state.poll.clone())
                            } else {
                                None
                            }
                        })
                        .collect()
                };
                for poll in pending {
                    poll.wake();
                }
            },
            "irq_waker_drain".into(),
            axconfig::TASK_STACK_SIZE,
        );
    }

    ensure_drain_task();

    let (poll, should_install) = {
        let mut states = POLL_IRQ.lock();
        if let Some(state) = states.get(&irq) {
            (state.poll.clone(), false)
        } else {
            let poll = Arc::new(PollSet::new());
            states.insert(
                irq,
                IrqPollState {
                    pending: false,
                    poll: poll.clone(),
                },
            );
            (poll, true)
        }
    };
    poll.register(waker);

    if should_install {
        axhal::irq::register(irq, irq_hook);
        axhal::irq::set_enable(irq, true);
    }
}
