use alloc::{
    boxed::Box,
    collections::VecDeque,
    format,
    sync::{Arc, Weak},
};
use core::{
    future::Future,
    mem::ManuallyDrop,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

use kspin::SpinNoIrq;
use lazyinit::LazyInit;

use crate::{WaitQueue, api::spawn_raw};

type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

const STATE_IDLE: u8 = 0;
const STATE_QUEUED: u8 = 1;
const STATE_POLLING: u8 = 2;
const STATE_POLLING_NOTIFIED: u8 = 3;
const STATE_CANCELLED: u8 = 4;
const STATE_COMPLETED: u8 = 5;

struct TaskSlot {
    state: AtomicU8,
    cancelled: AtomicBool,
    future: SpinNoIrq<Option<BoxFuture>>,
    executor: Weak<ExecutorInner>,
}

struct ExecutorInner {
    ready_queue: SpinNoIrq<VecDeque<Arc<TaskSlot>>>,
    driver_wq: WaitQueue,
    drivers_started: AtomicBool,
    spawn_drivers: bool,
    pending_count: AtomicUsize,
}

impl ExecutorInner {
    fn new(spawn_drivers: bool) -> Arc<Self> {
        Arc::new(Self {
            ready_queue: SpinNoIrq::new(VecDeque::new()),
            driver_wq: WaitQueue::new(),
            drivers_started: AtomicBool::new(false),
            spawn_drivers,
            pending_count: AtomicUsize::new(0),
        })
    }

    fn enqueue(&self, slot: Arc<TaskSlot>) {
        {
            let mut queue = self.ready_queue.lock();
            queue.push_back(slot);
        }
        self.driver_wq.notify_one(false);
    }

    fn pop_ready(&self) -> Option<Arc<TaskSlot>> {
        self.ready_queue.lock().pop_front()
    }

    fn ensure_background_drivers(self: &Arc<Self>) {
        if !self.spawn_drivers || self.drivers_started.load(Ordering::Acquire) {
            return;
        }
        if self
            .drivers_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let num_drivers = axhal::cpu_num().clamp(1, 4);
        for idx in 0..num_drivers {
            let inner = Arc::clone(self);
            spawn_raw(
                move || {
                    driver_loop(inner);
                },
                format!("async-exec-{idx}"),
                axconfig::TASK_STACK_SIZE,
            );
        }
    }
}

fn driver_loop(inner: Arc<ExecutorInner>) {
    loop {
        if let Some(slot) = inner.pop_ready() {
            poll_slot_from_queue(&inner, slot);
            continue;
        }

        inner
            .driver_wq
            .wait_until(|| !inner.ready_queue.lock().is_empty());
    }
}

impl TaskSlot {
    fn wake(slot: &Arc<Self>) {
        let mut cur = slot.state.load(Ordering::Acquire);
        loop {
            match cur {
                STATE_IDLE => {
                    match slot.state.compare_exchange_weak(
                        STATE_IDLE,
                        STATE_QUEUED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            if let Some(inner) = slot.executor.upgrade() {
                                inner.enqueue(Arc::clone(slot));
                            }
                            return;
                        }
                        Err(actual) => cur = actual,
                    }
                }
                STATE_POLLING => {
                    match slot.state.compare_exchange_weak(
                        STATE_POLLING,
                        STATE_POLLING_NOTIFIED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) | Err(STATE_POLLING_NOTIFIED) => return,
                        Err(actual) => cur = actual,
                    }
                }
                // Deduplicated: already queued, already notified during poll,
                // cancelled, or completed.
                STATE_QUEUED | STATE_POLLING_NOTIFIED | STATE_CANCELLED | STATE_COMPLETED => {
                    return;
                }
                _ => return,
            }
        }
    }

    fn waker(self: &Arc<Self>) -> Waker {
        let ptr = Arc::into_raw(Arc::clone(self)) as *const ();
        // SAFETY: `ptr` comes from `Arc::into_raw` on `TaskSlot`, and `VTABLE`
        // pairs every clone/wake/drop with matching `Arc` refcount operations.
        unsafe { Waker::from_raw(RawWaker::new(ptr, &WAKER_VTABLE)) }
    }
}

const WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    raw_waker_clone,
    raw_waker_wake,
    raw_waker_wake_by_ref,
    raw_waker_drop,
);

unsafe fn raw_waker_clone(ptr: *const ()) -> RawWaker {
    // SAFETY: Caller holds a valid `RawWaker` created from `Arc::into_raw`.
    unsafe { Arc::increment_strong_count(ptr as *const TaskSlot) };
    RawWaker::new(ptr, &WAKER_VTABLE)
}

unsafe fn raw_waker_wake(ptr: *const ()) {
    // SAFETY: Consumes the `Arc` strong reference owned by this `RawWaker`.
    let slot = unsafe { Arc::from_raw(ptr as *const TaskSlot) };
    TaskSlot::wake(&slot);
}

unsafe fn raw_waker_wake_by_ref(ptr: *const ()) {
    // SAFETY: Borrows the `Arc` strong reference without consuming it.
    let slot = unsafe { ManuallyDrop::new(Arc::from_raw(ptr as *const TaskSlot)) };
    TaskSlot::wake(&slot);
}

unsafe fn raw_waker_drop(ptr: *const ()) {
    // SAFETY: Consumes the `Arc` strong reference owned by this `RawWaker`.
    drop(unsafe { Arc::from_raw(ptr as *const TaskSlot) });
}

/// Cancellation handle for a task spawned onto [`KernelExecutor`].
#[derive(Clone)]
pub struct CancelHandle {
    slot: Arc<TaskSlot>,
}

impl CancelHandle {
    /// Cancels the spawned task if it has not yet completed.
    ///
    /// Guarantees the underlying `Future` is never dropped while `SpinNoIrq`
    /// is held or concurrently while another thread is polling it.
    pub fn cancel(&self) {
        self.slot.cancelled.store(true, Ordering::Release);
        let mut cur = self.slot.state.load(Ordering::Acquire);
        loop {
            match cur {
                STATE_IDLE | STATE_QUEUED => {
                    match self.slot.state.compare_exchange_weak(
                        cur,
                        STATE_CANCELLED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            let fut = self.slot.future.lock().take();
                            let _ = self.slot.state.compare_exchange(
                                STATE_CANCELLED,
                                STATE_COMPLETED,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            );
                            if let Some(fut) = fut {
                                if let Some(inner) = self.slot.executor.upgrade() {
                                    inner.pending_count.fetch_sub(1, Ordering::AcqRel);
                                }
                                drop(fut);
                            }
                            return;
                        }
                        Err(actual) => cur = actual,
                    }
                }
                STATE_POLLING | STATE_POLLING_NOTIFIED => {
                    match self.slot.state.compare_exchange_weak(
                        cur,
                        STATE_CANCELLED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            // The thread currently inside `Future::poll` will
                            // observe `STATE_CANCELLED` and drop the future
                            // immediately outside any spinlock once `poll` returns.
                            return;
                        }
                        Err(actual) => cur = actual,
                    }
                }
                STATE_CANCELLED | STATE_COMPLETED => return,
                _ => return,
            }
        }
    }

    /// Returns `true` if cancellation was requested for this task.
    pub fn is_cancelled(&self) -> bool {
        self.slot.cancelled.load(Ordering::Acquire)
    }

    /// Returns `true` if this task has finished executing or been cancelled and dropped.
    pub fn is_done(&self) -> bool {
        self.slot.state.load(Ordering::Acquire) == STATE_COMPLETED
    }
}

/// Dual-mode kernel multi-Future executor supporting inline first poll,
/// cooperative `drive_ready(budget)`, IRQ-safe deduplicated waking, and lazy
/// background driver threads.
pub struct KernelExecutor {
    inner: Arc<ExecutorInner>,
}

impl KernelExecutor {
    /// Creates a new executor with lazy background driver threads enabled on
    /// multi-task kernel builds (disabled under `#[cfg(test)]`).
    pub fn new() -> Self {
        Self::with_background_drivers(cfg!(not(test)))
    }

    /// Creates a new executor explicitly controlling background driver spawning.
    pub fn with_background_drivers(spawn_drivers: bool) -> Self {
        Self {
            inner: ExecutorInner::new(spawn_drivers),
        }
    }

    /// Spawns a future, performs the initial `poll()` inline in the caller's
    /// task context, and returns a [`CancelHandle`].
    pub fn spawn_and_poll_once<F>(&self, fut: F) -> CancelHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let boxed: BoxFuture = Box::pin(fut);
        self.spawn_boxed_and_poll_once(boxed)
    }

    /// Boxed variant of [`Self::spawn_and_poll_once`].
    pub fn spawn_boxed_and_poll_once(&self, fut: BoxFuture) -> CancelHandle {
        let slot = Arc::new(TaskSlot {
            state: AtomicU8::new(STATE_POLLING),
            cancelled: AtomicBool::new(false),
            future: SpinNoIrq::new(None),
            executor: Arc::downgrade(&self.inner),
        });
        let handle = CancelHandle {
            slot: Arc::clone(&slot),
        };
        self.inner.pending_count.fetch_add(1, Ordering::AcqRel);

        let pending = poll_owned_future(&self.inner, &slot, fut);
        if pending {
            self.inner.ensure_background_drivers();
        }
        handle
    }

    /// Cooperatively polls up to `budget` ready tasks in the caller's task
    /// context and returns the number of tasks polled.
    pub fn drive_ready(&self, budget: usize) -> usize {
        let mut polled = 0;
        while polled < budget {
            let Some(slot) = self.inner.pop_ready() else {
                break;
            };
            if poll_slot_from_queue(&self.inner, slot) {
                polled += 1;
            }
        }
        polled
    }

    /// Returns the number of queued tasks waiting to be polled.
    pub fn ready_len(&self) -> usize {
        self.inner.ready_queue.lock().len()
    }

    /// Returns the number of incomplete tasks tracked by this executor.
    pub fn pending_count(&self) -> usize {
        self.inner.pending_count.load(Ordering::Acquire)
    }
}

impl Default for KernelExecutor {
    fn default() -> Self {
        Self::new()
    }
}

fn poll_slot_from_queue(inner: &Arc<ExecutorInner>, slot: Arc<TaskSlot>) -> bool {
    match slot.state.compare_exchange(
        STATE_QUEUED,
        STATE_POLLING,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {}
        Err(_) => return false,
    }

    let fut = slot.future.lock().take();
    let Some(fut) = fut else {
        // Cancelled before we took ownership of the future.
        let _ = slot.state.compare_exchange(
            STATE_POLLING,
            STATE_COMPLETED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        return false;
    };

    poll_owned_future(inner, &slot, fut);
    true
}

/// Polls a future currently owned by this thread (`state` is `STATE_POLLING`
/// or `STATE_POLLING_NOTIFIED`, or transitioned to `STATE_CANCELLED` while polling).
///
/// Returns `true` if the future remains pending in the executor after returning.
fn poll_owned_future(inner: &Arc<ExecutorInner>, slot: &Arc<TaskSlot>, mut fut: BoxFuture) -> bool {
    let waker = slot.waker();
    let mut cx = Context::from_waker(&waker);

    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(()) => {
            slot.state.store(STATE_COMPLETED, Ordering::Release);
            inner.pending_count.fetch_sub(1, Ordering::AcqRel);
            drop(fut);
            false
        }
        Poll::Pending => {
            if slot.state.load(Ordering::Acquire) == STATE_CANCELLED {
                slot.state.store(STATE_COMPLETED, Ordering::Release);
                inner.pending_count.fetch_sub(1, Ordering::AcqRel);
                drop(fut);
                return false;
            }

            // Store the future back BEFORE publishing `STATE_IDLE` or
            // `STATE_QUEUED`, so any concurrent `cancel()` or worker that later
            // transitions out of `IDLE`/`QUEUED` observes `Some(fut)`.
            {
                let mut guard = slot.future.lock();
                *guard = Some(fut);
            }

            let mut cur = slot.state.load(Ordering::Acquire);
            loop {
                match cur {
                    STATE_POLLING => {
                        match slot.state.compare_exchange_weak(
                            STATE_POLLING,
                            STATE_IDLE,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => return true,
                            Err(actual) => cur = actual,
                        }
                    }
                    STATE_POLLING_NOTIFIED => {
                        match slot.state.compare_exchange_weak(
                            STATE_POLLING_NOTIFIED,
                            STATE_QUEUED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => {
                                inner.enqueue(Arc::clone(slot));
                                return true;
                            }
                            Err(actual) => cur = actual,
                        }
                    }
                    STATE_CANCELLED => {
                        let taken = slot.future.lock().take();
                        let _ = slot.state.compare_exchange(
                            STATE_CANCELLED,
                            STATE_COMPLETED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        );
                        if let Some(taken) = taken {
                            inner.pending_count.fetch_sub(1, Ordering::AcqRel);
                            drop(taken);
                        }
                        return false;
                    }
                    _ => return false,
                }
            }
        }
    }
}

static GLOBAL_EXECUTOR: LazyInit<KernelExecutor> = LazyInit::new();

/// Returns the process-wide shared kernel multi-Future executor.
pub fn global_executor() -> &'static KernelExecutor {
    GLOBAL_EXECUTOR.call_once(KernelExecutor::new);
    GLOBAL_EXECUTOR.get().expect("global executor initialized")
}

/// Spawns a future onto the global [`KernelExecutor`], running its initial
/// `poll()` inline in the caller's task context.
pub fn spawn_and_poll_once<F>(fut: F) -> CancelHandle
where
    F: Future<Output = ()> + Send + 'static,
{
    global_executor().spawn_and_poll_once(fut)
}

/// Cooperatively polls up to `budget` ready tasks on the global [`KernelExecutor`].
pub fn drive_ready(budget: usize) -> usize {
    global_executor().drive_ready(budget)
}
