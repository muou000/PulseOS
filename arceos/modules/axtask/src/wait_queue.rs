use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::{
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    task::Waker,
};

use kernel_guard::{NoOp, NoPreemptIrqSave};
use kspin::{SpinNoIrq, SpinNoIrqGuard};

use crate::{AxTaskRef, CurrentTask, current_run_queue, select_wake_run_queue};

/// A queue to store sleeping tasks.
///
/// # Examples
///
/// ```
/// use core::sync::atomic::{AtomicU32, Ordering};
///
/// use axtask::WaitQueue;
///
/// static VALUE: AtomicU32 = AtomicU32::new(0);
/// static WQ: WaitQueue = WaitQueue::new();
///
/// axtask::init_scheduler();
/// // spawn a new task that updates `VALUE` and notifies the main task
/// axtask::spawn(|| {
///     assert_eq!(VALUE.load(Ordering::Acquire), 0);
///     VALUE.fetch_add(1, Ordering::Release);
///     WQ.notify_one(true); // wake up the main task
/// });
///
/// WQ.wait(); // block until `notify()` is called
/// assert_eq!(VALUE.load(Ordering::Acquire), 1);
/// ```
pub struct WaitQueue {
    queue: SpinNoIrq<VecDeque<AxTaskRef>>,
    wakers: SpinNoIrq<VecDeque<WakerEntry>>,
}

/// A registered waker plus its companion notification flag.
///
/// `notified` is set to `true` by `notify_one` / `notify_all` immediately
/// before the stored `waker` is invoked. Holders of the `Arc<AtomicBool>`
/// (e.g. [`crate::future::WaitFuture`]) can poll this flag to detect that a
/// matching notification has occurred without having to rely on `waker.wake()`
/// to schedule another poll.
struct WakerEntry {
    id: u64,
    task_id: u64,
    notified: Arc<AtomicBool>,
    waker: Waker,
}

static WAKER_ENTRY_ID: AtomicU64 = AtomicU64::new(1);

/// An opaque handle for one independently owned waker registration.
pub struct WakerRegistration(u64);

pub(crate) type WaitQueueGuard<'a> = SpinNoIrqGuard<'a, VecDeque<AxTaskRef>>;

/// Semantic reason for a task entering an off-CPU wait interval.
///
/// Values are part of the PulseOS qperf marker ABI. Append new variants instead
/// of renumbering existing ones.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitReason {
    WaitQueue      = 1,
    Future         = 2,
    MultiWait      = 3,
    Sleep          = 4,
    Mutex          = 5,
    RwLockRead     = 6,
    RwLockWrite    = 7,
    Futex          = 8,
    FutexWaitV     = 9,
    VirtioBlkRead  = 10,
    VirtioBlkWrite = 11,
    Gc             = 12,
    ChildWait      = 13,
    Vfork          = 14,
    Signal         = 15,
    NetworkPoll    = 16,
}

/// Typed context retained with a blocked task interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitContext {
    #[cfg(feature = "qperf-trace")]
    reason: WaitReason,
    #[cfg(feature = "qperf-trace")]
    resource_id: u64,
    #[cfg(feature = "qperf-trace")]
    resource_detail: u64,
}

impl WaitContext {
    pub const fn new(reason: WaitReason, resource_id: u64, resource_detail: u64) -> Self {
        #[cfg(not(feature = "qperf-trace"))]
        let _ = (reason, resource_id, resource_detail);
        Self {
            #[cfg(feature = "qperf-trace")]
            reason,
            #[cfg(feature = "qperf-trace")]
            resource_id,
            #[cfg(feature = "qperf-trace")]
            resource_detail,
        }
    }

    #[cfg(feature = "qperf-trace")]
    pub(crate) const fn reason(self) -> WaitReason {
        self.reason
    }

    #[cfg(feature = "qperf-trace")]
    pub(crate) const fn resource_id(self) -> u64 {
        self.resource_id
    }

    #[cfg(feature = "qperf-trace")]
    pub(crate) const fn resource_detail(self) -> u64 {
        self.resource_detail
    }
}

/// Semantic origin of a blocked-to-ready transition.
///
/// The source is separate from the task executing the wake path because device
/// and timer callbacks often run in the context of an interrupted task.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeSource {
    Unknown   = 0,
    Task      = 1,
    Timer     = 2,
    Future    = 3,
    Futex     = 4,
    Device    = 5,
    Signal    = 6,
    Interrupt = 7,
}

/// Typed context retained with a task wake event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeContext {
    #[cfg(feature = "qperf-trace")]
    source: WakeSource,
    #[cfg(feature = "qperf-trace")]
    source_id: u64,
}

impl WakeContext {
    pub const fn new(source: WakeSource, source_id: u64) -> Self {
        #[cfg(not(feature = "qperf-trace"))]
        let _ = (source, source_id);
        Self {
            #[cfg(feature = "qperf-trace")]
            source,
            #[cfg(feature = "qperf-trace")]
            source_id,
        }
    }

    pub const fn unknown() -> Self {
        Self::new(WakeSource::Unknown, 0)
    }

    pub const fn task() -> Self {
        Self::new(WakeSource::Task, 0)
    }

    #[cfg(feature = "qperf-trace")]
    pub(crate) const fn source(self) -> WakeSource {
        self.source
    }

    #[cfg(feature = "qperf-trace")]
    pub(crate) const fn source_id(self) -> u64 {
        self.source_id
    }
}

impl WaitQueue {
    /// Creates an empty wait queue.
    pub const fn new() -> Self {
        Self {
            queue: SpinNoIrq::new(VecDeque::new()),
            wakers: SpinNoIrq::new(VecDeque::new()),
        }
    }

    /// Creates an empty wait queue with space for at least `capacity` elements.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            queue: SpinNoIrq::new(VecDeque::with_capacity(capacity)),
            wakers: SpinNoIrq::new(VecDeque::with_capacity(capacity)),
        }
    }

    #[inline]
    fn wait_context(&self) -> WaitContext {
        WaitContext::new(
            WaitReason::WaitQueue,
            self as *const Self as usize as u64,
            0,
        )
    }

    /// Cancel events by removing the task from the wait queue.
    /// If `from_timer_list` is true, try to remove the task from the timer list.
    fn cancel_events(&self, curr: &CurrentTask, _from_timer_list: bool) {
        // A task can be wake up only one events (timer or `notify()`), remove
        // the event from another queue. Use the queue membership as the source
        // of truth instead of the task-local flag to avoid stale state.
        let still_queued = {
            let mut wq = self.queue.lock();
            let still_queued = wq.iter().any(|t| Arc::ptr_eq(curr.as_task_ref(), t));
            if still_queued {
                wq.retain(|t| !Arc::ptr_eq(curr.as_task_ref(), t));
            }
            still_queued
        };
        if still_queued {
            curr.set_in_wait_queue(false);
        }

        // Try to cancel a timer event from timer lists.
        // Just mark task's current timer ticket ID as expired.
        #[cfg(feature = "irq")]
        if _from_timer_list {
            curr.timer_ticket_expired();
            // Note:
            //  this task is still not removed from timer list of target CPU,
            //  which may cause some redundant timer events because it still needs to
            //  go through the process of expiring an event from the timer list and invoking the callback.
            //  (it can be considered a lazy-removal strategy, it will be ignored when it is about to take effect.)
        }
    }

    /// Blocks the current task and put it into the wait queue, until other task
    /// notifies it.
    pub fn wait(&self) {
        self.wait_with_context(self.wait_context());
    }

    /// Blocks the current task with an explicitly typed wait context.
    pub fn wait_with_context(&self, context: WaitContext) {
        let curr = crate::current();
        let mut rq = current_run_queue::<NoPreemptIrqSave>();
        rq.blocked_resched(self.queue.lock(), context);
        self.cancel_events(&curr, false);
    }

    /// Blocks the current task and put it into the wait queue, until the given
    /// `condition` becomes true.
    ///
    /// Note that even other tasks notify this task, it will not wake up until
    /// the condition becomes true.
    pub fn wait_until<F>(&self, condition: F)
    where
        F: Fn() -> bool,
    {
        self.wait_until_with_context(self.wait_context(), condition);
    }

    /// Blocks until `condition` becomes true and records an explicitly typed wait context.
    pub fn wait_until_with_context<F>(&self, context: WaitContext, condition: F)
    where
        F: Fn() -> bool,
    {
        let curr = crate::current();
        loop {
            let mut rq = current_run_queue::<NoPreemptIrqSave>();
            let wq = self.queue.lock();
            if condition() {
                break;
            }
            rq.blocked_resched(wq, context);
            // Preemption may occur here.
        }
        self.cancel_events(&curr, false);
    }

    /// Blocks the current task and put it into the wait queue, until other tasks
    /// notify it, or the given duration has elapsed.
    #[cfg(feature = "irq")]
    pub fn wait_timeout(&self, dur: core::time::Duration) -> bool {
        self.wait_timeout_with_context(self.wait_context(), dur)
    }

    /// Blocks until notification or timeout and records an explicitly typed wait context.
    #[cfg(feature = "irq")]
    pub fn wait_timeout_with_context(
        &self,
        context: WaitContext,
        dur: core::time::Duration,
    ) -> bool {
        let mut rq = current_run_queue::<NoPreemptIrqSave>();
        let curr = crate::current();
        let deadline = axhal::time::monotonic_time() + dur;
        debug!(
            "task wait_timeout: {} deadline={:?}",
            curr.id_name(),
            deadline
        );
        crate::timers::set_alarm_wakeup(deadline, curr.clone());

        rq.blocked_resched(self.queue.lock(), context);

        let timeout = self
            .queue
            .lock()
            .iter()
            .any(|t| Arc::ptr_eq(t, curr.as_task_ref())); // still in the wait queue, must have timed out

        // Always try to remove the task from the timer list.
        self.cancel_events(&curr, true);
        timeout
    }

    /// Blocks the current task and put it into the wait queue, until the given
    /// `condition` becomes true, or the given duration has elapsed.
    ///
    /// Note that even other tasks notify this task, it will not wake up until
    /// the above conditions are met.
    #[cfg(feature = "irq")]
    pub fn wait_timeout_until<F>(&self, dur: core::time::Duration, condition: F) -> bool
    where
        F: Fn() -> bool,
    {
        self.wait_timeout_until_with_context(self.wait_context(), dur, condition)
    }

    /// Blocks until `condition` or timeout and records an explicitly typed wait context.
    #[cfg(feature = "irq")]
    pub fn wait_timeout_until_with_context<F>(
        &self,
        context: WaitContext,
        dur: core::time::Duration,
        condition: F,
    ) -> bool
    where
        F: Fn() -> bool,
    {
        let curr = crate::current();
        let deadline = axhal::time::monotonic_time() + dur;
        debug!(
            "task wait_timeout: {}, deadline={:?}",
            curr.id_name(),
            deadline
        );
        crate::timers::set_alarm_wakeup(deadline, curr.clone());

        let mut timeout = true;
        loop {
            let mut rq = current_run_queue::<NoPreemptIrqSave>();
            if axhal::time::monotonic_time() >= deadline {
                break;
            }
            let wq = self.queue.lock();
            if condition() {
                timeout = false;
                break;
            }

            rq.blocked_resched(wq, context);
            // Preemption may occur here.
        }
        // Always try to remove the task from the timer list.
        self.cancel_events(&curr, true);
        timeout
    }

    /// Blocks the current task and put it into multiple wait queues, until the given
    /// `condition` becomes true, or the given duration has elapsed, or it is awoken
    /// by any of the given wait queues.
    ///
    /// Returns `Ok(index)` if woken by the queue at the given index, or `Err(timeout)`
    /// indicating whether a timeout occurred (`true`) or the condition aborted the wait (`false`).
    #[cfg(feature = "irq")]
    pub fn wait_multiple_timeout_until<F>(
        queues: &[&WaitQueue],
        dur: Option<core::time::Duration>,
        condition: F,
    ) -> Result<usize, bool>
    where
        F: FnMut() -> bool,
    {
        let resource_id = queues
            .first()
            .map(|queue| *queue as *const WaitQueue as usize as u64)
            .unwrap_or(0);
        Self::wait_multiple_timeout_until_with_context(
            queues,
            dur,
            WaitContext::new(WaitReason::MultiWait, resource_id, queues.len() as u64),
            condition,
        )
    }

    /// Waits on multiple queues with an explicitly typed wait context.
    #[cfg(feature = "irq")]
    pub fn wait_multiple_timeout_until_with_context<F>(
        queues: &[&WaitQueue],
        dur: Option<core::time::Duration>,
        context: WaitContext,
        mut condition: F,
    ) -> Result<usize, bool>
    where
        F: FnMut() -> bool,
    {
        let curr = crate::current();
        let deadline = dur.map(|d| axhal::time::monotonic_time() + d);
        if let Some(d) = deadline {
            crate::timers::set_alarm_wakeup(d, curr.clone());
        }

        let mut timeout = dur.is_some();
        let mut woken_by = None;

        loop {
            if let Some(d) = deadline {
                if axhal::time::monotonic_time() >= d {
                    break;
                }
            }

            // The condition may enter a sleeping kernel lock, so it must be
            // checked while the current task is still Running and without a
            // run-queue guard held.
            if condition() {
                timeout = false;
                break;
            }

            // Enroll while still Running. A concurrent notifier that removes
            // an entry in this window records the wake by clearing
            // `in_wait_queue`; this is checked again after changing the state.
            curr.set_in_wait_queue(true);
            for q in queues {
                let mut wq = q.queue.lock();
                if !wq.iter().any(|t| Arc::ptr_eq(t, curr.as_task_ref())) {
                    wq.push_back(curr.as_task_ref().clone());
                }
            }

            // Close the check/enroll race. If readiness changed before the
            // task was visible in a queue, this second check observes it.
            if condition() {
                timeout = false;
                break;
            }

            let mut rq = crate::run_queue::current_run_queue::<NoPreemptIrqSave>();
            #[cfg(feature = "qperf-trace")]
            let qperf_sequence = curr.next_qperf_block_sequence();
            curr.set_state(crate::task::TaskState::Blocked);

            // A notifier may have consumed an entry while the task was still
            // Running. Restore Running locally if it won that race; if it
            // already changed Blocked to Ready, reschedule to consume the
            // queued wakeup normally.
            let consumed_while_running = !curr.in_wait_queue()
                && curr.transition_state(
                    crate::task::TaskState::Blocked,
                    crate::task::TaskState::Running,
                );
            if consumed_while_running {
                drop(rq);
            } else {
                rq.resched_blocked(
                    #[cfg(feature = "qperf-trace")]
                    qperf_sequence,
                    context,
                );
            }

            for (i, q) in queues.iter().enumerate() {
                let wq = q.queue.lock();
                if !wq.iter().any(|t| Arc::ptr_eq(t, curr.as_task_ref())) {
                    woken_by = Some(i);
                    break;
                }
            }
            if woken_by.is_some() {
                break;
            }
        }

        for q in queues {
            q.cancel_events(&curr, false);
        }
        curr.set_in_wait_queue(false);
        if deadline.is_some() {
            if let Some(q) = queues.first() {
                q.cancel_events(&curr, true);
            }
        }

        if let Some(idx) = woken_by {
            Ok(idx)
        } else {
            Err(timeout)
        }
    }

    /// Wake up a task in the wait queue.
    ///
    /// If `resched` is true, the current task will yield the CPU.
    pub fn notify_one(&self, resched: bool) -> bool {
        self.notify_one_with_context(resched, WakeContext::unknown())
    }

    /// Wakes one waiter and records an explicitly typed wake source.
    pub fn notify_one_with_context(&self, resched: bool, context: WakeContext) -> bool {
        let mut wq = self.queue.lock();
        let mut target = None;
        let mut consumed_running = false;
        while let Some(task) = wq.pop_front() {
            match task.state() {
                crate::task::TaskState::Blocked => {
                    target = Some(task);
                    break;
                }
                crate::task::TaskState::Running if task.consume_wait_queue_entry() => {
                    // `wait_multiple_timeout_until` enrolls the current task
                    // before changing it to Blocked. Consuming that Running
                    // entry is the one notification; do not drain later
                    // Running waiters while looking for a Blocked task.
                    consumed_running = true;
                    break;
                }
                _ => {
                    // A timeout or a notification through another queue can
                    // leave a stale entry behind until the waiter cleans up.
                    task.set_in_wait_queue(false);
                }
            }
        }
        drop(wq);

        if let Some(task) = target {
            unblock_one_task(task, resched, context);
            true
        } else if consumed_running {
            true
        } else {
            // Only remove and wake one registered waker, matching the
            // single-task semantics of `notify_one`. All other wakers
            // remain registered for future notifications.
            let entry = {
                let mut wakers = self.wakers.lock();
                let entry = wakers.pop_front();
                if let Some(entry) = entry.as_ref() {
                    // Keep this store under the queue lock. A concurrent poll
                    // that fails to find the removed registration must then
                    // observe the completed notification.
                    entry.notified.store(true, Ordering::Release);
                }
                entry
            };
            if let Some(entry) = entry {
                entry.waker.wake();
                true
            } else {
                false
            }
        }
    }

    /// Wakes all tasks in the wait queue.
    ///
    /// If `resched` is true, the current task will be preempted when the
    /// preemption is enabled.
    pub fn notify_all(&self, resched: bool) {
        self.notify_all_with_context(resched, WakeContext::unknown());
    }

    /// Wakes all waiters and records an explicitly typed wake source.
    pub fn notify_all_with_context(&self, resched: bool, context: WakeContext) {
        let tasks = {
            let mut wq = self.queue.lock();
            core::mem::take(&mut *wq)
        };

        if !tasks.is_empty() {
            let _guard = NoPreemptIrqSave::new();
            for task in tasks {
                if task.state() == crate::task::TaskState::Blocked {
                    unblock_one_task_locked(task, resched, context);
                } else {
                    task.set_in_wait_queue(false);
                }
            }
        }

        let wakers = {
            let mut wakers = self.wakers.lock();
            for entry in wakers.iter() {
                entry.notified.store(true, Ordering::Release);
            }
            core::mem::take(&mut *wakers)
        };
        for entry in wakers {
            entry.waker.wake();
        }
    }

    /// Wake up the given task in the wait queue.
    ///
    /// If `resched` is true, the current task will be preempted when the
    /// preemption is enabled.
    pub fn notify_task(&mut self, resched: bool, task: &AxTaskRef) -> bool {
        self.notify_task_with_context(resched, task, WakeContext::unknown())
    }

    /// Wakes a selected waiter and records an explicitly typed wake source.
    pub fn notify_task_with_context(
        &mut self,
        resched: bool,
        task: &AxTaskRef,
        context: WakeContext,
    ) -> bool {
        let task = {
            let mut wq = self.queue.lock();
            if let Some(index) = wq.iter().position(|t| Arc::ptr_eq(t, task)) {
                wq.remove(index)
            } else {
                None
            }
        };

        if let Some(task) = task {
            unblock_one_task(task, resched, context);
            true
        } else {
            false
        }
    }

    /// Transfers up to `count` tasks from this wait queue to another wait queue.
    ///
    /// Note: If the current wait queue contains fewer than `count` tasks, all available tasks will be moved.
    ///
    /// ## Arguments
    /// * `count` - The maximum number of tasks to be moved.
    /// * `target` - The target wait queue to which tasks will be moved.
    ///
    /// ## Returns
    /// The number of tasks actually requeued.
    pub fn requeue(&self, mut count: usize, target: &WaitQueue) -> usize {
        let tasks: Vec<_> = {
            let mut wq = self.queue.lock();
            count = count.min(wq.len());
            wq.drain(..count).collect()
        };
        if !tasks.is_empty() {
            let mut wq = target.queue.lock();
            wq.extend(tasks);
        }
        count
    }

    /// Returns the number of tasks in the wait queue.
    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    /// Returns true if the wait queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.lock().is_empty()
    }

    /// Remove all exited tasks from the wait queue.
    pub fn prune_exited(&self) {
        self.queue
            .lock()
            .retain(|t| t.state() != crate::task::TaskState::Exited);
    }

    /// Registers a waker to the wait queue.
    ///
    /// Returns a shared notification flag (`Arc<AtomicBool>`) tied to the
    /// current task's registration. `notify_one` / `notify_all` will set this
    /// flag to `true` before invoking the waker; holders of the returned
    /// `Arc` (such as [`crate::future::WaitFuture`]) should treat the flag
    /// as the authoritative completion signal rather than relying on the
    /// waker alone, since spurious or unrelated wakes are permitted by the
    /// `Future` contract.
    ///
    /// Callers that do not need to observe the flag directly may simply
    /// discard the returned value; the waker is still registered and will be
    /// invoked on the next matching notification.
    pub fn register_waker(&self, waker: &core::task::Waker) -> Arc<AtomicBool> {
        self.register_waker_inner(waker, true).1
    }

    /// Registers a waker without task-level deduplication.
    ///
    /// The returned handle owns exactly one queue entry and must eventually
    /// be passed to [`WaitQueue::unregister_waker`].
    pub fn register_owned_waker(&self, waker: &core::task::Waker) -> WakerRegistration {
        WakerRegistration(self.register_waker_inner(waker, false).0)
    }

    fn register_waker_inner(
        &self,
        waker: &core::task::Waker,
        deduplicate_task: bool,
    ) -> (u64, Arc<AtomicBool>) {
        let mut wakers = self.wakers.lock();
        let task_id = crate::current().id().as_u64();
        if deduplicate_task {
            if let Some(entry) = wakers.iter_mut().find(|entry| entry.task_id == task_id) {
                if !entry.waker.will_wake(waker) {
                    entry.waker = waker.clone();
                }
                return (entry.id, entry.notified.clone());
            }
        }

        let id = WAKER_ENTRY_ID.fetch_add(1, Ordering::Relaxed);
        let notified = Arc::new(AtomicBool::new(false));
        wakers.push_back(WakerEntry {
            id,
            task_id,
            notified: notified.clone(),
            waker: waker.clone(),
        });
        (id, notified)
    }

    pub(crate) fn register_wait_future_waker(
        &self,
        waker: &core::task::Waker,
    ) -> (WakerRegistration, Arc<AtomicBool>) {
        let (id, notified) = self.register_waker_inner(waker, false);
        (WakerRegistration(id), notified)
    }

    pub(crate) fn update_registered_waker(
        &self,
        registration: &WakerRegistration,
        waker: &core::task::Waker,
    ) {
        let mut wakers = self.wakers.lock();
        if let Some(entry) = wakers.iter_mut().find(|entry| entry.id == registration.0)
            && !entry.waker.will_wake(waker)
        {
            entry.waker = waker.clone();
        }
    }

    pub fn unregister_waker(&self, registration: WakerRegistration) {
        self.wakers
            .lock()
            .retain(|entry| entry.id != registration.0);
    }

    /// Returns a future that waits for the wait queue.
    pub fn wait_async(&self) -> crate::future::WaitFuture {
        crate::future::WaitFuture::new(self)
    }

    #[cfg(test)]
    pub(crate) fn enqueue_task_for_test(&self, task: AxTaskRef) {
        self.queue.lock().push_back(task);
    }
}

fn unblock_one_task(task: AxTaskRef, resched: bool, context: WakeContext) {
    let _guard = NoPreemptIrqSave::new();
    unblock_one_task_locked(task, resched, context);
}

fn unblock_one_task_locked(task: AxTaskRef, resched: bool, context: WakeContext) {
    // Mark task as not in wait queue.
    task.set_in_wait_queue(false);
    // Select run queue by the CPU set of the task.
    // Use `NoOp` kernel guard here because the function is called with holding the
    // lock of wait queue, or an explicit `NoPreemptIrqSave` guard.
    select_wake_run_queue::<NoOp>(&task).unblock_task_with_context(task, resched, context)
}
