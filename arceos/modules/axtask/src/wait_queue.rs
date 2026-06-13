use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use kernel_guard::{NoOp, NoPreemptIrqSave};
use kspin::{SpinNoIrq, SpinNoIrqGuard};

use crate::{AxTaskRef, CurrentTask, current_run_queue, select_run_queue};

/// A queue to store sleeping tasks.
///
/// # Examples
///
/// ```
/// use axtask::WaitQueue;
/// use core::sync::atomic::{AtomicU32, Ordering};
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
}

pub(crate) type WaitQueueGuard<'a> = SpinNoIrqGuard<'a, VecDeque<AxTaskRef>>;

impl WaitQueue {
    /// Creates an empty wait queue.
    pub const fn new() -> Self {
        Self {
            queue: SpinNoIrq::new(VecDeque::new()),
        }
    }

    /// Creates an empty wait queue with space for at least `capacity` elements.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            queue: SpinNoIrq::new(VecDeque::with_capacity(capacity)),
        }
    }

    /// Cancel events by removing the task from the wait queue.
    /// If `from_timer_list` is true, try to remove the task from the timer list.
    fn cancel_events(&self, curr: &CurrentTask, _from_timer_list: bool) {
        if !curr.in_wait_queue() {
            return;
        }

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
        let curr = crate::current();
        let mut rq = current_run_queue::<NoPreemptIrqSave>();
        rq.blocked_resched(self.queue.lock());
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
        let curr = crate::current();
        loop {
            let mut rq = current_run_queue::<NoPreemptIrqSave>();
            let wq = self.queue.lock();
            if condition() {
                break;
            }
            rq.blocked_resched(wq);
            // Preemption may occur here.
        }
        self.cancel_events(&curr, false);
    }

    /// Blocks the current task and put it into the wait queue, until other tasks
    /// notify it, or the given duration has elapsed.
    #[cfg(feature = "irq")]
    pub fn wait_timeout(&self, dur: core::time::Duration) -> bool {
        let mut rq = current_run_queue::<NoPreemptIrqSave>();
        let curr = crate::current();
        let deadline = axhal::time::wall_time() + dur;
        debug!(
            "task wait_timeout: {} deadline={:?}",
            curr.id_name(),
            deadline
        );
        crate::timers::set_alarm_wakeup(deadline, curr.clone());

        rq.blocked_resched(self.queue.lock());

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
        let curr = crate::current();
        let deadline = axhal::time::wall_time() + dur;
        debug!(
            "task wait_timeout: {}, deadline={:?}",
            curr.id_name(),
            deadline
        );
        crate::timers::set_alarm_wakeup(deadline, curr.clone());

        let mut timeout = true;
        loop {
            let mut rq = current_run_queue::<NoPreemptIrqSave>();
            if axhal::time::wall_time() >= deadline {
                break;
            }
            let wq = self.queue.lock();
            if condition() {
                timeout = false;
                break;
            }

            rq.blocked_resched(wq);
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
        mut condition: F,
    ) -> Result<usize, bool>
    where
        F: FnMut() -> bool,
    {
        let curr = crate::current();
        let deadline = dur.map(|d| axhal::time::wall_time() + d);
        if let Some(d) = deadline {
            crate::timers::set_alarm_wakeup(d, curr.clone());
        }

        let mut timeout = dur.is_some();
        let mut woken_by = None;

        loop {
            let mut rq = crate::run_queue::current_run_queue::<NoPreemptIrqSave>();
            if let Some(d) = deadline {
                if axhal::time::wall_time() >= d {
                    break;
                }
            }

            curr.set_state(crate::task::TaskState::Blocked);
            curr.set_in_wait_queue(true);

            for q in queues {
                let mut wq = q.queue.lock();
                if !wq.iter().any(|t| Arc::ptr_eq(t, curr.as_task_ref())) {
                    wq.push_back(curr.as_task_ref().clone());
                }
            }

            if condition() {
                timeout = false;
                if curr.transition_state(crate::task::TaskState::Blocked, crate::task::TaskState::Running) {
                    curr.set_in_wait_queue(false);
                    break;
                }
            }

            rq.resched_blocked();

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

    /// Wakes up one task in the wait queue, usually the first one.
    ///
    /// If `resched` is true, the current task will be preempted when the
    /// preemption is enabled.
    pub fn notify_one(&self, resched: bool) -> bool {
        let task = {
            let mut wq = self.queue.lock();
            let mut target = None;
            while let Some(task) = wq.pop_front() {
                if task.state() == crate::task::TaskState::Blocked {
                    target = Some(task);
                    break;
                }
                // The task is no longer blocked (e.g., timed out), but still in the wait queue.
                // We should mark it as not in the wait queue.
                task.set_in_wait_queue(false);
            }
            target
        };

        if let Some(task) = task {
            unblock_one_task(task, resched);
            true
        } else {
            false
        }
    }

    /// Wakes all tasks in the wait queue.
    ///
    /// If `resched` is true, the current task will be preempted when the
    /// preemption is enabled.
    pub fn notify_all(&self, resched: bool) {
        let tasks = {
            let mut wq = self.queue.lock();
            core::mem::take(&mut *wq)
        };

        if !tasks.is_empty() {
            let _guard = NoPreemptIrqSave::new();
            for task in tasks {
                if task.state() == crate::task::TaskState::Blocked {
                    unblock_one_task_locked(task, resched);
                } else {
                    task.set_in_wait_queue(false);
                }
            }
        }
    }

    /// Wake up the given task in the wait queue.
    ///
    /// If `resched` is true, the current task will be preempted when the
    /// preemption is enabled.
    pub fn notify_task(&mut self, resched: bool, task: &AxTaskRef) -> bool {
        let task = {
            let mut wq = self.queue.lock();
            if let Some(index) = wq.iter().position(|t| Arc::ptr_eq(t, task)) {
                wq.remove(index)
            } else {
                None
            }
        };

        if let Some(task) = task {
            unblock_one_task(task, resched);
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
        self.queue.lock().retain(|t| t.state() != crate::task::TaskState::Exited);
    }
}

fn unblock_one_task(task: AxTaskRef, resched: bool) {
    let _guard = NoPreemptIrqSave::new();
    unblock_one_task_locked(task, resched);
}

fn unblock_one_task_locked(task: AxTaskRef, resched: bool) {
    // Mark task as not in wait queue.
    task.set_in_wait_queue(false);
    // Select run queue by the CPU set of the task.
    // Use `NoOp` kernel guard here because the function is called with holding the
    // lock of wait queue, or an explicit `NoPreemptIrqSave` guard.
    select_run_queue::<NoOp>(&task).unblock_task(task, resched)
}
