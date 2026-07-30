#![cfg_attr(not(test), no_std)]
#![doc = include_str!("../README.md")]

mod cfs;
mod eevdf;
mod fifo;
mod round_robin;

#[cfg(test)]
mod tests;

extern crate alloc;

pub use cfs::{CFSTask, CFScheduler};
pub use eevdf::{EEVDFScheduler, EEVDFTask};
pub use fifo::{FifoScheduler, FifoTask};
pub use round_robin::{RRScheduler, RRTask};

/// Describes why a runnable task is inserted into a scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedEnqueueReason {
    /// A newly created task enters the scheduler for the first time.
    Spawn,
    /// A blocked task becomes runnable again.
    Wake,
    /// The running task voluntarily gives up the CPU.
    Yield,
    /// The running task is involuntarily preempted.
    Preempt,
    /// A runnable task moves between per-CPU schedulers.
    Migration,
}

/// The base scheduler trait that all schedulers should implement.
///
/// All tasks in the scheduler are considered runnable. If a task is go to
/// sleep, it should be removed from the scheduler.
pub trait BaseScheduler {
    /// Type of scheduled entities. Often a task struct.
    type SchedItem;

    /// Initializes the scheduler.
    fn init(&mut self);

    /// Adds a task to the scheduler.
    fn add_task(&mut self, task: Self::SchedItem);

    /// Adds or returns a task to the scheduler with lifecycle context.
    ///
    /// The default implementation preserves the behavior of schedulers that do
    /// not need timestamps or enqueue reasons.
    fn enqueue_task(&mut self, task: Self::SchedItem, reason: SchedEnqueueReason, _now_ns: u64) {
        match reason {
            SchedEnqueueReason::Spawn => self.add_task(task),
            SchedEnqueueReason::Preempt => self.put_prev_task(task, true),
            SchedEnqueueReason::Wake
            | SchedEnqueueReason::Yield
            | SchedEnqueueReason::Migration => self.put_prev_task(task, false),
        }
    }

    /// Removes a task by its reference from the scheduler. Returns the owned
    /// removed task with ownership if it exists.
    ///
    /// # Safety
    ///
    /// The caller should ensure that the task is in the scheduler, otherwise
    /// the behavior is undefined.
    fn remove_task(&mut self, task: &Self::SchedItem) -> Option<Self::SchedItem>;

    /// Picks the next task to run, it will be removed from the scheduler.
    /// Returns [`None`] if there is not runnable task.
    fn pick_next_task(&mut self) -> Option<Self::SchedItem>;

    /// Picks the next task at the given monotonic timestamp.
    fn pick_next_task_at(&mut self, _now_ns: u64) -> Option<Self::SchedItem> {
        self.pick_next_task()
    }

    /// Puts the previous task back to the scheduler. The previous task is
    /// usually placed at the end of the ready queue, making it less likely
    /// to be re-scheduled.
    ///
    /// `preempt` indicates whether the previous task is preempted by the next
    /// task. In this case, the previous task may be placed at the front of the
    /// ready queue.
    fn put_prev_task(&mut self, prev: Self::SchedItem, preempt: bool);

    /// Records that a task started executing at `now_ns`.
    fn task_started(&mut self, _task: &Self::SchedItem, _now_ns: u64) {}

    /// Accounts a task's final execution interval before it stops running.
    fn task_stopped(&mut self, _task: &Self::SchedItem, _now_ns: u64) {}

    /// Advances the scheduler state at each timer tick. Returns `true` if
    /// re-scheduling is required.
    ///
    /// `current` is the current running task.
    fn task_tick(&mut self, current: &Self::SchedItem) -> bool;

    /// Advances scheduler state using a monotonic nanosecond timestamp.
    fn task_tick_at(&mut self, current: &Self::SchedItem, _now_ns: u64) -> bool {
        self.task_tick(current)
    }

    /// Returns whether `candidate` should preempt `current` immediately.
    fn should_preempt(
        &mut self,
        _current: &Self::SchedItem,
        _candidate: &Self::SchedItem,
        _now_ns: u64,
    ) -> bool {
        false
    }

    /// Returns the next scheduler-owned preemption deadline in nanoseconds.
    fn next_preemption_deadline(&self, _current: &Self::SchedItem, _now_ns: u64) -> Option<u64> {
        None
    }

    /// set priority for a task
    fn set_priority(&mut self, task: &Self::SchedItem, prio: isize) -> bool;

    /// Sets task priority after accounting execution through `now_ns`.
    fn set_priority_at(&mut self, task: &Self::SchedItem, prio: isize, _now_ns: u64) -> bool {
        self.set_priority(task, prio)
    }

    /// Returns `true` if there are no tasks in the scheduler's ready queue.
    fn is_empty(&self) -> bool;
}
