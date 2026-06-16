use alloc::sync::Arc;
use core::ops::Deref;
use core::sync::atomic::{AtomicIsize, Ordering};

use linked_list_r4l::{GetLinks, Links, List};

use crate::BaseScheduler;

/// A task wrapper for the [`RRScheduler`].
///
/// It add a time slice counter to use in round-robin scheduling.
pub struct RRTask<T, const MAX_TIME_SLICE: usize> {
    inner: T,
    time_slice: AtomicIsize,
    priority: AtomicIsize,
    links: Links<Self>,
}

impl<T, const S: usize> RRTask<T, S> {
    /// Creates a new [`RRTask`] from the inner task struct.
    pub const fn new(inner: T) -> Self {
        Self {
            inner,
            time_slice: AtomicIsize::new(S as isize),
            priority: AtomicIsize::new(-100), // Default is normal nice 0, encoded as -100
            links: Links::new(),
        }
    }

    fn time_slice(&self) -> isize {
        self.time_slice.load(Ordering::Acquire)
    }

    fn reset_time_slice(&self) {
        self.time_slice.store(S as isize, Ordering::Release);
    }

    pub fn priority(&self) -> isize {
        self.priority.load(Ordering::Acquire)
    }

    pub fn set_priority(&self, prio: isize) {
        self.priority.store(prio, Ordering::Release);
    }

    /// Returns a reference to the inner task struct.
    pub const fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T, const MAX_TIME_SLICE: usize> GetLinks for RRTask<T, MAX_TIME_SLICE> {
    type EntryType = Self;

    fn get_links(data: &Self::EntryType) -> &Links<Self::EntryType> {
        &data.links
    }
}

impl<T, const S: usize> Deref for RRTask<T, S> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// A simple [Round-Robin] (RR) preemptive scheduler.
///
/// It's very similar to the [`FifoScheduler`], but every task has a time slice
/// counter that is decremented each time a timer tick occurs. When the current
/// task's time slice counter reaches zero, the task is preempted and needs to
/// be rescheduled.
///
/// It internally uses a linked list as the ready queue.
///
/// [Round-Robin]: https://en.wikipedia.org/wiki/Round-robin_scheduling
/// [`FifoScheduler`]: crate::FifoScheduler
pub struct RRScheduler<T, const MAX_TIME_SLICE: usize> {
    rt_queues: [List<Arc<RRTask<T, MAX_TIME_SLICE>>>; 99],
    rt_bitmap: u128,
    normal_queue: List<Arc<RRTask<T, MAX_TIME_SLICE>>>,
}

impl<T, const S: usize> RRScheduler<T, S> {
    /// Creates a new empty [`RRScheduler`].
    pub const fn new() -> Self {
        Self {
            rt_queues: [const { List::new() }; 99],
            rt_bitmap: 0,
            normal_queue: List::new(),
        }
    }
    /// get the name of scheduler
    pub fn scheduler_name() -> &'static str {
        "Round-robin with RT priority"
    }
}

impl<T, const S: usize> BaseScheduler for RRScheduler<T, S> {
    type SchedItem = Arc<RRTask<T, S>>;

    fn init(&mut self) {}

    fn add_task(&mut self, task: Self::SchedItem) {
        let prio = task.priority();
        if (1..=99).contains(&prio) {
            let index = (99 - prio) as usize;
            self.rt_queues[index].push_back(task);
            self.rt_bitmap |= 1u128 << index;
        } else {
            self.normal_queue.push_back(task);
        }
    }

    fn remove_task(&mut self, task: &Self::SchedItem) -> Option<Self::SchedItem> {
        let prio = task.priority();
        if (1..=99).contains(&prio) {
            let index = (99 - prio) as usize;
            let removed = unsafe { self.rt_queues[index].remove(task) };
            if removed.is_some() && self.rt_queues[index].is_empty() {
                self.rt_bitmap &= !(1u128 << index);
            }
            removed
        } else {
            unsafe { self.normal_queue.remove(task) }
        }
    }

    fn pick_next_task(&mut self) -> Option<Self::SchedItem> {
        if self.rt_bitmap != 0 {
            let index = self.rt_bitmap.trailing_zeros() as usize;
            let task = self.rt_queues[index].pop_front();
            if self.rt_queues[index].is_empty() {
                self.rt_bitmap &= !(1u128 << index);
            }
            task
        } else {
            self.normal_queue.pop_front()
        }
    }

    fn put_prev_task(&mut self, prev: Self::SchedItem, preempt: bool) {
        let prio = prev.priority();
        let is_rt = (1..=99).contains(&prio);
        let time_slice_pos = prev.time_slice() > 0;

        if is_rt {
            let index = (99 - prio) as usize;
            if time_slice_pos && preempt {
                self.rt_queues[index].push_front(prev);
            } else {
                prev.reset_time_slice();
                self.rt_queues[index].push_back(prev);
            }
            self.rt_bitmap |= 1u128 << index;
        } else {
            if time_slice_pos && preempt {
                self.normal_queue.push_front(prev);
            } else {
                prev.reset_time_slice();
                self.normal_queue.push_back(prev);
            }
        }
    }

    fn task_tick(&mut self, current: &Self::SchedItem) -> bool {
        let old_slice = current.time_slice.fetch_sub(1, Ordering::Release);
        old_slice <= 1
    }

    fn set_priority(&mut self, task: &Self::SchedItem, prio: isize) -> bool {
        let was_in_queue = self.remove_task(task).is_some();
        task.set_priority(prio);
        if was_in_queue {
            self.add_task(task.clone());
        }
        true
    }
}

impl<T, const S: usize> Default for RRScheduler<T, S> {
    fn default() -> Self {
        Self::new()
    }
}
