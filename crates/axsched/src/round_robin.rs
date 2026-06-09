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
            priority: AtomicIsize::new(0),
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
    rt_queue: List<Arc<RRTask<T, MAX_TIME_SLICE>>>,
    normal_queue: List<Arc<RRTask<T, MAX_TIME_SLICE>>>,
}

impl<T, const S: usize> RRScheduler<T, S> {
    /// Creates a new empty [`RRScheduler`].
    pub const fn new() -> Self {
        Self {
            rt_queue: List::new(),
            normal_queue: List::new(),
        }
    }
    /// get the name of scheduler
    pub fn scheduler_name() -> &'static str {
        "Round-robin with RT priority"
    }

    unsafe fn clone_arc(task: &RRTask<T, S>) -> Arc<RRTask<T, S>> {
        let ptr = task as *const RRTask<T, S>;
        unsafe {
            Arc::increment_strong_count(ptr);
            Arc::from_raw(ptr)
        }
    }
}

impl<T, const S: usize> BaseScheduler for RRScheduler<T, S> {
    type SchedItem = Arc<RRTask<T, S>>;

    fn init(&mut self) {}

    fn add_task(&mut self, task: Self::SchedItem) {
        if task.priority() < 0 {
            self.rt_queue.push_back(task);
        } else {
            self.normal_queue.push_back(task);
        }
    }

    fn remove_task(&mut self, task: &Self::SchedItem) -> Option<Self::SchedItem> {
        if task.priority() < 0 {
            unsafe { self.rt_queue.remove(task) }
        } else {
            unsafe { self.normal_queue.remove(task) }
        }
    }

    fn pick_next_task(&mut self) -> Option<Self::SchedItem> {
        if self.rt_queue.is_empty() {
            self.normal_queue.pop_front()
        } else {
            // Find the task with the highest priority (lowest priority() value)
            let mut best: Option<Self::SchedItem> = None;
            for task in self.rt_queue.iter() {
                if let Some(ref b) = best {
                    if task.priority() < b.priority() {
                        best = Some(unsafe { Self::clone_arc(task) });
                    }
                } else {
                    best = Some(unsafe { Self::clone_arc(task) });
                }
            }
            if let Some(ref task) = best {
                unsafe { self.rt_queue.remove(task) }
            } else {
                None
            }
        }
    }

    fn put_prev_task(&mut self, prev: Self::SchedItem, preempt: bool) {
        let is_rt = prev.priority() < 0;
        let queue = if is_rt { &mut self.rt_queue } else { &mut self.normal_queue };

        if prev.time_slice() > 0 && preempt {
            queue.push_front(prev)
        } else {
            prev.reset_time_slice();
            queue.push_back(prev)
        }
    }

    fn task_tick(&mut self, current: &Self::SchedItem) -> bool {
        let old_slice = current.time_slice.fetch_sub(1, Ordering::Release);
        old_slice <= 1
    }

    fn set_priority(&mut self, task: &Self::SchedItem, prio: isize) -> bool {
        task.priority.store(prio, Ordering::Release);
        true
    }
}

impl<T, const S: usize> Default for RRScheduler<T, S> {
    fn default() -> Self {
        Self::new()
    }
}
