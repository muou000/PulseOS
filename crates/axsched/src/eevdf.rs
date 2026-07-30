use alloc::sync::Arc;
use core::{
    ops::Deref,
    sync::atomic::{AtomicBool, AtomicI64, AtomicIsize, AtomicU64, Ordering},
};

use linked_list_r4l::{GetLinks, Links, List};

use crate::{BaseScheduler, SchedEnqueueReason};

const NICE_0_WEIGHT: u64 = 1024;
const RT_TIME_SLICE_NS: u64 = 50_000_000;

const NICE_TO_WEIGHT: [u64; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

/// A task wrapper containing EEVDF and real-time round-robin state.
pub struct EEVDFTask<T> {
    inner: T,
    priority: AtomicIsize,
    vruntime: AtomicU64,
    deadline: AtomicU64,
    exec_start: AtomicU64,
    running: AtomicBool,
    saved_vlag: AtomicI64,
    lag_vtime: AtomicU64,
    has_saved_lag: AtomicBool,
    queue_id: AtomicU64,
    rt_remaining: AtomicU64,
    links: Links<Self>,
}

impl<T> EEVDFTask<T> {
    /// Creates an ordinary nice-0 task.
    pub const fn new(inner: T) -> Self {
        Self {
            inner,
            priority: AtomicIsize::new(-100),
            vruntime: AtomicU64::new(0),
            deadline: AtomicU64::new(0),
            exec_start: AtomicU64::new(0),
            running: AtomicBool::new(false),
            saved_vlag: AtomicI64::new(0),
            lag_vtime: AtomicU64::new(0),
            has_saved_lag: AtomicBool::new(false),
            queue_id: AtomicU64::new(0),
            rt_remaining: AtomicU64::new(RT_TIME_SLICE_NS),
            links: Links::new(),
        }
    }

    /// Returns the scheduler priority encoding.
    ///
    /// Values 1 through 99 are real-time priorities. Ordinary nice values
    /// -20 through 19 are encoded as -120 through -81.
    pub fn priority(&self) -> isize {
        self.priority.load(Ordering::Acquire)
    }

    /// Sets the raw scheduler priority encoding before the task is enqueued.
    ///
    /// Returns `false` for values outside the real-time range `1..=99` and the
    /// encoded ordinary range `-120..=-81`. Call
    /// [`BaseScheduler::set_priority`] for a task already owned by a scheduler
    /// so its queue position is updated atomically.
    #[must_use]
    pub fn set_priority(&self, priority: isize) -> bool {
        if !valid_priority(priority) {
            return false;
        }
        self.priority.store(priority, Ordering::Release);
        true
    }

    /// Returns the task's accumulated virtual runtime.
    pub fn vruntime(&self) -> u64 {
        self.vruntime.load(Ordering::Acquire)
    }

    /// Returns the task's current virtual deadline.
    pub fn virtual_deadline(&self) -> u64 {
        self.deadline.load(Ordering::Acquire)
    }

    /// Returns a reference to the wrapped task.
    pub const fn inner(&self) -> &T {
        &self.inner
    }

    fn is_rt(&self) -> bool {
        (1..=99).contains(&self.priority())
    }

    fn nice(&self) -> Option<isize> {
        let priority = self.priority();
        if (-120..=-81).contains(&priority) {
            Some(priority + 100)
        } else {
            None
        }
    }

    fn weight(&self) -> u64 {
        self.nice()
            .map(|nice| NICE_TO_WEIGHT[(nice + 20) as usize])
            .unwrap_or(NICE_0_WEIGHT)
    }

    fn start_running(&self, now_ns: u64) {
        self.exec_start.store(now_ns, Ordering::Release);
        self.running.store(true, Ordering::Release);
    }

    fn account_runtime(&self, now_ns: u64, keep_running: bool) -> u64 {
        if !self.running.load(Ordering::Acquire) {
            return 0;
        }
        let start = self.exec_start.swap(now_ns, Ordering::AcqRel);
        let delta_exec = now_ns.saturating_sub(start);
        if !keep_running {
            self.running.store(false, Ordering::Release);
        }

        if self.is_rt() {
            let remaining = self.rt_remaining.load(Ordering::Acquire);
            self.rt_remaining
                .store(remaining.saturating_sub(delta_exec), Ordering::Release);
        } else {
            let delta_vruntime = calc_delta_fair(delta_exec, self.weight());
            let vruntime = self.vruntime();
            self.vruntime
                .store(vruntime.saturating_add(delta_vruntime), Ordering::Release);
        }
        delta_exec
    }

    fn unaccounted_runtime(&self, now_ns: u64) -> u64 {
        if self.running.load(Ordering::Acquire) {
            now_ns.saturating_sub(self.exec_start.load(Ordering::Acquire))
        } else {
            0
        }
    }

    fn reset_rt_slice(&self) {
        self.rt_remaining.store(RT_TIME_SLICE_NS, Ordering::Release);
    }
}

impl<T> GetLinks for EEVDFTask<T> {
    type EntryType = Self;

    fn get_links(data: &Self::EntryType) -> &Links<Self::EntryType> {
        &data.links
    }
}

impl<T> Deref for EEVDFTask<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// An Earliest Eligible Virtual Deadline First scheduler.
///
/// Real-time priorities 1 through 99 retain strict priority and round-robin
/// semantics. Ordinary tasks are eligible when their virtual runtime is not
/// ahead of the run queue's weighted-average virtual time; the eligible task
/// with the earliest virtual deadline runs next.
pub struct EEVDFScheduler<T, const BASE_SLICE_NS: u64> {
    rt_queues: [List<Arc<EEVDFTask<T>>>; 99],
    rt_bitmap: u128,
    normal_queue: List<Arc<EEVDFTask<T>>>,
    current: Option<Arc<EEVDFTask<T>>>,
    virtual_time: u64,
    sequence: u64,
    clock_ns: u64,
}

impl<T, const S: u64> EEVDFScheduler<T, S> {
    /// Creates an empty EEVDF scheduler.
    pub const fn new() -> Self {
        assert!(S > 0, "EEVDF base slice must be non-zero");
        Self {
            rt_queues: [const { List::new() }; 99],
            rt_bitmap: 0,
            normal_queue: List::new(),
            current: None,
            virtual_time: 0,
            sequence: 0,
            clock_ns: 0,
        }
    }

    /// Returns the scheduler name.
    pub fn scheduler_name() -> &'static str {
        "EEVDF with RT priority"
    }

    /// Returns the number of ordinary tasks waiting in this scheduler.
    pub fn normal_task_count(&self) -> usize {
        self.normal_queue.iter().count()
    }

    /// Detaches an ordinary task accepted by `predicate` for CPU migration.
    pub fn detach_normal_task(
        &mut self,
        mut predicate: impl FnMut(&EEVDFTask<T>) -> bool,
    ) -> Option<Arc<EEVDFTask<T>>> {
        let selected = self
            .normal_queue
            .iter()
            .find(|task| predicate(task))
            .map(|task| task as *const EEVDFTask<T>)?;
        let virtual_time = self.update_virtual_time();
        let task = self.remove_normal_ptr(selected)?;
        self.save_lag(&task, virtual_time);
        Some(task)
    }

    fn advance_clock(&mut self, now_ns: u64) {
        self.clock_ns = self.clock_ns.max(now_ns);
    }

    fn next_sequence(&mut self) -> u64 {
        loop {
            self.sequence = self.sequence.wrapping_add(1);
            if self.sequence != 0 {
                return self.sequence;
            }
        }
    }

    fn virtual_slice(task: &EEVDFTask<T>) -> u64 {
        calc_delta_fair(S, task.weight()).max(1)
    }

    fn lag_limit(task: &EEVDFTask<T>) -> i64 {
        Self::virtual_slice(task)
            .saturating_mul(2)
            .min(i64::MAX as u64) as i64
    }

    fn update_virtual_time(&mut self) -> u64 {
        let current = self.current.as_ref().filter(|task| !task.is_rt());
        let mut minimum = current.map(|task| task.vruntime());
        for task in self.normal_queue.iter() {
            minimum = Some(minimum.map_or(task.vruntime(), |value| value.min(task.vruntime())));
        }
        let Some(minimum) = minimum else {
            return self.virtual_time;
        };

        let mut weighted_delta = 0u128;
        let mut total_weight = 0u128;
        if let Some(task) = current {
            let weight = task.weight() as u128;
            weighted_delta = weighted_delta
                .saturating_add(task.vruntime().saturating_sub(minimum) as u128 * weight);
            total_weight = total_weight.saturating_add(weight);
        }
        for task in self.normal_queue.iter() {
            let weight = task.weight() as u128;
            weighted_delta = weighted_delta
                .saturating_add(task.vruntime().saturating_sub(minimum) as u128 * weight);
            total_weight = total_weight.saturating_add(weight);
        }

        let average = minimum
            .saturating_add((weighted_delta / total_weight.max(1)).min(u64::MAX as u128) as u64);
        self.virtual_time = self.virtual_time.max(average);
        self.virtual_time
    }

    fn save_lag(&self, task: &EEVDFTask<T>, virtual_time: u64) {
        if task.is_rt() {
            return;
        }
        let lag = signed_difference(virtual_time, task.vruntime())
            .clamp(-Self::lag_limit(task), Self::lag_limit(task));
        task.saved_vlag.store(lag, Ordering::Release);
        task.lag_vtime.store(virtual_time, Ordering::Release);
        task.has_saved_lag.store(true, Ordering::Release);
    }

    fn place_task(&mut self, task: &EEVDFTask<T>, reason: SchedEnqueueReason) {
        let virtual_time = self.update_virtual_time();
        let mut lag = if matches!(
            reason,
            SchedEnqueueReason::Wake | SchedEnqueueReason::Migration
        ) && task.has_saved_lag.swap(false, Ordering::AcqRel)
        {
            task.saved_vlag.load(Ordering::Acquire)
        } else {
            0
        };

        if reason == SchedEnqueueReason::Wake {
            let slept_vtime = virtual_time.saturating_sub(task.lag_vtime.load(Ordering::Acquire));
            let decay = slept_vtime.min(i64::MAX as u64) as i64;
            lag = if lag > 0 {
                lag.saturating_sub(decay).max(0)
            } else {
                lag.saturating_add(decay).min(0)
            };
        }
        lag = lag.clamp(-Self::lag_limit(task), Self::lag_limit(task));

        let vruntime = apply_lag(virtual_time, lag);
        task.vruntime.store(vruntime, Ordering::Release);
        task.deadline.store(
            vruntime.saturating_add(Self::virtual_slice(task)),
            Ordering::Release,
        );
    }

    fn refresh_deadline(&self, task: &EEVDFTask<T>, force: bool) {
        let vruntime = task.vruntime();
        if force || task.virtual_deadline() == 0 || vruntime >= task.virtual_deadline() {
            task.deadline.store(
                vruntime.saturating_add(Self::virtual_slice(task)),
                Ordering::Release,
            );
        }
    }

    fn insert_normal(&mut self, task: Arc<EEVDFTask<T>>) {
        let sequence = self.next_sequence();
        task.queue_id.store(sequence, Ordering::Release);
        self.normal_queue.push_back(task);
    }

    fn remove_normal_ptr(&mut self, selected: *const EEVDFTask<T>) -> Option<Arc<EEVDFTask<T>>> {
        let mut cursor = self.normal_queue.cursor_front_mut();
        while let Some(task) = cursor.current() {
            if core::ptr::eq(task, selected) {
                return cursor.remove_current();
            }
            cursor.move_next();
        }
        None
    }

    fn enqueue_at(&mut self, task: Arc<EEVDFTask<T>>, reason: SchedEnqueueReason, now_ns: u64) {
        self.advance_clock(now_ns);
        if task.is_rt() {
            self.stop_task(&task, now_ns);
            let priority = task.priority();
            let index = (99 - priority) as usize;
            let keep_slice = reason == SchedEnqueueReason::Preempt
                && task.rt_remaining.load(Ordering::Acquire) > 0;
            if keep_slice {
                self.rt_queues[index].push_front(task);
            } else {
                task.reset_rt_slice();
                self.rt_queues[index].push_back(task);
            }
            self.rt_bitmap |= 1u128 << index;
            return;
        }

        if matches!(
            reason,
            SchedEnqueueReason::Wake | SchedEnqueueReason::Migration
        ) && self
            .current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &task))
        {
            self.stop_task(&task, now_ns);
        }

        match reason {
            SchedEnqueueReason::Spawn
            | SchedEnqueueReason::Wake
            | SchedEnqueueReason::Migration => self.place_task(&task, reason),
            SchedEnqueueReason::Preempt => {
                self.stop_task(&task, now_ns);
                self.refresh_deadline(&task, false);
            }
            SchedEnqueueReason::Yield => {
                self.stop_task(&task, now_ns);
                let virtual_time = self.update_virtual_time();
                if task.vruntime() <= virtual_time {
                    task.vruntime.store(
                        task.virtual_deadline().max(task.vruntime()),
                        Ordering::Release,
                    );
                }
                self.refresh_deadline(&task, true);
            }
        }
        self.insert_normal(task);
    }

    fn stop_task(&mut self, task: &Arc<EEVDFTask<T>>, now_ns: u64) {
        let is_current = self
            .current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, task));
        if !is_current && !task.running.load(Ordering::Acquire) {
            return;
        }

        task.account_runtime(now_ns, false);
        if !task.is_rt() {
            let virtual_time = self.update_virtual_time();
            self.save_lag(task, virtual_time);
        }
        if is_current {
            self.current = None;
        }
    }

    fn pick_normal(&mut self) -> Option<Arc<EEVDFTask<T>>> {
        let virtual_time = self.update_virtual_time();
        let selected = self
            .normal_queue
            .iter()
            .filter(|task| task.vruntime() <= virtual_time)
            .min_by_key(|task| {
                (
                    task.virtual_deadline(),
                    task.queue_id.load(Ordering::Acquire),
                )
            })
            .map(|task| task as *const EEVDFTask<T>)
            .or_else(|| {
                self.normal_queue
                    .iter()
                    .min_by_key(|task| {
                        (
                            task.vruntime(),
                            task.virtual_deadline(),
                            task.queue_id.load(Ordering::Acquire),
                        )
                    })
                    .map(|task| task as *const EEVDFTask<T>)
            })?;
        self.remove_normal_ptr(selected)
    }

    fn pick_at(&mut self, now_ns: u64) -> Option<Arc<EEVDFTask<T>>> {
        self.advance_clock(now_ns);
        if self.rt_bitmap != 0 {
            let index = self.rt_bitmap.trailing_zeros() as usize;
            let task = self.rt_queues[index].pop_front();
            if self.rt_queues[index].is_empty() {
                self.rt_bitmap &= !(1u128 << index);
            }
            task
        } else {
            self.pick_normal()
        }
    }

    fn remove_queued(&mut self, task: &Arc<EEVDFTask<T>>) -> Option<Arc<EEVDFTask<T>>> {
        if task.is_rt() {
            let index = (99 - task.priority()) as usize;
            let removed = unsafe { self.rt_queues[index].remove(task) };
            if removed.is_some() && self.rt_queues[index].is_empty() {
                self.rt_bitmap &= !(1u128 << index);
            }
            removed
        } else {
            unsafe { self.normal_queue.remove(task) }
        }
    }

    fn earliest_eligible_deadline(&mut self) -> Option<u64> {
        let virtual_time = self.update_virtual_time();
        self.normal_queue
            .iter()
            .filter(|task| task.vruntime() <= virtual_time)
            .min_by_key(|task| {
                (
                    task.virtual_deadline(),
                    task.queue_id.load(Ordering::Acquire),
                )
            })
            .map(EEVDFTask::virtual_deadline)
    }

    fn set_priority_inner(
        &mut self,
        task: &Arc<EEVDFTask<T>>,
        priority: isize,
        now_ns: u64,
    ) -> bool {
        if !valid_priority(priority) {
            return false;
        }
        self.advance_clock(now_ns);
        let is_current = self
            .current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, task));
        if is_current {
            task.account_runtime(now_ns, true);
        }
        let queued = if is_current {
            None
        } else {
            let virtual_time = self.update_virtual_time();
            self.save_lag(task, virtual_time);
            self.remove_queued(task)
        };

        task.priority.store(priority, Ordering::Release);
        if task.is_rt() {
            task.has_saved_lag.store(false, Ordering::Release);
            task.reset_rt_slice();
        } else if is_current {
            let virtual_time = self.update_virtual_time();
            task.vruntime.store(virtual_time, Ordering::Release);
            self.refresh_deadline(task, true);
        }

        if let Some(queued) = queued {
            self.enqueue_at(queued, SchedEnqueueReason::Migration, now_ns);
        }
        true
    }
}

impl<T, const S: u64> BaseScheduler for EEVDFScheduler<T, S> {
    type SchedItem = Arc<EEVDFTask<T>>;

    fn init(&mut self) {}

    fn add_task(&mut self, task: Self::SchedItem) {
        self.enqueue_at(task, SchedEnqueueReason::Spawn, self.clock_ns);
    }

    fn enqueue_task(&mut self, task: Self::SchedItem, reason: SchedEnqueueReason, now_ns: u64) {
        self.enqueue_at(task, reason, now_ns);
    }

    fn remove_task(&mut self, task: &Self::SchedItem) -> Option<Self::SchedItem> {
        if self
            .current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, task))
        {
            return None;
        }
        let virtual_time = self.update_virtual_time();
        self.save_lag(task, virtual_time);
        self.remove_queued(task)
    }

    fn pick_next_task(&mut self) -> Option<Self::SchedItem> {
        self.pick_at(self.clock_ns)
    }

    fn pick_next_task_at(&mut self, now_ns: u64) -> Option<Self::SchedItem> {
        self.pick_at(now_ns)
    }

    fn put_prev_task(&mut self, prev: Self::SchedItem, preempt: bool) {
        let reason = if preempt {
            SchedEnqueueReason::Preempt
        } else {
            SchedEnqueueReason::Yield
        };
        self.enqueue_at(prev, reason, self.clock_ns);
    }

    fn task_started(&mut self, task: &Self::SchedItem, now_ns: u64) {
        self.advance_clock(now_ns);
        if !task.is_rt() && task.virtual_deadline() == 0 {
            let virtual_time = self.update_virtual_time();
            task.vruntime.store(virtual_time, Ordering::Release);
            self.refresh_deadline(task, true);
        }
        self.current = Some(task.clone());
        task.start_running(now_ns);
    }

    fn task_stopped(&mut self, task: &Self::SchedItem, now_ns: u64) {
        self.advance_clock(now_ns);
        self.stop_task(task, now_ns);
    }

    fn task_tick(&mut self, current: &Self::SchedItem) -> bool {
        let now_ns = self.clock_ns.saturating_add(S);
        self.task_tick_at(current, now_ns)
    }

    fn task_tick_at(&mut self, current: &Self::SchedItem, now_ns: u64) -> bool {
        self.advance_clock(now_ns);
        if self
            .current
            .as_ref()
            .map_or(true, |task| !Arc::ptr_eq(task, current))
        {
            self.current = Some(current.clone());
            current.start_running(now_ns);
        } else {
            current.account_runtime(now_ns, true);
        }

        if current.is_rt() {
            if self.rt_bitmap != 0 {
                let highest_ready = 99 - self.rt_bitmap.trailing_zeros() as isize;
                if highest_ready > current.priority() {
                    return true;
                }
                if highest_ready == current.priority()
                    && current.rt_remaining.load(Ordering::Acquire) == 0
                {
                    return true;
                }
            }
            if current.rt_remaining.load(Ordering::Acquire) == 0 {
                current.reset_rt_slice();
            }
            return false;
        }

        if self.rt_bitmap != 0 {
            return true;
        }
        if self.normal_queue.is_empty() {
            self.refresh_deadline(current, false);
            return false;
        }
        if current.vruntime() >= current.virtual_deadline() {
            self.refresh_deadline(current, true);
            return true;
        }
        self.earliest_eligible_deadline()
            .is_some_and(|deadline| deadline < current.virtual_deadline())
    }

    fn should_preempt(
        &mut self,
        current: &Self::SchedItem,
        candidate: &Self::SchedItem,
        now_ns: u64,
    ) -> bool {
        self.advance_clock(now_ns);
        if self
            .current
            .as_ref()
            .is_some_and(|task| Arc::ptr_eq(task, current))
        {
            current.account_runtime(now_ns, true);
        }

        match (current.is_rt(), candidate.is_rt()) {
            (false, true) => true,
            (true, false) => false,
            (true, true) => {
                candidate.priority() > current.priority()
                    || (candidate.priority() == current.priority()
                        && current.rt_remaining.load(Ordering::Acquire) == 0)
            }
            (false, false) => {
                let virtual_time = self.update_virtual_time();
                candidate.vruntime() <= virtual_time
                    && (current.vruntime() > virtual_time
                        || candidate.virtual_deadline() < current.virtual_deadline())
            }
        }
    }

    fn next_preemption_deadline(&self, current: &Self::SchedItem, now_ns: u64) -> Option<u64> {
        if current.is_rt() {
            if self.rt_bitmap == 0 {
                return None;
            }
            let highest_ready = 99 - self.rt_bitmap.trailing_zeros() as isize;
            if highest_ready > current.priority() {
                return Some(now_ns);
            }
            if highest_ready < current.priority() {
                return None;
            }
            let remaining = current
                .rt_remaining
                .load(Ordering::Acquire)
                .saturating_sub(current.unaccounted_runtime(now_ns));
            return Some(now_ns.saturating_add(remaining));
        }
        if self.rt_bitmap != 0 {
            return Some(now_ns);
        }
        if self.normal_queue.is_empty() {
            return None;
        }
        let current_vruntime = current.vruntime().saturating_add(calc_delta_fair(
            current.unaccounted_runtime(now_ns),
            current.weight(),
        ));
        let remaining_vruntime = current.virtual_deadline().saturating_sub(current_vruntime);
        let remaining_ns = ((remaining_vruntime as u128 * current.weight() as u128)
            .saturating_add((NICE_0_WEIGHT - 1) as u128)
            / NICE_0_WEIGHT as u128)
            .min(u64::MAX as u128) as u64;
        Some(now_ns.saturating_add(remaining_ns))
    }

    fn set_priority(&mut self, task: &Self::SchedItem, priority: isize) -> bool {
        self.set_priority_inner(task, priority, self.clock_ns)
    }

    fn set_priority_at(&mut self, task: &Self::SchedItem, priority: isize, now_ns: u64) -> bool {
        self.set_priority_inner(task, priority, now_ns)
    }

    fn is_empty(&self) -> bool {
        self.rt_bitmap == 0 && self.normal_queue.is_empty()
    }
}

impl<T, const S: u64> Default for EEVDFScheduler<T, S> {
    fn default() -> Self {
        Self::new()
    }
}

fn valid_priority(priority: isize) -> bool {
    (1..=99).contains(&priority) || (-120..=-81).contains(&priority)
}

fn calc_delta_fair(delta_exec: u64, weight: u64) -> u64 {
    ((delta_exec as u128 * NICE_0_WEIGHT as u128) / weight.max(1) as u128).min(u64::MAX as u128)
        as u64
}

fn signed_difference(lhs: u64, rhs: u64) -> i64 {
    if lhs >= rhs {
        lhs.saturating_sub(rhs).min(i64::MAX as u64) as i64
    } else {
        -(rhs.saturating_sub(lhs).min(i64::MAX as u64) as i64)
    }
}

fn apply_lag(virtual_time: u64, lag: i64) -> u64 {
    if lag >= 0 {
        virtual_time.saturating_sub(lag as u64)
    } else {
        virtual_time.saturating_add(lag.unsigned_abs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Scheduler = EEVDFScheduler<usize, 1_000>;
    type Task = EEVDFTask<usize>;

    fn task(id: usize) -> Arc<Task> {
        Arc::new(Task::new(id))
    }

    fn enqueue(scheduler: &mut Scheduler, task: Arc<Task>, reason: SchedEnqueueReason, now: u64) {
        scheduler.enqueue_task(task, reason, now);
    }

    #[test]
    fn earliest_deadline_is_filtered_by_eligibility() {
        let mut scheduler = Scheduler::new();
        let first = task(0);
        let second = task(1);
        enqueue(&mut scheduler, first.clone(), SchedEnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, second.clone(), SchedEnqueueReason::Spawn, 0);

        let running = scheduler.pick_next_task_at(0).unwrap();
        assert!(Arc::ptr_eq(&running, &first));
        scheduler.task_started(&running, 0);
        enqueue(&mut scheduler, running, SchedEnqueueReason::Preempt, 600);

        assert!(Arc::ptr_eq(
            &scheduler.pick_next_task_at(600).unwrap(),
            &second
        ));
    }

    #[test]
    fn yield_forfeits_the_remaining_request() {
        let mut scheduler = Scheduler::new();
        let first = task(0);
        let second = task(1);
        enqueue(&mut scheduler, first.clone(), SchedEnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, second.clone(), SchedEnqueueReason::Spawn, 0);

        let running = scheduler.pick_next_task_at(0).unwrap();
        scheduler.task_started(&running, 0);
        enqueue(&mut scheduler, running, SchedEnqueueReason::Yield, 100);

        assert!(Arc::ptr_eq(
            &scheduler.pick_next_task_at(100).unwrap(),
            &second
        ));
    }

    #[test]
    fn weighted_share_tracks_nice_weights() {
        let mut scheduler = Scheduler::new();
        let normal = task(0);
        let heavy = task(1);
        assert!(heavy.set_priority(-105)); // nice -5, weight 3121
        enqueue(&mut scheduler, normal, SchedEnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, heavy, SchedEnqueueReason::Spawn, 0);

        let mut runtime = [0u64; 2];
        let mut now = 0;
        for _ in 0..20_000 {
            let running = scheduler.pick_next_task_at(now).unwrap();
            scheduler.task_started(&running, now);
            now += 100;
            runtime[*running.inner()] += 100;
            enqueue(&mut scheduler, running, SchedEnqueueReason::Preempt, now);
        }

        let ratio = runtime[1] as f64 / runtime[0] as f64;
        assert!((2.8..3.3).contains(&ratio), "runtime={runtime:?}");
    }

    #[test]
    fn wakeup_with_shorter_virtual_deadline_preempts() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        enqueue(
            &mut scheduler,
            current.clone(),
            SchedEnqueueReason::Spawn,
            0,
        );
        let current = scheduler.pick_next_task_at(0).unwrap();
        scheduler.task_started(&current, 0);
        scheduler.task_tick_at(&current, 100);

        let candidate = task(1);
        assert!(candidate.set_priority(-105));
        enqueue(
            &mut scheduler,
            candidate.clone(),
            SchedEnqueueReason::Spawn,
            100,
        );
        assert!(scheduler.should_preempt(&current, &candidate, 100));
    }

    #[test]
    fn wakeup_of_current_task_accounts_runtime_before_requeue() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        enqueue(
            &mut scheduler,
            current.clone(),
            SchedEnqueueReason::Spawn,
            0,
        );
        let current = scheduler.pick_next_task_at(0).unwrap();
        scheduler.task_started(&current, 0);

        enqueue(
            &mut scheduler,
            current.clone(),
            SchedEnqueueReason::Wake,
            250,
        );

        assert!(scheduler.current.is_none());
        assert_eq!(scheduler.normal_queue.iter().count(), 1);
        assert!(current.vruntime() > 0);
        assert!(Arc::ptr_eq(
            &scheduler.pick_next_task_at(250).unwrap(),
            &current
        ));
    }

    #[test]
    fn initial_running_task_receives_a_request_deadline() {
        let mut scheduler = Scheduler::new();
        let current = task(0);

        scheduler.task_started(&current, 0);

        assert_eq!(current.virtual_deadline(), 1_000);
    }

    #[test]
    fn preemption_timer_subtracts_unaccounted_runtime() {
        let mut scheduler = Scheduler::new();
        let first = task(0);
        let second = task(1);
        enqueue(&mut scheduler, first.clone(), SchedEnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, second, SchedEnqueueReason::Spawn, 0);
        let current = scheduler.pick_next_task_at(0).unwrap();
        scheduler.task_started(&current, 0);

        assert_eq!(
            scheduler.next_preemption_deadline(&current, 250),
            Some(1_000)
        );
    }

    #[test]
    fn migration_rebases_saved_lag_on_the_destination_clock() {
        let mut source = Scheduler::new();
        source.virtual_time = 10_000;
        let migrant = task(0);
        migrant.vruntime.store(9_500, Ordering::Release);
        migrant.deadline.store(10_500, Ordering::Release);
        source.insert_normal(migrant.clone());

        let migrant = source.detach_normal_task(|_| true).unwrap();
        let mut destination = Scheduler::new();
        destination.virtual_time = 1_000_000;
        enqueue(
            &mut destination,
            migrant.clone(),
            SchedEnqueueReason::Migration,
            0,
        );

        assert_eq!(migrant.vruntime(), 999_500);
    }

    #[test]
    fn sleeping_task_lag_decays_toward_zero() {
        let mut scheduler = Scheduler::new();
        let sleeper = task(0);
        let worker = task(1);
        enqueue(
            &mut scheduler,
            sleeper.clone(),
            SchedEnqueueReason::Spawn,
            0,
        );
        enqueue(&mut scheduler, worker.clone(), SchedEnqueueReason::Spawn, 0);

        let running = scheduler.pick_next_task_at(0).unwrap();
        scheduler.task_started(&running, 0);
        scheduler.task_stopped(&running, 2_000);

        let mut now = 2_000;
        for _ in 0..20 {
            let running = scheduler.pick_next_task_at(now).unwrap();
            assert!(Arc::ptr_eq(&running, &worker));
            scheduler.task_started(&running, now);
            now += 500;
            enqueue(&mut scheduler, running, SchedEnqueueReason::Preempt, now);
        }

        enqueue(
            &mut scheduler,
            sleeper.clone(),
            SchedEnqueueReason::Wake,
            now,
        );
        assert!(sleeper.vruntime().abs_diff(worker.vruntime()) <= 1_000);
    }

    #[test]
    fn real_time_priority_precedes_eevdf() {
        let mut scheduler = Scheduler::new();
        let normal = task(0);
        let low = task(1);
        let high = task(2);
        assert!(low.set_priority(10));
        assert!(high.set_priority(99));

        enqueue(&mut scheduler, normal, SchedEnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, low.clone(), SchedEnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, high.clone(), SchedEnqueueReason::Spawn, 0);

        assert!(Arc::ptr_eq(&scheduler.pick_next_task_at(0).unwrap(), &high));
        assert!(Arc::ptr_eq(&scheduler.pick_next_task_at(0).unwrap(), &low));
        assert_eq!(*scheduler.pick_next_task_at(0).unwrap().inner(), 0);
    }

    #[test]
    fn arithmetic_saturates_instead_of_wrapping() {
        let mut scheduler = Scheduler::new();
        let task = task(0);
        task.vruntime.store(u64::MAX - 5, Ordering::Release);
        task.deadline.store(u64::MAX, Ordering::Release);
        scheduler.current = Some(task.clone());
        task.start_running(u64::MAX - 10);
        scheduler.task_stopped(&task, u64::MAX);
        scheduler.refresh_deadline(&task, true);

        assert_eq!(task.vruntime(), u64::MAX);
        assert_eq!(task.virtual_deadline(), u64::MAX);
    }

    #[test]
    fn priority_encoding_is_unambiguous() {
        let task = task(0);

        assert!(!task.set_priority(0));
        assert!(!task.set_priority(-20));
        assert_eq!(task.priority(), -100);
        assert!(task.set_priority(-81));
        assert_eq!(task.nice(), Some(19));
        assert!(task.set_priority(1));
        assert!(task.is_rt());
    }

    #[test]
    fn running_task_is_not_removed_as_if_it_were_queued() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        enqueue(
            &mut scheduler,
            current.clone(),
            SchedEnqueueReason::Spawn,
            0,
        );
        let current = scheduler.pick_next_task_at(0).unwrap();
        scheduler.task_started(&current, 0);

        assert!(scheduler.remove_task(&current).is_none());
        assert!(
            scheduler
                .current
                .as_ref()
                .is_some_and(|running| Arc::ptr_eq(running, &current))
        );
    }

    #[test]
    fn lower_priority_rt_task_does_not_force_slice_rotation() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        let lower = task(1);
        assert!(current.set_priority(99));
        assert!(lower.set_priority(10));
        enqueue(
            &mut scheduler,
            current.clone(),
            SchedEnqueueReason::Spawn,
            0,
        );
        enqueue(&mut scheduler, lower, SchedEnqueueReason::Spawn, 0);
        let current = scheduler.pick_next_task_at(0).unwrap();
        scheduler.task_started(&current, 0);

        assert!(!scheduler.task_tick_at(&current, RT_TIME_SLICE_NS));
        assert_eq!(
            scheduler.next_preemption_deadline(&current, RT_TIME_SLICE_NS),
            None
        );
    }

    #[test]
    fn equal_priority_rt_task_rotates_at_slice_boundary() {
        let mut scheduler = Scheduler::new();
        let first = task(0);
        let second = task(1);
        assert!(first.set_priority(50));
        assert!(second.set_priority(50));
        enqueue(&mut scheduler, first.clone(), SchedEnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, second, SchedEnqueueReason::Spawn, 0);
        let current = scheduler.pick_next_task_at(0).unwrap();
        scheduler.task_started(&current, 0);

        assert_eq!(
            scheduler.next_preemption_deadline(&current, 0),
            Some(RT_TIME_SLICE_NS)
        );
        assert!(scheduler.task_tick_at(&current, RT_TIME_SLICE_NS));
    }

    #[test]
    fn returning_from_rt_does_not_restore_stale_fair_lag() {
        let mut scheduler = Scheduler::new();
        scheduler.virtual_time = 10_000;
        let task = task(0);
        task.vruntime.store(9_500, Ordering::Release);
        task.deadline.store(10_500, Ordering::Release);
        scheduler.insert_normal(task.clone());

        assert!(scheduler.set_priority_at(&task, 50, 0));
        scheduler.virtual_time = 1_000_000;
        assert!(scheduler.set_priority_at(&task, -100, 0));

        assert_eq!(task.vruntime(), 1_000_000);
    }
}
