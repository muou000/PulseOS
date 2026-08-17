use alloc::sync::Arc;
use core::{
    ops::Deref,
    sync::atomic::{AtomicBool, AtomicI64, AtomicIsize, AtomicU8, AtomicU64, Ordering},
};

use intrusive_collections::{KeyAdapter, RBTree, RBTreeAtomicLink, intrusive_adapter};
use linked_list_r4l::{GetLinks, Links, List};

const NICE_0_WEIGHT: u64 = 1024;
const RT_TIME_SLICE_NS: u64 = 50_000_000;

const NICE_TO_WEIGHT: [u64; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

const fn normal_virtual_slices(base_slice_ns: u64) -> [u64; 40] {
    let mut slices = [0; 40];
    let mut index = 0;
    while index < NICE_TO_WEIGHT.len() {
        let scaled =
            (base_slice_ns as u128 * NICE_0_WEIGHT as u128) / NICE_TO_WEIGHT[index] as u128;
        let slice = if scaled > u64::MAX as u128 {
            u64::MAX
        } else {
            scaled as u64
        };
        slices[index] = if slice == 0 { 1 } else { slice };
        index += 1;
    }
    slices
}

/// Describes why a runnable task enters the EEVDF run queue.
///
/// The event controls lag placement, virtual-request renewal, and the position
/// of real-time tasks within an equal-priority queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnqueueReason {
    /// A newly created task enters the scheduler for the first time.
    Spawn,
    /// A blocked task becomes runnable again.
    Wake,
    /// The running task voluntarily gives up the CPU.
    Yield,
    /// The running task is involuntarily preempted.
    Preempt,
    /// A runnable task moves between run queues.
    Migration,
}

/// The same-priority behavior of a real-time task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RtPolicy {
    /// Run until blocking, yielding, or preemption by a higher RT priority.
    Fifo       = 0,
    /// Rotate with equal-priority peers after a fixed time slice.
    RoundRobin = 1,
}

/// Result of checking whether the ordinary queue can preempt a request.
///
/// The set of eligible queued tasks can only grow while the queue is unchanged,
/// because virtual time is monotonic and queued entities keep their virtual
/// runtime. A negative result therefore remains valid until the first
/// ineligible entity that can preempt reaches eligibility.
#[derive(Clone, Copy)]
struct EligiblePreemptionCache {
    has_eligible_preemption: bool,
    preemption_current_deadline: u64,
    preemption_vruntime: Option<u64>,
}

impl EligiblePreemptionCache {
    #[inline]
    fn covers(self, virtual_time: u64) -> bool {
        self.has_eligible_preemption
            || self
                .preemption_vruntime
                .map_or(true, |threshold| virtual_time < threshold)
    }
}

/// A task wrapper containing EEVDF and real-time scheduling state.
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
    rt_policy: AtomicU8,
    rt_remaining: AtomicU64,
    normal_eligible_link: RBTreeAtomicLink,
    normal_ineligible_link: RBTreeAtomicLink,
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
            rt_policy: AtomicU8::new(RtPolicy::RoundRobin as u8),
            rt_remaining: AtomicU64::new(RT_TIME_SLICE_NS),
            normal_eligible_link: RBTreeAtomicLink::new(),
            normal_ineligible_link: RBTreeAtomicLink::new(),
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
    /// [`EEVDFScheduler::update_priority_at`] for a task already owned by a
    /// scheduler so its queue position is updated atomically.
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

    /// Returns the entity weight used for CPU placement.
    ///
    /// Ordinary tasks use their nice weight. Real-time tasks use the nice-0
    /// weight as a placement proxy; their strict priority remains independent
    /// of this estimate.
    pub fn placement_weight(&self) -> usize {
        self.weight() as usize
    }

    /// Returns the real-time policy that controls equal-priority behavior.
    pub fn rt_policy(&self) -> RtPolicy {
        match self.rt_policy.load(Ordering::Acquire) {
            0 => RtPolicy::Fifo,
            _ => RtPolicy::RoundRobin,
        }
    }

    /// Sets the real-time policy used when this task has an RT priority.
    ///
    /// This is intended for a task that is not currently running. Use
    /// [`EEVDFScheduler::set_rt_policy_at`] for a running task so its elapsed
    /// execution is charged under the old policy before the new one starts.
    pub fn set_rt_policy(&self, policy: RtPolicy) {
        self.rt_policy.store(policy as u8, Ordering::Release);
        if policy == RtPolicy::RoundRobin {
            self.reset_rt_slice();
        }
    }

    /// Returns the round-robin time slice used by EEVDF RT tasks.
    pub const fn rt_time_slice_ns() -> u64 {
        RT_TIME_SLICE_NS
    }

    /// Returns a reference to the wrapped task.
    pub const fn inner(&self) -> &T {
        &self.inner
    }

    fn is_rt(&self) -> bool {
        (1..=99).contains(&self.priority())
    }

    fn is_round_robin(&self) -> bool {
        self.rt_policy() == RtPolicy::RoundRobin
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

        let priority = self.priority();
        if is_rt_priority(priority) {
            if self.is_round_robin() {
                let remaining = self.rt_remaining.load(Ordering::Acquire);
                self.rt_remaining
                    .store(remaining.saturating_sub(delta_exec), Ordering::Release);
            }
        } else {
            let delta_vruntime = calc_delta_fair(delta_exec, weight_for_priority(priority));
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

intrusive_adapter!(NormalEligibleAdapter<T> = Arc<EEVDFTask<T>>: EEVDFTask<T> {
    normal_eligible_link: RBTreeAtomicLink
});

impl<'a, T> KeyAdapter<'a> for NormalEligibleAdapter<T> {
    type Key = (u64, u64);

    fn get_key(&self, task: &'a EEVDFTask<T>) -> Self::Key {
        // A normal task's ordering fields are assigned before linking and are
        // only changed after unlinking while the scheduler lock is held.
        (
            task.deadline.load(Ordering::Relaxed),
            task.queue_id.load(Ordering::Relaxed),
        )
    }
}

intrusive_adapter!(NormalIneligibleAdapter<T> = Arc<EEVDFTask<T>>: EEVDFTask<T> {
    normal_ineligible_link: RBTreeAtomicLink
});

impl<'a, T> KeyAdapter<'a> for NormalIneligibleAdapter<T> {
    type Key = (u64, u64, u64);

    fn get_key(&self, task: &'a EEVDFTask<T>) -> Self::Key {
        (
            task.vruntime.load(Ordering::Relaxed),
            task.deadline.load(Ordering::Relaxed),
            task.queue_id.load(Ordering::Relaxed),
        )
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
/// Real-time priorities 1 through 99 retain strict priority. FIFO tasks run
/// until they block, yield, or meet a higher RT priority; round-robin tasks
/// rotate with equal-priority peers after their time slice. Ordinary tasks are
/// eligible when their virtual runtime is not ahead of the run queue's
/// weighted-average virtual time; the eligible task with the earliest virtual
/// deadline runs next.
pub struct EEVDFScheduler<T, const BASE_SLICE_NS: u64> {
    rt_queues: [List<Arc<EEVDFTask<T>>>; 99],
    rt_bitmap: u128,
    /// Eligible ordinary entities, sorted by `(deadline, enqueue sequence)`.
    normal_eligible: RBTree<NormalEligibleAdapter<T>>,
    /// Ineligible ordinary entities, sorted by `(vruntime, deadline, sequence)`.
    normal_ineligible: RBTree<NormalIneligibleAdapter<T>>,
    /// A lower bound for the smallest deadline in `normal_ineligible`.
    ///
    /// Removals may leave this value stale-low, but never stale-high. That
    /// makes `lower_bound >= current_deadline` sufficient to rule out an
    /// ineligible preemption without traversing the tree.
    normal_ineligible_deadline_lower_bound: Option<u64>,
    normal_task_count: usize,
    /// Aggregate state for queued normal tasks. The running task is kept out
    /// of the trees and is accounted for directly when virtual time advances.
    normal_total_weight: u128,
    normal_weighted_vruntime: u128,
    /// Whether queued ordinary work can preempt the current request, cached
    /// until a queue mutation or the next preempting eligibility boundary.
    normal_preemption_cache: Option<EligiblePreemptionCache>,
    #[cfg(test)]
    normal_eligibility_scans: usize,
    #[cfg(test)]
    normal_eligibility_candidates_examined: usize,
    current: Option<Arc<EEVDFTask<T>>>,
    virtual_time: u64,
    sequence: u64,
    clock_ns: u64,
}

impl<T, const S: u64> EEVDFScheduler<T, S> {
    /// Virtual request sizes for ordinary priorities, indexed by `priority + 120`.
    const NORMAL_VIRTUAL_SLICES: [u64; 40] = normal_virtual_slices(S);

    /// Creates an empty EEVDF scheduler.
    pub fn new() -> Self {
        assert!(S > 0, "EEVDF base slice must be non-zero");
        Self {
            rt_queues: [const { List::new() }; 99],
            rt_bitmap: 0,
            normal_eligible: RBTree::new(NormalEligibleAdapter::new()),
            normal_ineligible: RBTree::new(NormalIneligibleAdapter::new()),
            normal_ineligible_deadline_lower_bound: None,
            normal_task_count: 0,
            normal_total_weight: 0,
            normal_weighted_vruntime: 0,
            normal_preemption_cache: None,
            #[cfg(test)]
            normal_eligibility_scans: 0,
            #[cfg(test)]
            normal_eligibility_candidates_examined: 0,
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
        self.normal_task_count
    }

    /// Switches a task's real-time policy after accounting execution through
    /// `now_ns` when it is the current task.
    pub fn set_rt_policy_at(&mut self, task: &Arc<EEVDFTask<T>>, policy: RtPolicy, now_ns: u64) {
        self.advance_clock(now_ns);
        if self
            .current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, task))
        {
            task.account_runtime(now_ns, true);
        }
        task.set_rt_policy(policy);
    }

    /// Detaches an ordinary task accepted by `predicate` for CPU migration.
    pub fn detach_normal_task(
        &mut self,
        mut predicate: impl FnMut(&EEVDFTask<T>) -> bool,
    ) -> Option<Arc<EEVDFTask<T>>> {
        let virtual_time = self.update_virtual_time();
        self.promote_normal_eligible(virtual_time);
        let task = self
            .detach_normal_from_eligible(&mut predicate)
            .or_else(|| self.detach_normal_from_ineligible(&mut predicate))?;
        self.finish_normal_remove(&task);
        self.save_lag(&task, virtual_time);
        Some(task)
    }

    fn detach_normal_from_eligible(
        &mut self,
        predicate: &mut impl FnMut(&EEVDFTask<T>) -> bool,
    ) -> Option<Arc<EEVDFTask<T>>> {
        let mut cursor = self.normal_eligible.front_mut();
        loop {
            let task = cursor.get()?;
            if predicate(task) {
                return cursor.remove();
            }
            cursor.move_next();
        }
    }

    fn detach_normal_from_ineligible(
        &mut self,
        predicate: &mut impl FnMut(&EEVDFTask<T>) -> bool,
    ) -> Option<Arc<EEVDFTask<T>>> {
        let mut cursor = self.normal_ineligible.front_mut();
        loop {
            let task = cursor.get()?;
            if predicate(task) {
                let removed = cursor.remove();
                drop(cursor);
                self.note_normal_ineligible_remove();
                return removed;
            }
            cursor.move_next();
        }
    }

    fn promote_normal_eligible(&mut self, virtual_time: u64) {
        let mut promoted = false;
        loop {
            let task = {
                let mut cursor = self.normal_ineligible.front_mut();
                if !cursor
                    .get()
                    .is_some_and(|task| task.vruntime() <= virtual_time)
                {
                    break;
                }
                cursor
                    .remove()
                    .expect("eligible normal task must remain linked")
            };
            self.normal_eligible.insert(task);
            promoted = true;
        }
        if promoted {
            self.note_normal_ineligible_remove();
        }
    }

    #[inline]
    fn normal_eligible_deadline(&self) -> Option<u64> {
        self.normal_eligible
            .front()
            .get()
            .map(EEVDFTask::virtual_deadline)
    }

    fn insert_normal_ineligible(&mut self, task: Arc<EEVDFTask<T>>) {
        let deadline = task.virtual_deadline();
        self.normal_ineligible_deadline_lower_bound = Some(
            self.normal_ineligible_deadline_lower_bound
                .map_or(deadline, |lower_bound| lower_bound.min(deadline)),
        );
        self.normal_ineligible.insert(task);
    }

    fn note_normal_ineligible_remove(&mut self) {
        if self.normal_ineligible.is_empty() {
            self.normal_ineligible_deadline_lower_bound = None;
        }
    }

    fn remove_normal_task(&mut self, task: &Arc<EEVDFTask<T>>) -> Option<Arc<EEVDFTask<T>>> {
        let (removed, removed_from_ineligible) = if task.normal_eligible_link.is_linked() {
            // The link identifies the node in this tree while the scheduler
            // lock excludes all concurrent queue mutations.
            let mut cursor = unsafe { self.normal_eligible.cursor_mut_from_ptr(Arc::as_ptr(task)) };
            (cursor.remove(), false)
        } else if task.normal_ineligible_link.is_linked() {
            // See the eligible-tree removal above.
            let mut cursor = unsafe {
                self.normal_ineligible
                    .cursor_mut_from_ptr(Arc::as_ptr(task))
            };
            (cursor.remove(), true)
        } else {
            (None, false)
        };
        if removed_from_ineligible && removed.is_some() {
            self.note_normal_ineligible_remove();
        }
        if let Some(removed_task) = &removed {
            self.finish_normal_remove(removed_task);
        }
        removed
    }

    fn finish_normal_remove(&mut self, task: &EEVDFTask<T>) {
        debug_assert!(self.normal_task_count != 0);
        self.normal_task_count = self.normal_task_count.saturating_sub(1);
        self.account_normal_remove(task);
        self.normal_preemption_cache = None;
    }

    fn pick_normal_from_eligible(&mut self) -> Option<Arc<EEVDFTask<T>>> {
        let task = self.normal_eligible.front_mut().remove();
        if let Some(task) = &task {
            self.finish_normal_remove(task);
        }
        task
    }

    fn pick_normal_from_ineligible(&mut self) -> Option<Arc<EEVDFTask<T>>> {
        let task = self.normal_ineligible.front_mut().remove();
        if let Some(task) = &task {
            self.note_normal_ineligible_remove();
            self.finish_normal_remove(task);
        }
        task
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

    #[inline]
    fn virtual_slice(task: &EEVDFTask<T>) -> u64 {
        let priority = task.priority();
        if (-120..=-81).contains(&priority) {
            Self::NORMAL_VIRTUAL_SLICES[(priority + 120) as usize]
        } else {
            S.max(1)
        }
    }

    fn lag_limit(task: &EEVDFTask<T>) -> i64 {
        Self::virtual_slice(task)
            .saturating_mul(2)
            .min(i64::MAX as u64) as i64
    }

    fn update_virtual_time(&mut self) -> u64 {
        let current = self.current.as_ref().filter(|task| !task.is_rt());
        let mut total_weight = self.normal_total_weight;
        let mut weighted_vruntime = self.normal_weighted_vruntime;
        if let Some(task) = current {
            let weight = task.weight() as u128;
            weighted_vruntime =
                weighted_vruntime.saturating_add((task.vruntime() as u128).saturating_mul(weight));
            total_weight = total_weight.saturating_add(weight);
        }
        if total_weight == 0 {
            return self.virtual_time;
        }

        let average = (weighted_vruntime / total_weight).min(u64::MAX as u128) as u64;
        self.virtual_time = self.virtual_time.max(average);
        self.virtual_time
    }

    fn save_lag(&self, task: &EEVDFTask<T>, virtual_time: u64) {
        if task.is_rt() {
            return;
        }
        let lag_limit = Self::lag_limit(task);
        let lag = signed_difference(virtual_time, task.vruntime()).clamp(-lag_limit, lag_limit);
        task.saved_vlag.store(lag, Ordering::Release);
        task.lag_vtime.store(virtual_time, Ordering::Release);
        task.has_saved_lag.store(true, Ordering::Release);
    }

    fn place_task(&mut self, task: &EEVDFTask<T>, reason: EnqueueReason) {
        let virtual_time = self.update_virtual_time();
        let mut lag = if matches!(reason, EnqueueReason::Wake | EnqueueReason::Migration)
            && task.has_saved_lag.swap(false, Ordering::AcqRel)
        {
            task.saved_vlag.load(Ordering::Acquire)
        } else {
            0
        };

        if reason == EnqueueReason::Wake {
            let slept_vtime = virtual_time.saturating_sub(task.lag_vtime.load(Ordering::Acquire));
            let decay = slept_vtime.min(i64::MAX as u64) as i64;
            lag = if lag > 0 {
                lag.saturating_sub(decay).max(0)
            } else {
                lag.saturating_add(decay).min(0)
            };
        }
        let lag_limit = Self::lag_limit(task);
        lag = lag.clamp(-lag_limit, lag_limit);

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
        let virtual_time = self.update_virtual_time();
        self.promote_normal_eligible(virtual_time);
        let sequence = self.next_sequence();
        task.queue_id.store(sequence, Ordering::Release);
        self.account_normal_insert(&task);
        self.normal_task_count = self.normal_task_count.saturating_add(1);
        if task.vruntime() <= virtual_time {
            self.normal_eligible.insert(task);
        } else {
            self.insert_normal_ineligible(task);
        }

        let virtual_time = self.update_virtual_time();
        self.promote_normal_eligible(virtual_time);
        self.normal_preemption_cache = None;
    }

    #[inline]
    fn account_normal_insert(&mut self, task: &EEVDFTask<T>) {
        let weight = task.weight() as u128;
        self.normal_total_weight = self.normal_total_weight.saturating_add(weight);
        self.normal_weighted_vruntime = self
            .normal_weighted_vruntime
            .saturating_add((task.vruntime() as u128).saturating_mul(weight));
    }

    #[inline]
    fn account_normal_remove(&mut self, task: &EEVDFTask<T>) {
        let weight = task.weight() as u128;
        let weighted_vruntime = (task.vruntime() as u128).saturating_mul(weight);
        debug_assert!(self.normal_total_weight >= weight);
        debug_assert!(self.normal_weighted_vruntime >= weighted_vruntime);
        self.normal_total_weight = self.normal_total_weight.saturating_sub(weight);
        self.normal_weighted_vruntime = self
            .normal_weighted_vruntime
            .saturating_sub(weighted_vruntime);
    }

    fn enqueue_at(&mut self, task: Arc<EEVDFTask<T>>, reason: EnqueueReason, now_ns: u64) {
        self.advance_clock(now_ns);
        if task.is_rt() {
            self.stop_task(&task, now_ns);
            let priority = task.priority();
            let index = (99 - priority) as usize;
            let keep_slice = task.is_round_robin()
                && reason == EnqueueReason::Preempt
                && task.rt_remaining.load(Ordering::Acquire) > 0;
            if reason == EnqueueReason::Preempt && (!task.is_round_robin() || keep_slice) {
                self.rt_queues[index].push_front(task);
            } else {
                if task.is_round_robin() {
                    task.reset_rt_slice();
                }
                self.rt_queues[index].push_back(task);
            }
            self.rt_bitmap |= 1u128 << index;
            return;
        }

        if matches!(reason, EnqueueReason::Wake | EnqueueReason::Migration)
            && self
                .current
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &task))
        {
            self.stop_task(&task, now_ns);
        }

        match reason {
            EnqueueReason::Spawn | EnqueueReason::Wake | EnqueueReason::Migration => {
                self.place_task(&task, reason)
            }
            EnqueueReason::Preempt => {
                self.stop_task(&task, now_ns);
                self.refresh_deadline(&task, false);
            }
            EnqueueReason::Yield => {
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
        self.promote_normal_eligible(virtual_time);
        self.pick_normal_from_eligible()
            .or_else(|| self.pick_normal_from_ineligible())
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
            self.remove_normal_task(task)
        }
    }

    fn has_eligible_preemption(&mut self, current_deadline: u64) -> bool {
        let virtual_time = self.update_virtual_time();
        self.promote_normal_eligible(virtual_time);
        if let Some(cache) = self.normal_preemption_cache {
            if cache.covers(virtual_time) && cache.preemption_current_deadline == current_deadline {
                return cache.has_eligible_preemption;
            }
        }

        #[cfg(test)]
        {
            self.normal_eligibility_scans += 1;
        }
        let has_eligible_preemption = self
            .normal_eligible_deadline()
            .is_some_and(|deadline| deadline < current_deadline);
        let may_have_ineligible_preemption = self
            .normal_ineligible_deadline_lower_bound
            .map_or(!self.normal_ineligible.is_empty(), |deadline| {
                deadline < current_deadline
            });
        #[cfg(test)]
        let mut candidates_examined = 0;
        // The tree is ordered by `(vruntime, deadline, sequence)`, so its
        // first candidate that can preempt is also the earliest such boundary.
        // An already eligible preempting task makes that scan unnecessary.
        let preemption = (!has_eligible_preemption && may_have_ineligible_preemption).then(|| {
            self.normal_ineligible.iter().find_map(|task| {
                #[cfg(test)]
                {
                    candidates_examined += 1;
                }
                (task.virtual_deadline() < current_deadline)
                    .then(|| (task.vruntime(), task.virtual_deadline()))
            })
        });
        #[cfg(test)]
        {
            self.normal_eligibility_candidates_examined = self
                .normal_eligibility_candidates_examined
                .saturating_add(candidates_examined);
        }
        let preemption_vruntime = preemption.flatten().map(|(vruntime, _)| vruntime);
        self.normal_preemption_cache = Some(EligiblePreemptionCache {
            has_eligible_preemption,
            preemption_current_deadline: current_deadline,
            preemption_vruntime,
        });
        has_eligible_preemption
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
        let was_rt = task.is_rt();
        if is_current {
            task.account_runtime(now_ns, true);
            // Account the current task under its old ordinary weight before a
            // priority change can remove it from the fair virtual-time model.
            if !was_rt {
                self.update_virtual_time();
            }
        }
        let queued = if is_current {
            None
        } else {
            let virtual_time = self.update_virtual_time();
            self.save_lag(task, virtual_time);
            self.remove_queued(task)
        };

        task.priority.store(priority, Ordering::Release);
        if is_rt_priority(priority) {
            task.has_saved_lag.store(false, Ordering::Release);
            if task.is_round_robin() {
                task.reset_rt_slice();
            }
        } else if is_current {
            let virtual_time = self.update_virtual_time();
            task.vruntime.store(virtual_time, Ordering::Release);
            self.refresh_deadline(task, true);
        }

        if let Some(queued) = queued {
            self.enqueue_at(queued, EnqueueReason::Migration, now_ns);
        }
        true
    }
}

impl<T, const S: u64> EEVDFScheduler<T, S> {
    /// Adds a newly created task using the scheduler's current clock.
    pub fn enqueue_new(&mut self, task: Arc<EEVDFTask<T>>) {
        self.enqueue_at(task, EnqueueReason::Spawn, self.clock_ns);
    }

    /// Enqueues a task with its lifecycle reason at monotonic time `now_ns`.
    pub fn enqueue(&mut self, task: Arc<EEVDFTask<T>>, reason: EnqueueReason, now_ns: u64) {
        self.enqueue_at(task, reason, now_ns);
    }

    /// Removes a queued task while preserving its lag for a later return.
    pub fn remove(&mut self, task: &Arc<EEVDFTask<T>>) -> Option<Arc<EEVDFTask<T>>> {
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

    /// Picks the next task using the scheduler's current clock.
    pub fn pick_next(&mut self) -> Option<Arc<EEVDFTask<T>>> {
        self.pick_at(self.clock_ns)
    }

    /// Picks the next task at monotonic time `now_ns`.
    pub fn pick_next_at(&mut self, now_ns: u64) -> Option<Arc<EEVDFTask<T>>> {
        self.pick_at(now_ns)
    }

    /// Returns the previous task after preemption or voluntary yield.
    pub fn requeue_previous(&mut self, prev: Arc<EEVDFTask<T>>, preempt: bool) {
        let reason = if preempt {
            EnqueueReason::Preempt
        } else {
            EnqueueReason::Yield
        };
        self.enqueue_at(prev, reason, self.clock_ns);
    }

    /// Records that `task` started executing at monotonic time `now_ns`.
    pub fn on_task_start(&mut self, task: &Arc<EEVDFTask<T>>, now_ns: u64) {
        self.advance_clock(now_ns);
        if !task.is_rt() && task.virtual_deadline() == 0 {
            let virtual_time = self.update_virtual_time();
            task.vruntime.store(virtual_time, Ordering::Release);
            self.refresh_deadline(task, true);
        }
        self.current = Some(task.clone());
        task.start_running(now_ns);
    }

    /// Accounts the final execution interval before `task` stops running.
    pub fn on_task_stop(&mut self, task: &Arc<EEVDFTask<T>>, now_ns: u64) {
        self.advance_clock(now_ns);
        self.stop_task(task, now_ns);
    }

    /// Advances by one base slice and reports whether rescheduling is required.
    pub fn tick(&mut self, current: &Arc<EEVDFTask<T>>) -> bool {
        let now_ns = self.clock_ns.saturating_add(S);
        self.tick_at(current, now_ns)
    }

    /// Advances to `now_ns` and reports whether rescheduling is required.
    pub fn tick_at(&mut self, current: &Arc<EEVDFTask<T>>, now_ns: u64) -> bool {
        self.advance_clock(now_ns);
        let current_is_running = self
            .current
            .as_ref()
            .is_some_and(|task| Arc::ptr_eq(task, current));
        let current_is_rt = current.is_rt();
        if !current_is_running {
            self.current = Some(current.clone());
            current.start_running(now_ns);
        } else if current_is_rt && !current.is_round_robin() {
            if self.rt_bitmap == 0 {
                return false;
            }
            let highest_ready = 99 - self.rt_bitmap.trailing_zeros() as isize;
            return highest_ready > current.priority();
        } else {
            current.account_runtime(now_ns, true);
        }

        if current_is_rt {
            if self.rt_bitmap != 0 {
                let highest_ready = 99 - self.rt_bitmap.trailing_zeros() as isize;
                if highest_ready > current.priority() {
                    return true;
                }
                if current.is_round_robin()
                    && highest_ready == current.priority()
                    && current.rt_remaining.load(Ordering::Acquire) == 0
                {
                    return true;
                }
            }
            if current.is_round_robin() && current.rt_remaining.load(Ordering::Acquire) == 0 {
                current.reset_rt_slice();
            }
            return false;
        }

        if self.rt_bitmap != 0 {
            return true;
        }
        if self.normal_task_count == 0 {
            self.refresh_deadline(current, false);
            return false;
        }
        let current_deadline = current.virtual_deadline();
        if current.vruntime() >= current_deadline {
            self.refresh_deadline(current, true);
            return true;
        }
        self.has_eligible_preemption(current_deadline)
    }

    /// Returns whether `candidate` should immediately preempt `current`.
    pub fn candidate_preempts(
        &mut self,
        current: &Arc<EEVDFTask<T>>,
        candidate: &Arc<EEVDFTask<T>>,
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
                    || (current.is_round_robin()
                        && candidate.priority() == current.priority()
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

    /// Returns the next preemption deadline without mutating scheduler state.
    pub fn preemption_deadline(&self, current: &Arc<EEVDFTask<T>>, now_ns: u64) -> Option<u64> {
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
            if !current.is_round_robin() {
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
        if self.normal_task_count == 0 {
            return None;
        }
        let current_weight = current.weight();
        let current_deadline = current.virtual_deadline();
        let current_vruntime = current.vruntime().saturating_add(calc_delta_fair(
            current.unaccounted_runtime(now_ns),
            current_weight,
        ));
        let remaining_vruntime = current_deadline.saturating_sub(current_vruntime);
        let remaining_ns = ceil_div_u128(
            (remaining_vruntime as u128).saturating_mul(current_weight as u128),
            NICE_0_WEIGHT as u128,
        )
        .min(u64::MAX as u128) as u64;
        Some(now_ns.saturating_add(remaining_ns))
    }

    /// Sets a task's priority using the scheduler's current clock.
    pub fn update_priority(&mut self, task: &Arc<EEVDFTask<T>>, priority: isize) -> bool {
        self.set_priority_inner(task, priority, self.clock_ns)
    }

    /// Sets a task's priority after accounting execution through `now_ns`.
    pub fn update_priority_at(
        &mut self,
        task: &Arc<EEVDFTask<T>>,
        priority: isize,
        now_ns: u64,
    ) -> bool {
        self.set_priority_inner(task, priority, now_ns)
    }

    /// Returns `true` when no task is waiting in the run queue.
    pub fn queued_is_empty(&self) -> bool {
        self.rt_bitmap == 0 && self.normal_task_count == 0
    }
}

impl<T, const S: u64> Default for EEVDFScheduler<T, S> {
    fn default() -> Self {
        Self::new()
    }
}

fn valid_priority(priority: isize) -> bool {
    is_rt_priority(priority) || (-120..=-81).contains(&priority)
}

#[inline]
fn is_rt_priority(priority: isize) -> bool {
    (1..=99).contains(&priority)
}

#[inline]
fn weight_for_priority(priority: isize) -> u64 {
    if (-120..=-81).contains(&priority) {
        NICE_TO_WEIGHT[(priority + 120) as usize]
    } else {
        NICE_0_WEIGHT
    }
}

fn calc_delta_fair(delta_exec: u64, weight: u64) -> u64 {
    ((delta_exec as u128 * NICE_0_WEIGHT as u128) / weight.max(1) as u128).min(u64::MAX as u128)
        as u64
}

fn ceil_div_u128(value: u128, divisor: u128) -> u128 {
    debug_assert!(divisor != 0);
    value / divisor + if value % divisor == 0 { 0 } else { 1 }
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

    fn enqueue(scheduler: &mut Scheduler, task: Arc<Task>, reason: EnqueueReason, now: u64) {
        scheduler.enqueue(task, reason, now);
    }

    fn scanned_normal_aggregate(scheduler: &Scheduler) -> (u128, u128) {
        let mut total_weight = 0u128;
        let mut weighted_vruntime = 0u128;
        for task in scheduler.normal_eligible.iter() {
            let weight = task.weight() as u128;
            total_weight = total_weight.saturating_add(weight);
            weighted_vruntime =
                weighted_vruntime.saturating_add((task.vruntime() as u128).saturating_mul(weight));
        }
        for task in scheduler.normal_ineligible.iter() {
            let weight = task.weight() as u128;
            total_weight = total_weight.saturating_add(weight);
            weighted_vruntime =
                weighted_vruntime.saturating_add((task.vruntime() as u128).saturating_mul(weight));
        }
        (total_weight, weighted_vruntime)
    }

    fn scanned_virtual_time(scheduler: &Scheduler) -> u64 {
        let current = scheduler.current.as_ref().filter(|task| !task.is_rt());
        let mut minimum = current.map(|task| task.vruntime());
        for task in scheduler.normal_eligible.iter() {
            minimum = Some(minimum.map_or(task.vruntime(), |value| value.min(task.vruntime())));
        }
        for task in scheduler.normal_ineligible.iter() {
            minimum = Some(minimum.map_or(task.vruntime(), |value| value.min(task.vruntime())));
        }
        let Some(minimum) = minimum else {
            return scheduler.virtual_time;
        };

        let mut weighted_delta = 0u128;
        let mut total_weight = 0u128;
        if let Some(task) = current {
            let weight = task.weight() as u128;
            weighted_delta = weighted_delta.saturating_add(
                (task.vruntime().saturating_sub(minimum) as u128).saturating_mul(weight),
            );
            total_weight = total_weight.saturating_add(weight);
        }
        for task in scheduler.normal_eligible.iter() {
            let weight = task.weight() as u128;
            weighted_delta = weighted_delta.saturating_add(
                (task.vruntime().saturating_sub(minimum) as u128).saturating_mul(weight),
            );
            total_weight = total_weight.saturating_add(weight);
        }
        for task in scheduler.normal_ineligible.iter() {
            let weight = task.weight() as u128;
            weighted_delta = weighted_delta.saturating_add(
                (task.vruntime().saturating_sub(minimum) as u128).saturating_mul(weight),
            );
            total_weight = total_weight.saturating_add(weight);
        }

        scheduler.virtual_time.max(
            minimum.saturating_add(
                (weighted_delta / total_weight.max(1)).min(u64::MAX as u128) as u64,
            ),
        )
    }

    fn assert_normal_aggregate_matches_scan(scheduler: &mut Scheduler) {
        let (total_weight, weighted_vruntime) = scanned_normal_aggregate(scheduler);
        assert_eq!(scheduler.normal_total_weight, total_weight);
        assert_eq!(scheduler.normal_weighted_vruntime, weighted_vruntime);
        assert_eq!(
            scheduler.normal_task_count,
            scheduler.normal_eligible.iter().count() + scheduler.normal_ineligible.iter().count()
        );
        let actual_ineligible_deadline = scheduler
            .normal_ineligible
            .iter()
            .map(EEVDFTask::virtual_deadline)
            .min();
        match actual_ineligible_deadline {
            Some(actual_deadline) => assert!(
                scheduler
                    .normal_ineligible_deadline_lower_bound
                    .is_some_and(|lower_bound| lower_bound <= actual_deadline)
            ),
            None => assert_eq!(scheduler.normal_ineligible_deadline_lower_bound, None),
        }

        let expected_virtual_time = scanned_virtual_time(scheduler);
        assert_eq!(scheduler.update_virtual_time(), expected_virtual_time);
    }

    #[test]
    fn earliest_deadline_is_filtered_by_eligibility() {
        let mut scheduler = Scheduler::new();
        let first = task(0);
        let second = task(1);
        enqueue(&mut scheduler, first.clone(), EnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, second.clone(), EnqueueReason::Spawn, 0);

        let running = scheduler.pick_next_at(0).unwrap();
        assert!(Arc::ptr_eq(&running, &first));
        scheduler.on_task_start(&running, 0);
        enqueue(&mut scheduler, running, EnqueueReason::Preempt, 600);

        assert!(Arc::ptr_eq(&scheduler.pick_next_at(600).unwrap(), &second));
    }

    #[test]
    fn normal_selection_prefers_eligible_earliest_deadline() {
        let mut scheduler = Scheduler::new();
        let ineligible = task(0);
        let later_eligible = task(1);
        let earlier_eligible = task(2);

        ineligible.vruntime.store(200, Ordering::Release);
        ineligible.deadline.store(201, Ordering::Release);
        later_eligible.vruntime.store(90, Ordering::Release);
        later_eligible.deadline.store(130, Ordering::Release);
        earlier_eligible.vruntime.store(80, Ordering::Release);
        earlier_eligible.deadline.store(120, Ordering::Release);
        scheduler.insert_normal(ineligible);
        scheduler.insert_normal(later_eligible);
        scheduler.insert_normal(earlier_eligible.clone());

        let selected = scheduler.pick_next_at(0).unwrap();
        assert!(Arc::ptr_eq(&selected, &earlier_eligible));
    }

    #[test]
    fn normal_selection_falls_back_to_lowest_vruntime() {
        let mut scheduler = Scheduler::new();
        let later = task(0);
        let first_lowest = task(1);
        let second_lowest = task(2);

        later.vruntime.store(300, Ordering::Release);
        later.deadline.store(301, Ordering::Release);
        first_lowest.vruntime.store(200, Ordering::Release);
        first_lowest.deadline.store(250, Ordering::Release);
        second_lowest.vruntime.store(200, Ordering::Release);
        second_lowest.deadline.store(260, Ordering::Release);
        scheduler.insert_normal(later);
        scheduler.insert_normal(second_lowest);
        scheduler.insert_normal(first_lowest.clone());

        let selected = scheduler.pick_next_at(0).unwrap();
        assert!(Arc::ptr_eq(&selected, &first_lowest));
    }

    #[test]
    fn normal_tree_promotes_at_eligibility_boundary() {
        let mut scheduler = Scheduler::new();
        let eligible = task(0);
        let first_ineligible = task(1);
        let second_ineligible = task(2);

        eligible.vruntime.store(80, Ordering::Release);
        eligible.deadline.store(300, Ordering::Release);
        first_ineligible.vruntime.store(150, Ordering::Release);
        first_ineligible.deadline.store(100, Ordering::Release);
        second_ineligible.vruntime.store(200, Ordering::Release);
        second_ineligible.deadline.store(50, Ordering::Release);
        scheduler.insert_normal(eligible.clone());
        scheduler.insert_normal(first_ineligible.clone());
        scheduler.insert_normal(second_ineligible.clone());

        scheduler.virtual_time = 100;
        let first = scheduler.pick_next_at(0).unwrap();
        assert!(Arc::ptr_eq(&first, &eligible));
        assert!(!eligible.normal_eligible_link.is_linked());
        assert!(!eligible.normal_ineligible_link.is_linked());

        scheduler.virtual_time = 150;
        let second = scheduler.pick_next_at(0).unwrap();
        assert!(Arc::ptr_eq(&second, &first_ineligible));
        assert!(!first_ineligible.normal_eligible_link.is_linked());
        assert!(!first_ineligible.normal_ineligible_link.is_linked());

        scheduler.virtual_time = 200;
        let third = scheduler.pick_next_at(0).unwrap();
        assert!(Arc::ptr_eq(&third, &second_ineligible));
        assert_eq!(scheduler.normal_ineligible_deadline_lower_bound, None);
        assert!(scheduler.queued_is_empty());
    }

    #[test]
    fn normal_tree_removes_tasks_from_each_partition() {
        let mut scheduler = Scheduler::new();
        let eligible = task(0);
        let ineligible = task(1);

        scheduler.virtual_time = 100;
        eligible.vruntime.store(80, Ordering::Release);
        eligible.deadline.store(120, Ordering::Release);
        ineligible.vruntime.store(200, Ordering::Release);
        ineligible.deadline.store(220, Ordering::Release);
        scheduler.insert_normal(eligible.clone());
        scheduler.insert_normal(ineligible.clone());

        assert!(eligible.normal_eligible_link.is_linked());
        assert!(ineligible.normal_ineligible_link.is_linked());
        assert!(scheduler.remove(&eligible).is_some());
        assert!(!eligible.normal_eligible_link.is_linked());
        assert!(scheduler.remove(&ineligible).is_some());
        assert!(!ineligible.normal_ineligible_link.is_linked());
        assert!(scheduler.queued_is_empty());
        assert_normal_aggregate_matches_scan(&mut scheduler);
    }

    #[test]
    fn normal_tree_matches_reference_selection_for_many_tasks() {
        let mut scheduler = Scheduler::new();
        let mut tasks = alloc::vec::Vec::new();

        for id in 0..64 {
            let queued = task(id);
            queued
                .vruntime
                .store((id * 37 % 1_013) as u64, Ordering::Release);
            queued
                .deadline
                .store((id * 71 % 1_021) as u64 + 1, Ordering::Release);
            scheduler.insert_normal(queued.clone());
            tasks.push(queued);
        }

        while !tasks.is_empty() {
            let virtual_time = scheduler.update_virtual_time();
            let expected = tasks
                .iter()
                .filter(|task| task.vruntime() <= virtual_time)
                .min_by_key(|task| {
                    (
                        task.virtual_deadline(),
                        task.queue_id.load(Ordering::Acquire),
                    )
                })
                .or_else(|| {
                    tasks.iter().min_by_key(|task| {
                        (
                            task.vruntime(),
                            task.virtual_deadline(),
                            task.queue_id.load(Ordering::Acquire),
                        )
                    })
                })
                .unwrap()
                .clone();

            let selected = scheduler.pick_next_at(0).unwrap();
            assert!(Arc::ptr_eq(&selected, &expected));
            tasks.retain(|task| !Arc::ptr_eq(task, &selected));
            assert_normal_aggregate_matches_scan(&mut scheduler);
        }
        assert!(scheduler.queued_is_empty());
    }

    #[test]
    fn normal_pick_releases_intrusive_link_for_reenqueue() {
        let mut scheduler = Scheduler::new();
        let first = task(0);
        let second = task(1);

        first.deadline.store(100, Ordering::Release);
        second.deadline.store(200, Ordering::Release);
        scheduler.insert_normal(first.clone());
        scheduler.insert_normal(second.clone());

        let selected = scheduler.pick_next_at(0).unwrap();
        assert!(Arc::ptr_eq(&selected, &first));
        assert_eq!(Arc::strong_count(&first), 2);
        assert_normal_aggregate_matches_scan(&mut scheduler);

        scheduler.enqueue(selected, EnqueueReason::Preempt, 0);
        assert_eq!(Arc::strong_count(&first), 2);
        assert_normal_aggregate_matches_scan(&mut scheduler);

        let selected_again = scheduler.pick_next_at(0).unwrap();
        assert!(Arc::ptr_eq(&selected_again, &first));
        assert_eq!(Arc::strong_count(&first), 2);
        assert_normal_aggregate_matches_scan(&mut scheduler);
    }

    #[test]
    fn preemption_cache_invalidates_at_boundary_and_queue_mutation() {
        let mut scheduler = Scheduler::new();
        let eligible = task(0);
        let later = task(1);

        eligible.vruntime.store(100, Ordering::Release);
        eligible.deadline.store(400, Ordering::Release);
        later.vruntime.store(200, Ordering::Release);
        later.deadline.store(300, Ordering::Release);
        scheduler.insert_normal(eligible);
        scheduler.insert_normal(later);

        scheduler.virtual_time = 150;
        assert!(!scheduler.has_eligible_preemption(350));
        assert_eq!(scheduler.normal_eligibility_scans, 1);
        let cache = scheduler.normal_preemption_cache.unwrap();
        assert!(!cache.has_eligible_preemption);
        assert_eq!(cache.preemption_current_deadline, 350);
        assert_eq!(cache.preemption_vruntime, Some(200));

        scheduler.virtual_time = 199;
        assert!(!scheduler.has_eligible_preemption(350));
        assert_eq!(scheduler.normal_eligibility_scans, 1);
        assert_eq!(
            scheduler
                .normal_preemption_cache
                .unwrap()
                .preemption_vruntime,
            Some(200)
        );

        scheduler.virtual_time = 200;
        assert!(scheduler.has_eligible_preemption(350));
        assert_eq!(scheduler.normal_eligibility_scans, 2);

        let new_earliest = task(2);
        new_earliest.vruntime.store(190, Ordering::Release);
        new_earliest.deadline.store(250, Ordering::Release);
        scheduler.insert_normal(new_earliest.clone());
        assert!(scheduler.normal_preemption_cache.is_none());
        assert!(scheduler.has_eligible_preemption(350));
        assert_eq!(scheduler.normal_eligibility_scans, 3);

        assert!(scheduler.remove(&new_earliest).is_some());
        assert!(scheduler.normal_preemption_cache.is_none());
        assert!(scheduler.has_eligible_preemption(350));
        assert_eq!(scheduler.normal_eligibility_scans, 4);
    }

    #[test]
    fn preemption_timer_query_does_not_mutate_scheduler_state() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        let candidate = task(1);

        scheduler.on_task_start(&current, 0);
        assert_eq!(current.virtual_deadline(), 1_000);
        candidate.vruntime.store(500, Ordering::Release);
        candidate.deadline.store(750, Ordering::Release);
        scheduler.insert_normal(candidate.clone());

        assert_eq!(scheduler.virtual_time, 250);
        assert!(candidate.normal_ineligible_link.is_linked());
        assert!(scheduler.normal_preemption_cache.is_none());
        assert_eq!(scheduler.preemption_deadline(&current, 0), Some(1_000));
        assert_eq!(scheduler.preemption_deadline(&current, 250), Some(1_000));
        assert_eq!(current.vruntime(), 0);
        assert_eq!(current.unaccounted_runtime(250), 250);
        assert_eq!(scheduler.virtual_time, 250);
        assert!(candidate.normal_ineligible_link.is_linked());
        assert!(!candidate.normal_eligible_link.is_linked());
        assert!(scheduler.normal_preemption_cache.is_none());
        assert_eq!(scheduler.normal_eligibility_scans, 0);
        assert!(scheduler.tick_at(&current, 500));
        assert!(candidate.normal_eligible_link.is_linked());
    }

    #[test]
    fn wakeup_preemption_does_not_require_timer_query_side_effects() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        let candidate = task(1);

        scheduler.on_task_start(&current, 0);
        candidate.deadline.store(500, Ordering::Release);
        scheduler.insert_normal(candidate.clone());

        assert!(scheduler.candidate_preempts(&current, &candidate, 0));
        assert_eq!(scheduler.preemption_deadline(&current, 0), Some(1_000));
        assert!(scheduler.normal_preemption_cache.is_none());
        assert_eq!(scheduler.normal_eligibility_scans, 0);
    }

    #[test]
    fn preemption_cache_stops_at_first_ineligible_candidate() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        let later_deadline = task(1);
        let first_preempting = task(2);
        let later_preempting = task(3);

        assert!(current.set_priority(-120)); // Keep virtual time below all candidates.
        assert!(later_deadline.set_priority(-81));
        assert!(first_preempting.set_priority(-81));
        assert!(later_preempting.set_priority(-81));
        scheduler.on_task_start(&current, 0);
        current.deadline.store(1_000, Ordering::Release);

        later_deadline.vruntime.store(100, Ordering::Release);
        later_deadline.deadline.store(1_200, Ordering::Release);
        first_preempting.vruntime.store(200, Ordering::Release);
        first_preempting.deadline.store(900, Ordering::Release);
        later_preempting.vruntime.store(300, Ordering::Release);
        later_preempting.deadline.store(100, Ordering::Release);
        scheduler.insert_normal(later_deadline);
        scheduler.insert_normal(first_preempting);
        scheduler.insert_normal(later_preempting);

        assert!(!scheduler.has_eligible_preemption(1_000));
        let cache = scheduler.normal_preemption_cache.unwrap();
        assert_eq!(cache.preemption_vruntime, Some(200));
        assert_eq!(scheduler.normal_eligibility_scans, 1);
        assert_eq!(scheduler.normal_eligibility_candidates_examined, 2);
    }

    #[test]
    fn ineligible_deadline_lower_bound_skips_nonpreempting_scan() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        let candidate = task(1);

        scheduler.on_task_start(&current, 0);
        candidate.vruntime.store(1_000, Ordering::Release);
        candidate.deadline.store(1_000, Ordering::Release);
        scheduler.insert_normal(candidate);
        assert_eq!(
            scheduler.normal_ineligible_deadline_lower_bound,
            Some(1_000)
        );

        assert!(!scheduler.has_eligible_preemption(1_000));
        assert_eq!(scheduler.normal_eligibility_scans, 1);
        assert_eq!(scheduler.normal_eligibility_candidates_examined, 0);

        assert!(!scheduler.has_eligible_preemption(1_001));
        assert_eq!(scheduler.normal_eligibility_scans, 2);
        assert_eq!(scheduler.normal_eligibility_candidates_examined, 1);
    }

    #[test]
    fn eligible_preemption_skips_ineligible_tree_scan() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        let eligible = task(1);
        let ineligible = task(2);

        scheduler.on_task_start(&current, 0);
        current.deadline.store(1_000, Ordering::Release);
        eligible.deadline.store(500, Ordering::Release);
        ineligible.vruntime.store(100, Ordering::Release);
        ineligible.deadline.store(100, Ordering::Release);
        scheduler.insert_normal(eligible);
        scheduler.insert_normal(ineligible);

        assert!(scheduler.has_eligible_preemption(current.virtual_deadline()));
        assert_eq!(scheduler.normal_eligibility_scans, 1);
        assert_eq!(scheduler.normal_eligibility_candidates_examined, 0);
    }

    #[test]
    fn ineligible_deadline_lower_bound_skips_nonpreempting_tree_scan() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        let later = task(1);
        let latest = task(2);

        scheduler.on_task_start(&current, 0);
        current.deadline.store(1_000, Ordering::Release);
        later.vruntime.store(10_000, Ordering::Release);
        later.deadline.store(1_100, Ordering::Release);
        latest.vruntime.store(20_000, Ordering::Release);
        latest.deadline.store(1_200, Ordering::Release);
        scheduler.insert_normal(later);
        scheduler.insert_normal(latest);

        assert!(!scheduler.has_eligible_preemption(current.virtual_deadline()));
        assert_eq!(scheduler.normal_eligibility_scans, 1);
        assert_eq!(scheduler.normal_eligibility_candidates_examined, 0);
    }

    #[test]
    fn preemption_timer_uses_slice_deadline_without_eligibility_probe() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        let candidate = task(1);

        assert!(current.set_priority(-101)); // nice -1, weight 1277
        scheduler.on_task_start(&current, 0);
        current.deadline.store(2_000, Ordering::Release);
        candidate.vruntime.store(1_000, Ordering::Release);
        candidate.deadline.store(1_500, Ordering::Release);
        scheduler.insert_normal(candidate);

        assert_eq!(scheduler.preemption_deadline(&current, 0), Some(2_495));
        assert_eq!(current.vruntime(), 0);
        assert!(scheduler.normal_preemption_cache.is_none());
        assert!(scheduler.tick_at(&current, 1_248));
    }

    #[test]
    fn preemption_timer_keeps_slice_for_later_boundary_deadline() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        let candidate = task(1);

        scheduler.on_task_start(&current, 0);
        candidate.vruntime.store(500, Ordering::Release);
        candidate.deadline.store(1_500, Ordering::Release);
        scheduler.insert_normal(candidate);

        assert_eq!(scheduler.preemption_deadline(&current, 0), Some(1_000));
        assert!(scheduler.normal_preemption_cache.is_none());
    }

    #[test]
    fn preemption_timer_tracks_current_request_deadline() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        let candidate = task(1);

        scheduler.on_task_start(&current, 0);
        candidate.vruntime.store(500, Ordering::Release);
        candidate.deadline.store(750, Ordering::Release);
        scheduler.insert_normal(candidate);

        assert_eq!(scheduler.preemption_deadline(&current, 0), Some(1_000));

        // A renewed request changes only its own time-slice deadline.
        current.deadline.store(700, Ordering::Release);
        assert_eq!(scheduler.preemption_deadline(&current, 0), Some(700));
        assert!(scheduler.normal_preemption_cache.is_none());
    }

    #[test]
    fn preemption_timer_ignores_cached_eligibility_boundary() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        let early = task(1);
        let later = task(2);

        scheduler.on_task_start(&current, 0);
        early.vruntime.store(400, Ordering::Release);
        early.deadline.store(1_200, Ordering::Release);
        later.vruntime.store(600, Ordering::Release);
        later.deadline.store(750, Ordering::Release);
        scheduler.insert_normal(early);
        scheduler.insert_normal(later);

        assert!(!scheduler.has_eligible_preemption(current.virtual_deadline()));
        let cache = scheduler.normal_preemption_cache.unwrap();
        assert_eq!(cache.preemption_vruntime, Some(600));
        assert_eq!(scheduler.preemption_deadline(&current, 0), Some(1_000));
        assert!(scheduler.tick_at(&current, 800));
    }

    #[test]
    fn preemption_cache_skips_nonpreempting_eligibility() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        let early = task(1);
        let later = task(2);

        scheduler.on_task_start(&current, 0);
        early.vruntime.store(400, Ordering::Release);
        early.deadline.store(1_200, Ordering::Release);
        later.vruntime.store(600, Ordering::Release);
        later.deadline.store(750, Ordering::Release);
        scheduler.insert_normal(early);
        scheduler.insert_normal(later);

        assert!(!scheduler.has_eligible_preemption(current.virtual_deadline()));
        assert_eq!(scheduler.normal_eligibility_scans, 1);

        scheduler.virtual_time = 400;
        assert!(!scheduler.has_eligible_preemption(current.virtual_deadline()));
        assert_eq!(scheduler.normal_eligibility_scans, 1);

        scheduler.virtual_time = 600;
        assert!(scheduler.has_eligible_preemption(current.virtual_deadline()));
        assert_eq!(scheduler.normal_eligibility_scans, 2);
    }

    #[test]
    fn detach_normal_task_updates_aggregate_and_invalidates_cache() {
        let mut scheduler = Scheduler::new();
        let detached = task(0);
        let remaining = task(1);

        detached.vruntime.store(100, Ordering::Release);
        detached.deadline.store(500, Ordering::Release);
        remaining.vruntime.store(100, Ordering::Release);
        remaining.deadline.store(400, Ordering::Release);
        scheduler.insert_normal(detached.clone());
        scheduler.insert_normal(remaining);

        scheduler.virtual_time = 100;
        assert!(scheduler.has_eligible_preemption(600));
        assert!(scheduler.normal_preemption_cache.is_some());

        let removed = scheduler
            .detach_normal_task(|candidate| candidate.inner() == &0)
            .unwrap();
        assert!(Arc::ptr_eq(&removed, &detached));
        assert!(scheduler.normal_preemption_cache.is_none());
        assert_normal_aggregate_matches_scan(&mut scheduler);
        assert!(scheduler.has_eligible_preemption(600));
    }

    #[test]
    fn normal_aggregate_tracks_queue_lifecycle() {
        let mut scheduler = Scheduler::new();
        let normal = task(0);
        let heavy = task(1);
        let light = task(2);
        assert!(heavy.set_priority(-105)); // nice -5
        assert!(light.set_priority(-81)); // nice 19

        enqueue(&mut scheduler, normal.clone(), EnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, heavy.clone(), EnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, light.clone(), EnqueueReason::Spawn, 0);
        assert_normal_aggregate_matches_scan(&mut scheduler);

        let running = scheduler.pick_next_at(0).unwrap();
        assert!(Arc::ptr_eq(&running, &heavy));
        assert_normal_aggregate_matches_scan(&mut scheduler);

        scheduler.on_task_start(&running, 0);
        scheduler.tick_at(&running, 400);
        assert_normal_aggregate_matches_scan(&mut scheduler);

        scheduler.on_task_stop(&running, 800);
        scheduler.enqueue(running, EnqueueReason::Preempt, 800);
        assert_normal_aggregate_matches_scan(&mut scheduler);

        let detached = scheduler
            .detach_normal_task(|candidate| candidate.inner() == &0)
            .unwrap();
        assert!(Arc::ptr_eq(&detached, &normal));
        assert_normal_aggregate_matches_scan(&mut scheduler);

        scheduler.enqueue(detached, EnqueueReason::Migration, 900);
        assert_normal_aggregate_matches_scan(&mut scheduler);

        assert!(scheduler.update_priority_at(&light, 50, 900));
        assert_normal_aggregate_matches_scan(&mut scheduler);
        assert!(scheduler.update_priority_at(&light, -100, 900));
        assert_normal_aggregate_matches_scan(&mut scheduler);

        assert!(scheduler.remove(&normal).is_some());
        assert_normal_aggregate_matches_scan(&mut scheduler);
    }

    #[test]
    fn yield_forfeits_the_remaining_request() {
        let mut scheduler = Scheduler::new();
        let first = task(0);
        let second = task(1);
        enqueue(&mut scheduler, first.clone(), EnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, second.clone(), EnqueueReason::Spawn, 0);

        let running = scheduler.pick_next_at(0).unwrap();
        scheduler.on_task_start(&running, 0);
        enqueue(&mut scheduler, running, EnqueueReason::Yield, 100);

        assert!(Arc::ptr_eq(&scheduler.pick_next_at(100).unwrap(), &second));
    }

    #[test]
    fn weighted_share_tracks_nice_weights() {
        let mut scheduler = Scheduler::new();
        let normal = task(0);
        let heavy = task(1);
        assert!(heavy.set_priority(-105)); // nice -5, weight 3121
        enqueue(&mut scheduler, normal, EnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, heavy, EnqueueReason::Spawn, 0);

        let mut runtime = [0u64; 2];
        let mut now = 0;
        for _ in 0..20_000 {
            let running = scheduler.pick_next_at(now).unwrap();
            scheduler.on_task_start(&running, now);
            now += 100;
            runtime[*running.inner()] += 100;
            enqueue(&mut scheduler, running, EnqueueReason::Preempt, now);
        }

        let ratio = runtime[1] as f64 / runtime[0] as f64;
        assert!((2.8..3.3).contains(&ratio), "runtime={runtime:?}");
    }

    #[test]
    fn placement_weight_tracks_nice_weight() {
        let normal = task(0);
        let heavy = task(1);
        let light = task(2);
        let realtime = task(3);
        assert!(heavy.set_priority(-120)); // nice -20
        assert!(light.set_priority(-81)); // nice 19
        assert!(realtime.set_priority(1));

        assert_eq!(normal.placement_weight(), 1024);
        assert_eq!(heavy.placement_weight(), 88761);
        assert_eq!(light.placement_weight(), 15);
        assert_eq!(realtime.placement_weight(), 1024);
    }

    #[test]
    fn precomputed_virtual_slices_match_weighted_delta() {
        let normal = task(0);

        for priority in -120..=-81 {
            assert!(normal.set_priority(priority));
            assert_eq!(
                Scheduler::virtual_slice(&normal),
                calc_delta_fair(1_000, normal.weight()).max(1),
                "priority={priority}"
            );
        }
    }

    #[test]
    fn wakeup_with_shorter_virtual_deadline_preempts() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        enqueue(&mut scheduler, current.clone(), EnqueueReason::Spawn, 0);
        let current = scheduler.pick_next_at(0).unwrap();
        scheduler.on_task_start(&current, 0);
        scheduler.tick_at(&current, 100);

        let candidate = task(1);
        assert!(candidate.set_priority(-105));
        enqueue(&mut scheduler, candidate.clone(), EnqueueReason::Spawn, 100);
        assert!(scheduler.candidate_preempts(&current, &candidate, 100));
    }

    #[test]
    fn current_normal_to_rt_preserves_virtual_time_for_new_normal_work() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        let peer = task(1);
        let woken = task(2);

        enqueue(&mut scheduler, current.clone(), EnqueueReason::Spawn, 0);
        let current = scheduler.pick_next_at(0).unwrap();
        scheduler.on_task_start(&current, 0);
        enqueue(&mut scheduler, peer, EnqueueReason::Spawn, 0);

        assert!(scheduler.update_priority_at(&current, 50, 1_000));
        assert_eq!(scheduler.virtual_time, 500);

        enqueue(&mut scheduler, woken.clone(), EnqueueReason::Wake, 1_000);
        assert_eq!(woken.vruntime(), 500);
    }

    #[test]
    fn wakeup_of_current_task_accounts_runtime_before_requeue() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        enqueue(&mut scheduler, current.clone(), EnqueueReason::Spawn, 0);
        let current = scheduler.pick_next_at(0).unwrap();
        scheduler.on_task_start(&current, 0);

        enqueue(&mut scheduler, current.clone(), EnqueueReason::Wake, 250);

        assert!(scheduler.current.is_none());
        assert_eq!(scheduler.normal_task_count(), 1);
        assert!(current.vruntime() > 0);
        assert!(Arc::ptr_eq(&scheduler.pick_next_at(250).unwrap(), &current));
    }

    #[test]
    fn initial_running_task_receives_a_request_deadline() {
        let mut scheduler = Scheduler::new();
        let current = task(0);

        scheduler.on_task_start(&current, 0);

        assert_eq!(current.virtual_deadline(), 1_000);
    }

    #[test]
    fn single_task_deadline_query_defers_runtime_accounting() {
        let mut scheduler = Scheduler::new();
        let current = task(0);

        scheduler.on_task_start(&current, 0);
        assert_eq!(scheduler.preemption_deadline(&current, 250), None);
        assert_eq!(current.vruntime(), 0);

        assert!(!scheduler.tick_at(&current, 500));
        assert_eq!(current.vruntime(), 500);
    }

    #[test]
    fn preemption_timer_subtracts_unaccounted_runtime() {
        let mut scheduler = Scheduler::new();
        let first = task(0);
        let second = task(1);
        enqueue(&mut scheduler, first.clone(), EnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, second, EnqueueReason::Spawn, 0);
        let current = scheduler.pick_next_at(0).unwrap();
        scheduler.on_task_start(&current, 0);

        assert_eq!(scheduler.preemption_deadline(&current, 250), Some(1_000));
    }

    #[test]
    fn preemption_timer_handles_an_untracked_running_task() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        let queued = task(1);

        current.deadline.store(1_000, Ordering::Release);
        current.start_running(0);
        queued.deadline.store(1_000, Ordering::Release);
        scheduler.insert_normal(queued);

        assert_eq!(scheduler.preemption_deadline(&current, 250), Some(1_000));
        assert_eq!(current.vruntime(), 0);
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
            EnqueueReason::Migration,
            0,
        );

        assert_eq!(migrant.vruntime(), 999_500);
    }

    #[test]
    fn sleeping_task_lag_decays_toward_zero() {
        let mut scheduler = Scheduler::new();
        let sleeper = task(0);
        let worker = task(1);
        enqueue(&mut scheduler, sleeper.clone(), EnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, worker.clone(), EnqueueReason::Spawn, 0);

        let running = scheduler.pick_next_at(0).unwrap();
        scheduler.on_task_start(&running, 0);
        scheduler.on_task_stop(&running, 2_000);

        let mut now = 2_000;
        for _ in 0..20 {
            let running = scheduler.pick_next_at(now).unwrap();
            assert!(Arc::ptr_eq(&running, &worker));
            scheduler.on_task_start(&running, now);
            now += 500;
            enqueue(&mut scheduler, running, EnqueueReason::Preempt, now);
        }

        enqueue(&mut scheduler, sleeper.clone(), EnqueueReason::Wake, now);
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

        enqueue(&mut scheduler, normal, EnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, low.clone(), EnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, high.clone(), EnqueueReason::Spawn, 0);

        assert!(Arc::ptr_eq(&scheduler.pick_next_at(0).unwrap(), &high));
        assert!(Arc::ptr_eq(&scheduler.pick_next_at(0).unwrap(), &low));
        assert_eq!(*scheduler.pick_next_at(0).unwrap().inner(), 0);
    }

    #[test]
    fn arithmetic_saturates_instead_of_wrapping() {
        let mut scheduler = Scheduler::new();
        let task = task(0);
        task.vruntime.store(u64::MAX - 5, Ordering::Release);
        task.deadline.store(u64::MAX, Ordering::Release);
        scheduler.current = Some(task.clone());
        task.start_running(u64::MAX - 10);
        scheduler.on_task_stop(&task, u64::MAX);
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
        enqueue(&mut scheduler, current.clone(), EnqueueReason::Spawn, 0);
        let current = scheduler.pick_next_at(0).unwrap();
        scheduler.on_task_start(&current, 0);

        assert!(scheduler.remove(&current).is_none());
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
        enqueue(&mut scheduler, current.clone(), EnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, lower, EnqueueReason::Spawn, 0);
        let current = scheduler.pick_next_at(0).unwrap();
        scheduler.on_task_start(&current, 0);

        assert!(!scheduler.tick_at(&current, RT_TIME_SLICE_NS));
        assert_eq!(
            scheduler.preemption_deadline(&current, RT_TIME_SLICE_NS),
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
        enqueue(&mut scheduler, first.clone(), EnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, second, EnqueueReason::Spawn, 0);
        let current = scheduler.pick_next_at(0).unwrap();
        scheduler.on_task_start(&current, 0);

        assert_eq!(
            scheduler.preemption_deadline(&current, 0),
            Some(RT_TIME_SLICE_NS)
        );
        assert!(scheduler.tick_at(&current, RT_TIME_SLICE_NS));
    }

    #[test]
    fn fifo_rt_task_does_not_rotate_with_equal_priority_peer() {
        let mut scheduler = Scheduler::new();
        let first = task(0);
        let second = task(1);
        assert!(first.set_priority(50));
        assert!(second.set_priority(50));
        first.set_rt_policy(RtPolicy::Fifo);
        second.set_rt_policy(RtPolicy::Fifo);
        enqueue(&mut scheduler, first.clone(), EnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, second, EnqueueReason::Spawn, 0);
        let current = scheduler.pick_next_at(0).unwrap();
        scheduler.on_task_start(&current, 0);

        assert_eq!(EEVDFTask::<usize>::rt_time_slice_ns(), RT_TIME_SLICE_NS);
        assert_eq!(scheduler.preemption_deadline(&current, 0), None);
        assert!(!scheduler.tick_at(&current, RT_TIME_SLICE_NS));
        assert_eq!(
            current.unaccounted_runtime(RT_TIME_SLICE_NS),
            RT_TIME_SLICE_NS
        );
    }

    #[test]
    fn fifo_runtime_does_not_charge_normal_vruntime() {
        let mut scheduler = Scheduler::new();
        let current = task(0);
        assert!(current.set_priority(50));
        current.set_rt_policy(RtPolicy::Fifo);
        enqueue(&mut scheduler, current.clone(), EnqueueReason::Spawn, 0);
        let current = scheduler.pick_next_at(0).unwrap();
        scheduler.on_task_start(&current, 0);

        assert!(!scheduler.tick_at(&current, 1_000));
        assert_eq!(current.vruntime(), 0);
    }

    #[test]
    fn fifo_to_round_robin_starts_a_fresh_slice() {
        let mut scheduler = Scheduler::new();
        let first = task(0);
        let second = task(1);
        assert!(first.set_priority(50));
        assert!(second.set_priority(50));
        first.set_rt_policy(RtPolicy::Fifo);
        enqueue(&mut scheduler, first.clone(), EnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, second, EnqueueReason::Spawn, 0);
        let current = scheduler.pick_next_at(0).unwrap();
        scheduler.on_task_start(&current, 0);

        scheduler.set_rt_policy_at(&current, RtPolicy::RoundRobin, 1_000);
        assert_eq!(
            scheduler.preemption_deadline(&current, 1_000),
            Some(1_000 + RT_TIME_SLICE_NS)
        );
        assert!(!scheduler.tick_at(&current, 1_000 + RT_TIME_SLICE_NS - 1));
        assert!(scheduler.tick_at(&current, 1_000 + RT_TIME_SLICE_NS));
    }

    #[test]
    fn fifo_rt_task_rejoins_head_after_higher_priority_preemption() {
        let mut scheduler = Scheduler::new();
        let first = task(0);
        let peer = task(1);
        let higher = task(2);
        assert!(first.set_priority(50));
        assert!(peer.set_priority(50));
        assert!(higher.set_priority(51));
        first.set_rt_policy(RtPolicy::Fifo);
        peer.set_rt_policy(RtPolicy::Fifo);
        higher.set_rt_policy(RtPolicy::Fifo);
        enqueue(&mut scheduler, first.clone(), EnqueueReason::Spawn, 0);
        enqueue(&mut scheduler, peer, EnqueueReason::Spawn, 0);
        let current = scheduler.pick_next_at(0).unwrap();
        scheduler.on_task_start(&current, 0);

        enqueue(&mut scheduler, higher.clone(), EnqueueReason::Spawn, 1);
        assert!(scheduler.candidate_preempts(&current, &higher, 1));
        enqueue(&mut scheduler, current.clone(), EnqueueReason::Preempt, 1);

        assert!(Arc::ptr_eq(&scheduler.pick_next_at(1).unwrap(), &higher));
        assert!(Arc::ptr_eq(&scheduler.pick_next_at(1).unwrap(), &first));
    }

    #[test]
    fn returning_from_rt_does_not_restore_stale_fair_lag() {
        let mut scheduler = Scheduler::new();
        scheduler.virtual_time = 10_000;
        let task = task(0);
        task.vruntime.store(9_500, Ordering::Release);
        task.deadline.store(10_500, Ordering::Release);
        scheduler.insert_normal(task.clone());

        assert!(scheduler.update_priority_at(&task, 50, 0));
        scheduler.virtual_time = 1_000_000;
        assert!(scheduler.update_priority_at(&task, -100, 0));

        assert_eq!(task.vruntime(), 1_000_000);
    }
}
