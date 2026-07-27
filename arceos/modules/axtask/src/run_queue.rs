use alloc::{collections::VecDeque, sync::Arc};
use core::mem::MaybeUninit;
#[cfg(feature = "smp")]
use core::sync::atomic::{AtomicBool, Ordering};

use axhal::percpu::this_cpu_id;
use axsched::BaseScheduler;
use kernel_guard::{BaseGuard, NoPreemptIrqSave};
use kspin::{SpinNoIrqGuard, SpinRaw};
use lazyinit::LazyInit;

use crate::{
    AxCpuMask, AxTaskRef, Scheduler, TaskInner, WaitQueue,
    task::{CurrentTask, TaskState},
    wait_queue::{WaitContext, WaitQueueGuard, WaitReason, WakeContext},
};

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

percpu_static! {
    RUN_QUEUE: LazyInit<AxRunQueue> = LazyInit::new(),
    EXITED_TASKS: VecDeque<AxTaskRef> = VecDeque::new(),
    WAIT_FOR_EXIT: WaitQueue = WaitQueue::new(),
    IDLE_TASK: LazyInit<AxTaskRef> = LazyInit::new(),
    /// Keeps the previous task alive until the non-preemptible switch completes.
    #[cfg(feature = "smp")]
    PREV_TASK: Option<AxTaskRef> = None,
}

/// An array of references to run queues, one for each CPU, indexed by cpu_id.
///
/// This static variable holds references to the run queues for each CPU in the system.
///
/// # Safety
///
/// Access to this variable is marked as `unsafe` because it contains `MaybeUninit` references,
/// which require careful handling to avoid undefined behavior. The array should be fully
/// initialized before being accessed to ensure safe usage.
static mut RUN_QUEUES: [MaybeUninit<&'static mut AxRunQueue>; axconfig::plat::MAX_CPU_NUM] =
    [ARRAY_REPEAT_VALUE; axconfig::plat::MAX_CPU_NUM];
#[allow(clippy::declare_interior_mutable_const)] // It's ok because it's used only for initialization `RUN_QUEUES`.
const ARRAY_REPEAT_VALUE: MaybeUninit<&'static mut AxRunQueue> = MaybeUninit::uninit();

#[cfg(feature = "smp")]
static RUN_QUEUE_READY: [AtomicBool; axconfig::plat::MAX_CPU_NUM] =
    [const { AtomicBool::new(false) }; axconfig::plat::MAX_CPU_NUM];

#[cfg(all(feature = "smp", feature = "ipi"))]
static REMOTE_RESCHEDULE_PENDING: [AtomicBool; axconfig::plat::MAX_CPU_NUM] =
    [const { AtomicBool::new(false) }; axconfig::plat::MAX_CPU_NUM];

/// Returns a reference to the current run queue in [`CurrentRunQueueRef`].
///
/// ## Safety
///
/// This function returns a static reference to the current run queue, which
/// is inherently unsafe. It assumes that the `RUN_QUEUE` has been properly
/// initialized and is not accessed concurrently in a way that could cause
/// data races or undefined behavior.
///
/// ## Returns
///
/// * [`CurrentRunQueueRef`] - a static reference to the current [`AxRunQueue`].
#[inline(always)]
pub(crate) fn current_run_queue<G: BaseGuard>() -> CurrentRunQueueRef<'static, G> {
    let irq_state = G::acquire();
    CurrentRunQueueRef {
        inner: unsafe { RUN_QUEUE.current_ref_mut_raw() },
        current_task: crate::current(),
        state: irq_state,
        _phantom: core::marker::PhantomData,
    }
}

/// Yields the current task after avoiding the task lookup when no peer is ready.
pub(crate) fn yield_current() {
    let irq_state = NoPreemptIrqSave::acquire();
    let inner = unsafe { RUN_QUEUE.current_ref_mut_raw() };

    if inner.scheduler.lock().is_empty() {
        NoPreemptIrqSave::release(irq_state);
        return;
    }

    let mut run_queue: CurrentRunQueueRef<'_, NoPreemptIrqSave> = CurrentRunQueueRef {
        inner,
        current_task: crate::current(),
        state: irq_state,
        _phantom: core::marker::PhantomData,
    };
    run_queue.yield_current();
}

/// Selects the run queue index based on a CPU set bitmap and load balancing.
///
/// This function filters the available run queues based on the provided `cpumask` and
/// selects the run queue index for the next task. The selection is based on a round-robin algorithm.
///
/// ## Arguments
///
/// * `cpumask` - A bitmap representing the CPUs that are eligible for task execution.
///
/// ## Returns
///
/// The index (cpu_id) of the selected run queue.
///
/// ## Panics
///
/// This function will panic if `cpu_mask` is empty, indicating that there are no available CPUs for task execution.
#[cfg(feature = "smp")]
#[allow(clippy::modulo_one)]
#[inline]
fn select_run_queue_index(cpumask: AxCpuMask) -> usize {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static RUN_QUEUE_INDEX: AtomicUsize = AtomicUsize::new(0);

    assert!(!cpumask.is_empty(), "No available CPU for task execution");

    let cpu_num = axhal::cpu_num();
    let start = RUN_QUEUE_INDEX.fetch_add(1, Ordering::Relaxed) % cpu_num;
    for offset in 0..cpu_num {
        let index = (start + offset) % cpu_num;
        if cpumask.get(index)
            && axhal::is_cpu_online(index)
            && RUN_QUEUE_READY[index].load(Ordering::Acquire)
        {
            return index;
        }
    }
    panic!("no online CPU matches task affinity");
}

/// Retrieves a `'static` reference to the run queue corresponding to the given index.
///
/// This function asserts that the provided index is within the range of available CPUs
/// and returns a reference to the corresponding run queue.
///
/// ## Arguments
///
/// * `index` - The index of the run queue to retrieve.
///
/// ## Returns
///
/// A reference to the `AxRunQueue` corresponding to the provided index.
///
/// ## Panics
///
/// This function will panic if the index is out of bounds.
#[cfg(feature = "smp")]
#[inline]
fn get_run_queue(index: usize) -> &'static mut AxRunQueue {
    unsafe { RUN_QUEUES[index].assume_init_mut() }
}

#[cfg(all(feature = "smp", feature = "ipi"))]
fn request_current_reschedule() {
    REMOTE_RESCHEDULE_PENDING[this_cpu_id()].store(false, Ordering::Release);
    if let Some(current) = crate::current_may_uninit() {
        #[cfg(feature = "preempt")]
        current.set_preempt_pending(true);
    }
}

#[cfg(all(feature = "smp", feature = "ipi"))]
fn kick_remote_cpu(cpu_id: usize) {
    if cpu_id != this_cpu_id()
        && axhal::is_cpu_online(cpu_id)
        && !REMOTE_RESCHEDULE_PENDING[cpu_id].swap(true, Ordering::AcqRel)
        && let Err(error) = axipi::run_on_cpu(cpu_id, request_current_reschedule)
    {
        REMOTE_RESCHEDULE_PENDING[cpu_id].store(false, Ordering::Release);
        debug!("failed to kick CPU {cpu_id}: {error}");
    }
}

#[cfg(all(feature = "smp", feature = "ipi"))]
fn force_kick_remote_cpu(cpu_id: usize) {
    if cpu_id == this_cpu_id() || !axhal::is_cpu_online(cpu_id) {
        return;
    }

    let was_pending = REMOTE_RESCHEDULE_PENDING[cpu_id].swap(true, Ordering::AcqRel);
    if let Err(error) = axipi::run_on_cpu(cpu_id, request_current_reschedule) {
        if !was_pending {
            REMOTE_RESCHEDULE_PENDING[cpu_id].store(false, Ordering::Release);
        }
        debug!("failed to force-kick CPU {cpu_id}: {error}");
    }
}

/// Selects the appropriate run queue for the provided task.
///
/// * In a single-core system, this function always returns a reference to the global run queue.
/// * In a multi-core system, this function selects the run queue based on the task's CPU affinity and load balance.
///
/// ## Arguments
///
/// * `task` - A reference to the task for which a run queue is being selected.
///
/// ## Returns
///
/// * [`AxRunQueueRef`] - a static reference to the selected [`AxRunQueue`] (current or remote).
///
/// ## TODO
///
/// 1. Implement better load balancing across CPUs for more efficient task distribution.
/// 2. Use a more generic load balancing algorithm that can be customized or replaced.
#[inline]
pub(crate) fn select_run_queue<G: BaseGuard>(task: &AxTaskRef) -> AxRunQueueRef<'static, G> {
    let irq_state = G::acquire();
    #[cfg(not(feature = "smp"))]
    {
        let _ = task;
        // When SMP is disabled, all tasks are scheduled on the same global run queue.
        AxRunQueueRef {
            inner: unsafe { RUN_QUEUE.current_ref_mut_raw() },
            state: irq_state,
            _phantom: core::marker::PhantomData,
        }
    }
    #[cfg(feature = "smp")]
    {
        // When SMP is enabled, select the run queue based on the task's CPU affinity and load balance.
        let index = select_run_queue_index(task.cpumask());
        AxRunQueueRef {
            inner: get_run_queue(index),
            state: irq_state,
            _phantom: core::marker::PhantomData,
        }
    }
}

/// Selects a run queue for waking a blocked task.
///
/// Wakeups prefer the task's previous CPU. Besides preserving cache locality,
/// this keeps per-CPU timer registrations and other CPU-local wait state valid
/// across a `block_on` suspension. If affinity excludes that CPU, the CPU
/// performing the wakeup is preferred before falling back to normal placement.
#[inline]
pub(crate) fn select_wake_run_queue<G: BaseGuard>(task: &AxTaskRef) -> AxRunQueueRef<'static, G> {
    let irq_state = G::acquire();
    #[cfg(not(feature = "smp"))]
    {
        let _ = task;
        AxRunQueueRef {
            inner: unsafe { RUN_QUEUE.current_ref_mut_raw() },
            state: irq_state,
            _phantom: core::marker::PhantomData,
        }
    }
    #[cfg(feature = "smp")]
    {
        let current_cpu = this_cpu_id();
        let previous_cpu = task.cpu_id() as usize;
        let cpu_num = axhal::cpu_num();
        let cpumask = task.cpumask();
        let index = if previous_cpu < cpu_num
            && cpumask.get(previous_cpu)
            && axhal::is_cpu_online(previous_cpu)
            && RUN_QUEUE_READY[previous_cpu].load(Ordering::Acquire)
        {
            previous_cpu
        } else if current_cpu < cpu_num
            && cpumask.get(current_cpu)
            && axhal::is_cpu_online(current_cpu)
            && RUN_QUEUE_READY[current_cpu].load(Ordering::Acquire)
        {
            current_cpu
        } else {
            select_run_queue_index(cpumask)
        };
        AxRunQueueRef {
            inner: get_run_queue(index),
            state: irq_state,
            _phantom: core::marker::PhantomData,
        }
    }
}

/// [`AxRunQueue`] represents a run queue for global system or a specific CPU.
pub(crate) struct AxRunQueue {
    /// The ID of the CPU this run queue is associated with.
    cpu_id: usize,
    /// The core scheduler of this run queue.
    /// Since irq and preempt are preserved by the kernel guard hold by `AxRunQueueRef`,
    /// we just use a simple raw spin lock here.
    scheduler: SpinRaw<Scheduler>,
}

/// A reference to the run queue with specific guard.
///
/// Note:
/// [`AxRunQueueRef`] is used to get a reference to the run queue on current CPU
/// or a remote CPU, which is used to add tasks to the run queue or unblock tasks.
/// If you want to perform scheduling operations on the current run queue,
/// see [`CurrentRunQueueRef`].
pub(crate) struct AxRunQueueRef<'a, G: BaseGuard> {
    inner: &'a mut AxRunQueue,
    state: G::State,
    _phantom: core::marker::PhantomData<G>,
}

impl<G: BaseGuard> Drop for AxRunQueueRef<'_, G> {
    fn drop(&mut self) {
        G::release(self.state);
    }
}

/// A reference to the current run queue with specific guard.
///
/// Note:
/// [`CurrentRunQueueRef`] is used to get a reference to the run queue on current CPU,
/// in which scheduling operations can be performed.
pub(crate) struct CurrentRunQueueRef<'a, G: BaseGuard> {
    pub(crate) inner: &'a mut AxRunQueue,
    current_task: CurrentTask,
    state: G::State,
    _phantom: core::marker::PhantomData<G>,
}

impl<G: BaseGuard> Drop for CurrentRunQueueRef<'_, G> {
    fn drop(&mut self) {
        G::release(self.state);
    }
}

/// Management operations for run queue, including adding tasks, unblocking tasks, etc.
impl<G: BaseGuard> AxRunQueueRef<'_, G> {
    /// Adds a task to the scheduler.
    ///
    /// This function is used to add a new task to the scheduler.
    pub fn add_task(&mut self, task: AxTaskRef) {
        let cpu_id = self.inner.cpu_id;
        trace!("task add: {} on run_queue {}", task.id_name(), cpu_id);
        assert!(task.is_ready());
        #[cfg(feature = "smp")]
        task.set_cpu_id(cpu_id as _);
        self.inner.scheduler.lock().add_task(task);
        #[cfg(all(feature = "smp", feature = "ipi"))]
        kick_remote_cpu(cpu_id);
        #[cfg(feature = "irq")]
        crate::timers::reprogram_timer();
    }

    /// Unblock one task by inserting it into the run queue.
    ///
    /// This function does nothing if the task is not in [`TaskState::Blocked`],
    /// which means the task is already unblocked by other cores.
    pub fn unblock_task(&mut self, task: AxTaskRef, resched: bool) {
        self.unblock_task_with_context(task, resched, WakeContext::unknown());
    }

    /// Unblocks one task and records the semantic source of the wakeup.
    pub(crate) fn unblock_task_with_context(
        &mut self,
        task: AxTaskRef,
        resched: bool,
        context: WakeContext,
    ) {
        let task_id_name = if log_enabled!(log::Level::Trace) {
            Some(task.id_name())
        } else {
            None
        };
        // Try to change the state of the task from `Blocked` to `Ready`,
        // if successful, the task will be put into this run queue,
        // otherwise, the task is already unblocked by other cores.
        // Note:
        // target task can not be insert into the run queue until it finishes its scheduling process.
        if self
            .inner
            .put_task_with_state(task, TaskState::Blocked, resched, context)
        {
            // Since now, the task to be unblocked is in the `Ready` state.
            let cpu_id = self.inner.cpu_id;
            if let Some(id_name) = task_id_name {
                trace!("task unblock: {} on run_queue {}", id_name, cpu_id);
            }
            // Note: when the task is unblocked on another CPU's run queue,
            // we just ingiore the `resched` flag.
            if resched && cpu_id == this_cpu_id() {
                #[cfg(feature = "preempt")]
                crate::current().set_preempt_pending(true);
            }
            #[cfg(all(feature = "smp", feature = "ipi"))]
            kick_remote_cpu(cpu_id);
            #[cfg(feature = "irq")]
            crate::timers::reprogram_timer();
        }
    }
}

/// Core functions of run queue.
impl<G: BaseGuard> CurrentRunQueueRef<'_, G> {
    /// Waits efficiently when the current task is idle, or schedules ready work.
    pub fn idle_wait(&mut self) {
        #[cfg(target_arch = "riscv64")]
        {
            if self.inner.scheduler.lock().is_empty() {
                // The NoPreemptIrqSave guard keeps SIE clear across the empty
                // check and WFI. A timer or reschedule IPI remains pending and
                // wakes WFI, then is handled when the guard restores SIE.
                axhal::asm::wait_for_irqs_disabled();
                return;
            }
        }

        self.yield_current();
    }

    #[cfg(feature = "irq")]
    pub fn scheduler_timer_tick(&mut self) {
        let curr = &self.current_task;
        let need_resched = {
            let mut scheduler = self.inner.scheduler.lock();
            if curr.is_idle() {
                !scheduler.is_empty()
            } else {
                scheduler.task_tick(curr.as_task_ref())
            }
        };
        if need_resched {
            #[cfg(feature = "preempt")]
            curr.set_preempt_pending(true);
        }
    }

    /// Yield the current task and reschedule.
    /// This function will put the current task into this run queue with `Ready` state,
    /// and reschedule to the next task on this run queue.
    pub fn yield_current(&mut self) {
        // Yielding cannot make progress when this CPU has no other ready task.
        // Avoid enqueueing and immediately switching back to the current task.
        if self.inner.scheduler.lock().is_empty() {
            return;
        }

        let curr = self.current_task.clone();
        trace!("task yield: {}", curr.id_name());
        assert!(curr.is_running());

        self.inner.put_task_with_state(
            curr.clone(),
            TaskState::Running,
            false,
            WakeContext::unknown(),
        );

        self.resched();
    }

    /// Migrate the current task to a new run queue matching its CPU affinity and reschedule.
    /// This function will spawn a new `migration_task` to perform the migration, which will set
    /// current task to `Ready` state and select a proper run queue for it according to its CPU affinity,
    /// switch to the migration task immediately after migration task is prepared.
    ///
    /// Note: the ownership if migrating task (which is current task) is handed over to the migration task,
    /// before the migration task inserted it into the target run queue.
    #[cfg(feature = "smp")]
    pub fn migrate_current(&mut self, migration_task: AxTaskRef) {
        let curr = self.current_task.clone();
        trace!("task migrate: {}", curr.id_name());
        assert!(curr.is_running());

        // Mark current task's state as `Ready`,
        // but, do not put current task to the scheduler of this run queue.
        curr.set_state(TaskState::Ready);

        // Call `switch_to` to reschedule to the migration task that performs the migration directly.
        self.inner.switch_to(crate::current(), migration_task);
    }

    /// Preempts the current task and reschedules.
    /// This function is used to preempt the current task and reschedule
    /// to next task on current run queue.
    ///
    /// This function is called by `current_check_preempt_pending` with IRQs and preemption disabled.
    ///
    /// Note:
    /// preemption may happened in `enable_preempt`, which is called
    /// each time a [`kspin::NoPreemptGuard`] is dropped.
    #[cfg(feature = "preempt")]
    pub fn preempt_resched(&mut self) {
        // There is no need to disable IRQ and preemption here, because
        // they both have been disabled in `current_check_preempt_pending`.
        let curr = self.current_task.clone();
        assert!(curr.is_running());

        // When we call `preempt_resched()`, both IRQs and preemption must
        // have been disabled by `kernel_guard::NoPreemptIrqSave`. So we need
        // to set `current_disable_count` to 1 in `can_preempt()` to obtain
        // the preemption permission.
        let can_preempt = curr.can_preempt(1);

        trace!(
            "current task is to be preempted: {}, allow={}",
            curr.id_name(),
            can_preempt
        );
        if can_preempt {
            self.inner.put_task_with_state(
                curr.clone(),
                TaskState::Running,
                true,
                WakeContext::unknown(),
            );
            self.resched();
        } else {
            curr.set_preempt_pending(true);
        }
    }

    /// Exit the current task with the specified exit code.
    /// This function will never return.
    pub fn exit_current(&mut self, exit_code: i32) -> ! {
        let curr = &self.current_task;
        assert!(curr.is_running(), "task is not running: {:?}", curr.state());
        assert!(!curr.is_idle());
        if curr.is_init() {
            // Safety: it is called from `current_run_queue::<NoPreemptIrqSave>().exit_current(exit_code)`,
            // which disabled IRQs and preemption.
            unsafe {
                EXITED_TASKS.current_ref_mut_raw().clear();
            }
            axhal::power::system_off();
        } else {
            curr.set_state(TaskState::Exited);
            #[cfg(feature = "qperf-trace")]
            crate::qperf_trace::task_exit(curr);

            // Notify the joiner task.
            curr.notify_exit(exit_code);

            // Safety: it is called from `current_run_queue::<NoPreemptIrqSave>().exit_current(exit_code)`,
            // which disabled IRQs and preemption.
            unsafe {
                // Push current task to the `EXITED_TASKS` list, which will be consumed by the GC task.
                EXITED_TASKS.current_ref_mut_raw().push_back(curr.clone());
                // Wake up the GC task to drop the exited tasks.
                WAIT_FOR_EXIT
                    .current_ref_mut_raw()
                    .notify_one_with_context(false, WakeContext::task());
            }

            // The GC task is woken through WAIT_FOR_EXIT and must be selected
            // through the scheduler. Bypassing its Blocked/Ready transition can
            // leave it both running and linked in the wait queue.
            self.resched();
        }
        unreachable!("task exited!");
    }

    /// Block the current task, put current task into the wait queue and reschedule.
    /// Mark the state of current task as `Blocked`, set the `in_wait_queue` flag as true.
    /// Note:
    ///     1. The caller must hold the lock of the wait queue.
    ///     2. The caller must ensure that the current task is in the running state.
    ///     3. The caller must ensure that the current task is not the idle task.
    ///     4. The lock of the wait queue will be released explicitly after current task is pushed into it.
    pub fn blocked_resched(&mut self, mut wq_guard: WaitQueueGuard, context: WaitContext) {
        let curr = self.current_task.clone();
        assert!(curr.is_running());
        assert!(!curr.is_idle());
        // we must not block current task with preemption disabled.
        // Current expected preempt count is 2.
        // 1 for `NoPreemptIrqSave`, 1 for wait queue's `SpinNoIrq`.
        #[cfg(feature = "preempt")]
        assert!(curr.can_preempt(2));

        #[cfg(feature = "qperf-trace")]
        let qperf_sequence = curr.next_qperf_block_sequence();

        // Mark the task as blocked, this has to be done before adding it to the wait queue
        // while holding the lock of the wait queue.
        curr.set_state(TaskState::Blocked);
        curr.set_in_wait_queue(true);

        wq_guard.push_back(curr.clone());
        #[cfg(feature = "qperf-trace")]
        crate::qperf_trace::task_block(&curr, qperf_sequence, context);
        // Drop the lock of wait queue explictly.
        drop(wq_guard);

        // Current task's state has been changed to `Blocked` and added to the wait queue.
        // Note that the state may have been set as `Ready` in `unblock_task()`,
        // see `unblock_task()` for details.

        trace!("task block: {}", curr.id_name());
        self.resched();
    }

    /// Block the current task and reschedule, with a "woke" flag.
    ///
    /// The caller must ensure the "woke" flag is protected by a lock that
    /// is also held when waking the task.
    pub fn blocked_resched_woke(&mut self, mut woke: SpinNoIrqGuard<'_, bool>) {
        let curr = self.current_task.clone();
        assert!(curr.is_running());
        assert!(!curr.is_idle());
        #[cfg(feature = "preempt")]
        assert!(curr.can_preempt(2));

        #[cfg(feature = "qperf-trace")]
        let qperf_sequence = curr.next_qperf_block_sequence();
        curr.set_state(TaskState::Blocked);
        *woke = false;
        #[cfg(feature = "qperf-trace")]
        crate::qperf_trace::task_block(
            &curr,
            qperf_sequence,
            WaitContext::new(
                WaitReason::Future,
                (&*woke as *const bool) as usize as u64,
                0,
            ),
        );
        drop(woke);

        trace!("task block woke: {}", curr.id_name());
        self.resched();
    }

    /// Block the current task and reschedule without a specific wait queue guard.
    /// This is used for multi-queue waiting where locks cannot be held.
    /// Note: The caller MUST ensure the task is already set to `Blocked` and `in_wait_queue` = true,
    /// and that proper condition checks have been performed.
    pub(crate) fn resched_blocked(
        &mut self,
        #[cfg(feature = "qperf-trace")] qperf_sequence: u64,
        context: WaitContext,
    ) {
        let curr = self.current_task.clone();
        assert!(!curr.is_idle());
        #[cfg(feature = "preempt")]
        assert!(curr.can_preempt(1)); // 1 for `NoPreemptIrqSave`

        #[cfg(feature = "qperf-trace")]
        if curr.state() == TaskState::Blocked {
            crate::qperf_trace::task_block(&curr, qperf_sequence, context);
        }
        trace!("task block multi: {}", curr.id_name());
        self.resched();
    }

    #[cfg(feature = "irq")]
    pub fn sleep_until(&mut self, deadline: axhal::time::TimeValue) {
        let curr = self.current_task.clone();
        trace!("task sleep: {}, deadline={:?}", curr.id_name(), deadline);
        assert!(curr.is_running());
        assert!(!curr.is_idle());

        let now = axhal::time::monotonic_time();
        if now < deadline {
            #[cfg(feature = "qperf-trace")]
            let qperf_sequence = curr.next_qperf_block_sequence();
            let _keep_alive = curr.clone();
            crate::timers::set_alarm_wakeup(deadline, curr.clone());
            curr.set_state(TaskState::Blocked);
            #[cfg(feature = "qperf-trace")]
            crate::qperf_trace::task_block(
                &curr,
                qperf_sequence,
                WaitContext::new(
                    WaitReason::Sleep,
                    deadline.as_nanos().min(u64::MAX as u128) as u64,
                    0,
                ),
            );
            self.resched();
            curr.timer_ticket_expired();
        }
    }

    pub fn set_current_priority(&mut self, prio: isize) -> bool {
        self.inner
            .scheduler
            .lock()
            .set_priority(self.current_task.as_task_ref(), prio)
    }

    /// Core reschedule subroutine.
    /// Pick the next task to run and switch to it.
    fn resched(&mut self) {
        let next = self
            .inner
            .scheduler
            .lock()
            .pick_next_task()
            .unwrap_or_else(|| unsafe {
                // Safety: IRQs must be disabled at this time.
                IDLE_TASK.current_ref_raw().get_unchecked().clone()
            });
        assert!(
            next.is_ready(),
            "next {} is not ready: {:?}",
            next.id_name(),
            next.state()
        );
        self.inner.switch_to(crate::current(), next);
    }
}

impl AxRunQueue {
    /// Create a new run queue for the specified CPU.
    /// The run queue is initialized with a per-CPU gc task in its scheduler.
    fn new(cpu_id: usize) -> Self {
        let gc_task = TaskInner::new(gc_entry, "gc".into(), axconfig::TASK_STACK_SIZE).into_arc();
        // gc task should be pinned to the current CPU.
        gc_task.set_cpumask(AxCpuMask::one_shot(cpu_id));

        let mut scheduler = Scheduler::new();
        scheduler.add_task(gc_task);
        Self {
            cpu_id,
            scheduler: SpinRaw::new(scheduler),
        }
    }

    /// Puts target task into current run queue with `Ready` state
    /// if its state matches `current_state` (except idle task).
    ///
    /// If `preempt`, keep current task's time slice, otherwise reset it.
    ///
    /// Returns `true` if the target task is put into this run queue successfully,
    /// otherwise `false`.
    fn put_task_with_state(
        &mut self,
        task: AxTaskRef,
        current_state: TaskState,
        preempt: bool,
        wake_context: WakeContext,
    ) -> bool {
        // If the task's state matches `current_state`, set its state to `Ready` and
        // put it back to the run queue (except idle task).
        if task.transition_state(current_state, TaskState::Ready) && !task.is_idle() {
            #[cfg(feature = "qperf-trace")]
            if current_state == TaskState::Blocked {
                crate::qperf_trace::task_wake(&task, wake_context);
            }
            #[cfg(feature = "smp")]
            let waking_current_task = current_state == TaskState::Blocked
                && self.cpu_id == this_cpu_id()
                && crate::current().ptr_eq(&task);

            // A remote CPU may wake a task after it becomes Blocked but before
            // its owning CPU has saved the complete context. Defer the enqueue
            // under the task's switch-state lock so another execution generation
            // cannot overtake the handoff.
            #[cfg(feature = "smp")]
            if current_state == TaskState::Blocked
                && !waking_current_task
                && task.defer_wake(self.cpu_id as _, task.clone())
            {
                task.set_cpu_id(self.cpu_id as _);
                return false;
            }
            // TODO: priority
            #[cfg(feature = "smp")]
            task.set_cpu_id(self.cpu_id as _);
            let is_preempt = if current_state == TaskState::Blocked {
                false
            } else {
                preempt
            };
            self.scheduler.lock().put_prev_task(task, is_preempt);
            true
        } else {
            false
        }
    }

    fn switch_to(&mut self, prev_task: CurrentTask, next_task: AxTaskRef) {
        // Make sure that IRQs are disabled by kernel guard or other means.
        #[cfg(all(not(test), feature = "irq"))] // Note: irq is faked under unit tests.
        assert!(
            !axhal::asm::irqs_enabled(),
            "IRQs must be disabled during scheduling"
        );
        #[cfg(feature = "preempt")]
        next_task.set_preempt_pending(false);
        next_task.set_state(TaskState::Running);
        if prev_task.ptr_eq(&next_task) {
            return;
        }

        // Claim the task as running, we do this before switching to it
        // such that any running task will have this set.
        #[cfg(feature = "smp")]
        next_task.claim_on_cpu();

        prev_task.leave_task_ext();
        next_task.enter_task_ext();

        unsafe {
            let prev_ctx_ptr = prev_task.ctx_mut_ptr();
            let next_ctx_ptr = next_task.ctx_mut_ptr();

            #[cfg(all(
                feature = "ipi",
                any(target_arch = "riscv64", target_arch = "loongarch64")
            ))]
            axipi::mark_current_cpu_asid_active((*next_ctx_ptr).page_table_asid());

            // Keep a counted reference until the next stack publishes that the
            // previous context is fully saved. GC must not reclaim it earlier.
            #[cfg(feature = "smp")]
            {
                *PREV_TASK.current_ref_mut_raw() = Some(prev_task.clone());
            }

            // The strong reference count of `prev_task` will be decremented by 1,
            // but won't be dropped until `gc_entry()` is called.
            assert!(Arc::strong_count(prev_task.as_task_ref()) > 1);
            assert!(Arc::strong_count(&next_task) >= 1);

            #[cfg(feature = "qperf-trace")]
            crate::qperf_trace::sched_switch(&prev_task, &next_task, prev_task.state() as u8);
            CurrentTask::set_current(prev_task, next_task);

            (*prev_ctx_ptr).switch_to(&*next_ctx_ptr);

            // Current it's **next_task** running on this CPU, clear the `prev_task`'s `on_cpu` field
            // to indicate that it has finished its scheduling process and no longer running on this CPU.
            #[cfg(feature = "smp")]
            clear_prev_task_on_cpu();
        }
    }
}

fn gc_entry() {
    loop {
        // Drop all exited tasks and recycle resources.
        let n = EXITED_TASKS.with_current(|exited_tasks| exited_tasks.len());
        for _ in 0..n {
            // Do not do the slow drops in the critical section.
            let task = EXITED_TASKS.with_current(|exited_tasks| exited_tasks.pop_front());
            if let Some(task) = task {
                if Arc::strong_count(&task) == 1 {
                    drop(task);
                } else {
                    // A switch frame or joiner still owns the task. Keep its
                    // stack alive until all of those references are gone.
                    EXITED_TASKS.with_current(|exited_tasks| exited_tasks.push_back(task));
                }
            }
        }
        // Note: we cannot block current task with preemption disabled,
        // use `current_ref_raw` to get the `WAIT_FOR_EXIT`'s reference here to avoid the use of `NoPreemptGuard`.
        // Since gc task is pinned to the current CPU, there is no affection if the gc task is preempted during the process.
        let wait_queue = unsafe { WAIT_FOR_EXIT.current_ref_raw() };
        let period = core::time::Duration::from_millis(100);
        let context = WaitContext::new(
            WaitReason::Gc,
            wait_queue as *const WaitQueue as usize as u64,
            period.as_nanos() as u64,
        );
        let _ = wait_queue.wait_timeout_with_context(context, period);
    }
}

/// The task routine for migrating the current task to the correct CPU.
///
/// It calls `select_run_queue` to get the correct run queue for the task, then
/// enqueues it and forces the target CPU to observe the migration.
#[cfg(feature = "smp")]
pub(crate) fn migrate_entry(migrated_task: AxTaskRef) {
    let run_queue = select_run_queue::<kernel_guard::NoPreemptIrqSave>(&migrated_task);
    let cpu_id = run_queue.inner.cpu_id;
    migrated_task.set_cpu_id(cpu_id as _);
    run_queue
        .inner
        .scheduler
        .lock()
        .put_prev_task(migrated_task, false);
    #[cfg(feature = "ipi")]
    force_kick_remote_cpu(cpu_id);
}

/// Clear the previous task's `on_cpu` field and finish a deferred remote wake.
#[cfg(feature = "smp")]
pub(crate) unsafe fn clear_prev_task_on_cpu() {
    let prev = unsafe { PREV_TASK.current_ref_mut_raw() }
        .take()
        .expect("PREV_TASK should have been set by switch_to");
    if let Some((target, task)) = prev
        .finish_switch_out()
        .map(|(cpu_id, task)| (cpu_id as usize, task))
    {
        get_run_queue(target)
            .scheduler
            .lock()
            .put_prev_task(task, false);
        if target != this_cpu_id() {
            #[cfg(feature = "ipi")]
            kick_remote_cpu(target);
        } else {
            #[cfg(feature = "preempt")]
            crate::current().set_preempt_pending(true);
        }
    }
}
pub(crate) fn init() {
    let cpu_id = this_cpu_id();

    // Idle handles timer, IPI, and scheduler paths on its own kernel stack.
    let idle_task = TaskInner::new(
        || crate::run_idle(),
        "idle".into(),
        axconfig::TASK_STACK_SIZE,
    );
    // idle task should be pinned to the current CPU.
    idle_task.set_cpumask(AxCpuMask::one_shot(cpu_id));
    IDLE_TASK.with_current(|i| {
        i.init_once(idle_task.into_arc());
    });

    // Put the subsequent execution into the `main` task.
    let main_task = TaskInner::new_init("main".into()).into_arc();
    main_task.set_state(TaskState::Running);
    unsafe { CurrentTask::init_current(main_task) }

    RUN_QUEUE.with_current(|rq| {
        rq.init_once(AxRunQueue::new(cpu_id));
    });
    unsafe {
        RUN_QUEUES[cpu_id].write(RUN_QUEUE.current_ref_mut_raw());
    }
    #[cfg(feature = "smp")]
    RUN_QUEUE_READY[cpu_id].store(true, Ordering::Release);
}

pub(crate) fn init_secondary() {
    let cpu_id = this_cpu_id();

    // Put the subsequent execution into the `idle` task.
    let idle_task = TaskInner::new_init("idle".into()).into_arc();
    idle_task.set_state(TaskState::Running);
    IDLE_TASK.with_current(|i| {
        i.init_once(idle_task.clone());
    });
    unsafe { CurrentTask::init_current(idle_task) }

    RUN_QUEUE.with_current(|rq| {
        rq.init_once(AxRunQueue::new(cpu_id));
    });
    unsafe {
        RUN_QUEUES[cpu_id].write(RUN_QUEUE.current_ref_mut_raw());
    }
    #[cfg(feature = "smp")]
    RUN_QUEUE_READY[cpu_id].store(true, Ordering::Release);
}
