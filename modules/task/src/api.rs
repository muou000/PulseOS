//! Task APIs for multi-task configuration.

use alloc::{
    string::String,
    sync::{Arc, Weak},
};
use core::sync::atomic::{AtomicPtr, Ordering};

use kernel_guard::NoPreemptIrqSave;

const MAX_TIMER_HOOKS: usize = 4;

/// Global timer hook function pointers invoked on each timer tick (e.g.
/// process itimers, block watchdog). Must be safe to call from IRQ context.
static TIMER_HOOKS: [AtomicPtr<()>; MAX_TIMER_HOOKS] = [
    AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()),
];

/// Register a callback that will be invoked on every timer tick.
///
/// Registration is idempotent: re-registering the same hook is a no-op.
///
/// # Safety
///
/// The callback must be safe to call from interrupt context (no blocking locks).
pub fn register_timer_hook(hook: fn()) {
    let target = hook as *mut ();
    for slot in &TIMER_HOOKS {
        let existing = slot.load(Ordering::Acquire);
        if existing == target {
            return;
        }
        if existing.is_null() {
            match slot.compare_exchange(
                core::ptr::null_mut(),
                target,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) if actual == target => return,
                Err(_) => {}
            }
        }
    }
    panic!("task timer hook table full");
}

fn invoke_timer_hooks() {
    for slot in &TIMER_HOOKS {
        let ptr = slot.load(Ordering::Acquire);
        if !ptr.is_null() {
            let hook: fn() = unsafe { core::mem::transmute(ptr) };
            hook();
        }
    }
}

#[cfg(test)]
pub(crate) fn invoke_timer_hooks_for_test() {
    invoke_timer_hooks();
}

/// Sets a generic oneshot timer that fires at the specified deadline.
#[cfg(feature = "irq")]
pub fn set_generic_timer(
    deadline_ns: u64,
    callback: alloc::boxed::Box<dyn FnOnce(timer_list::TimeValue) + Send + Sync>,
) {
    crate::timers::set_generic_timer(timer_list::TimeValue::from_nanos(deadline_ns), callback);
}

pub use sched::RtPolicy;

pub(crate) use crate::run_queue::{
    current_run_queue, select_run_queue, select_wake_run_queue, yield_current,
};
#[doc(cfg(feature = "multitask"))]
pub use crate::task::{CurrentTask, TaskId, TaskInner};
#[doc(cfg(feature = "multitask"))]
pub use crate::task_ext::{TaskExtMut, TaskExtRef, TaskExtSwitch};
#[doc(cfg(feature = "multitask"))]
pub use crate::wait_queue::{
    WaitContext, WaitQueue, WaitReason, WakeContext, WakeSource, WakerRegistration,
};

/// The reference type of a task.
pub type AxTaskRef = Arc<AxTask>;

/// The weak reference type of a task.
pub type AxTaskWeak = Weak<AxTask>;

/// The wrapper type for [`cpumask::CpuMask`] with SMP configuration.
pub type AxCpuMask = cpumask::CpuMask<{ config::plat::MAX_CPU_NUM }>;

cfg_if::cfg_if! {
    if #[cfg(feature = "sched-eevdf")] {
        const EEVDF_BASE_SLICE_NS: u64 = 4_000_000;
        pub(crate) type AxTask = sched::EEVDFTask<TaskInner>;
        pub(crate) type Scheduler = sched::EEVDFScheduler<TaskInner, EEVDF_BASE_SLICE_NS>;
    } else if #[cfg(feature = "sched-rr")] {
        const MAX_TIME_SLICE: usize = 5;
        pub(crate) type AxTask = sched::RRTask<TaskInner, MAX_TIME_SLICE>;
        pub(crate) type Scheduler = sched::RRScheduler<TaskInner, MAX_TIME_SLICE>;
    } else if #[cfg(feature = "sched-cfs")] {
        pub(crate) type AxTask = sched::CFSTask<TaskInner>;
        pub(crate) type Scheduler = sched::CFScheduler<TaskInner>;
    } else {
        // If no scheduler features are set, use FIFO as the default.
        pub(crate) type AxTask = sched::FifoTask<TaskInner>;
        pub(crate) type Scheduler = sched::FifoScheduler<TaskInner>;
    }
}

#[cfg(feature = "preempt")]
struct KernelGuardIfImpl;

#[cfg(feature = "preempt")]
#[crate_interface::impl_interface]
impl kernel_guard::KernelGuardIf for KernelGuardIfImpl {
    fn disable_preempt() {
        if let Some(curr) = current_may_uninit() {
            curr.disable_preempt();
        }
    }

    fn enable_preempt() {
        if let Some(curr) = current_may_uninit() {
            curr.enable_preempt(true);
        }
    }
}

/// Gets the current task, or returns [`None`] if the current task is not
/// initialized.
pub fn current_may_uninit() -> Option<CurrentTask> {
    CurrentTask::try_get()
}

/// Gets the current task.
///
/// # Panics
///
/// Panics if the current task is not initialized.
pub fn current() -> CurrentTask {
    CurrentTask::get()
}

/// Initializes the host test page pool and scheduler once per test binary.
#[cfg(all(feature = "test", not(target_os = "none")))]
#[doc(hidden)]
pub fn init_scheduler_for_test() {
    extern crate std;

    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        const POOL_SIZE: usize = 32 * 1024 * 1024;
        let layout = std::alloc::Layout::from_size_align(POOL_SIZE, 4096).unwrap();
        // SAFETY: the layout has nonzero size. The pool remains allocated and
        // exclusively owned by the kernel allocator for the host process lifetime.
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        kernel_alloc::global_init(ptr as usize, POOL_SIZE);
        init_scheduler();
    });
}

/// Initializes the task scheduler (for the primary CPU).
pub fn init_scheduler() {
    info!("Initialize scheduling...");

    // Initialize the cpu count information.
    init_cpu_mask_full();

    // Initialize the run queue.
    crate::run_queue::init();
    #[cfg(feature = "irq")]
    crate::timers::init();

    info!("  use {} scheduler.", Scheduler::scheduler_name());
}

/// The full CPU mask of the system.
static CPU_MASK_FULL: lazyinit::LazyInit<AxCpuMask> = lazyinit::LazyInit::new();

/// Gets the cpu count information and initializes related data structures.
fn init_cpu_mask_full() {
    let cpu_num = hal::cpu_num();
    let mut cpumask = AxCpuMask::new();
    for cpu_id in 0..cpu_num {
        cpumask.set(cpu_id, true);
    }

    CPU_MASK_FULL.call_once(|| cpumask);
}

pub(crate) fn cpu_mask_full() -> AxCpuMask {
    CPU_MASK_FULL
        .get()
        .expect("CPU mask not initialized")
        .clone()
}

struct CpuReservation {
    users: AxCpuMask,
    sqpoll: usize,
}

static CPU_RESERVATION: lazyinit::LazyInit<CpuReservation> = lazyinit::LazyInit::new();

/// Publishes CPU placement policy once all boot CPUs are online. Each bit in
/// `reserved` excludes a logical CPU from userspace, and `sqpoll` selects the
/// reserved CPUs that userspace can explicitly request for an SQ poller.
pub fn init_cpu_reservation(reserved: usize, sqpoll: usize) -> Result<(), &'static str> {
    let online = hal::online_cpu_mask();
    if reserved & !online != 0 {
        return Err("reserved CPU is offline");
    }
    if sqpoll & !reserved != 0 {
        return Err("SQPOLL service CPU is outside the reserved set");
    }
    let user_bits = online & !reserved;
    if user_bits == 0 {
        return Err("all online CPUs are reserved");
    }

    let mut users = AxCpuMask::new();
    for cpu in 0..hal::cpu_num() {
        users.set(cpu, user_bits & (1 << cpu) != 0);
    }
    CPU_RESERVATION.init_once(CpuReservation { users, sqpoll });
    info!("CPU reservation: reserved={reserved:#x} user={user_bits:#x} sqpoll={sqpoll:#x}");
    Ok(())
}

pub(crate) fn user_cpu_mask() -> AxCpuMask {
    CPU_RESERVATION.users
}

/// Returns whether the boot policy permits an SQ poller to bind to this reserved CPU.
pub fn is_sqpoll_service_cpu(cpu: usize) -> bool {
    cpu < usize::BITS as usize && CPU_RESERVATION.sqpoll & (1usize << cpu) != 0
}

/// Initializes the task scheduler for secondary CPUs.
pub fn init_scheduler_secondary() {
    crate::run_queue::init_secondary();
    #[cfg(feature = "irq")]
    crate::timers::init();
}

/// Handles periodic timer ticks for the task manager.
///
/// For example, advance scheduler states, checks timed events, etc.
#[cfg(feature = "irq")]
#[doc(cfg(feature = "irq"))]
pub fn on_timer_tick() {
    use kernel_guard::NoOp;
    crate::timers::check_events();
    crate::future::check_timer_events();
    // Invoke registered timer hooks (e.g. itimer check, block watchdog).
    invoke_timer_hooks();
    // Since irq and preemption are both disabled here,
    // we can get current run queue with the default `kernel_guard::NoOp`.
    current_run_queue::<NoOp>().scheduler_timer_tick();
    // Reprogram the hardware timer.
    crate::timers::reprogram_timer_from_tick();
}

/// Adds the given task to the run queue, returns the task reference.
pub fn spawn_task(task: TaskInner) -> AxTaskRef {
    let task_ref = task.into_arc();
    spawn_task_ref(task_ref.clone());
    task_ref
}

/// Adds the given task reference to the run queue.
pub fn spawn_task_ref(task_ref: AxTaskRef) {
    select_run_queue::<NoPreemptIrqSave>(&task_ref).add_task(task_ref);
}

/// Spawns a new task with the given parameters.
///
/// Returns the task reference.
pub fn spawn_raw<F>(f: F, name: String, stack_size: usize) -> AxTaskRef
where
    F: FnOnce() + Send + 'static,
{
    spawn_task(TaskInner::new(f, name, stack_size))
}

/// Spawns a new task with the default parameters.
///
/// The default task name is an empty string. The default task stack size is
/// [`config::TASK_STACK_SIZE`].
///
/// Returns the task reference.
pub fn spawn<F>(f: F) -> AxTaskRef
where
    F: FnOnce() + Send + 'static,
{
    spawn_raw(f, "".into(), config::TASK_STACK_SIZE)
}

/// Spawns a new stack-backed task that runs the given future to completion.
///
/// The future is driven by [`crate::future::block_on`] from a regular kernel
/// task. This keeps the normal current-task, kernel-stack, TLS, task-extension,
/// and scheduler semantics while allowing the future to suspend on wakers.
/// The future state itself remains heap-pinned so large async state machines do
/// not consume the task's kernel stack.
///
/// Returns the task reference.
pub fn spawn_async<F>(f: F) -> AxTaskRef
where
    F: core::future::Future<Output = ()> + Send + 'static,
{
    let future = alloc::boxed::Box::pin(f);
    spawn(move || crate::future::block_on(future))
}

/// Set the priority for current task.
///
/// The range of the priority is dependent on the underlying scheduler. EEVDF
/// uses 1 through 99 for real-time priorities and -120 through -81 for ordinary
/// nice values -20 through 19.
///
/// Returns `true` if the priority is set successfully.
pub fn set_priority(prio: isize) -> bool {
    current_run_queue::<NoPreemptIrqSave>().set_current_priority(prio)
}

/// Sets the current task's real-time policy.
///
/// EEVDF distinguishes FIFO and round-robin behavior for tasks with an RT
/// priority. Other scheduler implementations retain their existing behavior.
pub fn set_current_rt_policy(policy: RtPolicy) {
    #[cfg(feature = "sched-eevdf")]
    current_run_queue::<NoPreemptIrqSave>().set_current_rt_policy(policy);
    #[cfg(not(feature = "sched-eevdf"))]
    let _ = policy;
}

/// Returns the real-time round-robin time slice exposed to user space.
pub const fn rt_time_slice_ns() -> u64 {
    #[cfg(feature = "sched-eevdf")]
    {
        sched::EEVDFTask::<TaskInner>::rt_time_slice_ns()
    }
    #[cfg(not(feature = "sched-eevdf"))]
    {
        10_000_000
    }
}

/// Set the affinity for the current task.
/// [`AxCpuMask`] is used to specify the CPU affinity.
/// Returns `true` if the affinity is set successfully.
///
/// TODO: support set the affinity for other tasks.
pub fn set_current_affinity(cpumask: AxCpuMask) -> bool {
    let has_online_cpu =
        (0..hal::cpu_num()).any(|cpu_id| cpumask.get(cpu_id) && hal::is_cpu_online(cpu_id));
    if !has_online_cpu {
        return false;
    }
    let curr = current().clone();
    let effective = curr.set_cpumask(cpumask);
    if effective.is_empty() {
        return false;
    }
    #[cfg(feature = "smp")]
    if !effective.get(hal::percpu::this_cpu_id()) {
        // Migration executes scheduler and IPI paths on this stack.
        let migration_task = TaskInner::new(
            move || crate::run_queue::migrate_entry(curr),
            "migration-task".into(),
            config::TASK_STACK_SIZE,
        )
        .into_arc();
        current_run_queue::<NoPreemptIrqSave>().migrate_current(migration_task);
        assert!(
            effective.get(hal::percpu::this_cpu_id()),
            "Migration failed"
        );
    }
    true
}

/// Current task gives up the CPU time voluntarily, and switches to another
/// ready task.
pub fn yield_now() {
    yield_current()
}

/// Wakes a blocked task and puts it back into a run queue.
pub fn wake_task(task: AxTaskRef, resched: bool) {
    select_wake_run_queue::<NoPreemptIrqSave>(&task).unblock_task(task, resched)
}

/// Interrupts a task blocked in an interruptible future or wait operation.
pub fn interrupt_task(task: AxTaskRef, resched: bool) {
    interrupt_task_with_context(
        task,
        resched,
        WakeContext::new(|| (WakeSource::Interrupt, 0)),
    );
}

/// Interrupts a blocked task and records the semantic source of the interruption.
pub fn interrupt_task_with_context(task: AxTaskRef, resched: bool, context: WakeContext) {
    task.interrupt();
    if task.state() == crate::task::TaskState::Blocked {
        select_wake_run_queue::<NoPreemptIrqSave>(&task)
            .unblock_task_with_context(task, resched, context);
    }
}

/// Updates the saved page table root of the current task context.
pub fn set_current_page_table_root(pt_root: memory_addr::PhysAddr, asid: usize) {
    #[cfg(all(
        feature = "ipi",
        any(target_arch = "riscv64", target_arch = "loongarch64")
    ))]
    ipi::mark_current_cpu_asid_active(asid);
    let curr = current();
    unsafe {
        #[cfg(any(
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        ))]
        (*curr.ctx_mut_ptr()).set_page_table_root(pt_root, asid);
        #[cfg(not(any(
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        )))]
        {
            let _ = asid;
            (*curr.ctx_mut_ptr()).set_page_table_root(pt_root);
        }
    }
}

/// Current task is going to sleep for the given duration.
///
/// If the feature `irq` is not enabled, it uses busy-wait instead.
pub fn sleep(dur: core::time::Duration) {
    sleep_until(hal::time::monotonic_time() + dur);
}

/// Current task is going to sleep, it will be woken up at the given deadline.
///
/// If the feature `irq` is not enabled, it uses busy-wait instead.
pub fn sleep_until(deadline: hal::time::TimeValue) {
    #[cfg(feature = "irq")]
    current_run_queue::<NoPreemptIrqSave>().sleep_until(deadline);
    #[cfg(not(feature = "irq"))]
    hal::time::busy_wait_until(deadline);
}

/// Exits the current task.
pub fn exit(exit_code: i32) -> ! {
    current_run_queue::<NoPreemptIrqSave>().exit_current(exit_code)
}

/// The idle task routine.
///
/// It runs an infinite loop that waits for interrupts when no task is ready.
pub fn run_idle() -> ! {
    loop {
        current_run_queue::<NoPreemptIrqSave>().idle_wait();
    }
}

/// Reprogram the hardware timer.
#[cfg(feature = "irq")]
pub fn reprogram_timer() {
    crate::timers::reprogram_timer();
}

/// Check and trigger expired timer events.
#[cfg(feature = "irq")]
pub fn check_events() {
    crate::timers::check_events();
}

/// Gets the next timer event deadline.
#[cfg(feature = "irq")]
pub fn next_deadline() -> Option<hal::time::TimeValue> {
    crate::timers::next_deadline()
}

/// Check if the current task needs to be preempted, and reschedule if so.
pub fn check_preempt_pending() {
    #[cfg(feature = "preempt")]
    crate::task::TaskInner::current_check_preempt_pending();
}
