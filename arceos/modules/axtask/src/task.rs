use alloc::{boxed::Box, string::String, sync::Arc};
#[cfg(feature = "preempt")]
use core::sync::atomic::AtomicUsize;
use core::{
    cell::UnsafeCell,
    fmt,
    ops::Deref,
    sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, Ordering},
    task::{Context, Poll},
};

use axalloc::global_allocator;
use axerrno::{AxError, AxResult};
#[cfg(feature = "tls")]
use axhal::tls::TlsArea;
use axhal::{context::TaskContext, percpu::this_cpu_id};
use futures_util::task::AtomicWaker;
use kspin::SpinNoIrq;
#[cfg(feature = "smp")]
use kspin::SpinRaw;
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, VirtAddr, align_up_4k};

use crate::{AxCpuMask, AxTask, AxTaskRef, WaitQueue, task_ext::AxTaskExt};

/// A unique identifier for a thread.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TaskId(u64);

/// The possible states of a task.
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum TaskState {
    /// Task is running on some CPU.
    Running = 1,
    /// Task is ready to run on some scheduler's ready queue.
    Ready   = 2,
    /// Task is blocked (in the wait queue or timer list),
    /// and it has finished its scheduling process, it can be wake up by `notify()` on any run queue safely.
    Blocked = 3,
    /// Task is exited and waiting for being dropped.
    Exited  = 4,
}

#[cfg(feature = "smp")]
struct SwitchState {
    on_cpu: bool,
    deferred_wake: Option<(u32, AxTaskRef)>,
}

/// The inner task structure.
pub struct TaskInner {
    id: TaskId,
    name: SpinNoIrq<String>,
    is_idle: bool,
    is_init: bool,

    entry: SpinNoIrq<Option<Box<dyn FnOnce() + Send>>>,
    state: AtomicU8,
    #[cfg(feature = "qperf-trace")]
    qperf_block_sequence: AtomicU64,
    #[cfg(feature = "qperf-trace")]
    qperf_pending_wait_context: SpinNoIrq<Option<crate::wait_queue::WaitContext>>,

    /// CPU affinity mask.
    cpumask: SpinNoIrq<AxCpuMask>,

    /// Mark whether the task is in the wait queue.
    in_wait_queue: AtomicBool,

    /// Used to indicate the CPU ID where the task is running or will run.
    cpu_id: AtomicU32,
    /// Serializes context switch completion with a racing remote wake.
    #[cfg(feature = "smp")]
    switch_state: SpinRaw<SwitchState>,

    interrupted: AtomicBool,
    interrupt_waker: AtomicWaker,
    /// Reuses the allocation behind completed `block_on` invocations. A waker
    /// is cached only after every external registration has released it.
    block_on_waker: SpinNoIrq<Option<Arc<crate::future::AxWaker>>>,

    /// A ticket ID used to identify the timer event.
    /// Set by `set_timer_ticket()` when creating a timer event in `set_alarm_wakeup()`,
    /// expired by setting it as zero in `timer_ticket_expired()`, which is called by `cancel_events()`.
    #[cfg(feature = "irq")]
    timer_ticket_id: AtomicU64,

    #[cfg(feature = "preempt")]
    need_resched: AtomicBool,
    #[cfg(feature = "preempt")]
    preempt_disable_count: AtomicUsize,

    exit_code: AtomicI32,
    wait_for_exit: WaitQueue,

    kstack: SpinNoIrq<Option<TaskStack>>,
    ctx: UnsafeCell<TaskContext>,
    task_ext: AxTaskExt,

    #[cfg(feature = "tls")]
    tls: TlsArea,
}

impl TaskId {
    fn new() -> Self {
        static ID_COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(ID_COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Convert the task ID to a `u64`.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl From<u8> for TaskState {
    #[inline]
    fn from(state: u8) -> Self {
        match state {
            1 => Self::Running,
            2 => Self::Ready,
            3 => Self::Blocked,
            4 => Self::Exited,
            _ => panic!("invalid task state byte: {}", state),
        }
    }
}

unsafe impl Send for TaskInner {}
unsafe impl Sync for TaskInner {}

impl TaskInner {
    /// Create a new task with the given entry function and stack size.
    pub fn new<F>(entry: F, name: String, stack_size: usize) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self::try_new(entry, name, stack_size).unwrap_or_else(|_| {
            alloc::alloc::handle_alloc_error(
                core::alloc::Layout::from_size_align(align_up_4k(stack_size), PAGE_SIZE_4K)
                    .unwrap(),
            )
        })
    }

    /// Try to create a new task with the given entry function and stack size.
    pub fn try_new<F>(entry: F, name: String, stack_size: usize) -> AxResult<Self>
    where
        F: FnOnce() + Send + 'static,
    {
        let mut t = Self::new_common(TaskId::new(), name);
        debug!("new task: {}", t.id_name());
        let kstack = TaskStack::try_alloc(align_up_4k(stack_size))?;

        #[cfg(feature = "tls")]
        let tls = VirtAddr::from(t.tls.tls_ptr() as usize);
        #[cfg(not(feature = "tls"))]
        let tls = VirtAddr::from(0);

        *t.entry.lock() = Some(Box::new(entry));
        t.ctx_mut()
            .init(task_entry as *const () as usize, kstack.top(), tls);
        *t.kstack.lock() = Some(kstack);
        if *t.name.lock() == "idle" {
            t.is_idle = true;
        }
        #[cfg(feature = "qperf-trace")]
        crate::qperf_trace::task_metadata(t.id().as_u64(), 0, 0, t.name().as_bytes());
        Ok(t)
    }

    /// Gets the ID of the task.
    pub const fn id(&self) -> TaskId {
        self.id
    }

    #[cfg(feature = "qperf-trace")]
    pub(crate) fn next_qperf_block_sequence(&self) -> u64 {
        self.qperf_block_sequence.fetch_add(1, Ordering::Relaxed) + 1
    }

    #[cfg(feature = "qperf-trace")]
    pub(crate) fn qperf_block_sequence(&self) -> u64 {
        self.qperf_block_sequence.load(Ordering::Relaxed)
    }

    #[cfg(feature = "qperf-trace")]
    pub(crate) fn clear_qperf_pending_wait_context(&self) {
        *self.qperf_pending_wait_context.lock() = None;
    }

    #[cfg(feature = "qperf-trace")]
    pub(crate) fn set_qperf_pending_wait_context(&self, context: crate::wait_queue::WaitContext) {
        *self.qperf_pending_wait_context.lock() = Some(context);
    }

    #[cfg(feature = "qperf-trace")]
    pub(crate) fn take_qperf_pending_wait_context(&self) -> Option<crate::wait_queue::WaitContext> {
        self.qperf_pending_wait_context.lock().take()
    }

    pub(crate) fn take_block_on_waker(&self) -> Option<Arc<crate::future::AxWaker>> {
        self.block_on_waker.lock().take()
    }

    pub(crate) fn cache_block_on_waker(
        &self,
        waker: Arc<crate::future::AxWaker>,
    ) -> Result<(), Arc<crate::future::AxWaker>> {
        let mut cached = self.block_on_waker.lock();
        if cached.is_some() {
            Err(waker)
        } else {
            *cached = Some(waker);
            Ok(())
        }
    }

    /// Gets the name of the task.
    ///
    /// Note: This returns a copy of the name because it is protected by a lock.
    pub fn name(&self) -> String {
        self.name.lock().clone()
    }

    /// Sets the name of the task.
    pub fn set_name(&self, name: &str) {
        *self.name.lock() = String::from(name);
    }

    /// Get a combined string of the task ID and name.
    pub fn id_name(&self) -> alloc::string::String {
        alloc::format!("Task({}, {:?})", self.id.as_u64(), *self.name.lock())
    }

    /// Wait for the task to exit, and return the exit code.
    ///
    /// It will return immediately if the task has already exited (but not dropped).
    pub fn join(&self) -> Option<i32> {
        self.wait_for_exit
            .wait_until(|| self.state() == TaskState::Exited);
        Some(self.exit_code.load(Ordering::Acquire))
    }

    pub fn try_join(&self) -> Option<i32> {
        if self.state() == TaskState::Exited {
            Some(self.exit_code.load(Ordering::Acquire))
        } else {
            None
        }
    }

    /// Returns the pointer to the user-defined task extended data.
    ///
    /// # Safety
    ///
    /// The caller should not access the pointer directly, use [`TaskExtRef::task_ext`]
    /// or [`TaskExtMut::task_ext_mut`] instead.
    ///
    /// [`TaskExtRef::task_ext`]: crate::task_ext::TaskExtRef::task_ext
    /// [`TaskExtMut::task_ext_mut`]: crate::task_ext::TaskExtMut::task_ext_mut
    pub unsafe fn task_ext_ptr(&self) -> *mut u8 {
        self.task_ext.as_ptr()
    }

    /// Initialize the user-defined task extended data.
    ///
    /// Returns a reference to the task extended data if it has not been
    /// initialized yet (empty), otherwise returns [`None`].
    pub fn init_task_ext<T: Sized>(&mut self, data: T) -> Option<&T> {
        if self.task_ext.is_empty() {
            self.task_ext.write(data).map(|data| &*data)
        } else {
            None
        }
    }

    /// Returns a mutable reference to the task context.
    #[inline]
    pub const fn ctx_mut(&mut self) -> &mut TaskContext {
        self.ctx.get_mut()
    }

    /// Returns the top address of the kernel stack.
    #[inline]
    pub fn kernel_stack_top(&self) -> Option<VirtAddr> {
        self.kstack.lock().as_ref().map(TaskStack::top)
    }

    /// Returns the CPU ID where the task is running or will run.
    ///
    /// Note: the task may not be running on the CPU, it just exists in the run queue.
    #[inline]
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id.load(Ordering::Acquire)
    }

    /// Gets the cpu affinity mask of the task.
    ///
    /// Returns the cpu affinity mask of the task in type [`AxCpuMask`].
    #[inline]
    pub fn cpumask(&self) -> AxCpuMask {
        *self.cpumask.lock()
    }

    /// Sets the cpu affinity mask of the task.
    ///
    /// # Arguments
    /// `cpumask` - The cpu affinity mask to be set in type [`AxCpuMask`].
    #[inline]
    pub fn set_cpumask(&self, cpumask: AxCpuMask) {
        *self.cpumask.lock() = cpumask
    }

    /// Polls and consumes a pending task interruption.
    pub fn poll_interrupt(&self, cx: &Context<'_>) -> Poll<()> {
        self.interrupt_waker.register(cx.waker());
        if self.interrupted.swap(false, Ordering::AcqRel) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Clears a pending task interruption.
    pub fn clear_interrupt(&self) {
        self.interrupted.store(false, Ordering::Release);
    }

    /// Interrupts the task and wakes an interruptible future, if registered.
    pub fn interrupt(&self) {
        self.interrupted.store(true, Ordering::Release);
        self.interrupt_waker.wake();
    }
}

// private methods
impl TaskInner {
    fn new_common(id: TaskId, name: String) -> Self {
        let cpumask = crate::api::cpu_mask_full();

        Self {
            id,
            name: SpinNoIrq::new(name),
            is_idle: false,
            is_init: false,
            entry: SpinNoIrq::new(None),
            state: AtomicU8::new(TaskState::Ready as u8),
            #[cfg(feature = "qperf-trace")]
            qperf_block_sequence: AtomicU64::new(0),
            #[cfg(feature = "qperf-trace")]
            qperf_pending_wait_context: SpinNoIrq::new(None),
            // By default, the task is allowed to run on all CPUs.
            cpumask: SpinNoIrq::new(cpumask),
            in_wait_queue: AtomicBool::new(false),
            #[cfg(feature = "irq")]
            timer_ticket_id: AtomicU64::new(0),
            cpu_id: AtomicU32::new(0),
            #[cfg(feature = "smp")]
            switch_state: SpinRaw::new(SwitchState {
                on_cpu: false,
                deferred_wake: None,
            }),
            interrupted: AtomicBool::new(false),
            interrupt_waker: AtomicWaker::new(),
            block_on_waker: SpinNoIrq::new(None),
            #[cfg(feature = "preempt")]
            need_resched: AtomicBool::new(false),
            #[cfg(feature = "preempt")]
            preempt_disable_count: AtomicUsize::new(0),
            exit_code: AtomicI32::new(0),
            wait_for_exit: WaitQueue::new(),
            kstack: SpinNoIrq::new(None),
            ctx: UnsafeCell::new(TaskContext::new()),
            task_ext: AxTaskExt::empty(),
            #[cfg(feature = "tls")]
            tls: TlsArea::alloc(),
        }
    }

    /// Creates an "init task" using the current CPU states, to use as the
    /// current task.
    ///
    /// As it is the current task, no other task can switch to it until it
    /// switches out.
    ///
    /// And there is no need to set the `entry`, `kstack` or `tls` fields, as
    /// they will be filled automatically when the task is switches out.
    pub(crate) fn new_init(name: String) -> Self {
        let mut t = Self::new_common(TaskId::new(), name);
        t.is_init = true;
        #[cfg(feature = "smp")]
        t.claim_on_cpu();
        if *t.name.lock() == "idle" {
            t.is_idle = true;
        }
        #[cfg(feature = "qperf-trace")]
        crate::qperf_trace::task_metadata(t.id().as_u64(), 0, 0, t.name().as_bytes());
        t
    }

    pub fn into_arc(self) -> AxTaskRef {
        let task_ref = Arc::new(AxTask::new(self));
        #[cfg(any(feature = "sched-rr", feature = "sched-eevdf"))]
        if let Some(curr) = crate::current_may_uninit() {
            let prio = curr.as_task_ref().priority();
            let _ = task_ref.set_priority(prio);
            #[cfg(feature = "sched-eevdf")]
            task_ref.set_rt_policy(curr.as_task_ref().rt_policy());
        }
        task_ref
    }

    #[inline]
    pub(crate) fn state(&self) -> TaskState {
        self.state.load(Ordering::Acquire).into()
    }

    #[inline]
    pub(crate) fn set_state(&self, state: TaskState) {
        self.state.store(state as u8, Ordering::Release)
    }

    /// Transition the task state from `current_state` to `new_state`,
    /// Returns `true` if the current state is `current_state` and the state is successfully set to `new_state`,
    /// otherwise returns `false`.
    #[inline]
    pub(crate) fn transition_state(&self, current_state: TaskState, new_state: TaskState) -> bool {
        self.state
            .compare_exchange(
                current_state as u8,
                new_state as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    pub fn is_running(&self) -> bool {
        matches!(self.state(), TaskState::Running)
    }

    #[inline]
    pub fn is_ready(&self) -> bool {
        matches!(self.state(), TaskState::Ready)
    }

    #[inline]
    pub(crate) const fn is_init(&self) -> bool {
        self.is_init
    }

    #[inline]
    pub(crate) const fn is_idle(&self) -> bool {
        self.is_idle
    }

    #[inline]
    pub(crate) fn in_wait_queue(&self) -> bool {
        self.in_wait_queue.load(Ordering::Acquire)
    }

    #[inline]
    pub(crate) fn set_in_wait_queue(&self, in_wait_queue: bool) {
        self.in_wait_queue.store(in_wait_queue, Ordering::Release);
    }

    #[inline]
    pub(crate) fn consume_wait_queue_entry(&self) -> bool {
        self.in_wait_queue
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Returns task's current timer ticket ID.
    #[inline]
    #[cfg(feature = "irq")]
    pub(crate) fn timer_ticket(&self) -> u64 {
        self.timer_ticket_id.load(Ordering::Acquire)
    }

    /// Set the timer ticket ID.
    #[inline]
    #[cfg(feature = "irq")]
    pub(crate) fn set_timer_ticket(&self, timer_ticket_id: u64) {
        // CAN NOT set timer_ticket_id to 0,
        // because 0 is used to indicate the timer event is expired.
        assert!(timer_ticket_id != 0);
        self.timer_ticket_id
            .store(timer_ticket_id, Ordering::Release);
    }

    /// Expire timer ticket ID by setting it to 0,
    /// it can be used to identify one timer event is triggered or expired.
    #[inline]
    #[cfg(feature = "irq")]
    pub(crate) fn timer_ticket_expired(&self) {
        self.timer_ticket_id.store(0, Ordering::Release);
    }

    #[inline]
    #[cfg(feature = "preempt")]
    pub(crate) fn set_preempt_pending(&self, pending: bool) {
        self.need_resched.store(pending, Ordering::Release)
    }

    #[inline]
    #[cfg(feature = "preempt")]
    pub(crate) fn can_preempt(&self, current_disable_count: usize) -> bool {
        self.preempt_disable_count.load(Ordering::Acquire) == current_disable_count
    }

    #[inline]
    #[cfg(feature = "preempt")]
    pub(crate) fn disable_preempt(&self) {
        self.preempt_disable_count.fetch_add(1, Ordering::Release);
    }

    #[inline]
    #[cfg(feature = "preempt")]
    pub(crate) fn enable_preempt(&self, resched: bool) {
        if self.preempt_disable_count.fetch_sub(1, Ordering::Release) == 1 && resched {
            // If current task is pending to be preempted, do rescheduling.
            Self::current_check_preempt_pending();
        }
    }

    #[cfg(feature = "preempt")]
    pub(crate) fn current_check_preempt_pending() {
        use kernel_guard::NoPreemptIrqSave;
        let curr = crate::current();
        if curr.need_resched.load(Ordering::Acquire) && curr.can_preempt(0) {
            // Note: if we want to print log msg during `preempt_resched`, we have to
            // disable preemption here, because the axlog may cause preemption.
            let mut rq = crate::current_run_queue::<NoPreemptIrqSave>();
            if curr.need_resched.load(Ordering::Acquire) {
                rq.preempt_resched()
            }
        }
    }

    /// Notify all tasks that join on this task.
    pub(crate) fn notify_exit(&self, exit_code: i32) {
        self.exit_code.store(exit_code, Ordering::Release);
        self.wait_for_exit.notify_all(false);
    }

    #[inline]
    pub(crate) const unsafe fn ctx_mut_ptr(&self) -> *mut TaskContext {
        self.ctx.get()
    }

    #[inline]
    pub(crate) fn enter_task_ext(&self) {
        self.task_ext.on_enter();
    }

    #[inline]
    pub(crate) fn leave_task_ext(&self) {
        self.task_ext.on_leave();
    }

    /// Set the CPU ID where the task is running or will run.
    #[cfg(feature = "smp")]
    #[inline]
    pub(crate) fn set_cpu_id(&self, cpu_id: u32) {
        self.cpu_id.store(cpu_id, Ordering::Release);
    }

    /// Claims this task for execution after it has been selected by a run queue.
    #[cfg(feature = "smp")]
    #[inline]
    pub(crate) fn claim_on_cpu(&self) {
        let mut state = self.switch_state.lock();
        assert!(!state.on_cpu, "task is already owned by a CPU");
        assert!(
            state.deferred_wake.is_none(),
            "task has an unconsumed deferred wake"
        );
        state.on_cpu = true;
    }

    /// Returns whether a CPU still owns this task's execution context.
    #[cfg(feature = "smp")]
    #[inline]
    pub(crate) fn is_on_cpu(&self) -> bool {
        self.switch_state.lock().on_cpu
    }

    /// Records a wake that raced context switch-out.
    ///
    /// Returns `true` when the owning CPU must enqueue the task after saving its
    /// context, or `false` when the waker can enqueue it immediately. Ownership
    /// of `task` keeps the allocation alive between wait-queue removal and the
    /// deferred run-queue insertion.
    #[cfg(feature = "smp")]
    #[inline]
    pub(crate) fn defer_wake(&self, target_cpu: u32, task: AxTaskRef) -> bool {
        let mut state = self.switch_state.lock();
        if !state.on_cpu {
            return false;
        }
        assert!(
            state.deferred_wake.is_none(),
            "task already has a deferred wake"
        );
        state.deferred_wake = Some((target_cpu, task));
        true
    }

    /// Publishes a fully saved context and consumes a wake deferred to this CPU.
    #[cfg(feature = "smp")]
    #[inline]
    pub(crate) fn finish_switch_out(&self) -> Option<(u32, AxTaskRef)> {
        let mut state = self.switch_state.lock();
        assert!(state.on_cpu, "task is not owned by a CPU");
        state.on_cpu = false;
        state.deferred_wake.take()
    }
}

impl fmt::Debug for TaskInner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TaskInner")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("state", &self.state())
            .finish()
    }
}

impl Drop for TaskInner {
    fn drop(&mut self) {
        debug!("task drop: {}", self.id_name());
    }
}

const TASK_STACK_CACHE_CAPACITY: usize = 8;

struct TaskStackCache {
    starts: [usize; TASK_STACK_CACHE_CAPACITY],
    len: usize,
}

impl TaskStackCache {
    const fn new() -> Self {
        Self {
            starts: [0; TASK_STACK_CACHE_CAPACITY],
            len: 0,
        }
    }

    fn pop(&mut self) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        Some(self.starts[self.len])
    }

    fn push(&mut self, start: usize) -> bool {
        if self.len == TASK_STACK_CACHE_CAPACITY {
            return false;
        }
        self.starts[self.len] = start;
        self.len += 1;
        true
    }
}

static TASK_STACK_CACHES: [SpinNoIrq<TaskStackCache>; axconfig::plat::MAX_CPU_NUM] =
    [const { SpinNoIrq::new(TaskStackCache::new()) }; axconfig::plat::MAX_CPU_NUM];

struct TaskStack {
    start: VirtAddr,
    size: usize,
    num_pages: usize,
    cache_cpu: usize,
}

impl TaskStack {
    pub fn try_alloc(size: usize) -> AxResult<Self> {
        debug!(
            "TaskStack::try_alloc: size={:#x}, used_pages={}, available_pages={}",
            size,
            global_allocator().used_pages(),
            global_allocator().available_pages()
        );
        debug_assert_eq!(size % PAGE_SIZE_4K, 0);
        let num_pages = size / PAGE_SIZE_4K;
        let cache_cpu = this_cpu_id();
        if size == align_up_4k(axconfig::TASK_STACK_SIZE)
            && let Some(start) = TASK_STACK_CACHES[cache_cpu].lock().pop()
        {
            return Ok(Self {
                start: start.into(),
                size,
                num_pages,
                cache_cpu,
            });
        }
        let start = match global_allocator().alloc_pages(num_pages, PAGE_SIZE_4K) {
            Ok(start) => start,
            Err(_) => {
                return Err(AxError::NoMemory);
            }
        };
        Ok(Self {
            start: start.into(),
            size,
            num_pages,
            cache_cpu,
        })
    }

    pub fn top(&self) -> VirtAddr {
        self.start.add(self.size)
    }
}

impl Drop for TaskStack {
    fn drop(&mut self) {
        if self.size == align_up_4k(axconfig::TASK_STACK_SIZE)
            && TASK_STACK_CACHES[self.cache_cpu]
                .lock()
                .push(self.start.as_usize())
        {
            return;
        }
        global_allocator().dealloc_pages(self.start.as_usize(), self.num_pages);
    }
}

use core::mem::ManuallyDrop;

/// A wrapper of [`AxTaskRef`] as the current task.
///
/// It won't change the reference count of the task when created or dropped.
pub struct CurrentTask(ManuallyDrop<AxTaskRef>);

impl CurrentTask {
    pub(crate) fn try_get() -> Option<Self> {
        let ptr: *const super::AxTask = axhal::percpu::current_task_ptr();
        if !ptr.is_null() {
            Some(Self(unsafe { ManuallyDrop::new(AxTaskRef::from_raw(ptr)) }))
        } else {
            None
        }
    }

    pub(crate) fn get() -> Self {
        Self::try_get().expect("current task is uninitialized")
    }

    /// Converts [`CurrentTask`] to [`AxTaskRef`].
    pub fn as_task_ref(&self) -> &AxTaskRef {
        &self.0
    }

    pub(crate) fn clone(&self) -> AxTaskRef {
        self.0.deref().clone()
    }

    pub(crate) fn ptr_eq(&self, other: &AxTaskRef) -> bool {
        Arc::ptr_eq(&self.0, other)
    }

    pub(crate) unsafe fn init_current(init_task: AxTaskRef) {
        assert!(init_task.is_init());
        #[cfg(feature = "tls")]
        axhal::asm::write_thread_pointer(init_task.tls.tls_ptr() as usize);
        let ptr = Arc::into_raw(init_task);
        unsafe {
            axhal::percpu::set_current_task_ptr(ptr);
        }
    }

    pub(crate) unsafe fn set_current(prev: Self, next: AxTaskRef) {
        let Self(arc) = prev;
        ManuallyDrop::into_inner(arc); // `call Arc::drop()` to decrease prev task reference count.
        let ptr = Arc::into_raw(next);
        unsafe {
            axhal::percpu::set_current_task_ptr(ptr);
        }
    }
}

impl Deref for CurrentTask {
    type Target = TaskInner;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

extern "C" fn task_entry() -> ! {
    #[cfg(feature = "smp")]
    unsafe {
        // Clear the prev task on CPU before running the task entry function.
        crate::run_queue::clear_prev_task_on_cpu();
    }
    // Enable irq (if feature "irq" is enabled) before running the task entry function.
    #[cfg(feature = "irq")]
    axhal::asm::enable_irqs();
    let task = crate::current();
    let entry = {
        let mut entry_guard = task.entry.lock();
        entry_guard.take()
    };
    if let Some(entry) = entry {
        entry();
    }
    crate::exit(0);
}
