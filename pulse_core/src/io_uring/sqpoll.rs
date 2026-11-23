//! Per-ring SQ consumer, shared-memory sleep handshake and SQ space waiters.

use alloc::sync::{Arc, Weak};
use core::{
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
    time::Duration,
};

use axerrno::{LinuxError, LinuxResult};
use axhal::time::monotonic_time;
use axtask::{AxCpuMask, AxTaskWeak, TaskInner, WaitQueue};
use kspin::SpinNoIrq;
use linux_raw_sys::io_uring::{IORING_SETUP_SQ_AFF, io_uring_params};

use super::{AsyncExecContext, IoUringState};
use crate::task::{current_have_signals, current_thread};

pub(super) struct SqPoll {
    owner_pid: u64,
    stopping: AtomicBool,
    // Wait predicates must see the consumer's head without acquiring its sleeping submit lock.
    consumed_head: AtomicU32,
    kicks: AtomicU32,
    work: WaitQueue,
    space: WaitQueue,
    task: SpinNoIrq<AxTaskWeak>,
}

impl SqPoll {
    pub(super) fn new(owner_pid: u64) -> Self {
        Self {
            owner_pid,
            stopping: AtomicBool::new(false),
            consumed_head: AtomicU32::new(0),
            kicks: AtomicU32::new(0),
            work: WaitQueue::new(),
            space: WaitQueue::new(),
            task: SpinNoIrq::new(Weak::new()),
        }
    }
}

impl IoUringState {
    pub(super) fn start_sqpoll(
        self: &Arc<Self>,
        params: &io_uring_params,
        owner: AsyncExecContext,
    ) -> LinuxResult<()> {
        let poll = self.sqpoll.as_ref().expect("SQPOLL state");
        let allowed = axtask::current().cpumask();
        let cpu =
            (params.flags & IORING_SETUP_SQ_AFF != 0).then_some(params.sq_thread_cpu as usize);
        if let Some(cpu) = cpu
            && (cpu >= axhal::cpu_num() || !axhal::is_cpu_online(cpu) || !allowed.get(cpu))
        {
            return Err(LinuxError::EINVAL);
        }
        let idle = match params.sq_thread_idle {
            0 => Duration::from_secs(1),
            ms => Duration::from_millis(u64::from(ms)),
        };
        let state = self.clone();
        let task = TaskInner::try_new(
            move || state.poll_sq(owner, idle, cpu),
            alloc::format!("iou-sqp-{}", poll.owner_pid),
            axconfig::TASK_STACK_SIZE,
        )?;
        if let Some(cpu) = cpu {
            task.set_cpumask(AxCpuMask::one_shot(cpu));
        }
        let task = task.into_arc();
        *poll.task.lock() = Arc::downgrade(&task);
        axtask::spawn_task_ref(task);
        Ok(())
    }

    fn poll_sq(
        self: Arc<Self>,
        owner: AsyncExecContext,
        idle: Duration,
        mut report_cpu: Option<usize>,
    ) {
        let poll = self.sqpoll.as_ref().expect("SQPOLL state");
        let mut head = 0;
        let mut deadline = monotonic_time() + idle;
        while !poll.stopping.load(Ordering::Acquire) {
            if self.shared.sq_pending(head) != 0 {
                if let Some(cpu) = report_cpu.take() {
                    axlog::info!(
                        "SQPOLL affinity requested={} running={}",
                        cpu,
                        axhal::percpu::this_cpu_id()
                    );
                }
                self.submit_sqes(self.shared.layout().sq_entries, &owner);
                head = self.submit_lock.lock().sq.kernel_sq_head();
                poll.consumed_head.store(head, Ordering::Release);
                poll.space.notify_all(false);
                deadline = monotonic_time() + idle;
            } else if monotonic_time() >= deadline {
                let kicks = poll.kicks.load(Ordering::Acquire);
                self.shared.set_sq_need_wakeup();
                poll.work.wait_until(|| {
                    poll.stopping.load(Ordering::Acquire)
                        || self.shared.sq_pending(head) != 0
                        || poll.kicks.load(Ordering::Acquire) != kicks
                });
                self.shared.clear_sq_need_wakeup();
                deadline = monotonic_time() + idle;
            }
            axtask::yield_now();
        }
        // An inherited mapping must direct its next publisher to enter, which reports
        // EOWNERDEAD once the owner's poller has exited.
        self.shared.set_sq_need_wakeup();
        axlog::debug!(
            "SQPOLL stopped ring={} owner={}",
            self.ring_id,
            poll.owner_pid
        );
    }

    pub fn is_sqpoll(&self) -> bool {
        self.sqpoll.is_some()
    }

    pub fn sqpoll_stopped(&self) -> bool {
        self.sqpoll
            .as_ref()
            .is_some_and(|p| p.stopping.load(Ordering::Acquire))
    }

    pub fn sqpoll_enter(&self, wakeup: bool, wait: bool) -> LinuxResult<()> {
        let poll = self.sqpoll.as_ref().expect("SQPOLL enter");
        if wakeup {
            poll.kicks.fetch_add(1, Ordering::Release);
            poll.work.notify_one(true);
        }
        let has_space = || {
            self.shared
                .sq_pending(poll.consumed_head.load(Ordering::Acquire))
                < self.shared.layout().sq_entries
        };
        if wait && !has_space() {
            let thread = current_thread()?;
            let queues = [&poll.space, thread.signal_wait_queue()];
            let ready = || self.sqpoll_stopped() || has_space() || current_have_signals();
            while !ready() {
                let _ = WaitQueue::wait_multiple_timeout_until(&queues, None, ready);
            }
            // Linux also finishes SQ_WAIT on a pending signal and returns to_submit.
        }
        if self.sqpoll_stopped() {
            return Err(LinuxError::EOWNERDEAD);
        }
        Ok(())
    }

    pub(super) fn stop_sqpoll_for_owner(&self, pid: u64) {
        if self.sqpoll.as_ref().is_some_and(|p| p.owner_pid == pid) {
            self.stop_sqpoll();
        }
    }

    pub(super) fn stop_sqpoll(&self) {
        if let Some(poll) = &self.sqpoll {
            poll.stopping.store(true, Ordering::Release);
            poll.work.notify_one(true);
            poll.space.notify_all(true);
            self.cq_wait_queue.notify_all(true);
            let task = poll.task.lock().upgrade();
            if let Some(task) = task {
                task.join();
            }
        }
    }
}
