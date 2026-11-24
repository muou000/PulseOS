use alloc::{sync::Arc, vec::Vec};
use spin::Lazy;

use crate::{current_have_signals, current_process, process_by_pid, processes_snapshot};

#[percpu::def_percpu]
static LAST_TICK_NS: u64 = 0;

static STDIN_POLLING_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(true);
static STDIN_POLL_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static STDIN_POLL_INTERVAL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(20);

/// Timer callbacks run with local IRQs disabled. Keep their handoff to this
/// worker atomic and bounded; all process/queue locks stay in task context.
static TIMER_WORK_WAIT: task::WaitQueue = task::WaitQueue::new();
static TIMER_WORK_PENDING: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static TIMER_PROCESS_WORK_PENDING: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static STDIN_POLL_WORK_PENDING: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static TIMER_WORKER_STARTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// A timer IRQ already knows which process owns the expired timer. Keep a
// bounded PID handoff so the worker normally performs one registry lookup
// instead of sorting and scanning every process. Collisions fall back to a
// complete scan, preserving correctness when the fixed queue is saturated.
const TIMER_PROCESS_PID_SLOTS: usize = 64;
static TIMER_PROCESS_PID_QUEUE: Lazy<[core::sync::atomic::AtomicU64; TIMER_PROCESS_PID_SLOTS]> =
    Lazy::new(|| core::array::from_fn(|_| core::sync::atomic::AtomicU64::new(0)));
static TIMER_PROCESS_PID_OVERFLOW: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub fn set_stdin_polling_enabled(enabled: bool) {
    STDIN_POLLING_ENABLED.store(enabled, core::sync::atomic::Ordering::Relaxed);
}

pub fn is_stdin_polling_enabled() -> bool {
    STDIN_POLLING_ENABLED.load(core::sync::atomic::Ordering::Relaxed)
}

fn enqueue_timer_process(pid: u64) {
    if pid == 0 {
        TIMER_PROCESS_PID_OVERFLOW.store(true, core::sync::atomic::Ordering::Release);
        return;
    }
    let start = pid as usize % TIMER_PROCESS_PID_SLOTS;
    for offset in 0..4 {
        let slot = &TIMER_PROCESS_PID_QUEUE[(start + offset) % TIMER_PROCESS_PID_SLOTS];
        let current = slot.load(core::sync::atomic::Ordering::Acquire);
        if current == pid {
            return;
        }
        if current == 0
            && slot
                .compare_exchange(
                    0,
                    pid,
                    core::sync::atomic::Ordering::AcqRel,
                    core::sync::atomic::Ordering::Acquire,
                )
                .is_ok()
        {
            return;
        }
    }
    TIMER_PROCESS_PID_OVERFLOW.store(true, core::sync::atomic::Ordering::Release);
}

fn request_timer_work(process_work: bool, process_pid: Option<u64>) {
    if process_work {
        if let Some(pid) = process_pid {
            enqueue_timer_process(pid);
        } else {
            TIMER_PROCESS_PID_OVERFLOW.store(true, core::sync::atomic::Ordering::Release);
        }
        TIMER_PROCESS_WORK_PENDING.store(true, core::sync::atomic::Ordering::Release);
    }
    if !TIMER_WORK_PENDING.swap(true, core::sync::atomic::Ordering::AcqRel) {
        TIMER_WORK_WAIT.notify_one(false);
    }
}

fn drain_timer_process_work() {
    let mut pids = Vec::new();
    for slot in TIMER_PROCESS_PID_QUEUE.iter() {
        let pid = slot.swap(0, core::sync::atomic::Ordering::AcqRel);
        if pid != 0 {
            pids.push(pid);
        }
    }

    if TIMER_PROCESS_PID_OVERFLOW.swap(false, core::sync::atomic::Ordering::AcqRel) {
        for process in processes_snapshot() {
            process.drain_deferred_timer_work();
        }
        return;
    }

    for pid in pids {
        if let Some(process) = process_by_pid(pid) {
            process.drain_deferred_timer_work();
        }
    }
}

fn timer_work_loop() {
    loop {
        TIMER_WORK_WAIT
            .wait_until(|| TIMER_WORK_PENDING.swap(false, core::sync::atomic::Ordering::AcqRel));

        loop {
            if STDIN_POLL_WORK_PENDING.swap(false, core::sync::atomic::Ordering::AcqRel) {
                crate::fd::poll_stdin();
                let interval = if crate::fd::STDIN_WAIT_QUEUE.is_empty() {
                    20
                } else {
                    5
                };
                STDIN_POLL_INTERVAL.store(interval, core::sync::atomic::Ordering::Relaxed);
            }
            if TIMER_PROCESS_WORK_PENDING.swap(false, core::sync::atomic::Ordering::AcqRel) {
                drain_timer_process_work();
            }
            if !TIMER_WORK_PENDING.swap(false, core::sync::atomic::Ordering::AcqRel) {
                break;
            }
        }
    }
}

fn start_timer_worker() {
    // Initialize the fixed handoff before the first timer IRQ can touch it.
    let _ = Lazy::force(&TIMER_PROCESS_PID_QUEUE);
    if TIMER_WORKER_STARTED
        .compare_exchange(
            false,
            true,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }
    task::spawn_raw(
        timer_work_loop,
        "pulse_timer_work".into(),
        config::TASK_STACK_SIZE,
    );
}

fn itimer_tick_hook() {
    let now_ns = hal::time::monotonic_time_nanos() as u64;
    let last_ns = LAST_TICK_NS.read_current();
    LAST_TICK_NS.write_current(now_ns);
    let elapsed_ns = if last_ns == 0 {
        0
    } else {
        now_ns.saturating_sub(last_ns)
    };

    let mut stdin_work = false;
    if is_stdin_polling_enabled() {
        let count = STDIN_POLL_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let poll_interval = STDIN_POLL_INTERVAL.load(core::sync::atomic::Ordering::Relaxed);
        if count % poll_interval == 0 {
            STDIN_POLL_WORK_PENDING.store(true, core::sync::atomic::Ordering::Release);
            stdin_work = true;
        }
    }

    let mut process_work = false;
    let mut process_pid = None;
    if elapsed_ns > 0 {
        if let Ok(curr) = current_process() {
            process_pid = Some(curr.pid());
            process_work |= curr.check_itimer_virt_tick(elapsed_ns);
            process_work |= curr.check_itimer_prof_tick(elapsed_ns);
        }
    }
    if process_work || stdin_work {
        request_timer_work(process_work, process_pid);
    }
}

pub fn schedule_itimer_event(pid: u64, deadline: u64) {
    let Some(process) = process_by_pid(pid) else {
        return;
    };
    let process = Arc::downgrade(&process);
    task::set_generic_timer(
        deadline,
        alloc::boxed::Box::new(move |_now| {
            if let Some(proc) = process.upgrade()
                && proc.mark_itimer_real_expired_from_irq(deadline)
            {
                request_timer_work(true, Some(proc.pid()));
            }
        }),
    );
}

pub fn schedule_posix_timer_event(pid: u64, timer_id: usize, deadline: u64, generation: u64) {
    let Some(process) = process_by_pid(pid) else {
        return;
    };
    let process = Arc::downgrade(&process);
    task::set_generic_timer(
        deadline,
        alloc::boxed::Box::new(move |_now| {
            if let Some(proc) = process.upgrade()
                && proc.mark_posix_timer_expired_from_irq(timer_id, deadline, generation)
            {
                request_timer_work(true, Some(proc.pid()));
            }
        }),
    );
}

pub fn adjust_absolute_timers() {
    let procs = processes_snapshot();
    let new_offset = hal::time::current_epochoffset_nanos();
    for proc in procs {
        if proc.is_zombie() {
            continue;
        }
        let mut to_schedule = Vec::new();
        {
            let mut timers = proc.posix_timers.lock();
            for timer_opt in timers.iter_mut() {
                if let Some(timer) = timer_opt {
                    if timer.clock_id == 0
                        && timer.is_absolute
                        && !timer.first_expired
                        && timer.next_deadline_ns > 0
                    {
                        let sec = timer.itimer_spec.it_value.tv_sec as u64;
                        let nsec = timer.itimer_spec.it_value.tv_nsec as u64;
                        if let Some(req_ns) = sec
                            .checked_mul(1_000_000_000)
                            .and_then(|s| s.checked_add(nsec))
                        {
                            let new_deadline = req_ns.saturating_sub(new_offset);
                            timer.next_deadline_ns = new_deadline;
                            to_schedule.push((timer.id, new_deadline, timer.generation));
                        }
                    }
                }
            }
        }
        for (timer_id, new_deadline, generation) in to_schedule {
            schedule_posix_timer_event(proc.pid(), timer_id, new_deadline, generation);
        }
    }
}

/// Register the itimer tick hook with task. Should be called once during
/// process initialization.
pub fn init_itimer_hook() {
    start_timer_worker();
    task::register_timer_hook(itimer_tick_hook);
    axnet::register_have_signals_callback(current_have_signals);
}
