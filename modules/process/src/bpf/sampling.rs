//! Bounded timer-IRQ snapshots and deferred BPF execution.
//!
//! The IRQ observer freezes bounded FP addresses into a preallocated queue. It never
//! invokes a BPF program, retains a trap-frame/task reference, allocates, or
//! waits for a lock. The worker removes a snapshot before executing its program.

/// Snapshot-handoff statistics, separate from VM execution and transport loss.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SamplingQueueStats {
    /// Snapshots successfully put in a queue.
    pub enqueued: u64,
    /// Snapshots removed by the worker before per-event eligibility checks.
    pub dequeued: u64,
    /// New snapshots rejected because the shared queue was full.
    pub full: u64,
    /// New snapshots rejected because the queue or task-clock state was busy.
    pub busy: u64,
}

#[cfg(target_os = "none")]
mod runtime {
    use core::{
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
        time::Duration,
    };

    use hal::{
        context::TrapFrame,
        trap::{IRQ_OBSERVER, register_trap_handler},
    };
    use spin::Mutex;

    use bpf::{
        perf_event::{
            RuntimeSample, dispatch_runtime_sample, has_active_perf_events, observation_generation,
        },
        sampling::SampleQueue,
    };

    use super::SamplingQueueStats;

    const DRAIN_PER_ROUND: usize = SampleQueue::CAPACITY;

    struct CpuStats {
        enqueued: AtomicU64,
        dequeued: AtomicU64,
        full: AtomicU64,
        busy: AtomicU64,
    }

    impl CpuStats {
        const fn new() -> Self {
            Self {
                enqueued: AtomicU64::new(0),
                dequeued: AtomicU64::new(0),
                full: AtomicU64::new(0),
                busy: AtomicU64::new(0),
            }
        }

        fn stats(&self) -> SamplingQueueStats {
            SamplingQueueStats {
                enqueued: self.enqueued.load(Ordering::Relaxed),
                dequeued: self.dequeued.load(Ordering::Relaxed),
                full: self.full.load(Ordering::Relaxed),
                busy: self.busy.load(Ordering::Relaxed),
            }
        }
    }

    static CPU_STATS: [CpuStats; config::plat::MAX_CPU_NUM] =
        [const { CpuStats::new() }; config::plat::MAX_CPU_NUM];
    static SNAPSHOTS: Mutex<SampleQueue> = Mutex::new(SampleQueue::new());
    static WORKER_STARTED: AtomicBool = AtomicBool::new(false);

    #[cfg(target_arch = "riscv64")]
    fn is_timer_irq(vector: usize) -> bool {
        vector == ((1usize << (usize::BITS - 1)) | 5)
    }

    #[cfg(target_arch = "loongarch64")]
    fn is_timer_irq(vector: usize) -> bool {
        vector == 11
    }

    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
    #[register_trap_handler(IRQ_OBSERVER)]
    fn observe_timer_irq(vector: usize, tf: &TrapFrame, from_user: bool) {
        if !is_timer_irq(vector)
            || !WORKER_STARTED.load(Ordering::Acquire)
            || !has_active_perf_events()
            || hal::asm::irqs_enabled()
        {
            return;
        }

        // RV64/LA64 trap entry disables IRQs before calling this observer. This
        // path neither enables IRQs nor calls anything that schedules. Avoid a
        // NoPreempt guard here: its Drop could reschedule before the normal IRQ
        // handler has acknowledged/reprogrammed the timer. Only scalar copies
        // bounded no-fault frame reads and nonblocking atomics/try_lock calls
        // occur before all borrows end.
        let generation = observation_generation();
        let timestamp_ns = hal::time::monotonic_time_nanos();
        let cpu = hal::percpu::this_cpu_id();
        let Some(stats) = CPU_STATS.get(cpu) else {
            return;
        };
        let Some(task) = task::current_may_uninit() else {
            return;
        };
        let (pid, tid, task_clock_ns) = match crate::thread_ref_from_task(&task) {
            Ok(thread) => {
                let Some(clock_ns) = thread.sampling_clock_ns(timestamp_ns) else {
                    stats.busy.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                (thread.sampling_pid(), thread.tid(), clock_ns)
            }
            // Kernel tasks have no userspace PID/TID. CPU-clock observations
            // still retain their own task identity; task-clock scope won't match.
            Err(_) => (0, 0, 0),
        };
        let sample = RuntimeSample {
            timestamp_ns,
            cpu,
            pid,
            tid,
            task_id: task.id().as_u64(),
            ip: tf.ip() as u64,
            // SAFETY: IRQ_OBSERVER supplies the live architecture trap frame
            // and privilege bit. `task` was borrowed from this CPU's current
            // task above. IRQs remain disabled, no scheduling path is invoked,
            // and the user page-table root still belongs to that task. The
            // scheduler never runs one task concurrently on multiple CPUs.
            stack: unsafe { crate::bpf::stack_capture::freeze(tf, from_user, &task) },
            user_mode: from_user,
            task_clock_ns,
            generation,
        };

        // This callback finishes publication (or records a drop) before the
        // interrupted task can be rescheduled or migrate. Thus successful
        // snapshots from that task, including across different CPUs, enter one
        // FIFO in task-clock order. A single CPU's observers also cannot overlap
        // because IRQs stay disabled here. There is no promise of timestamp
        // ordering between independent CPUs/tasks. Using separate CPU queues
        // then draining by CPU number would break the task-clock ordering.
        let Some(mut queue) = SNAPSHOTS.try_lock() else {
            stats.busy.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if queue.push(sample) {
            stats.enqueued.fetch_add(1, Ordering::Relaxed);
        } else {
            stats.full.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn drain_once() {
        // Copy contexts while task holds its short drain guard, then release
        // that guard before any interpreter allocation, helper or notification.
        let mut records = [pulse_bpf_schema::EventRecord::empty(); 16];
        for cpu in 0..CPU_STATS.len() {
            let count = task::bpf_trace::drain_cpu_records(cpu, &mut records);
            for record in &records[..count] {
                bpf::perf_event::dispatch_tracepoint(
                    record.id, record.as_bytes(), record.generation,
                );
            }
        }
        for _ in 0..DRAIN_PER_ROUND {
            let sample = {
                let Some(mut queue) = SNAPSHOTS.try_lock() else {
                    break;
                };
                queue.pop()
            };
            let Some(sample) = sample else {
                break;
            };
            CPU_STATS[sample.cpu].dequeued.fetch_add(1, Ordering::Relaxed);
            // The queue lock is released before allocation or BPF execution.
            // Runtime checks each event's activation generation and accounts
            // cancellations; an unrelated control change cannot discard it.
            let _ = dispatch_runtime_sample(&sample);
        }
    }

    fn worker() {
        loop {
            drain_once();
            task::sleep(Duration::from_millis(1));
        }
    }

    /// Starts the deferred sampler after the task scheduler is initialized.
    /// Repeated calls are harmless; sampling remains gated by active events.
    pub fn init() {
        if WORKER_STARTED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        task::spawn_raw(worker, "pulse_bpf_sample".into(), config::TASK_STACK_SIZE);
    }

    /// Returns independently sampled monotonic totals. This is not an atomic
    /// view of all CPUs; consumers should compare snapshots over a session.
    pub fn stats_snapshot() -> SamplingQueueStats {
        let mut total = SamplingQueueStats::default();
        for cpu in &CPU_STATS {
            let stats = cpu.stats();
            total.enqueued = total.enqueued.saturating_add(stats.enqueued);
            total.dequeued = total.dequeued.saturating_add(stats.dequeued);
            total.full = total.full.saturating_add(stats.full);
            total.busy = total.busy.saturating_add(stats.busy);
        }
        total
    }
}

#[cfg(target_os = "none")]
pub use runtime::{init, stats_snapshot};
