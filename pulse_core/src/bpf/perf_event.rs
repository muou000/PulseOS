//! Perf Event core model, metadata and accounting lifecycle (#97).
//!
//! This file is the pure part of the PerfEvent subsystem: it only depends on
//! `core`, `alloc`, `spin` and `axerrno`, so `pulse_syscalls` host tests can compile
//! it directly. Descriptor wrapping (`PerfEventObject: FdObject`) lives in `object.rs`.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use axerrno::LinuxError;
use pulse_bpf_schema::{PerfEventContext, TracepointId};

#[cfg(target_os = "none")]
use super::{
    interpreter::BpfVmError,
    program::{BpfProgType, BpfProgram},
};

#[cfg(not(target_os = "none"))]
use super::{
    core_interpreter::BpfVmError,
    core_program::{BpfProgType, BpfProgram},
};

pub const PERF_EVENT_IOC_ENABLE: u32 = 0x2400;
pub const PERF_EVENT_IOC_DISABLE: u32 = 0x2401;
pub const PERF_EVENT_IOC_REFRESH: u32 = 0x2402;
pub const PERF_EVENT_IOC_RESET: u32 = 0x2403;
pub const PERF_EVENT_IOC_PERIOD: u32 = 0x40082404;
pub const PERF_EVENT_IOC_SET_BPF: u32 = 0x40042408;

pub const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;
pub const PERF_COUNT_SW_TASK_CLOCK: u64 = 1;

pub const PERF_TYPE_SOFTWARE: u32 = 1;
pub const PERF_TYPE_TRACEPOINT: u32 = 2;

pub const BPF_MAX_SAMPLING_CPUS: usize = 64;
static IN_SAMPLING_CPU: [AtomicBool; BPF_MAX_SAMPLING_CPUS] =
    [const { AtomicBool::new(false) }; BPF_MAX_SAMPLING_CPUS];

pub use pulse_bpf_schema::PerfEventSampleCounters;

pub struct SessionSampleCounters {
    pub delivered_samples: AtomicU64,
    pub re_entry_drops: AtomicU64,
    pub helper_failures: AtomicU64,
    pub budget_failures: AtomicU64,
}

static SESSION_SAMPLE_COUNTERS: SessionSampleCounters = SessionSampleCounters {
    delivered_samples: AtomicU64::new(0),
    re_entry_drops: AtomicU64::new(0),
    helper_failures: AtomicU64::new(0),
    budget_failures: AtomicU64::new(0),
};

static ACTIVE_PERF_EVENTS: spin::Mutex<Vec<Weak<PerfEvent>>> = spin::Mutex::new(Vec::new());
static ACTIVE_PERF_EVENT_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn total_perf_event_sample_counters() -> PerfEventSampleCounters {
    PerfEventSampleCounters {
        delivered_samples: SESSION_SAMPLE_COUNTERS.delivered_samples.load(Ordering::Relaxed),
        re_entry_drops: SESSION_SAMPLE_COUNTERS.re_entry_drops.load(Ordering::Relaxed),
        helper_failures: SESSION_SAMPLE_COUNTERS.helper_failures.load(Ordering::Relaxed),
        budget_failures: SESSION_SAMPLE_COUNTERS.budget_failures.load(Ordering::Relaxed),
    }
}

pub fn reset_total_perf_event_sample_counters() {
    SESSION_SAMPLE_COUNTERS.delivered_samples.store(0, Ordering::Relaxed);
    SESSION_SAMPLE_COUNTERS.re_entry_drops.store(0, Ordering::Relaxed);
    SESSION_SAMPLE_COUNTERS.helper_failures.store(0, Ordering::Relaxed);
    SESSION_SAMPLE_COUNTERS.budget_failures.store(0, Ordering::Relaxed);
}

pub fn register_active_perf_event(event: &Arc<PerfEvent>) {
    let mut list = ACTIVE_PERF_EVENTS.lock();
    list.retain(|w| w.upgrade().is_some());
    list.push(Arc::downgrade(event));
    ACTIVE_PERF_EVENT_COUNT.store(list.len(), Ordering::Release);
}

pub fn unregister_active_perf_event(event: &Arc<PerfEvent>) {
    let mut list = ACTIVE_PERF_EVENTS.lock();
    list.retain(|w| {
        if let Some(e) = w.upgrade() {
            !Arc::ptr_eq(&e, event)
        } else {
            false
        }
    });
    ACTIVE_PERF_EVENT_COUNT.store(list.len(), Ordering::Release);
}

pub fn perf_event_tick(now_ns: u64, cpu: usize, pid: u64, tid: u64, task_id: u64) {
    if ACTIVE_PERF_EVENT_COUNT.load(Ordering::Relaxed) == 0 {
        return;
    }
    let mut list = ACTIVE_PERF_EVENTS.lock();
    list.retain(|weak| {
        if let Some(event) = weak.upgrade() {
            let matches_scope = match event.spec.scope {
                PerfEventScope::PerCpu { cpu: target_cpu } => target_cpu == cpu,
                PerfEventScope::Task { pid: target_pid } => target_pid == pid,
            };
            if matches_scope {
                let _ = event.advance_and_maybe_sample(now_ns, cpu, pid, tid, task_id);
            }
            true
        } else {
            false
        }
    });
    ACTIVE_PERF_EVENT_COUNT.store(list.len(), Ordering::Release);
}

#[doc(hidden)]
pub fn set_in_sampling_for_test(cpu: usize, val: bool) {
    if cpu < BPF_MAX_SAMPLING_CPUS {
        IN_SAMPLING_CPU[cpu].store(val, Ordering::Relaxed);
    }
}

#[doc(hidden)]
pub fn is_in_sampling(cpu: usize) -> bool {
    if cpu < BPF_MAX_SAMPLING_CPUS {
        IN_SAMPLING_CPU[cpu].load(Ordering::Relaxed)
    } else {
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerfEventClock {
    CpuClock,
    TaskClock,
    Tracepoint(TracepointId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerfEventScope {
    PerCpu { cpu: usize },
    Task { pid: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerfEventSpec {
    pub clock: PerfEventClock,
    pub scope: PerfEventScope,
    pub sample_period: u64,
    pub disabled: bool,
    pub cloexec: bool,
}

struct PerfEventState {
    enabled: bool,
    accumulated_ns: u64,
    last_enabled_ns: u64,
    sample_period: u64,
    period_accumulated_ns: u64,
    last_sample_ns: u64,
    attached_prog: Option<Arc<BpfProgram>>,
}

pub struct PerfEvent {
    spec: PerfEventSpec,
    state: spin::Mutex<PerfEventState>,
    delivered_samples: AtomicU64,
    re_entry_drops: AtomicU64,
    helper_failures: AtomicU64,
    budget_failures: AtomicU64,
}

impl PerfEvent {
    pub fn new(spec: PerfEventSpec, now_ns: u64) -> Self {
        let enabled = !spec.disabled;
        let last_enabled_ns = if enabled { now_ns } else { 0 };
        Self {
            spec,
            state: spin::Mutex::new(PerfEventState {
                enabled,
                accumulated_ns: 0,
                last_enabled_ns,
                sample_period: spec.sample_period,
                period_accumulated_ns: 0,
                last_sample_ns: now_ns,
                attached_prog: None,
            }),
            delivered_samples: AtomicU64::new(0),
            re_entry_drops: AtomicU64::new(0),
            helper_failures: AtomicU64::new(0),
            budget_failures: AtomicU64::new(0),
        }
    }

    pub fn spec(&self) -> &PerfEventSpec {
        &self.spec
    }

    pub fn is_enabled(&self) -> bool {
        self.state.lock().enabled
    }

    pub fn sample_period(&self) -> u64 {
        self.state.lock().sample_period
    }

    pub fn sample_counters(&self) -> PerfEventSampleCounters {
        PerfEventSampleCounters {
            delivered_samples: self.delivered_samples.load(Ordering::Relaxed),
            re_entry_drops: self.re_entry_drops.load(Ordering::Relaxed),
            helper_failures: self.helper_failures.load(Ordering::Relaxed),
            budget_failures: self.budget_failures.load(Ordering::Relaxed),
        }
    }

    pub fn reset_sample_counters(&self) {
        self.delivered_samples.store(0, Ordering::Relaxed);
        self.re_entry_drops.store(0, Ordering::Relaxed);
        self.helper_failures.store(0, Ordering::Relaxed);
        self.budget_failures.store(0, Ordering::Relaxed);
    }

    pub fn enable_at(&self, now_ns: u64) {
        let mut state = self.state.lock();
        if !state.enabled {
            state.enabled = true;
            state.last_enabled_ns = now_ns;
            state.last_sample_ns = now_ns;
            state.period_accumulated_ns = 0;
        }
    }

    pub fn disable_at(&self, now_ns: u64) {
        let mut state = self.state.lock();
        if state.enabled {
            let elapsed = now_ns.saturating_sub(state.last_enabled_ns);
            state.accumulated_ns = state.accumulated_ns.saturating_add(elapsed);
            state.enabled = false;
        }
    }

    pub fn reset_at(&self, now_ns: u64) {
        let mut state = self.state.lock();
        state.accumulated_ns = 0;
        state.last_enabled_ns = now_ns;
        state.last_sample_ns = now_ns;
        state.period_accumulated_ns = 0;
    }

    pub fn set_period(&self, period: u64) {
        let mut state = self.state.lock();
        state.sample_period = period;
        state.period_accumulated_ns = 0;
    }

    pub fn sample_at(
        &self,
        now_ns: u64,
        cpu: usize,
        pid: u64,
        tid: u64,
        task_id: u64,
    ) -> Result<bool, LinuxError> {
        let (enabled, attached_prog, period) = {
            let state = self.state.lock();
            (state.enabled, state.attached_prog.clone(), state.sample_period)
        };

        if !enabled {
            return Ok(false);
        }

        let Some(prog) = attached_prog else {
            return Ok(false);
        };

        if cpu >= BPF_MAX_SAMPLING_CPUS {
            return Ok(false);
        }

        let cpu_idx = cpu;
        if IN_SAMPLING_CPU[cpu_idx]
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            self.re_entry_drops.fetch_add(1, Ordering::Relaxed);
            prog.record_re_entry_drop();
            SESSION_SAMPLE_COUNTERS.re_entry_drops.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        struct SamplingGuard(usize);
        impl Drop for SamplingGuard {
            fn drop(&mut self) {
                IN_SAMPLING_CPU[self.0].store(false, Ordering::Release);
            }
        }
        let _guard = SamplingGuard(cpu_idx);

        let ctx = PerfEventContext::new(
            period,
            0,
            now_ns,
            cpu as u32,
            pid as u32,
            tid as u32,
            task_id,
        );

        match prog.run(ctx.as_bytes()) {
            Ok(_) => {
                self.delivered_samples.fetch_add(1, Ordering::Relaxed);
                prog.record_sample_delivered();
                SESSION_SAMPLE_COUNTERS.delivered_samples.fetch_add(1, Ordering::Relaxed);
                Ok(true)
            }
            Err(BpfVmError::StepLimitExceeded) => {
                self.budget_failures.fetch_add(1, Ordering::Relaxed);
                prog.record_budget_failure();
                SESSION_SAMPLE_COUNTERS.budget_failures.fetch_add(1, Ordering::Relaxed);
                Ok(false)
            }
            Err(BpfVmError::RecursionLimitExceeded) => {
                self.re_entry_drops.fetch_add(1, Ordering::Relaxed);
                prog.record_re_entry_drop();
                SESSION_SAMPLE_COUNTERS.re_entry_drops.fetch_add(1, Ordering::Relaxed);
                Ok(false)
            }
            Err(BpfVmError::HelperFailed(_)) | Err(BpfVmError::InvalidHelperCall(_)) => {
                self.helper_failures.fetch_add(1, Ordering::Relaxed);
                prog.record_helper_failure();
                SESSION_SAMPLE_COUNTERS.helper_failures.fetch_add(1, Ordering::Relaxed);
                Ok(false)
            }
            Err(_) => {
                // Other runtime VM errors are not helper/budget/reentrancy failures
                Ok(false)
            }
        }
    }

    pub fn advance_and_maybe_sample(
        &self,
        now_ns: u64,
        cpu: usize,
        pid: u64,
        tid: u64,
        task_id: u64,
    ) -> Result<usize, LinuxError> {
        let (should_sample, sample_count) = {
            let mut state = self.state.lock();
            if !state.enabled || state.sample_period == 0 {
                return Ok(0);
            }
            let elapsed = now_ns.saturating_sub(state.last_sample_ns);
            state.last_sample_ns = now_ns;
            state.period_accumulated_ns = state.period_accumulated_ns.saturating_add(elapsed);
            if state.period_accumulated_ns >= state.sample_period {
                let count = state.period_accumulated_ns / state.sample_period;
                state.period_accumulated_ns %= state.sample_period;
                (true, count)
            } else {
                (false, 0)
            }
        };

        if should_sample {
            let mut delivered = 0;
            for _ in 0..sample_count {
                if self.sample_at(now_ns, cpu, pid, tid, task_id)? {
                    delivered += 1;
                }
            }
            Ok(delivered)
        } else {
            Ok(0)
        }
    }

    pub fn read_counter_at(&self, now_ns: u64) -> u64 {
        let state = self.state.lock();
        if state.enabled {
            let elapsed = now_ns.saturating_sub(state.last_enabled_ns);
            state.accumulated_ns.saturating_add(elapsed)
        } else {
            state.accumulated_ns
        }
    }

    pub fn read_into_at(&self, buf: &mut [u8], now_ns: u64) -> Result<usize, LinuxError> {
        if buf.len() < 8 {
            return Err(LinuxError::EINVAL);
        }
        let val = self.read_counter_at(now_ns);
        buf[..8].copy_from_slice(&val.to_ne_bytes());
        Ok(8)
    }

    pub fn ioctl_at(&self, cmd: u32, arg: usize, now_ns: u64) -> Result<isize, LinuxError> {
        match cmd {
            PERF_EVENT_IOC_ENABLE => {
                self.enable_at(now_ns);
                Ok(0)
            }
            PERF_EVENT_IOC_DISABLE => {
                self.disable_at(now_ns);
                Ok(0)
            }
            PERF_EVENT_IOC_RESET => {
                self.reset_at(now_ns);
                Ok(0)
            }
            PERF_EVENT_IOC_REFRESH => {
                self.enable_at(now_ns);
                Ok(0)
            }
            PERF_EVENT_IOC_PERIOD => {
                self.set_period(arg as u64);
                Ok(0)
            }
            _ => Err(LinuxError::ENOTTY),
        }
    }
}

static TRACEPOINT_SUBSCRIBER_COUNTS: [AtomicUsize; 32] = [
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
    const { AtomicUsize::new(0) },
];

fn register_tracepoint_probe(tp_id: pulse_bpf_schema::TracepointId) {
    let idx = tp_id as usize;
    if idx < TRACEPOINT_SUBSCRIBER_COUNTS.len() {
        if TRACEPOINT_SUBSCRIBER_COUNTS[idx].fetch_add(1, Ordering::SeqCst) == 0 {
            #[cfg(all(target_os = "none", feature = "bpf-trace"))]
            axtask::bpf_trace::register_probe(tp_id);
        }
    }
}

fn unregister_tracepoint_probe(tp_id: pulse_bpf_schema::TracepointId) {
    let idx = tp_id as usize;
    if idx < TRACEPOINT_SUBSCRIBER_COUNTS.len() {
        if TRACEPOINT_SUBSCRIBER_COUNTS[idx].fetch_sub(1, Ordering::SeqCst) == 1 {
            #[cfg(all(target_os = "none", feature = "bpf-trace"))]
            axtask::bpf_trace::unregister_probe(tp_id);
        }
    }
}

impl PerfEvent {
    pub fn attach_program(&self, prog: Arc<BpfProgram>) -> Result<(), LinuxError> {
        let mut state = self.state.lock();
        if state.attached_prog.is_some() {
            return Err(LinuxError::EBUSY);
        }
        match self.spec.clock {
            PerfEventClock::CpuClock | PerfEventClock::TaskClock => {
                if prog.prog_type() != BpfProgType::PerfEvent {
                    return Err(LinuxError::EINVAL);
                }
            }
            PerfEventClock::Tracepoint(_) => {
                if prog.prog_type() != BpfProgType::Tracepoint {
                    return Err(LinuxError::EINVAL);
                }
            }
        }
        state.attached_prog = Some(prog);
        if let PerfEventClock::Tracepoint(tp_id) = self.spec.clock {
            register_tracepoint_probe(tp_id);
        }
        Ok(())
    }

    pub fn detach_program(&self, prog: &Arc<BpfProgram>) -> Result<(), LinuxError> {
        let mut state = self.state.lock();
        if let Some(ref attached) = state.attached_prog {
            if Arc::ptr_eq(attached, prog) {
                state.attached_prog = None;
                if let PerfEventClock::Tracepoint(tp_id) = self.spec.clock {
                    unregister_tracepoint_probe(tp_id);
                }
                return Ok(());
            }
        }
        Err(LinuxError::EINVAL)
    }

    pub fn attached_prog(&self) -> Option<Arc<BpfProgram>> {
        self.state.lock().attached_prog.clone()
    }
}

impl Drop for PerfEvent {
    fn drop(&mut self) {
        if self.state.lock().attached_prog.is_some() {
            if let PerfEventClock::Tracepoint(tp_id) = self.spec.clock {
                unregister_tracepoint_probe(tp_id);
            }
        }
    }
}

