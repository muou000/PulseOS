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
    map::PerfEventOutputSink,
    program::{BpfProgType, BpfProgram},
};

#[cfg(not(target_os = "none"))]
use super::{
    core_interpreter::BpfVmError,
    core_map::PerfEventOutputSink,
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
pub const PERF_COUNT_SW_BPF_OUTPUT: u64 = 10;

pub const PERF_RECORD_LOST: u32 = 2;
pub const PERF_RECORD_SAMPLE: u32 = 9;

pub const PERF_MMAP_PAGE_OFFSET_HEAD: usize = 1024;
pub const PERF_MMAP_PAGE_OFFSET_TAIL: usize = 1032;
pub const PERF_MMAP_PAGE_OFFSET_DATA_OFFSET: usize = 1040;
pub const PERF_MMAP_PAGE_OFFSET_DATA_SIZE: usize = 1048;

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
    BpfOutput,
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

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerfEventHeader {
    pub event_type: u32,
    pub misc: u16,
    pub size: u16,
}

pub struct PerfBuffer {
    data_size: usize,
    raw_base: usize,
    total_size: usize,
    lost_count: AtomicU64,
    lock: spin::Mutex<()>,
    #[cfg(target_os = "none")]
    shared_frame: Option<Arc<axmm::SharedFrame>>,
    #[cfg(not(target_os = "none"))]
    _host_storage: Option<alloc::vec::Vec<u8>>,
}

impl core::fmt::Debug for PerfBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PerfBuffer")
            .field("data_size", &self.data_size)
            .field("total_size", &self.total_size)
            .field("head", &self.data_head())
            .field("tail", &self.data_tail())
            .field("lost", &self.lost_count())
            .finish()
    }
}

impl PerfBuffer {
    #[cfg(target_os = "none")]
    pub fn new(nr_data_pages: usize) -> Result<Arc<Self>, LinuxError> {
        if nr_data_pages == 0 || !nr_data_pages.is_power_of_two() {
            return Err(LinuxError::EINVAL);
        }
        let page_count = 1 + nr_data_pages;
        let vaddr = axalloc::global_allocator()
            .alloc_pages(page_count, memory_addr::PAGE_SIZE_4K)
            .map_err(|_| LinuxError::ENOMEM)?;
        unsafe {
            core::ptr::write_bytes(vaddr as *mut u8, 0, page_count * 4096);
        }
        let shared_frame = Arc::new(axmm::SharedFrame { vaddr, page_count });
        let buf = Arc::new(Self {
            data_size: nr_data_pages * 4096,
            raw_base: vaddr,
            total_size: page_count * 4096,
            lost_count: AtomicU64::new(0),
            lock: spin::Mutex::new(()),
            shared_frame: Some(shared_frame),
        });
        buf.init_header();
        Ok(buf)
    }

    #[cfg(not(target_os = "none"))]
    pub fn new(nr_data_pages: usize) -> Result<Arc<Self>, LinuxError> {
        if nr_data_pages == 0 || !nr_data_pages.is_power_of_two() {
            return Err(LinuxError::EINVAL);
        }
        let total_size = (1 + nr_data_pages) * 4096;
        let mut storage = alloc::vec![0u8; total_size];
        let raw_base = storage.as_mut_ptr() as usize;
        let buf = Arc::new(Self {
            data_size: nr_data_pages * 4096,
            raw_base,
            total_size,
            lost_count: AtomicU64::new(0),
            lock: spin::Mutex::new(()),
            _host_storage: Some(storage),
        });
        buf.init_header();
        Ok(buf)
    }

    fn init_header(&self) {
        unsafe {
            let base = self.raw_base as *mut u8;
            *(base as *mut u32) = 1;
            *(base.add(4) as *mut u32) = 1;
            *(base.add(72) as *mut u32) = 1024;
            *((base.add(PERF_MMAP_PAGE_OFFSET_HEAD)) as *mut u64) = 0;
            *((base.add(PERF_MMAP_PAGE_OFFSET_TAIL)) as *mut u64) = 0;
            *((base.add(PERF_MMAP_PAGE_OFFSET_DATA_OFFSET)) as *mut u64) = 4096;
            *((base.add(PERF_MMAP_PAGE_OFFSET_DATA_SIZE)) as *mut u64) = self.data_size as u64;
        }
    }

    pub fn data_head(&self) -> u64 {
        unsafe {
            let ptr = (self.raw_base + PERF_MMAP_PAGE_OFFSET_HEAD) as *const AtomicU64;
            (*ptr).load(Ordering::Acquire)
        }
    }

    pub fn data_tail(&self) -> u64 {
        unsafe {
            let ptr = (self.raw_base + PERF_MMAP_PAGE_OFFSET_TAIL) as *const AtomicU64;
            (*ptr).load(Ordering::Acquire)
        }
    }

    pub fn set_data_head(&self, val: u64) {
        unsafe {
            let ptr = (self.raw_base + PERF_MMAP_PAGE_OFFSET_HEAD) as *const AtomicU64;
            (*ptr).store(val, Ordering::Release);
        }
    }

    pub fn set_data_tail(&self, val: u64) {
        unsafe {
            let ptr = (self.raw_base + PERF_MMAP_PAGE_OFFSET_TAIL) as *const AtomicU64;
            (*ptr).store(val, Ordering::Release);
        }
    }

    pub fn data_size(&self) -> usize {
        self.data_size
    }

    pub fn total_size(&self) -> usize {
        self.total_size
    }

    pub fn raw_base(&self) -> usize {
        self.raw_base
    }

    pub fn lost_count(&self) -> u64 {
        self.lost_count.load(Ordering::Relaxed)
    }

    #[cfg(target_os = "none")]
    pub fn shared_frame(&self) -> Option<Arc<axmm::SharedFrame>> {
        self.shared_frame.clone()
    }

    pub fn write_circular(&self, offset_in_data: usize, bytes: &[u8]) {
        let data_start = (self.raw_base + 4096) as *mut u8;
        let space_to_end = self.data_size - offset_in_data;
        if bytes.len() <= space_to_end {
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), data_start.add(offset_in_data), bytes.len());
            }
        } else {
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), data_start.add(offset_in_data), space_to_end);
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(space_to_end),
                    data_start,
                    bytes.len() - space_to_end,
                );
            }
        }
    }

    pub fn read_circular(&self, offset_in_data: usize, buf: &mut [u8]) {
        let data_start = (self.raw_base + 4096) as *const u8;
        let space_to_end = self.data_size - offset_in_data;
        if buf.len() <= space_to_end {
            unsafe {
                core::ptr::copy_nonoverlapping(data_start.add(offset_in_data), buf.as_mut_ptr(), buf.len());
            }
        } else {
            unsafe {
                core::ptr::copy_nonoverlapping(data_start.add(offset_in_data), buf.as_mut_ptr(), space_to_end);
                core::ptr::copy_nonoverlapping(
                    data_start,
                    buf.as_mut_ptr().add(space_to_end),
                    buf.len() - space_to_end,
                );
            }
        }
    }

    fn write_sample_record(&self, at_head: u64, data: &[u8], rec_size: usize) {
        let mut header_buf = [0u8; 12];
        let header = PerfEventHeader {
            event_type: PERF_RECORD_SAMPLE,
            misc: 0,
            size: rec_size as u16,
        };
        header_buf[0..4].copy_from_slice(&header.event_type.to_ne_bytes());
        header_buf[4..6].copy_from_slice(&header.misc.to_ne_bytes());
        header_buf[6..8].copy_from_slice(&header.size.to_ne_bytes());
        header_buf[8..12].copy_from_slice(&(data.len() as u32).to_ne_bytes());

        let mut offset = (at_head % self.data_size as u64) as usize;
        self.write_circular(offset, &header_buf);
        offset = (offset + 12) % self.data_size;

        self.write_circular(offset, data);
        offset = (offset + data.len()) % self.data_size;

        let pad_len = rec_size - (12 + data.len());
        if pad_len > 0 {
            let zeroes = [0u8; 8];
            self.write_circular(offset, &zeroes[..pad_len]);
        }
    }

    pub fn output_sample(&self, data: &[u8]) -> Result<(), LinuxError> {
        let _guard = self.lock.lock();
        let payload_len = data.len();
        let sample_rec_size = (8 + 4 + payload_len + 7) & !7;
        if sample_rec_size > self.data_size {
            return Err(LinuxError::E2BIG);
        }

        let head = self.data_head();
        let tail = self.data_tail();
        let used = head.wrapping_sub(tail) as usize;
        if used > self.data_size {
            return Err(LinuxError::EINVAL);
        }
        let available = self.data_size - used;

        let lost_rec_size = 24usize;
        let pending_lost = self.lost_count.load(Ordering::Relaxed);

        if pending_lost > 0 && available >= lost_rec_size + sample_rec_size {
            self.lost_count.store(0, Ordering::Relaxed);
            let mut lost_buf = [0u8; 24];
            let lost_header = PerfEventHeader {
                event_type: PERF_RECORD_LOST,
                misc: 0,
                size: lost_rec_size as u16,
            };
            lost_buf[0..4].copy_from_slice(&lost_header.event_type.to_ne_bytes());
            lost_buf[4..6].copy_from_slice(&lost_header.misc.to_ne_bytes());
            lost_buf[6..8].copy_from_slice(&lost_header.size.to_ne_bytes());
            lost_buf[8..16].copy_from_slice(&0u64.to_ne_bytes());
            lost_buf[16..24].copy_from_slice(&pending_lost.to_ne_bytes());

            let offset = (head % self.data_size as u64) as usize;
            self.write_circular(offset, &lost_buf);
            let next_head = head.wrapping_add(lost_rec_size as u64);

            self.write_sample_record(next_head, data, sample_rec_size);
            self.set_data_head(next_head.wrapping_add(sample_rec_size as u64));
            Ok(())
        } else if available >= sample_rec_size {
            self.write_sample_record(head, data, sample_rec_size);
            self.set_data_head(head.wrapping_add(sample_rec_size as u64));
            Ok(())
        } else {
            self.lost_count.fetch_add(1, Ordering::Relaxed);
            Err(LinuxError::ENOSPC)
        }
    }
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
    buffer: spin::Mutex<Option<Arc<PerfBuffer>>>,
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
            buffer: spin::Mutex::new(None),
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
            PerfEventClock::BpfOutput => {
                return Err(LinuxError::EINVAL);
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

    pub fn set_buffer(&self, buffer: Arc<PerfBuffer>) {
        *self.buffer.lock() = Some(buffer);
    }

    pub fn buffer(&self) -> Option<Arc<PerfBuffer>> {
        self.buffer.lock().clone()
    }

    pub fn output_sample(&self, data: &[u8]) -> Result<(), LinuxError> {
        let buf = self.buffer.lock().clone().ok_or(LinuxError::ENOENT)?;
        buf.output_sample(data)
    }
}

impl PerfEventOutputSink for PerfEvent {
    fn output_sample(&self, data: &[u8]) -> Result<(), LinuxError> {
        self.output_sample(data)
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
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

