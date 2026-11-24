//! Perf Event core model, metadata and accounting lifecycle (#97).

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use axerrno::LinuxError;
use pulse_bpf_schema::{PerfEventContext, PerfSampleContext, TracepointId};

use super::{
    interpreter::{BpfEnv, BpfVmError},
    map::PerfEventOutputSink,
    program::{BpfProgType, BpfProgram},
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

/// Source snapshot captured before deferred execution.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeSample {
    pub timestamp_ns: u64,
    pub cpu: usize,
    pub pid: u64,
    pub tid: u64,
    pub task_id: u64,
    pub ip: u64,
    pub stack: pulse_bpf_schema::FrozenStack,
    pub user_mode: bool,
    pub task_clock_ns: u64,
    pub generation: u64,
}

struct ObservationEnv {
    timestamp_ns: u64,
    cpu: u32,
}

impl BpfEnv for ObservationEnv {
    fn ktime_get_ns(&self) -> u64 {
        self.timestamp_ns
    }

    fn get_smp_processor_id(&self) -> u32 {
        self.cpu
    }
}

struct RuntimeSamplingGuard(usize);

impl Drop for RuntimeSamplingGuard {
    fn drop(&mut self) {
        IN_SAMPLING_CPU[self.0].store(false, Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuntimeSampleCounters {
    /// Source observations matching this event's scope, before validation.
    pub observed: u64,
    /// Elapsed sampling periods with no distinct observed PC. They are not
    /// replayed as additional samples and are not transport-record losses.
    pub skipped_periods: u64,
    /// Observations rejected by disable, detach or an old generation.
    pub cancelled: u64,
    /// Invalid identities, PC, counter ordering or VM execution state.
    pub invalid: u64,
}

/// A read-only diagnostic snapshot. Individual counters are sampled, not a
/// system-wide atomic transaction. disabled + inflight=0 bounds VM completion.
#[derive(Clone, Copy, Debug)]
pub struct PerfEventDiagnostics {
    pub id: u64,
    pub clock: PerfEventClock,
    pub scope: PerfEventScope,
    pub period: u64,
    pub task_id: u64,
    pub generation: u64,
    pub enabled: bool,
    pub inflight: u64,
    pub program_id: u32,
    pub samples: PerfEventSampleCounters,
    pub runtime: RuntimeSampleCounters,
    pub transport_lost: u64,
    pub consumer: ConsumerErrorCounters,
}

static NEXT_PERF_EVENT_ID: AtomicU64 = AtomicU64::new(1);

struct RuntimeInvocation<'a>(&'a AtomicU64);
impl Drop for RuntimeInvocation<'_> {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::Release); }
}

pub use pulse_bpf_schema::{observation_generation, advance_observation_generation};

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
    let weak = Arc::downgrade(event);
    if !list.iter().any(|registered| registered.ptr_eq(&weak)) {
        list.push(weak);
    }
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

/// IRQ-side hint only: no event state or registry lock is acquired.
pub fn has_active_perf_events() -> bool {
    ACTIVE_PERF_EVENT_COUNT.load(Ordering::Acquire) != 0
}

/// Diagnostic live registry size, pruning retired weak entries. This is a
/// system-wide observation, not a count of enabled sources in one process.
pub fn registered_perf_event_count() -> usize {
    active_perf_events().len()
}

/// Dispatch a frozen source snapshot from worker context. No registry lock is
/// held while executing programs, running helpers, or notifying consumers.
pub fn dispatch_runtime_sample(sample: &RuntimeSample) -> usize {
    active_perf_events().iter().filter(|event| event.dispatch_sample(sample) == Ok(true)).count()
}

/// Dispatch an already dequeued tracepoint without retaining queue/IRQ guards.
pub fn dispatch_tracepoint(id: TracepointId, bytes: &[u8], generation: u64) -> usize {
    active_perf_events().iter()
        .filter(|event| event.dispatch_tracepoint(id, bytes, generation) == Ok(true)).count()
}

fn active_perf_events() -> Vec<Arc<PerfEvent>> {
    let mut list = ACTIVE_PERF_EVENTS.lock();
    let mut events = Vec::with_capacity(list.len());
    list.retain(|weak| {
        if let Some(event) = weak.upgrade() {
            events.push(event);
            true
        } else {
            false
        }
    });
    ACTIVE_PERF_EVENT_COUNT.store(list.len(), Ordering::Release);
    events
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PerfRecord {
    Sample {
        raw_len: u32,
        data: alloc::vec::Vec<u8>,
    },
    Lost {
        id: u64,
        lost: u64,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConsumerErrorCounters {
    pub corrupt_records: u64,
    pub out_of_bounds: u64,
}

pub struct PerfBuffer {
    data_size: usize,
    raw_base: usize,
    total_size: usize,
    lost_count: AtomicU64,
    total_lost: AtomicU64,
    consumer_corrupt_records: AtomicU64,
    consumer_out_of_bounds: AtomicU64,
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
            .field("total_lost", &self.total_lost())
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
            total_lost: AtomicU64::new(0),
            consumer_corrupt_records: AtomicU64::new(0),
            consumer_out_of_bounds: AtomicU64::new(0),
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
            total_lost: AtomicU64::new(0),
            consumer_corrupt_records: AtomicU64::new(0),
            consumer_out_of_bounds: AtomicU64::new(0),
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
        self.output_sample_with_id(0, data)
    }

    pub fn output_sample_with_id(&self, id: u64, data: &[u8]) -> Result<(), LinuxError> {
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
            lost_buf[8..16].copy_from_slice(&id.to_ne_bytes());
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
            self.total_lost.fetch_add(1, Ordering::Relaxed);
            Err(LinuxError::ENOSPC)
        }
    }

    pub fn total_lost(&self) -> u64 {
        self.total_lost.load(Ordering::Relaxed)
    }

    pub fn consumer_error_counters(&self) -> ConsumerErrorCounters {
        ConsumerErrorCounters {
            corrupt_records: self.consumer_corrupt_records.load(Ordering::Relaxed),
            out_of_bounds: self.consumer_out_of_bounds.load(Ordering::Relaxed),
        }
    }

    pub fn parse_records(
        &self,
    ) -> Result<(alloc::vec::Vec<PerfRecord>, u64), ConsumerErrorCounters> {
        let head = self.data_head();
        let mut tail = self.data_tail();

        let used = head.wrapping_sub(tail);
        if used as usize > self.data_size {
            self.consumer_out_of_bounds.fetch_add(1, Ordering::Relaxed);
            return Err(self.consumer_error_counters());
        }

        let mut records = alloc::vec::Vec::new();
        let mut lost_count = 0u64;

        while head.wrapping_sub(tail) > 0 {
            let offset = (tail % self.data_size as u64) as usize;
            let mut header_bytes = [0u8; 8];
            self.read_circular(offset, &mut header_bytes);
            let event_type = u32::from_ne_bytes(header_bytes[0..4].try_into().unwrap());
            let _misc = u16::from_ne_bytes(header_bytes[4..6].try_into().unwrap());
            let rec_size = u16::from_ne_bytes(header_bytes[6..8].try_into().unwrap()) as usize;

            if rec_size < 8 || rec_size > self.data_size || (rec_size as u64) > head.wrapping_sub(tail) {
                self.consumer_corrupt_records.fetch_add(1, Ordering::Relaxed);
                return Err(self.consumer_error_counters());
            }

            if event_type == PERF_RECORD_SAMPLE {
                let mut raw_len_bytes = [0u8; 4];
                self.read_circular((offset + 8) % self.data_size, &mut raw_len_bytes);
                let raw_len = u32::from_ne_bytes(raw_len_bytes);
                let mut data = alloc::vec![0u8; raw_len as usize];
                self.read_circular((offset + 12) % self.data_size, &mut data);
                records.push(PerfRecord::Sample { raw_len, data });
            } else if event_type == PERF_RECORD_LOST {
                let mut id_bytes = [0u8; 8];
                self.read_circular((offset + 8) % self.data_size, &mut id_bytes);
                let id = u64::from_ne_bytes(id_bytes);

                let mut lost_bytes = [0u8; 8];
                self.read_circular((offset + 16) % self.data_size, &mut lost_bytes);
                let lost = u64::from_ne_bytes(lost_bytes);
                lost_count = lost_count.saturating_add(lost);
                records.push(PerfRecord::Lost { id, lost });
            }

            tail = tail.wrapping_add(rec_size as u64);
            self.set_data_tail(tail);
        }

        Ok((records, lost_count))
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
    activation_generation: u64,
}

pub struct PerfEvent {
    id: u64,
    runtime_inflight: AtomicU64,
    spec: PerfEventSpec,
    // Stable scheduler identity, unlike the numeric TID selected at open time.
    bound_task_id: AtomicU64,
    state: spin::Mutex<PerfEventState>,
    buffer: spin::Mutex<Option<Arc<PerfBuffer>>>,
    delivered_samples: AtomicU64,
    re_entry_drops: AtomicU64,
    helper_failures: AtomicU64,
    budget_failures: AtomicU64,
    readable_sequence: AtomicU64,
    runtime_observed: AtomicU64,
    runtime_skipped_periods: AtomicU64,
    runtime_cancelled: AtomicU64,
    runtime_invalid: AtomicU64,
    #[cfg(target_os = "none")]
    read_wait_queue: axtask::WaitQueue,
}

impl PerfEvent {
    /// `now_ns` is the selected event clock: monotonic time for CPU clock,
    /// accumulated thread CPU time for task clock. The same clock must be used
    /// by enable/disable/reset/read `_at` operations, never worker wall time.
    pub fn new(spec: PerfEventSpec, now_ns: u64) -> Self {
        let enabled = !spec.disabled;
        let last_enabled_ns = if enabled { now_ns } else { 0 };
        Self {
            id: NEXT_PERF_EVENT_ID.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
                |id| id.checked_add(1)).unwrap_or(0),
            runtime_inflight: AtomicU64::new(0),
            spec,
            bound_task_id: AtomicU64::new(0),
            state: spin::Mutex::new(PerfEventState {
                enabled,
                accumulated_ns: 0,
                last_enabled_ns,
                sample_period: spec.sample_period,
                period_accumulated_ns: 0,
                last_sample_ns: now_ns,
                attached_prog: None,
                activation_generation: advance_observation_generation(),
            }),
            buffer: spin::Mutex::new(None),
            delivered_samples: AtomicU64::new(0),
            re_entry_drops: AtomicU64::new(0),
            helper_failures: AtomicU64::new(0),
            budget_failures: AtomicU64::new(0),
            readable_sequence: AtomicU64::new(0),
            runtime_observed: AtomicU64::new(0),
            runtime_skipped_periods: AtomicU64::new(0),
            runtime_cancelled: AtomicU64::new(0),
            runtime_invalid: AtomicU64::new(0),
            #[cfg(target_os = "none")]
            read_wait_queue: axtask::WaitQueue::new(),
        }
    }

    /// Bind a task-scoped event to its selected thread's stable scheduler ID.
    /// An exec TID rebind must not retarget an open event to a different thread.
    /// Binding is one-time (or idempotent for the same ID) and invalidates any
    /// observations queued before the binding was published.
    pub fn bind_task_identity(&self, task_id: u64) -> Result<(), LinuxError> {
        if task_id == 0 || !matches!(self.spec.scope, PerfEventScope::Task { .. }) {
            return Err(LinuxError::EINVAL);
        }
        let mut state = self.state.lock();
        match self.bound_task_id.compare_exchange(0, task_id, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                state.activation_generation = advance_observation_generation();
                Ok(())
            }
            Err(bound) if bound == task_id => Ok(()),
            Err(_) => Err(LinuxError::EBUSY),
        }
    }

    fn matches_task_identity(&self, observed_tid: u64, observed_task_id: u64) -> bool {
        let bound = self.bound_task_id.load(Ordering::Acquire);
        observed_tid != 0 && bound != 0 && bound == observed_task_id
    }

    pub fn diagnostics(&self) -> PerfEventDiagnostics {
        // Keep control state locked through counter reads. Once disabled and
        // inflight=0 is acquired, no invocation can start until this lock is
        // released; the final invocation's Release publishes its counters.
        let state = self.state.lock();
        let inflight = self.runtime_inflight.load(Ordering::Acquire);
        let buffer = self.buffer();
        PerfEventDiagnostics {
            id: self.id, clock: self.spec.clock, scope: self.spec.scope,
            period: state.sample_period, task_id: self.bound_task_id.load(Ordering::Acquire),
            enabled: state.enabled, generation: state.activation_generation,
            program_id: state.attached_prog.as_ref().map_or(0, |prog| prog.id()), inflight,
            samples: self.sample_counters(), runtime: self.runtime_counters(),
            transport_lost: buffer.as_ref().map_or(0, |buffer| buffer.total_lost()),
            consumer: buffer.as_ref().map_or(ConsumerErrorCounters::default(), |buffer| buffer.consumer_error_counters()),
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
            state.activation_generation = advance_observation_generation();
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
            state.activation_generation = advance_observation_generation();
        }
    }

    pub fn reset_at(&self, now_ns: u64) {
        let mut state = self.state.lock();
        state.activation_generation = advance_observation_generation();
        state.accumulated_ns = 0;
        state.last_enabled_ns = now_ns;
        state.last_sample_ns = now_ns;
        state.period_accumulated_ns = 0;
    }

    pub fn set_period(&self, period: u64) {
        let mut state = self.state.lock();
        state.activation_generation = advance_observation_generation();
        state.sample_period = period;
        state.period_accumulated_ns = 0;
    }

    /// Change the period with a fresh reading of this event's selected clock.
    /// Previously elapsed time must not be charged using the new period.
    pub fn set_period_at(&self, period: u64, now_ns: u64) {
        let mut state = self.state.lock();
        state.activation_generation = advance_observation_generation();
        state.sample_period = period;
        state.period_accumulated_ns = 0;
        state.last_sample_ns = now_ns;
    }

    pub fn runtime_counters(&self) -> RuntimeSampleCounters {
        RuntimeSampleCounters {
            observed: self.runtime_observed.load(Ordering::Relaxed),
            skipped_periods: self.runtime_skipped_periods.load(Ordering::Relaxed),
            cancelled: self.runtime_cancelled.load(Ordering::Relaxed),
            invalid: self.runtime_invalid.load(Ordering::Relaxed),
        }
    }

    /// Consume one source observation. A delayed observation may advance past
    /// several periods, but can execute the attached program at most once.
    ///
    /// The attachment is accepted under the state lock and kept alive by Arc.
    /// A control operation may cancel queued observations but cannot recall an
    /// already accepted invocation; that invocation never switches to a newly
    /// attached program. No state or registry lock is held across BPF execution.
    pub fn dispatch_sample(&self, sample: &RuntimeSample) -> Result<bool, LinuxError> {
        let clock_ns = match (self.spec.clock, self.spec.scope) {
            (PerfEventClock::CpuClock, PerfEventScope::PerCpu { cpu }) if cpu == sample.cpu => sample.timestamp_ns,
            (PerfEventClock::TaskClock, PerfEventScope::Task { .. })
                if self.matches_task_identity(sample.tid, sample.task_id) => sample.task_clock_ns,
            _ => return Ok(false),
        };
        if sample.cpu >= BPF_MAX_SAMPLING_CPUS || sample.pid > u32::MAX as u64
            || sample.tid > u32::MAX as u64 || sample.ip == 0
        {
            self.runtime_invalid.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }
        let (prog, period, due, _invocation) = {
            let mut state = self.state.lock();
            if !state.enabled || state.attached_prog.is_none()
                || state.activation_generation == u64::MAX || sample.generation == u64::MAX
                || sample.generation < state.activation_generation
                || sample.generation > observation_generation()
            {
                if sample.generation < state.activation_generation || sample.generation == u64::MAX
                    || sample.generation > observation_generation() {
                    self.runtime_cancelled.fetch_add(1, Ordering::Relaxed);
                }
                return Ok(false);
            }
            self.runtime_observed.fetch_add(1, Ordering::Relaxed);
            if state.sample_period == 0 {
                return Ok(false);
            }
            let Some(elapsed) = clock_ns.checked_sub(state.last_sample_ns) else {
                self.runtime_invalid.fetch_add(1, Ordering::Relaxed);
                return Ok(false);
            };
            state.last_sample_ns = clock_ns;
            state.period_accumulated_ns = state.period_accumulated_ns.saturating_add(elapsed);
            let due = state.period_accumulated_ns / state.sample_period;
            state.period_accumulated_ns %= state.sample_period;
            if due == 0 {
                return Ok(false);
            }
            self.runtime_inflight.fetch_add(1, Ordering::Relaxed);
            (state.attached_prog.as_ref().unwrap().clone(), state.sample_period, due,
             RuntimeInvocation(&self.runtime_inflight))
        };
        self.runtime_skipped_periods.fetch_add(due - 1, Ordering::Relaxed);
        let context = PerfSampleContext {
            base: PerfEventContext::new(period, 0, sample.timestamp_ns,
                sample.cpu as u32, sample.pid as u32, sample.tid as u32, sample.task_id),
            ip: sample.ip,
            mode: if sample.user_mode { 2 } else { 1 },
            version: 2,
        };
        let context = pulse_bpf_schema::PerfStackSampleContext {
            base: context,
            source_id: self.id,
            stack: sample.stack,
        };
        self.run_observation(prog, &context.to_bytes(), sample.cpu, sample.timestamp_ns)
    }

    fn run_observation(&self, prog: Arc<BpfProgram>, context: &[u8], cpu: usize, timestamp_ns: u64) -> Result<bool, LinuxError> {
        if IN_SAMPLING_CPU[cpu]
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err()
        {
            self.re_entry_drops.fetch_add(1, Ordering::Relaxed);
            prog.record_re_entry_drop();
            SESSION_SAMPLE_COUNTERS.re_entry_drops.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }
        let _guard = RuntimeSamplingGuard(cpu);
        match prog.run_with_env(context, &ObservationEnv { timestamp_ns, cpu: cpu as u32 }) {
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
                self.runtime_invalid.fetch_add(1, Ordering::Relaxed);
                Ok(false)
            }
        }
    }

    /// Execute the original fixed-layout trace context. Task scope refers to
    /// ContextCommon.tid (the event subject), not a guessed PID or wake target.
    pub fn dispatch_tracepoint(&self, id: TracepointId, bytes: &[u8], generation: u64) -> Result<bool, LinuxError> {
        if self.spec.clock != PerfEventClock::Tracepoint(id) {
            return Ok(false);
        }
        let metadata = pulse_bpf_schema::lookup_by_id(id.as_u32()).map_err(|_| LinuxError::EINVAL)?;
        if bytes.len() != metadata.context_size
            || u32::from_le_bytes(bytes[0..4].try_into().unwrap()) != id.as_u32()
            || u32::from_le_bytes(bytes[4..8].try_into().unwrap()) != metadata.version
        {
            self.runtime_invalid.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }
        let timestamp_ns = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let cpu = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let tid = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as u64;
        let task_id = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        if cpu >= BPF_MAX_SAMPLING_CPUS
            || matches!(self.spec.scope, PerfEventScope::Task { .. }) && tid == 0
        {
            self.runtime_invalid.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }
        let matches_scope = match self.spec.scope {
            PerfEventScope::PerCpu { cpu: selected } => selected == cpu,
            PerfEventScope::Task { .. } => self.matches_task_identity(tid, task_id),
        };
        if !matches_scope {
            return Ok(false);
        }
        let (prog, _invocation) = {
            let state = self.state.lock();
            if !state.enabled || state.attached_prog.is_none()
                || state.activation_generation == u64::MAX || generation == u64::MAX
                || generation < state.activation_generation
                || generation > observation_generation()
            {
                if generation < state.activation_generation || generation == u64::MAX
                    || generation > observation_generation() {
                    self.runtime_cancelled.fetch_add(1, Ordering::Relaxed);
                }
                return Ok(false);
            }
            self.runtime_observed.fetch_add(1, Ordering::Relaxed);
            self.runtime_inflight.fetch_add(1, Ordering::Relaxed);
            (state.attached_prog.as_ref().unwrap().clone(), RuntimeInvocation(&self.runtime_inflight))
        };
        self.run_observation(prog, bytes, cpu, timestamp_ns)
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
                self.set_period_at(arg as u64, now_ns);
                Ok(0)
            }
            _ => Err(LinuxError::ENOTTY),
        }
    }
}

// Serialize count transitions with the producer-mask update. Otherwise an old
// last-detach could clear the mask after a new first-attach has set it. Producers
// only read axtask's atomic mask and never acquire this control-plane lock.
static TRACEPOINT_SUBSCRIBER_CONTROL: spin::Mutex<()> = spin::Mutex::new(());

/// System-wide attached tracepoint subscriptions, including disabled sources.
/// The control lock makes the sum coherent with attach/detach updates.
pub fn tracepoint_subscription_count() -> usize {
    let _guard = TRACEPOINT_SUBSCRIBER_CONTROL.lock();
    TRACEPOINT_SUBSCRIBER_COUNTS.iter().map(|count| count.load(Ordering::Relaxed)).sum()
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
    let _guard = TRACEPOINT_SUBSCRIBER_CONTROL.lock();
    let idx = tp_id as usize;
    if idx < TRACEPOINT_SUBSCRIBER_COUNTS.len() {
        if TRACEPOINT_SUBSCRIBER_COUNTS[idx].fetch_add(1, Ordering::SeqCst) == 0 {
            #[cfg(all(target_os = "none", feature = "bpf-trace"))]
            axtask::bpf_trace::register_probe(tp_id);
        }
    }
}

fn unregister_tracepoint_probe(tp_id: pulse_bpf_schema::TracepointId) {
    let _guard = TRACEPOINT_SUBSCRIBER_CONTROL.lock();
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
        state.activation_generation = advance_observation_generation();
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
                state.activation_generation = advance_observation_generation();
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

    pub fn is_readable(&self) -> bool {
        if let Some(buf) = self.buffer() {
            buf.data_head() > buf.data_tail()
        } else {
            false
        }
    }

    pub fn poll_event_sequence(&self) -> u64 {
        self.readable_sequence.load(Ordering::Acquire)
    }

    pub fn notify_readable(&self) {
        self.readable_sequence.fetch_add(1, Ordering::Release);
        #[cfg(target_os = "none")]
        self.read_wait_queue.notify_all(true);
    }

    #[cfg(target_os = "none")]
    pub fn read_wait_queue(&self) -> &axtask::WaitQueue {
        &self.read_wait_queue
    }

    pub fn output_sample(&self, data: &[u8]) -> Result<(), LinuxError> {
        let buf = self.buffer.lock().clone().ok_or(LinuxError::ENOENT)?;
        let id = match self.spec.scope {
            PerfEventScope::PerCpu { cpu } => cpu as u64,
            PerfEventScope::Task { pid } => pid,
        };
        buf.output_sample_with_id(id, data)?;
        self.delivered_samples.fetch_add(1, Ordering::Relaxed);
        self.notify_readable();
        Ok(())
    }

    pub fn cpu(&self) -> Option<usize> {
        match self.spec.scope {
            PerfEventScope::PerCpu { cpu } => Some(cpu),
            _ => None,
        }
    }

    pub fn total_lost(&self) -> u64 {
        self.buffer().map(|b| b.total_lost()).unwrap_or(0)
    }

    pub fn lost_count(&self) -> u64 {
        self.buffer().map(|b| b.lost_count()).unwrap_or(0)
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
        #[cfg(target_os = "none")]
        self.read_wait_queue.notify_all(true);
        if self.state.lock().attached_prog.is_some() {
            if let PerfEventClock::Tracepoint(tp_id) = self.spec.clock {
                unregister_tracepoint_probe(tp_id);
            }
        }
    }
}


#[cfg(test)]
mod tests {
    extern crate std;

    use std::{sync::Barrier, thread};

    use super::*;
    use crate::insn::*;

    #[test]
    fn runtime_tracepoint_parallel_attachment_counts_preserve_live_subscribers() {
        let id = TracepointId::PhaseMarker;
        let count = || {
            let _guard = TRACEPOINT_SUBSCRIBER_CONTROL.lock();
            TRACEPOINT_SUBSCRIBER_COUNTS[id as usize].load(Ordering::Relaxed)
        };
        let initial = count();
        let ready = Barrier::new(5);
        let release = Barrier::new(5);
        let attached = thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    let event = PerfEvent::new(
                        PerfEventSpec {
                            clock: PerfEventClock::Tracepoint(id),
                            scope: PerfEventScope::PerCpu { cpu: 0 },
                            sample_period: 0,
                            disabled: true,
                            cloexec: false,
                        },
                        0,
                    );
                    let insns = Arc::new([
                        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
                        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
                    ]);
                    let prog = Arc::new(BpfProgram::new(
                        BpfProgType::Tracepoint,
                        [0; crate::BPF_OBJ_NAME_LEN],
                        insns,
                        Vec::new(),
                    ));
                    for _ in 0..100 {
                        event.attach_program(prog.clone()).unwrap();
                        event.detach_program(&prog).unwrap();
                    }
                    event.attach_program(prog).unwrap();
                    ready.wait();
                    release.wait();
                    // Dropping the event removes its final subscription.
                });
            }
            ready.wait();
            let attached = count();
            release.wait();
            attached
        });
        assert_eq!(attached, initial + 4);
        assert_eq!(count(), initial);
    }
}
