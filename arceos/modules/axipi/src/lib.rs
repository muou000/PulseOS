//! [ArceOS](https://github.com/arceos-org/arceos) Inter-Processor Interrupt (IPI) primitives.

#![cfg_attr(not(test), no_std)]

#[macro_use]
extern crate log;
extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering, fence};

use axhal::{
    irq::{IPI_IRQ, IpiError, IpiTarget},
    mem::{PAGE_SIZE_4K, VirtAddr},
    percpu::this_cpu_id,
};
use kspin::SpinNoIrq;
use lazyinit::LazyInit;

mod event;
mod queue;

pub use event::{Callback, MulticastCallback};
use queue::IpiEventQueue;

/// A TLB shootdown failure together with its completion guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlbShootdownError {
    /// No shootdown request was published, so stale remote translations may remain.
    Incomplete(IpiError),
    /// Direct delivery failed, but all targets completed through the fallback path.
    Completed(IpiError),
}

impl TlbShootdownError {
    /// Returns whether every targeted CPU acknowledged the shootdown.
    pub const fn completion_guaranteed(self) -> bool {
        matches!(self, Self::Completed(_))
    }
}

impl core::fmt::Display for TlbShootdownError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Incomplete(error) => write!(f, "incomplete TLB shootdown: {error}"),
            Self::Completed(error) => {
                write!(f, "TLB shootdown completed after delivery error: {error}")
            }
        }
    }
}

impl core::error::Error for TlbShootdownError {}

#[percpu::def_percpu]
static IPI_EVENT_QUEUE: LazyInit<SpinNoIrq<IpiEventQueue>> = LazyInit::new();

static IPI_CPU_READY: [AtomicBool; axconfig::plat::MAX_CPU_NUM] =
    [const { AtomicBool::new(false) }; axconfig::plat::MAX_CPU_NUM];

const TRACKED_ASID_COUNT: usize = 1024;
const TLB_RANGE_PAGE_LIMIT: usize = 32;
const TLB_MAILBOX_REQUEST_CAPACITY: usize = 4;
const NO_ACTIVE_ASID: usize = usize::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TlbFlushRequest {
    None,
    Range { asid: usize, start: usize, end: usize },
    Asid(usize),
    All,
}

impl TlbFlushRequest {
    const fn asid(self) -> Option<usize> {
        match self {
            Self::Range { asid, .. } | Self::Asid(asid) => Some(asid),
            Self::None | Self::All => None,
        }
    }
}

#[derive(Clone, Copy)]
struct TlbFlushBatch {
    requests: [TlbFlushRequest; TLB_MAILBOX_REQUEST_CAPACITY],
    len: usize,
}

#[derive(Clone, Copy, Default)]
struct TlbEnqueueResult {
    coalesced: bool,
    promoted_to_asid: bool,
    promoted_to_all: bool,
}

impl TlbFlushBatch {
    const fn new() -> Self {
        Self {
            requests: [TlbFlushRequest::None; TLB_MAILBOX_REQUEST_CAPACITY],
            len: 0,
        }
    }

    const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn enqueue(&mut self, request: TlbFlushRequest) -> TlbEnqueueResult {
        if matches!(request, TlbFlushRequest::None) {
            return TlbEnqueueResult::default();
        }
        if matches!(request, TlbFlushRequest::All) {
            let coalesced = !self.is_empty();
            self.requests = [TlbFlushRequest::None; TLB_MAILBOX_REQUEST_CAPACITY];
            self.requests[0] = TlbFlushRequest::All;
            self.len = 1;
            return TlbEnqueueResult {
                coalesced,
                promoted_to_asid: false,
                promoted_to_all: false,
            };
        }
        if self.len == 1 && matches!(self.requests[0], TlbFlushRequest::All) {
            return TlbEnqueueResult {
                coalesced: true,
                promoted_to_asid: false,
                promoted_to_all: false,
            };
        }
        if let Some(asid) = request.asid() {
            for pending in &mut self.requests[..self.len] {
                if pending.asid() == Some(asid) {
                    let range_pair = matches!(*pending, TlbFlushRequest::Range { .. })
                        && matches!(request, TlbFlushRequest::Range { .. });
                    let merged = merge_tlb_flush(*pending, request);
                    *pending = merged;
                    return TlbEnqueueResult {
                        coalesced: true,
                        promoted_to_asid: range_pair
                            && matches!(merged, TlbFlushRequest::Asid(_)),
                        promoted_to_all: false,
                    };
                }
            }
        }
        if self.len < TLB_MAILBOX_REQUEST_CAPACITY {
            self.requests[self.len] = request;
            self.len += 1;
            return TlbEnqueueResult::default();
        }
        self.requests = [TlbFlushRequest::None; TLB_MAILBOX_REQUEST_CAPACITY];
        self.requests[0] = TlbFlushRequest::All;
        self.len = 1;
        TlbEnqueueResult {
            coalesced: true,
            promoted_to_asid: false,
            promoted_to_all: true,
        }
    }

    fn take(&mut self) -> Self {
        core::mem::replace(self, Self::new())
    }

    fn iter(&self) -> impl Iterator<Item = TlbFlushRequest> + '_ {
        self.requests[..self.len].iter().copied()
    }
}

struct TlbShootdownMailbox {
    batch: TlbFlushBatch,
}

impl TlbShootdownMailbox {
    const fn new() -> Self {
        Self {
            batch: TlbFlushBatch::new(),
        }
    }
}

struct TlbShootdownCounters {
    requests: AtomicUsize,
    range_requests: AtomicUsize,
    asid_requests: AtomicUsize,
    all_requests: AtomicUsize,
    target_cpus: AtomicUsize,
    remote_cpus: AtomicUsize,
    zero_target_requests: AtomicUsize,
    local_only_requests: AtomicUsize,
    remote_requests: AtomicUsize,
    max_target_cpus: AtomicUsize,
    max_remote_cpus: AtomicUsize,
    range_changed_pages: AtomicUsize,
    ipi_sends: AtomicUsize,
    ipi_sends_avoided: AtomicUsize,
    mailbox_coalesces: AtomicUsize,
    range_to_asid_promotions: AtomicUsize,
    full_promotions: AtomicUsize,
    wait_spins: AtomicUsize,
    lazy_asid_flushes: AtomicUsize,
}

impl TlbShootdownCounters {
    const fn new() -> Self {
        Self {
            requests: AtomicUsize::new(0),
            range_requests: AtomicUsize::new(0),
            asid_requests: AtomicUsize::new(0),
            all_requests: AtomicUsize::new(0),
            target_cpus: AtomicUsize::new(0),
            remote_cpus: AtomicUsize::new(0),
            zero_target_requests: AtomicUsize::new(0),
            local_only_requests: AtomicUsize::new(0),
            remote_requests: AtomicUsize::new(0),
            max_target_cpus: AtomicUsize::new(0),
            max_remote_cpus: AtomicUsize::new(0),
            range_changed_pages: AtomicUsize::new(0),
            ipi_sends: AtomicUsize::new(0),
            ipi_sends_avoided: AtomicUsize::new(0),
            mailbox_coalesces: AtomicUsize::new(0),
            range_to_asid_promotions: AtomicUsize::new(0),
            full_promotions: AtomicUsize::new(0),
            wait_spins: AtomicUsize::new(0),
            lazy_asid_flushes: AtomicUsize::new(0),
        }
    }
}

/// Aggregate low-overhead TLB shootdown counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TlbShootdownStats {
    pub requests: usize,
    pub range_requests: usize,
    pub asid_requests: usize,
    pub all_requests: usize,
    pub target_cpus: usize,
    pub remote_cpus: usize,
    pub zero_target_requests: usize,
    pub local_only_requests: usize,
    pub remote_requests: usize,
    pub max_target_cpus: usize,
    pub max_remote_cpus: usize,
    pub range_changed_pages: usize,
    pub ipi_sends: usize,
    pub ipi_sends_avoided: usize,
    pub mailbox_coalesces: usize,
    pub range_to_asid_promotions: usize,
    pub full_promotions: usize,
    pub wait_spins: usize,
    pub lazy_asid_flushes: usize,
}

static ASID_GENERATIONS: [AtomicUsize; TRACKED_ASID_COUNT] =
    [const { AtomicUsize::new(0) }; TRACKED_ASID_COUNT];
static CPU_ACTIVE_ASIDS: [AtomicUsize; axconfig::plat::MAX_CPU_NUM] =
    [const { AtomicUsize::new(NO_ACTIVE_ASID) }; axconfig::plat::MAX_CPU_NUM];
static CPU_ASID_GENERATIONS: [[AtomicUsize; TRACKED_ASID_COUNT]; axconfig::plat::MAX_CPU_NUM] =
    [const { [const { AtomicUsize::new(0) }; TRACKED_ASID_COUNT] };
        axconfig::plat::MAX_CPU_NUM];
static TLB_SHOOTDOWN_REQUESTED: [AtomicUsize; axconfig::plat::MAX_CPU_NUM] =
    [const { AtomicUsize::new(0) }; axconfig::plat::MAX_CPU_NUM];
static TLB_SHOOTDOWN_COMPLETED: [AtomicUsize; axconfig::plat::MAX_CPU_NUM] =
    [const { AtomicUsize::new(0) }; axconfig::plat::MAX_CPU_NUM];
static TLB_SHOOTDOWN_MAILBOXES: [SpinNoIrq<TlbShootdownMailbox>; axconfig::plat::MAX_CPU_NUM] =
    [const { SpinNoIrq::new(TlbShootdownMailbox::new()) }; axconfig::plat::MAX_CPU_NUM];
static TLB_SHOOTDOWN_COUNTERS: [TlbShootdownCounters; axconfig::plat::MAX_CPU_NUM] =
    [const { TlbShootdownCounters::new() }; axconfig::plat::MAX_CPU_NUM];

/// Returns an aggregate snapshot of all per-CPU shootdown counters.
pub fn tlb_shootdown_stats() -> TlbShootdownStats {
    let mut stats = TlbShootdownStats::default();
    for counters in &TLB_SHOOTDOWN_COUNTERS {
        stats.requests += counters.requests.load(Ordering::Relaxed);
        stats.range_requests += counters.range_requests.load(Ordering::Relaxed);
        stats.asid_requests += counters.asid_requests.load(Ordering::Relaxed);
        stats.all_requests += counters.all_requests.load(Ordering::Relaxed);
        stats.target_cpus += counters.target_cpus.load(Ordering::Relaxed);
        stats.remote_cpus += counters.remote_cpus.load(Ordering::Relaxed);
        stats.zero_target_requests += counters.zero_target_requests.load(Ordering::Relaxed);
        stats.local_only_requests += counters.local_only_requests.load(Ordering::Relaxed);
        stats.remote_requests += counters.remote_requests.load(Ordering::Relaxed);
        stats.max_target_cpus = stats
            .max_target_cpus
            .max(counters.max_target_cpus.load(Ordering::Relaxed));
        stats.max_remote_cpus = stats
            .max_remote_cpus
            .max(counters.max_remote_cpus.load(Ordering::Relaxed));
        stats.range_changed_pages += counters.range_changed_pages.load(Ordering::Relaxed);
        stats.ipi_sends += counters.ipi_sends.load(Ordering::Relaxed);
        stats.ipi_sends_avoided += counters.ipi_sends_avoided.load(Ordering::Relaxed);
        stats.mailbox_coalesces += counters.mailbox_coalesces.load(Ordering::Relaxed);
        stats.range_to_asid_promotions += counters
            .range_to_asid_promotions
            .load(Ordering::Relaxed);
        stats.full_promotions += counters.full_promotions.load(Ordering::Relaxed);
        stats.wait_spins += counters.wait_spins.load(Ordering::Relaxed);
        stats.lazy_asid_flushes += counters.lazy_asid_flushes.load(Ordering::Relaxed);
    }
    stats
}

/// Initialize the per-CPU IPI event queue.
pub fn init() {
    IPI_EVENT_QUEUE.with_current(|ipi_queue| {
        ipi_queue.init_once(SpinNoIrq::new(IpiEventQueue::default()));
    });
}

/// Marks the current CPU ready to receive IPI callbacks.
pub fn mark_current_cpu_ready() {
    IPI_CPU_READY[this_cpu_id()].store(true, Ordering::Release);
}

/// Waits until all online CPUs can receive IPI callbacks.
pub fn wait_for_all_cpus_ready() {
    while (0..axhal::cpu_num()).any(|cpu_id| {
        axhal::is_cpu_online(cpu_id) && !IPI_CPU_READY[cpu_id].load(Ordering::Acquire)
    }) {
        core::hint::spin_loop();
    }
}

/// Publishes that the current CPU is switching to `asid`.
///
/// A CPU that skipped an eager shootdown while this ASID was inactive catches
/// up with one local ASID flush before publishing itself as active.
pub fn mark_current_cpu_asid_active(asid: usize) {
    let Some(generation) = ASID_GENERATIONS.get(asid) else {
        CPU_ACTIVE_ASIDS[this_cpu_id()].store(NO_ACTIVE_ASID, Ordering::SeqCst);
        return;
    };
    let cpu_id = this_cpu_id();
    loop {
        let expected = generation.load(Ordering::SeqCst);
        let seen = CPU_ASID_GENERATIONS[cpu_id][asid].load(Ordering::Acquire);
        if seen != expected {
            axhal::asm::flush_tlb_asid(asid);
            CPU_ASID_GENERATIONS[cpu_id][asid].store(expected, Ordering::Release);
            TLB_SHOOTDOWN_COUNTERS[cpu_id]
                .lazy_asid_flushes
                .fetch_add(1, Ordering::Relaxed);
        }
        CPU_ACTIVE_ASIDS[cpu_id].store(asid, Ordering::SeqCst);
        if generation.load(Ordering::SeqCst) == expected {
            return;
        }
        CPU_ACTIVE_ASIDS[cpu_id].store(NO_ACTIVE_ASID, Ordering::SeqCst);
    }
}

/// Returns online CPUs currently published as running `asid`.
pub fn asid_active_cpu_mask(asid: usize) -> usize {
    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
    {
        if asid >= TRACKED_ASID_COUNT {
            return axhal::online_cpu_mask();
        }
        let mut mask = 0usize;
        for cpu_id in 0..axhal::cpu_num() {
            if CPU_ACTIVE_ASIDS[cpu_id].load(Ordering::SeqCst) == asid {
                mask |= 1usize << cpu_id;
            }
        }
        mask & axhal::online_cpu_mask()
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
    {
        let _ = asid;
        axhal::online_cpu_mask()
    }
}

/// Advances residency state before a retired ASID is reused.
///
/// Per-CPU generations are deliberately preserved so stale entries from the
/// previous owner force a local flush on the next activation.
pub fn reset_asid_active_cpu_mask(asid: usize) {
    if let Some(generation) = ASID_GENERATIONS.get(asid) {
        generation.fetch_add(1, Ordering::SeqCst);
    }
}

/// Executes a callback on the specified destination CPU via IPI.
pub fn run_on_cpu<T: Into<Callback>>(dest_cpu: usize, callback: T) -> Result<(), IpiError> {
    debug!("Send IPI event to CPU {}", dest_cpu);
    if dest_cpu == this_cpu_id() {
        // Execute callback on current CPU immediately
        callback.into().call();
        Ok(())
    } else {
        if dest_cpu >= axhal::cpu_num() {
            return Err(IpiError::InvalidTarget);
        }
        if !axhal::is_cpu_online(dest_cpu) || !IPI_CPU_READY[dest_cpu].load(Ordering::Acquire) {
            return Err(IpiError::CpuOffline);
        }

        let mut queue = unsafe { IPI_EVENT_QUEUE.remote_ref_raw(dest_cpu) }.lock();
        queue.push(this_cpu_id(), callback.into());
        if let Err(error) = axhal::irq::send_ipi(IPI_IRQ, IpiTarget::Other { cpu_id: dest_cpu }) {
            queue.pop_back();
            return Err(error);
        }
        Ok(())
    }
}

/// Executes a callback on all other CPUs via IPI.
pub fn run_on_each_cpu<T: Into<MulticastCallback>>(callback: T) -> Result<(), IpiError> {
    debug!("Send IPI event to all other CPUs");
    let current_cpu_id = this_cpu_id();
    let cpu_num = axhal::cpu_num();
    let callback = callback.into();

    // Execute callback on current CPU immediately
    callback.clone().call();
    // Queue and signal each target atomically so a failed send can be rolled back.
    for cpu_id in 0..cpu_num {
        if cpu_id != current_cpu_id && axhal::is_cpu_online(cpu_id) {
            run_on_cpu(cpu_id, callback.clone().into_unicast())?;
        }
    }
    Ok(())
}

/// Flushes the TLB on every online CPU and waits for completion.
///
/// TLB shootdowns use fixed per-CPU mailboxes instead of queued callbacks so
/// they remain safe when multiple CPUs fault concurrently with IRQs disabled.
pub fn flush_tlb_all_cpus() -> Result<(), TlbShootdownError> {
    flush_tlb_on_cpus(TlbFlushRequest::All, axhal::online_cpu_mask())
}

/// Flushes one ASID on CPUs where that address space may have run.
///
pub fn flush_tlb_asid_cpus(asid: usize) -> Result<(), TlbShootdownError> {
    debug_assert!(asid < TRACKED_ASID_COUNT);
    flush_asid_request(asid, TlbFlushRequest::Asid(asid))
}

/// Flushes a bounded virtual-address range for one ASID on the selected CPUs.
pub fn flush_tlb_asid_range_cpus(
    asid: usize,
    start: usize,
    size: usize,
    changed_pages: usize,
) -> Result<(), TlbShootdownError> {
    debug_assert!(asid < TRACKED_ASID_COUNT);
    debug_assert!(start % PAGE_SIZE_4K == 0);
    debug_assert!(size % PAGE_SIZE_4K == 0);
    if size == 0 {
        return Ok(());
    }
    let Some(end) = start.checked_add(size) else {
        return Err(TlbShootdownError::Incomplete(IpiError::InvalidTarget));
    };
    TLB_SHOOTDOWN_COUNTERS[this_cpu_id()]
        .range_changed_pages
        .fetch_add(changed_pages, Ordering::Relaxed);
    let page_count = size / PAGE_SIZE_4K;
    let request = if page_count <= TLB_RANGE_PAGE_LIMIT {
        TlbFlushRequest::Range {
            asid,
            start,
            end,
        }
    } else {
        TLB_SHOOTDOWN_COUNTERS[this_cpu_id()]
            .range_to_asid_promotions
            .fetch_add(1, Ordering::Relaxed);
        TlbFlushRequest::Asid(asid)
    };
    flush_asid_request(asid, request)
}

fn flush_asid_request(
    asid: usize,
    request: TlbFlushRequest,
) -> Result<(), TlbShootdownError> {
    let generation = ASID_GENERATIONS[asid]
        .fetch_add(1, Ordering::SeqCst)
        .wrapping_add(1);
    let mut target_mask = asid_active_cpu_mask(asid);
    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
    if axhal::asm::read_current_asid() == asid {
        target_mask |= 1usize << this_cpu_id();
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
    {
        target_mask |= 1usize << this_cpu_id();
    }

    let result = flush_tlb_on_cpus(request, target_mask);
    let completion_guaranteed = match &result {
        Ok(()) => true,
        Err(error) => error.completion_guaranteed(),
    };
    if completion_guaranteed {
        record_completed_generation(asid, generation, target_mask);
    }
    result
}

fn record_completed_generation(asid: usize, generation: usize, target_mask: usize) {
    for cpu_id in 0..axhal::cpu_num() {
        if target_mask & (1usize << cpu_id) == 0 {
            continue;
        }
        let seen = &CPU_ASID_GENERATIONS[cpu_id][asid];
        let mut current = seen.load(Ordering::Relaxed);
        while current < generation {
            match seen.compare_exchange_weak(
                current,
                generation,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }
}

fn flush_tlb_on_cpus(
    request: TlbFlushRequest,
    target_mask: usize,
) -> Result<(), TlbShootdownError> {
    let current_cpu_id = this_cpu_id();
    let cpu_num = axhal::cpu_num();
    let current_cpu_bit = 1usize << current_cpu_id;
    let target_mask = target_mask & axhal::online_cpu_mask();
    let remote_mask = target_mask & !current_cpu_bit;
    let mut target_tickets = [0usize; axconfig::plat::MAX_CPU_NUM];
    let counters = &TLB_SHOOTDOWN_COUNTERS[current_cpu_id];
    counters.requests.fetch_add(1, Ordering::Relaxed);
    match request {
        TlbFlushRequest::Range { .. } => {
            counters.range_requests.fetch_add(1, Ordering::Relaxed);
        }
        TlbFlushRequest::Asid(_) => {
            counters.asid_requests.fetch_add(1, Ordering::Relaxed);
        }
        TlbFlushRequest::All => {
            counters.all_requests.fetch_add(1, Ordering::Relaxed);
        }
        TlbFlushRequest::None => {}
    }
    counters
        .target_cpus
        .fetch_add(target_mask.count_ones() as usize, Ordering::Relaxed);
    counters
        .remote_cpus
        .fetch_add(remote_mask.count_ones() as usize, Ordering::Relaxed);
    let target_count = target_mask.count_ones() as usize;
    let remote_count = remote_mask.count_ones() as usize;
    counters
        .max_target_cpus
        .fetch_max(target_count, Ordering::Relaxed);
    counters
        .max_remote_cpus
        .fetch_max(remote_count, Ordering::Relaxed);
    if target_count == 0 {
        counters
            .zero_target_requests
            .fetch_add(1, Ordering::Relaxed);
    } else if remote_count == 0 {
        counters
            .local_only_requests
            .fetch_add(1, Ordering::Relaxed);
    } else {
        counters.remote_requests.fetch_add(1, Ordering::Relaxed);
    }

    // CPU readiness is published before the CPU is marked online and remains
    // stable for its lifetime. Validate every target before publishing any
    // shootdown request so an error cannot leave a partially armed operation.
    for cpu_id in 0..cpu_num {
        if remote_mask & (1usize << cpu_id) == 0 {
            continue;
        }
        if !IPI_CPU_READY[cpu_id].load(Ordering::Acquire) {
            return Err(TlbShootdownError::Incomplete(IpiError::CpuOffline));
        }
    }

    fence(Ordering::Release);
    if target_mask & current_cpu_bit != 0 {
        execute_tlb_flush(request);
    }
    let mut delivery_error = None;
    for cpu_id in 0..cpu_num {
        if remote_mask & (1usize << cpu_id) != 0 {
            let send_result = {
                // Serialize ticket publication with target-side service so
                // completion cannot race ahead of the delivery attempt.
                let mut mailbox = TLB_SHOOTDOWN_MAILBOXES[cpu_id].lock();
                let enqueue = mailbox.batch.enqueue(request);
                if enqueue.coalesced {
                    counters.mailbox_coalesces.fetch_add(1, Ordering::Relaxed);
                }
                if enqueue.promoted_to_asid {
                    counters
                        .range_to_asid_promotions
                        .fetch_add(1, Ordering::Relaxed);
                }
                if enqueue.promoted_to_all {
                    counters.full_promotions.fetch_add(1, Ordering::Relaxed);
                }
                let previous_requested = TLB_SHOOTDOWN_REQUESTED[cpu_id]
                    .fetch_add(1, Ordering::AcqRel);
                let ticket = previous_requested
                    .checked_add(1)
                    .expect("TLB shootdown ticket overflow");
                target_tickets[cpu_id] = ticket;

                let completed = TLB_SHOOTDOWN_COMPLETED[cpu_id].load(Ordering::Acquire);
                if completed >= previous_requested {
                    counters.ipi_sends.fetch_add(1, Ordering::Relaxed);
                    axhal::irq::send_ipi(IPI_IRQ, IpiTarget::Other { cpu_id })
                } else {
                    counters.ipi_sends_avoided.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
            };

            if let Err(error) = send_result {
                delivery_error.get_or_insert(error);
            }
        }
    }

    // Keep failed deliveries armed: the periodic interrupt path services the
    // mailbox, so no caller observes an error while a remote stale TLB remains.
    let wait_spins = wait_for_tlb_shootdowns(remote_mask, &target_tickets, cpu_num);
    counters.wait_spins.fetch_add(wait_spins, Ordering::Relaxed);
    delivery_error.map_or(Ok(()), |error| Err(TlbShootdownError::Completed(error)))
}

#[inline]
fn merge_tlb_flush(pending: TlbFlushRequest, requested: TlbFlushRequest) -> TlbFlushRequest {
    use TlbFlushRequest::{All, Asid, None, Range};

    match (pending, requested) {
        (None, request) | (request, None) => request,
        (All, _) | (_, All) => All,
        (Asid(left), Asid(right)) if left == right => Asid(left),
        (Asid(left), Range { asid, .. }) | (Range { asid, .. }, Asid(left))
            if left == asid =>
        {
            Asid(left)
        }
        (
            Range {
                asid: left_asid,
                start: left_start,
                end: left_end,
            },
            Range {
                asid: right_asid,
                start: right_start,
                end: right_end,
            },
        ) if left_asid == right_asid => {
            let start = left_start.min(right_start);
            let end = left_end.max(right_end);
            if end.saturating_sub(start) / PAGE_SIZE_4K <= TLB_RANGE_PAGE_LIMIT {
                Range {
                    asid: left_asid,
                    start,
                    end,
                }
            } else {
                Asid(left_asid)
            }
        }
        _ => All,
    }
}

#[inline]
fn execute_tlb_flush(request: TlbFlushRequest) {
    match request {
        TlbFlushRequest::None => {}
        TlbFlushRequest::Range { asid, start, end } => {
            for addr in (start..end).step_by(PAGE_SIZE_4K) {
                #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
                axhal::asm::flush_tlb_asid_vaddr(asid, VirtAddr::from(addr));
                #[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
                {
                    let _ = asid;
                    axhal::asm::flush_tlb(Some(VirtAddr::from(addr)));
                }
            }
        }
        TlbFlushRequest::Asid(asid) => axhal::asm::flush_tlb_asid(asid),
        TlbFlushRequest::All => axhal::asm::flush_tlb(None),
    }
}

fn wait_for_tlb_shootdowns(
    target_mask: usize,
    target_tickets: &[usize],
    cpu_num: usize,
) -> usize {
    let mut spins = 0usize;
    while (0..cpu_num).any(|cpu_id| {
        target_mask & (1usize << cpu_id) != 0
            && TLB_SHOOTDOWN_COMPLETED[cpu_id].load(Ordering::Acquire) < target_tickets[cpu_id]
    }) {
        // A peer can be waiting here with IRQs disabled as well. Only service
        // the fixed TLB mailbox; draining arbitrary IPI callbacks is unsafe in
        // a page-fault critical section.
        service_tlb_shootdown();
        core::hint::spin_loop();
        spins = spins.saturating_add(1);
    }
    spins
}

/// Services pending fixed-mailbox TLB shootdowns on the current CPU.
///
/// A periodic interrupt must also call this so a failed IPI delivery cannot
/// leave a pending TLB shootdown unserviced.
pub fn service_tlb_shootdown() {
    let cpu_id = this_cpu_id();
    let mut mailbox = TLB_SHOOTDOWN_MAILBOXES[cpu_id].lock();
    loop {
        let requested = TLB_SHOOTDOWN_REQUESTED[cpu_id].load(Ordering::Acquire);
        if TLB_SHOOTDOWN_COMPLETED[cpu_id].load(Ordering::Relaxed) >= requested {
            return;
        }
        fence(Ordering::Acquire);
        let batch = mailbox.batch.take();
        for request in batch.iter() {
            execute_tlb_flush(request);
        }
        TLB_SHOOTDOWN_COMPLETED[cpu_id].store(requested, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::{TlbFlushBatch, TlbFlushRequest, merge_tlb_flush};

    #[test]
    fn merges_nearby_ranges_for_one_asid() {
        let left = TlbFlushRequest::Range {
            asid: 7,
            start: 0x1000,
            end: 0x3000,
        };
        let right = TlbFlushRequest::Range {
            asid: 7,
            start: 0x3000,
            end: 0x5000,
        };
        assert_eq!(
            merge_tlb_flush(left, right),
            TlbFlushRequest::Range {
                asid: 7,
                start: 0x1000,
                end: 0x5000,
            }
        );
    }

    #[test]
    fn promotes_large_range_to_asid() {
        let left = TlbFlushRequest::Range {
            asid: 11,
            start: 0,
            end: 0x1000,
        };
        let right = TlbFlushRequest::Range {
            asid: 11,
            start: 0x20000,
            end: 0x21000,
        };
        assert_eq!(merge_tlb_flush(left, right), TlbFlushRequest::Asid(11));
    }

    #[test]
    fn mailbox_reports_range_to_asid_promotion() {
        let mut batch = TlbFlushBatch::new();
        batch.enqueue(TlbFlushRequest::Range {
            asid: 11,
            start: 0,
            end: 0x1000,
        });
        let result = batch.enqueue(TlbFlushRequest::Range {
            asid: 11,
            start: 0x20000,
            end: 0x21000,
        });

        assert!(result.coalesced);
        assert!(result.promoted_to_asid);
        assert_eq!(
            batch.iter().collect::<alloc::vec::Vec<_>>(),
            [TlbFlushRequest::Asid(11)]
        );
    }

    #[test]
    fn different_asids_share_mailbox_without_global_flush() {
        let mut batch = TlbFlushBatch::new();
        batch.enqueue(TlbFlushRequest::Asid(1));
        batch.enqueue(TlbFlushRequest::Asid(2));
        assert_eq!(batch.iter().collect::<alloc::vec::Vec<_>>(), [
            TlbFlushRequest::Asid(1),
            TlbFlushRequest::Asid(2),
        ]);
    }

    #[test]
    fn mailbox_overflow_promotes_to_global_flush() {
        let mut batch = TlbFlushBatch::new();
        for asid in 0..4 {
            batch.enqueue(TlbFlushRequest::Asid(asid));
        }
        let result = batch.enqueue(TlbFlushRequest::Asid(4));
        assert!(result.promoted_to_all);
        assert_eq!(batch.iter().collect::<alloc::vec::Vec<_>>(), [
            TlbFlushRequest::All,
        ]);
    }
}

/// The handler for IPI events. It retrieves the events from the queue and calls the corresponding callbacks.
pub fn ipi_handler() {
    service_tlb_shootdown();
    while let Some((src_cpu_id, callback)) = unsafe { IPI_EVENT_QUEUE.current_ref_mut_raw() }
        .lock()
        .pop_one()
    {
        debug!("Received IPI event from CPU {}", src_cpu_id);
        callback.call();
    }
    service_tlb_shootdown();
}
