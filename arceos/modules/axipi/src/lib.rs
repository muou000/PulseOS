//! [ArceOS](https://github.com/arceos-org/arceos) Inter-Processor Interrupt (IPI) primitives.

#![cfg_attr(not(test), no_std)]

#[macro_use]
extern crate log;
extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering, fence};

use axhal::{
    irq::{IPI_IRQ, IpiError, IpiTarget},
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
const TLB_FLUSH_ALL: usize = usize::MAX - 1;
const TLB_FLUSH_NONE: usize = usize::MAX;

static ASID_ACTIVE_CPU_MASKS: [AtomicUsize; TRACKED_ASID_COUNT] =
    [const { AtomicUsize::new(0) }; TRACKED_ASID_COUNT];
static TLB_SHOOTDOWN_REQUESTED: [AtomicUsize; axconfig::plat::MAX_CPU_NUM] =
    [const { AtomicUsize::new(0) }; axconfig::plat::MAX_CPU_NUM];
static TLB_SHOOTDOWN_COMPLETED: [AtomicUsize; axconfig::plat::MAX_CPU_NUM] =
    [const { AtomicUsize::new(0) }; axconfig::plat::MAX_CPU_NUM];
static TLB_SHOOTDOWN_FLUSH: [AtomicUsize; axconfig::plat::MAX_CPU_NUM] =
    [const { AtomicUsize::new(TLB_FLUSH_NONE) }; axconfig::plat::MAX_CPU_NUM];
static TLB_SHOOTDOWN_STATE_LOCKS: [SpinNoIrq<()>; axconfig::plat::MAX_CPU_NUM] =
    [const { SpinNoIrq::new(()) }; axconfig::plat::MAX_CPU_NUM];

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

/// Records that the current CPU may cache translations for `asid`.
pub fn mark_current_cpu_asid_active(asid: usize) {
    let Some(mask) = ASID_ACTIVE_CPU_MASKS.get(asid) else {
        return;
    };
    let bit = 1usize << this_cpu_id();
    if mask.load(Ordering::Relaxed) & bit == 0 {
        mask.fetch_or(bit, Ordering::Release);
    }
}

/// Returns the online CPUs that may cache translations for `asid`.
pub fn asid_active_cpu_mask(asid: usize) -> usize {
    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
    {
        ASID_ACTIVE_CPU_MASKS
            .get(asid)
            .map(|mask| mask.load(Ordering::Acquire) & axhal::online_cpu_mask())
            .unwrap_or_else(axhal::online_cpu_mask)
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
    {
        let _ = asid;
        axhal::online_cpu_mask()
    }
}

/// Clears CPU residency state before a retired ASID is reused.
pub fn reset_asid_active_cpu_mask(asid: usize) {
    if let Some(mask) = ASID_ACTIVE_CPU_MASKS.get(asid) {
        mask.store(0, Ordering::Release);
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
    flush_tlb_on_cpus(TLB_FLUSH_ALL, axhal::online_cpu_mask())
}

/// Flushes one ASID on CPUs where that address space may have run.
///
/// The current CPU is always included as a conservative fallback for callers
/// that mutate a page table before their task residency has been published.
pub fn flush_tlb_asid_cpus(asid: usize, target_mask: usize) -> Result<(), TlbShootdownError> {
    debug_assert!(asid < TRACKED_ASID_COUNT);
    let target_mask = target_mask | (1usize << this_cpu_id());
    flush_tlb_on_cpus(asid, target_mask)
}

fn flush_tlb_on_cpus(flush: usize, target_mask: usize) -> Result<(), TlbShootdownError> {
    let current_cpu_id = this_cpu_id();
    let cpu_num = axhal::cpu_num();
    let current_cpu_bit = 1usize << current_cpu_id;
    let target_mask = target_mask & axhal::online_cpu_mask();
    let remote_mask = target_mask & !current_cpu_bit;
    let mut target_tickets = [0usize; axconfig::plat::MAX_CPU_NUM];

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
        execute_tlb_flush(flush);
    }
    let mut delivery_error = None;
    for cpu_id in 0..cpu_num {
        if remote_mask & (1usize << cpu_id) != 0 {
            let send_result = {
                // Serialize ticket publication with target-side service so
                // completion cannot race ahead of the delivery attempt.
                let _state_guard = TLB_SHOOTDOWN_STATE_LOCKS[cpu_id].lock();
                let pending = TLB_SHOOTDOWN_FLUSH[cpu_id].load(Ordering::Relaxed);
                TLB_SHOOTDOWN_FLUSH[cpu_id]
                    .store(merge_tlb_flush(pending, flush), Ordering::Release);
                let ticket = TLB_SHOOTDOWN_REQUESTED[cpu_id]
                    .fetch_add(1, Ordering::AcqRel)
                    .checked_add(1)
                    .expect("TLB shootdown ticket overflow");
                target_tickets[cpu_id] = ticket;

                axhal::irq::send_ipi(IPI_IRQ, IpiTarget::Other { cpu_id })
            };

            if let Err(error) = send_result {
                delivery_error.get_or_insert(error);
            }
        }
    }

    // Keep failed deliveries armed: the periodic interrupt path services the
    // mailbox, so no caller observes an error while a remote stale TLB remains.
    wait_for_tlb_shootdowns(remote_mask, &target_tickets, cpu_num);
    delivery_error.map_or(Ok(()), |error| Err(TlbShootdownError::Completed(error)))
}

#[inline]
fn merge_tlb_flush(pending: usize, requested: usize) -> usize {
    if pending == TLB_FLUSH_NONE || pending == requested {
        requested
    } else {
        TLB_FLUSH_ALL
    }
}

#[inline]
fn execute_tlb_flush(flush: usize) {
    if flush < TRACKED_ASID_COUNT {
        axhal::asm::flush_tlb_asid(flush);
    } else {
        axhal::asm::flush_tlb(None);
    }
}

fn wait_for_tlb_shootdowns(target_mask: usize, target_tickets: &[usize], cpu_num: usize) {
    while (0..cpu_num).any(|cpu_id| {
        target_mask & (1usize << cpu_id) != 0
            && TLB_SHOOTDOWN_COMPLETED[cpu_id].load(Ordering::Acquire) < target_tickets[cpu_id]
    }) {
        // A peer can be waiting here with IRQs disabled as well. Only service
        // the fixed TLB mailbox; draining arbitrary IPI callbacks is unsafe in
        // a page-fault critical section.
        service_tlb_shootdown();
        core::hint::spin_loop();
    }
}

/// Services pending fixed-mailbox TLB shootdowns on the current CPU.
///
/// A periodic interrupt must also call this so a failed IPI delivery cannot
/// leave a pending TLB shootdown unserviced.
pub fn service_tlb_shootdown() {
    let cpu_id = this_cpu_id();
    let _state_guard = TLB_SHOOTDOWN_STATE_LOCKS[cpu_id].lock();
    loop {
        let requested = TLB_SHOOTDOWN_REQUESTED[cpu_id].load(Ordering::Acquire);
        if TLB_SHOOTDOWN_COMPLETED[cpu_id].load(Ordering::Relaxed) >= requested {
            return;
        }
        fence(Ordering::Acquire);
        let flush = TLB_SHOOTDOWN_FLUSH[cpu_id].swap(TLB_FLUSH_NONE, Ordering::AcqRel);
        execute_tlb_flush(flush);
        TLB_SHOOTDOWN_COMPLETED[cpu_id].store(requested, Ordering::Release);
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
