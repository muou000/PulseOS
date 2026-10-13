//! Semantic tracepoint registry and BPF v1 event hooks.

pub use pulse_bpf_schema::*;

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use crate::{TaskInner, WaitContext, WakeContext};

pub const TRACE_QUEUE_CAPACITY: usize = 128;
pub const MAX_CPUS: usize = axconfig::plat::MAX_CPU_NUM;

static SUBSCRIBER_MASK: AtomicU32 = AtomicU32::new(0);

static CPU_QUEUES: [BoundedTraceQueue<TRACE_QUEUE_CAPACITY>; MAX_CPUS] =
    [const { BoundedTraceQueue::new() }; MAX_CPUS];

static DRAIN_LOCKS: [kspin::SpinNoIrq<()>; MAX_CPUS] =
    [const { kspin::SpinNoIrq::new(()) }; MAX_CPUS];

#[deprecated(note = "Direct synchronous probes in critical paths are removed for safety; use bounded drain")]
pub type TracepointProbe = fn(id: TracepointId, context_ptr: *const u8, context_len: usize);

#[deprecated(note = "Direct synchronous probes in critical paths are removed for safety; use bounded drain")]
pub fn set_probe_handler(_handler: Option<TracepointProbe>) {}

#[inline(always)]
pub fn has_subscribers(id: TracepointId) -> bool {
    (SUBSCRIBER_MASK.load(Ordering::Relaxed) & (1 << (id as u32))) != 0
}

#[inline(always)]
pub fn register_probe(id: TracepointId) {
    SUBSCRIBER_MASK.fetch_or(1 << (id as u32), Ordering::Release);
}

#[inline(always)]
pub fn unregister_probe(id: TracepointId) {
    SUBSCRIBER_MASK.fetch_and(!(1 << (id as u32)), Ordering::Release);
}

/// Query drop and enqueue statistics for a specific CPU.
#[inline]
pub fn cpu_drop_stats(cpu_id: usize) -> DropStats {
    if cpu_id < MAX_CPUS {
        CPU_QUEUES[cpu_id].drop_stats()
    } else {
        DropStats::default()
    }
}

/// Query aggregated drop and enqueue statistics across all CPUs.
pub fn total_drop_stats() -> DropStats {
    let mut total = DropStats::default();
    for q in &CPU_QUEUES {
        let s = q.drop_stats();
        total.dropped_full += s.dropped_full;
        total.dropped_recursive += s.dropped_recursive;
        total.total_enqueued += s.total_enqueued;
    }
    total
}

/// Reset drop and enqueue statistics across all CPUs.
pub fn reset_drop_stats() {
    for q in &CPU_QUEUES {
        q.reset_drop_stats();
    }
}

/// Drain up to `max_count` events from the specified CPU's bounded buffer.
/// Safe and nonblocking for event producers; only contends with other concurrent drainers of the same CPU.
pub fn drain_cpu_events<F: FnMut(TracepointId, &[u8])>(
    cpu_id: usize,
    max_count: usize,
    consumer: F,
) -> usize {
    if cpu_id >= MAX_CPUS {
        return 0;
    }
    let _guard = DRAIN_LOCKS[cpu_id].lock();
    CPU_QUEUES[cpu_id].drain(max_count, consumer)
}

/// Drain events from all CPUs' bounded buffers.
pub fn drain_all_events<F: FnMut(usize, TracepointId, &[u8])>(
    max_count_per_cpu: usize,
    mut consumer: F,
) -> usize {
    let mut total = 0;
    for cpu_id in 0..MAX_CPUS {
        total += drain_cpu_events(cpu_id, max_count_per_cpu, |id, slice| {
            consumer(cpu_id, id, slice);
        });
    }
    total
}

#[inline(always)]
fn enqueue_event<T: Copy>(id: TracepointId, ctx: &T) {
    let _guard = kernel_guard::NoPreemptIrqSave::new();
    let cpu_id = axhal::percpu::this_cpu_id();
    if cpu_id < MAX_CPUS {
        let slice = unsafe {
            core::slice::from_raw_parts(ctx as *const T as *const u8, core::mem::size_of::<T>())
        };
        let _ = CPU_QUEUES[cpu_id].enqueue_bytes(id, slice);
    }
}

#[inline(always)]
pub fn sched_switch(prev_task: &TaskInner, next_task: &TaskInner, prev_state: u8) {
    if !has_subscribers(TracepointId::SchedSwitch) {
        return;
    }
    let timestamp_ns = axhal::time::monotonic_time_nanos();
    let cpu_id = axhal::percpu::this_cpu_id() as u32;
    let ctx = SchedSwitchContext {
        common: ContextCommon::new(
            TracepointId::SchedSwitch,
            timestamp_ns,
            cpu_id,
            0,
            0,
            prev_task.id().as_u64(),
        ),
        prev_task_id: prev_task.id().as_u64(),
        next_task_id: next_task.id().as_u64(),
        prev_state: prev_state as u32,
        prev_prio: 0,
        next_prio: 0,
        _pad: 0,
    };
    enqueue_event(TracepointId::SchedSwitch, &ctx);
}

#[inline(always)]
pub fn task_block(task: &TaskInner, sequence: u64, context: WaitContext) {
    if !has_subscribers(TracepointId::TaskBlock) {
        return;
    }
    let timestamp_ns = axhal::time::monotonic_time_nanos();
    let cpu_id = axhal::percpu::this_cpu_id() as u32;
    #[cfg(any(feature = "qperf-trace", feature = "bpf-trace"))]
    let (wait_reason, resource_id, resource_detail) = (
        context.reason() as u32,
        context.resource_id(),
        context.resource_detail(),
    );
    #[cfg(not(any(feature = "qperf-trace", feature = "bpf-trace")))]
    let (wait_reason, resource_id, resource_detail) = {
        let _ = context;
        (0, 0, 0)
    };

    let ctx = TaskBlockContext {
        common: ContextCommon::new(
            TracepointId::TaskBlock,
            timestamp_ns,
            cpu_id,
            0,
            0,
            task.id().as_u64(),
        ),
        block_sequence: sequence,
        wait_reason,
        _pad: 0,
        resource_id,
        resource_detail,
    };
    enqueue_event(TracepointId::TaskBlock, &ctx);
}

#[inline(always)]
pub fn task_wake(task: &TaskInner, sequence: u64, waker_task_id: u64, context: WakeContext) {
    if !has_subscribers(TracepointId::TaskWake) {
        return;
    }
    let timestamp_ns = axhal::time::monotonic_time_nanos();
    let cpu_id = axhal::percpu::this_cpu_id() as u32;
    #[cfg(any(feature = "qperf-trace", feature = "bpf-trace"))]
    let (wake_source, source_id) = (context.source() as u32, context.source_id());
    #[cfg(not(any(feature = "qperf-trace", feature = "bpf-trace")))]
    let (wake_source, source_id) = {
        let _ = context;
        (0, 0)
    };

    let ctx = TaskWakeContext {
        common: ContextCommon::new(
            TracepointId::TaskWake,
            timestamp_ns,
            cpu_id,
            0,
            0,
            waker_task_id,
        ),
        target_task_id: task.id().as_u64(),
        block_sequence: sequence,
        waker_task_id,
        wake_source,
        _pad: 0,
        source_id,
    };
    enqueue_event(TracepointId::TaskWake, &ctx);
}

#[inline(always)]
pub fn task_exit(task: &TaskInner) {
    if !has_subscribers(TracepointId::TaskExit) {
        return;
    }
    let timestamp_ns = axhal::time::monotonic_time_nanos();
    let cpu_id = axhal::percpu::this_cpu_id() as u32;
    let ctx = TaskExitContext {
        common: ContextCommon::new(
            TracepointId::TaskExit,
            timestamp_ns,
            cpu_id,
            0,
            0,
            task.id().as_u64(),
        ),
        exit_task_id: task.id().as_u64(),
        exit_code: 0,
        _pad: 0,
    };
    enqueue_event(TracepointId::TaskExit, &ctx);
}

#[inline(always)]
pub fn task_enqueue(
    task: &TaskInner,
    enqueue_cpu: usize,
    target_cpu: usize,
    queue_depth: usize,
    reason: u32,
) {
    if !has_subscribers(TracepointId::TaskEnqueue) {
        return;
    }
    let timestamp_ns = axhal::time::monotonic_time_nanos();
    let cpu_id = axhal::percpu::this_cpu_id() as u32;
    let ctx = TaskEnqueueContext {
        common: ContextCommon::new(
            TracepointId::TaskEnqueue,
            timestamp_ns,
            cpu_id,
            0,
            0,
            task.id().as_u64(),
        ),
        enqueue_task_id: task.id().as_u64(),
        enqueue_cpu: enqueue_cpu as u32,
        target_cpu: target_cpu as u32,
        queue_depth: queue_depth as u32,
        enqueue_reason: reason,
    };
    enqueue_event(TracepointId::TaskEnqueue, &ctx);
}

#[inline(always)]
pub fn task_metadata(task_id: u64, pid: u64, tid: u64, comm: &[u8]) {
    if !has_subscribers(TracepointId::TaskMetadata) {
        return;
    }
    let timestamp_ns = axhal::time::monotonic_time_nanos();
    let cpu_id = axhal::percpu::this_cpu_id() as u32;
    let mut comm_fixed = [0u8; 16];
    let len = comm.len().min(16);
    comm_fixed[..len].copy_from_slice(&comm[..len]);
    let ctx = TaskMetadataContext {
        common: ContextCommon::new(
            TracepointId::TaskMetadata,
            timestamp_ns,
            cpu_id,
            pid as u32,
            tid as u32,
            task_id,
        ),
        target_task_id: task_id,
        target_pid: pid as u32,
        target_tid: tid as u32,
        comm: comm_fixed,
    };
    enqueue_event(TracepointId::TaskMetadata, &ctx);
}

#[inline(always)]
pub fn phase_marker(boundary: u32, phase: &[u8]) {
    if !has_subscribers(TracepointId::PhaseMarker) {
        return;
    }
    let timestamp_ns = axhal::time::monotonic_time_nanos();
    let cpu_id = axhal::percpu::this_cpu_id() as u32;
    let task_id = crate::CurrentTask::try_get().map(|c| c.id().as_u64()).unwrap_or(0);
    let mut phase_fixed = [0u8; 16];
    let len = phase.len().min(16);
    phase_fixed[..len].copy_from_slice(&phase[..len]);
    let ctx = PhaseMarkerContext {
        common: ContextCommon::new(
            TracepointId::PhaseMarker,
            timestamp_ns,
            cpu_id,
            0,
            0,
            task_id,
        ),
        phase_boundary: boundary,
        phase_len: len as u32,
        phase_name: phase_fixed,
    };
    enqueue_event(TracepointId::PhaseMarker, &ctx);
}

// -----------------------------------------------------------------------------
// Static checks for critical call sites
// -----------------------------------------------------------------------------

const _: () = {
    assert!(core::mem::size_of::<SchedSwitchContext>() <= MAX_CONTEXT_SIZE);
    assert!(core::mem::size_of::<TaskBlockContext>() <= MAX_CONTEXT_SIZE);
    assert!(core::mem::size_of::<TaskWakeContext>() <= MAX_CONTEXT_SIZE);
    assert!(core::mem::size_of::<TaskExitContext>() <= MAX_CONTEXT_SIZE);
    assert!(core::mem::size_of::<TaskEnqueueContext>() <= MAX_CONTEXT_SIZE);
    assert!(core::mem::size_of::<TaskMetadataContext>() <= MAX_CONTEXT_SIZE);
    assert!(core::mem::size_of::<PhaseMarkerContext>() <= MAX_CONTEXT_SIZE);
};

