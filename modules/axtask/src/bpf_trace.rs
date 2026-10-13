//! Semantic tracepoint registry and BPF v1 event hooks.

pub use pulse_bpf_schema::*;

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use crate::{TaskInner, WaitContext, WakeContext};

static SUBSCRIBER_MASK: AtomicU32 = AtomicU32::new(0);

pub type TracepointProbe = fn(id: TracepointId, context_ptr: *const u8, context_len: usize);
static PROBE_HANDLER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

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

pub fn set_probe_handler(handler: Option<TracepointProbe>) {
    let ptr = match handler {
        Some(h) => h as *const () as *mut (),
        None => core::ptr::null_mut(),
    };
    PROBE_HANDLER.store(ptr, Ordering::Release);
}

#[inline(always)]
fn dispatch_probe(id: TracepointId, ptr: *const u8, len: usize) {
    let raw_fn = PROBE_HANDLER.load(Ordering::Acquire);
    if !raw_fn.is_null() {
        let probe: TracepointProbe = unsafe { core::mem::transmute(raw_fn) };
        probe(id, ptr, len);
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
    dispatch_probe(
        TracepointId::SchedSwitch,
        &ctx as *const SchedSwitchContext as *const u8,
        core::mem::size_of::<SchedSwitchContext>(),
    );
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
    dispatch_probe(
        TracepointId::TaskBlock,
        &ctx as *const TaskBlockContext as *const u8,
        core::mem::size_of::<TaskBlockContext>(),
    );
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
    dispatch_probe(
        TracepointId::TaskWake,
        &ctx as *const TaskWakeContext as *const u8,
        core::mem::size_of::<TaskWakeContext>(),
    );
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
    dispatch_probe(
        TracepointId::TaskExit,
        &ctx as *const TaskExitContext as *const u8,
        core::mem::size_of::<TaskExitContext>(),
    );
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
    dispatch_probe(
        TracepointId::TaskEnqueue,
        &ctx as *const TaskEnqueueContext as *const u8,
        core::mem::size_of::<TaskEnqueueContext>(),
    );
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
    dispatch_probe(
        TracepointId::TaskMetadata,
        &ctx as *const TaskMetadataContext as *const u8,
        core::mem::size_of::<TaskMetadataContext>(),
    );
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
    dispatch_probe(
        TracepointId::PhaseMarker,
        &ctx as *const PhaseMarkerContext as *const u8,
        core::mem::size_of::<PhaseMarkerContext>(),
    );
}

