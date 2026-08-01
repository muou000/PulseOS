//! Feature-gated guest marker ABI consumed by the qperf QEMU plugin.

use crate::{TaskInner, WaitContext, WakeContext};

pub const TRACE_SYMBOL: &str = "__pulse_qperf_trace_v1";

const TASK_METADATA: u64 = 1;
const SCHED_SWITCH: u64 = 2;
const TASK_BLOCK: u64 = 3;
const TASK_WAKE: u64 = 4;
const TASK_EXIT: u64 = 5;
const TASK_ENQUEUE: u64 = 6;
const PHASE_MARKER: u64 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum PhaseBoundary {
    Begin = 1,
    End   = 2,
}

#[derive(Clone, Copy)]
pub(crate) enum EnqueueReason {
    Spawn             = 1,
    Wake              = 2,
    Preempt           = 3,
    Yield             = 4,
    AffinityMigration = 5,
    DeferredWake      = 6,
    #[allow(dead_code)] // Unused when scheduler load balancing is disabled.
    WorkSteal         = 7,
}

/// Stable marker entry recognized by qperf when the `qperf-trace` feature is enabled.
///
/// The function is intentionally a no-op in the guest. qperf instruments its entry
/// address and reads the six ABI argument registers before the body executes.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __pulse_qperf_trace_v1(
    kind: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
) {
    core::hint::black_box((kind, arg0, arg1, arg2, arg3, arg4));
}

#[inline]
fn emit(kind: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) {
    __pulse_qperf_trace_v1(kind, arg0, arg1, arg2, arg3, arg4);
}

pub fn task_metadata(task_id: u64, pid: u64, tid: u64, comm: &[u8]) {
    let mut encoded = [0_u8; 16];
    let len = comm.len().min(encoded.len());
    encoded[..len].copy_from_slice(&comm[..len]);
    let comm0 = u64::from_le_bytes(encoded[..8].try_into().unwrap());
    let comm1 = u64::from_le_bytes(encoded[8..].try_into().unwrap());
    emit(TASK_METADATA, task_id, pid, tid, comm0, comm1);
}

pub(crate) fn sched_switch(prev_task: &TaskInner, next_task: &TaskInner, prev_state: u8) {
    emit(
        SCHED_SWITCH,
        prev_task.id().as_u64(),
        next_task.id().as_u64(),
        u64::from(prev_state),
        0,
        0,
    );
}

pub(crate) fn task_block(task: &TaskInner, sequence: u64, context: WaitContext) {
    emit(
        TASK_BLOCK,
        task.id().as_u64(),
        sequence,
        context.reason() as u64,
        context.resource_id(),
        context.resource_detail(),
    );
}

pub(crate) fn task_wake(task: &TaskInner, context: WakeContext) {
    let waker_task_id = crate::CurrentTask::try_get()
        .map(|current| current.id().as_u64())
        .unwrap_or(0);
    emit(
        TASK_WAKE,
        task.id().as_u64(),
        task.qperf_block_sequence(),
        waker_task_id,
        context.source() as u64,
        context.source_id(),
    );
}

pub(crate) fn task_exit(task: &TaskInner) {
    emit(TASK_EXIT, task.id().as_u64(), 0, 0, 0, 0);
}

pub(crate) fn task_enqueue(
    task: &TaskInner,
    enqueue_cpu: usize,
    target_cpu: usize,
    queue_depth: usize,
    reason: EnqueueReason,
) {
    emit(
        TASK_ENQUEUE,
        task.id().as_u64(),
        enqueue_cpu as u64,
        target_cpu as u64,
        queue_depth as u64,
        reason as u64,
    );
}

pub fn phase_marker(boundary: PhaseBoundary, phase: &[u8]) {
    let mut encoded = [0_u8; 16];
    let len = phase.len().min(encoded.len());
    encoded[..len].copy_from_slice(&phase[..len]);
    let phase0 = u64::from_le_bytes(encoded[..8].try_into().unwrap());
    let phase1 = u64::from_le_bytes(encoded[8..].try_into().unwrap());
    let task_id = crate::CurrentTask::try_get()
        .map(|current| current.id().as_u64())
        .unwrap_or(0);
    emit(PHASE_MARKER, boundary as u64, task_id, phase0, phase1, 0);
}
