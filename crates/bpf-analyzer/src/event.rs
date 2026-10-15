use bpf_capture::record::NormalizedRecord;
use bpf_capture::schema::PERF_EVENT_SOFTWARE_ID;
use pulse_bpf_schema::{PhaseBoundary, TracepointId};
use std::collections::HashMap;

/// Parsed typed event payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventPayload {
    TaskMetadata {
        target_task_id: u64,
        target_pid: u32,
        target_tid: u32,
        comm: String,
    },
    SchedSwitch {
        prev_task_id: u64,
        next_task_id: u64,
        prev_state: u32,
        prev_prio: u32,
        next_prio: u32,
    },
    TaskBlock {
        block_sequence: u64,
        wait_reason: u32,
        resource_id: u64,
        resource_detail: u64,
    },
    TaskWake {
        target_task_id: u64,
        block_sequence: u64,
        waker_task_id: u64,
        wake_source: u32,
        source_id: u64,
    },
    TaskExit {
        exit_task_id: u64,
        exit_code: i32,
    },
    TaskEnqueue {
        enqueue_task_id: u64,
        enqueue_cpu: u32,
        target_cpu: u32,
        queue_depth: u32,
        enqueue_reason: u32,
    },
    PhaseMarker {
        phase_boundary: PhaseBoundary,
        phase_name: String,
    },
    SoftwareSample {
        sample_period: u64,
        pc: u64,
    },
    Raw {
        bytes: Vec<u8>,
    },
}

/// Normalized event with common context and resolved task comm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedEvent {
    pub sequence_index: usize,
    pub event_id: u32,
    pub schema_version: u32,
    pub timestamp_ns: u64,
    pub cpu_id: u32,
    pub pid: u32,
    pub tid: u32,
    pub task_id: u64,
    pub comm: Option<String>,
    pub payload: EventPayload,
}

impl NormalizedEvent {
    pub fn event_name(&self) -> &'static str {
        match self.event_id {
            x if x == TracepointId::TaskMetadata as u32 => "task_metadata",
            x if x == TracepointId::SchedSwitch as u32 => "sched_switch",
            x if x == TracepointId::TaskBlock as u32 => "task_block",
            x if x == TracepointId::TaskWake as u32 => "task_wake",
            x if x == TracepointId::TaskExit as u32 => "task_exit",
            x if x == TracepointId::TaskEnqueue as u32 => "task_enqueue",
            x if x == TracepointId::PhaseMarker as u32 => "phase_marker",
            x if x == PERF_EVENT_SOFTWARE_ID => "perf_sample",
            _ => "unknown",
        }
    }
}

fn parse_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

pub fn parse_records(records: &[NormalizedRecord]) -> Vec<NormalizedEvent> {
    // 1. Build initial task comm mapping
    let mut comm_map: HashMap<u64, String> = HashMap::new();
    for rec in records {
        if rec.event_id == TracepointId::TaskMetadata as u32 && rec.payload.len() >= 32 {
            let target_task_id = u64::from_le_bytes(rec.payload[0..8].try_into().unwrap());
            let comm = parse_string(&rec.payload[16..32]);
            if !comm.is_empty() {
                comm_map.insert(target_task_id, comm);
            }
        }
    }

    // 2. Parse records into NormalizedEvent
    let mut parsed: Vec<NormalizedEvent> = records
        .iter()
        .enumerate()
        .map(|(idx, rec)| {
            let payload = parse_payload(rec.event_id, &rec.payload);
            let comm = comm_map.get(&rec.task_id).cloned().or_else(|| {
                if let EventPayload::TaskMetadata { ref comm, .. } = payload {
                    Some(comm.clone())
                } else {
                    None
                }
            });

            NormalizedEvent {
                sequence_index: idx,
                event_id: rec.event_id,
                schema_version: rec.schema_version,
                timestamp_ns: rec.timestamp_ns,
                cpu_id: rec.cpu_id,
                pid: rec.pid,
                tid: rec.tid,
                task_id: rec.task_id,
                comm,
                payload,
            }
        })
        .collect();

    // 3. Anchor A2: Sort globally by timestamp_ns ascending, with stable tie-breaker
    parsed.sort_by(|a, b| {
        a.timestamp_ns
            .cmp(&b.timestamp_ns)
            .then_with(|| a.sequence_index.cmp(&b.sequence_index))
    });

    parsed
}

fn parse_payload(event_id: u32, payload: &[u8]) -> EventPayload {
    match event_id {
        x if x == TracepointId::TaskMetadata as u32 && payload.len() >= 32 => {
            let target_task_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            let target_pid = u32::from_le_bytes(payload[8..12].try_into().unwrap());
            let target_tid = u32::from_le_bytes(payload[12..16].try_into().unwrap());
            let comm = parse_string(&payload[16..32]);
            EventPayload::TaskMetadata {
                target_task_id,
                target_pid,
                target_tid,
                comm,
            }
        }
        x if x == TracepointId::SchedSwitch as u32 && payload.len() >= 28 => {
            let prev_task_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            let next_task_id = u64::from_le_bytes(payload[8..16].try_into().unwrap());
            let prev_state = u32::from_le_bytes(payload[16..20].try_into().unwrap());
            let prev_prio = u32::from_le_bytes(payload[20..24].try_into().unwrap());
            let next_prio = u32::from_le_bytes(payload[24..28].try_into().unwrap());
            EventPayload::SchedSwitch {
                prev_task_id,
                next_task_id,
                prev_state,
                prev_prio,
                next_prio,
            }
        }
        x if x == TracepointId::TaskBlock as u32 && payload.len() >= 32 => {
            let block_sequence = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            let wait_reason = u32::from_le_bytes(payload[8..12].try_into().unwrap());
            let resource_id = u64::from_le_bytes(payload[16..24].try_into().unwrap());
            let resource_detail = u64::from_le_bytes(payload[24..32].try_into().unwrap());
            EventPayload::TaskBlock {
                block_sequence,
                wait_reason,
                resource_id,
                resource_detail,
            }
        }
        x if x == TracepointId::TaskWake as u32 && payload.len() >= 40 => {
            let target_task_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            let block_sequence = u64::from_le_bytes(payload[8..16].try_into().unwrap());
            let waker_task_id = u64::from_le_bytes(payload[16..24].try_into().unwrap());
            let wake_source = u32::from_le_bytes(payload[24..28].try_into().unwrap());
            let source_id = u64::from_le_bytes(payload[32..40].try_into().unwrap());
            EventPayload::TaskWake {
                target_task_id,
                block_sequence,
                waker_task_id,
                wake_source,
                source_id,
            }
        }
        x if x == TracepointId::TaskExit as u32 && payload.len() >= 12 => {
            let exit_task_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            let exit_code = i32::from_le_bytes(payload[8..12].try_into().unwrap());
            EventPayload::TaskExit {
                exit_task_id,
                exit_code,
            }
        }
        x if x == TracepointId::TaskEnqueue as u32 && payload.len() >= 24 => {
            let enqueue_task_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            let enqueue_cpu = u32::from_le_bytes(payload[8..12].try_into().unwrap());
            let target_cpu = u32::from_le_bytes(payload[12..16].try_into().unwrap());
            let queue_depth = u32::from_le_bytes(payload[16..20].try_into().unwrap());
            let enqueue_reason = u32::from_le_bytes(payload[20..24].try_into().unwrap());
            EventPayload::TaskEnqueue {
                enqueue_task_id,
                enqueue_cpu,
                target_cpu,
                queue_depth,
                enqueue_reason,
            }
        }
        x if x == TracepointId::PhaseMarker as u32 && payload.len() >= 24 => {
            let raw_boundary = u32::from_le_bytes(payload[0..4].try_into().unwrap());
            let phase_boundary = if raw_boundary == PhaseBoundary::End as u32 {
                PhaseBoundary::End
            } else {
                PhaseBoundary::Begin
            };
            let phase_len = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
            let end_idx = 8 + phase_len.min(16);
            let phase_name = parse_string(&payload[8..end_idx]);
            EventPayload::PhaseMarker {
                phase_boundary,
                phase_name,
            }
        }
        x if x == PERF_EVENT_SOFTWARE_ID && payload.len() >= 16 => {
            let sample_period = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            let pc = u64::from_le_bytes(payload[8..16].try_into().unwrap());
            EventPayload::SoftwareSample { sample_period, pc }
        }
        _ => EventPayload::Raw {
            bytes: payload.to_vec(),
        },
    }
}
