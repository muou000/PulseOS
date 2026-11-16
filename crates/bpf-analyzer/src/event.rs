use bpf_capture::record::NormalizedRecord;
use bpf_capture::schema::{PERF_EVENT_SOFTWARE_V2_ID, PERF_EVENT_SOFTWARE_STACK_V3_ID};
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
    SoftwareSampleV2 {
        sample_period: u64,
        addr: u64,
        pc: u64,
        mode: u32,
    },
    SoftwareStackV3 {
        sample_period: u64,
        addr: u64,
        pc: u64,
        mode: u32,
        source_id: u64,
        stack: pulse_bpf_schema::FrozenStack,
    },
    PageFault {
        address: u64,
        start_ns: u64,
        elapsed_ns: u64,
        access: u32,
        origin: u32,
        outcome: u32,
        classification: u32,
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
    /// Captured CPU sample period. Tracepoints and opaque records carry no
    /// profile weight, even when they share the same query window.
    pub fn sample_period(&self) -> Option<u64> {
        match self.payload {
            EventPayload::SoftwareSampleV2 { sample_period, .. }
            | EventPayload::SoftwareStackV3 { sample_period, .. } => Some(sample_period),
            _ => None,
        }
    }

    pub fn event_name(&self) -> &'static str {
        match self.event_id {
            x if x == TracepointId::TaskMetadata as u32 => "task_metadata",
            x if x == TracepointId::SchedSwitch as u32 => "sched_switch",
            x if x == TracepointId::TaskBlock as u32 => "task_block",
            x if x == TracepointId::TaskWake as u32 => "task_wake",
            x if x == TracepointId::TaskExit as u32 => "task_exit",
            x if x == TracepointId::TaskEnqueue as u32 => "task_enqueue",
            x if x == TracepointId::PhaseMarker as u32 => "phase_marker",
            x if x == TracepointId::PageFault as u32 => "page_fault",
            x if x == PERF_EVENT_SOFTWARE_V2_ID => "perf_sample_v2",
            x if x == PERF_EVENT_SOFTWARE_STACK_V3_ID => "software_stack_v3",
            _ => "unknown",
        }
    }
}

fn parse_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

pub fn parse_records(records: &[NormalizedRecord]) -> Vec<NormalizedEvent> {
    let mut parsed: Vec<_> = records
        .iter()
        .enumerate()
        .map(|(idx, rec)| NormalizedEvent {
            sequence_index: idx,
            event_id: rec.event_id,
            schema_version: rec.schema_version,
            timestamp_ns: rec.timestamp_ns,
            cpu_id: rec.cpu_id,
            pid: rec.pid,
            tid: rec.tid,
            task_id: rec.task_id,
            comm: None,
            payload: if rec.event_id == PERF_EVENT_SOFTWARE_STACK_V3_ID {
                match rec.software_stack_v3() {
                    Ok(context) => EventPayload::SoftwareStackV3 {
                        sample_period: context.base.base.sample_period,
                        addr: context.base.base.addr,
                        pc: context.base.ip,
                        mode: context.base.mode,
                        source_id: context.source_id,
                        stack: context.stack,
                    },
                    Err(_) => EventPayload::Raw { bytes: rec.payload.clone() },
                }
            } else { parse_payload(rec.event_id, &rec.payload) },
        })
        .collect();
    parsed.sort_by_key(|event| (event.timestamp_ns, event.sequence_index));
    let mut names: HashMap<u64, String> = HashMap::new();
    let mut offset = 0;
    while offset < parsed.len() {
        let time = parsed[offset].timestamp_ns;
        let end = parsed[offset..]
            .iter()
            .position(|e| e.timestamp_ns != time)
            .map_or(parsed.len(), |n| offset + n);
        let mut updates: HashMap<u64, Vec<(u32, usize, String)>> = HashMap::new();
        for event in &parsed[offset..end] {
            if let EventPayload::TaskMetadata {
                target_task_id,
                comm,
                ..
            } = &event.payload
            {
                updates.entry(*target_task_id).or_default().push((
                    event.cpu_id,
                    event.sequence_index,
                    comm.clone(),
                ));
            }
        }
        for event in &mut parsed[offset..end] {
            event.comm = names.get(&event.task_id).cloned();
            if let Some(values) = updates.get(&event.task_id) {
                for (cpu, sequence, name) in values {
                    if *cpu == event.cpu_id && *sequence <= event.sequence_index {
                        event.comm = (!name.is_empty()).then(|| name.clone());
                    }
                }
                if values
                    .iter()
                    .any(|(cpu, _, name)| *cpu != event.cpu_id && event.comm.as_ref() != Some(name))
                {
                    // Equal timestamps from different CPUs do not establish
                    // whether a rename occurred before this observation.
                    event.comm = None;
                }
            }
        }
        for (task, values) in updates {
            if values.iter().any(|(cpu, ..)| *cpu != values[0].0)
                && values.iter().any(|(_, _, name)| *name != values[0].2)
            {
                names.remove(&task);
            } else if let Some((_, _, name)) = values.last() {
                if name.is_empty() {
                    names.remove(&task);
                } else {
                    names.insert(task, name.clone());
                }
            }
        }
        for event in &parsed[offset..end] {
            if let EventPayload::TaskExit { exit_task_id, .. } = &event.payload {
                names.remove(exit_task_id);
            }
        }
        offset = end;
    }
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
            let phase_boundary = match raw_boundary {
                value if value == PhaseBoundary::Begin as u32 => PhaseBoundary::Begin,
                value if value == PhaseBoundary::End as u32 => PhaseBoundary::End,
                _ => return EventPayload::Raw { bytes: payload.to_vec() },
            };
            let phase_len = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
            let end_idx = 8 + phase_len.min(16);
            let phase_name = parse_string(&payload[8..end_idx]);
            EventPayload::PhaseMarker {
                phase_boundary,
                phase_name,
            }
        }
        x if x == TracepointId::PageFault as u32 && payload.len() == 40 => {
            EventPayload::PageFault {
                address:u64::from_le_bytes(payload[0..8].try_into().unwrap()),
                start_ns:u64::from_le_bytes(payload[8..16].try_into().unwrap()),
                elapsed_ns:u64::from_le_bytes(payload[16..24].try_into().unwrap()),
                access:u32::from_le_bytes(payload[24..28].try_into().unwrap()),
                origin:u32::from_le_bytes(payload[28..32].try_into().unwrap()),
                outcome:u32::from_le_bytes(payload[32..36].try_into().unwrap()),
                classification:u32::from_le_bytes(payload[36..40].try_into().unwrap()),
            }
        }
        x if x == PERF_EVENT_SOFTWARE_V2_ID && payload.len() == 32 => {
            EventPayload::SoftwareSampleV2 {
                sample_period: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
                addr: u64::from_le_bytes(payload[8..16].try_into().unwrap()),
                pc: u64::from_le_bytes(payload[16..24].try_into().unwrap()),
                mode: u32::from_le_bytes(payload[24..28].try_into().unwrap()),
            }
        }
        _ => EventPayload::Raw {
            bytes: payload.to_vec(),
        },
    }
}
