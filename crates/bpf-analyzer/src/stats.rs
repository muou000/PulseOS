use bpf_capture::session::LayeredLossCounters;
use std::collections::{BTreeMap, HashMap};

use crate::event::{EventPayload, NormalizedEvent};

/// CPU-level execution and sampling metrics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuStatistics {
    pub cpu_id: u32,
    pub event_count: u64,
    pub sample_count: u64,
    pub context_switches: u64,
    pub lost_records: u64,
    pub busy_time_ns: u64,
    pub idle_time_ns: u64,
}

/// Task-level execution, blocking, and wake statistics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskStatistics {
    pub task_id: u64,
    pub comm: Option<String>,
    pub pid: u32,
    pub tid: u32,
    pub on_cpu_time_ns: u64,
    pub off_cpu_wait_ns: u64,
    pub block_count: u64,
    pub wake_count: u64,
    pub sample_count: u64,
}

/// A contiguous interval where a task ran on a specific CPU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnCpuInterval {
    pub cpu_id: u32,
    pub task_id: u64,
    pub comm: Option<String>,
    pub start_ns: u64,
    pub end_ns: u64,
    pub duration_ns: u64,
}

/// A paired wait interval where a task was blocked until woken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffCpuInterval {
    pub task_id: u64,
    pub comm: Option<String>,
    pub block_sequence: u64,
    pub wait_reason: u32,
    pub resource_id: u64,
    pub start_ns: u64,
    pub end_ns: u64,
    pub duration_ns: u64,
    pub waker_task_id: u64,
}

/// Aggregated semantic session statistics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionStatistics {
    pub cpu_stats: BTreeMap<u32, CpuStatistics>,
    pub task_stats: BTreeMap<u64, TaskStatistics>,
    pub event_counts: BTreeMap<String, u64>,
    pub total_events: u64,
    pub unpaired_blocks: u64,
    pub unpaired_wakes: u64,
    pub on_cpu_intervals: Vec<OnCpuInterval>,
    pub off_cpu_intervals: Vec<OffCpuInterval>,
}

#[derive(Clone, Debug)]
struct BlockInfo {
    start_ns: u64,
    wait_reason: u32,
    resource_id: u64,
}

impl SessionStatistics {
    pub fn compute(events: &[NormalizedEvent], loss_counters: &LayeredLossCounters) -> Self {
        let mut stats = Self::default();

        // 1. CPU running task state: cpu_id -> (task_id, switch_in_ts)
        let mut running_on_cpu: HashMap<u32, (u64, u64)> = HashMap::new();

        // 2. Active blocks waiting for wake: (task_id, block_seq) -> BlockInfo
        let mut active_blocks: HashMap<(u64, u64), BlockInfo> = HashMap::new();

        for ev in events {
            stats.total_events += 1;
            *stats.event_counts.entry(ev.event_name().to_string()).or_insert(0) += 1;

            let cpu_stat = stats.cpu_stats.entry(ev.cpu_id).or_insert_with(|| CpuStatistics {
                cpu_id: ev.cpu_id,
                ..Default::default()
            });
            cpu_stat.event_count += 1;

            let task_stat = stats.task_stats.entry(ev.task_id).or_insert_with(|| TaskStatistics {
                task_id: ev.task_id,
                comm: ev.comm.clone(),
                pid: ev.pid,
                tid: ev.tid,
                ..Default::default()
            });
            if task_stat.comm.is_none() && ev.comm.is_some() {
                task_stat.comm = ev.comm.clone();
            }

            match ev.payload {
                EventPayload::SchedSwitch { prev_task_id, next_task_id, .. } => {
                    cpu_stat.context_switches += 1;

                    // Ensure entries exist
                    stats.task_stats.entry(prev_task_id).or_insert_with(|| TaskStatistics {
                        task_id: prev_task_id,
                        comm: ev.comm.clone(),
                        ..Default::default()
                    });
                    stats.task_stats.entry(next_task_id).or_insert_with(|| TaskStatistics {
                        task_id: next_task_id,
                        comm: None,
                        ..Default::default()
                    });

                    if let Some(&(curr_task, start_ts)) = running_on_cpu.get(&ev.cpu_id) {
                        // Validate that the task switched out matches recorded running task
                        if curr_task == prev_task_id {
                            let duration = ev.timestamp_ns.saturating_sub(start_ts);
                            if duration > 0 {
                                let prev_comm = stats.task_stats.get(&curr_task).and_then(|t| t.comm.clone());
                                stats.on_cpu_intervals.push(OnCpuInterval {
                                    cpu_id: ev.cpu_id,
                                    task_id: curr_task,
                                    comm: prev_comm,
                                    start_ns: start_ts,
                                    end_ns: ev.timestamp_ns,
                                    duration_ns: duration,
                                });
                                if let Some(t_entry) = stats.task_stats.get_mut(&curr_task) {
                                    t_entry.on_cpu_time_ns = t_entry.on_cpu_time_ns.saturating_add(duration);
                                }
                                if curr_task == 0 {
                                    cpu_stat.idle_time_ns = cpu_stat.idle_time_ns.saturating_add(duration);
                                } else {
                                    cpu_stat.busy_time_ns = cpu_stat.busy_time_ns.saturating_add(duration);
                                }
                            }
                        }
                    }

                    running_on_cpu.insert(ev.cpu_id, (next_task_id, ev.timestamp_ns));
                }
                EventPayload::TaskBlock {
                    block_sequence,
                    wait_reason,
                    resource_id,
                    ..
                } => {
                    task_stat.block_count += 1;
                    active_blocks.insert(
                        (ev.task_id, block_sequence),
                        BlockInfo {
                            start_ns: ev.timestamp_ns,
                            wait_reason,
                            resource_id,
                        },
                    );
                }
                EventPayload::TaskWake {
                    target_task_id,
                    block_sequence,
                    waker_task_id,
                    ..
                } => {
                    let target_stat = stats.task_stats.entry(target_task_id).or_insert_with(|| TaskStatistics {
                        task_id: target_task_id,
                        comm: None,
                        ..Default::default()
                    });
                    target_stat.wake_count += 1;

                    if let Some(block_info) = active_blocks.remove(&(target_task_id, block_sequence)) {
                        let duration = ev.timestamp_ns.saturating_sub(block_info.start_ns);
                        target_stat.off_cpu_wait_ns = target_stat.off_cpu_wait_ns.saturating_add(duration);
                        let target_comm = target_stat.comm.clone();
                        stats.off_cpu_intervals.push(OffCpuInterval {
                            task_id: target_task_id,
                            comm: target_comm,
                            block_sequence,
                            wait_reason: block_info.wait_reason,
                            resource_id: block_info.resource_id,
                            start_ns: block_info.start_ns,
                            end_ns: ev.timestamp_ns,
                            duration_ns: duration,
                            waker_task_id,
                        });
                    } else {
                        stats.unpaired_wakes += 1;
                    }
                }
                EventPayload::TaskMetadata { target_task_id, ref comm, .. } => {
                    let entry = stats.task_stats.entry(target_task_id).or_insert_with(|| TaskStatistics {
                        task_id: target_task_id,
                        comm: Some(comm.clone()),
                        ..Default::default()
                    });
                    entry.comm = Some(comm.clone());
                }
                EventPayload::SoftwareSample { .. } => {
                    cpu_stat.sample_count += 1;
                    task_stat.sample_count += 1;
                }
                _ => {}
            }
        }

        stats.unpaired_blocks = active_blocks.len() as u64;

        // Close trailing on-CPU interval up to the last event timestamp
        let last_ts = events.last().map(|e| e.timestamp_ns).unwrap_or(0);
        for (cpu_id, (curr_task, start_ts)) in running_on_cpu {
            let duration = last_ts.saturating_sub(start_ts);
            if duration > 0 {
                let curr_comm = stats.task_stats.get(&curr_task).and_then(|t| t.comm.clone());
                stats.on_cpu_intervals.push(OnCpuInterval {
                    cpu_id,
                    task_id: curr_task,
                    comm: curr_comm,
                    start_ns: start_ts,
                    end_ns: last_ts,
                    duration_ns: duration,
                });
                if let Some(t_entry) = stats.task_stats.get_mut(&curr_task) {
                    t_entry.on_cpu_time_ns = t_entry.on_cpu_time_ns.saturating_add(duration);
                }
                let cpu_stat = stats.cpu_stats.entry(cpu_id).or_insert_with(|| CpuStatistics {
                    cpu_id,
                    ..Default::default()
                });
                if curr_task == 0 {
                    cpu_stat.idle_time_ns = cpu_stat.idle_time_ns.saturating_add(duration);
                } else {
                    cpu_stat.busy_time_ns = cpu_stat.busy_time_ns.saturating_add(duration);
                }
            }
        }

        // Populate per-CPU lost records from session loss counters
        for &(cpu, count) in &loss_counters.per_cpu_lost {
            stats.cpu_stats.entry(cpu).or_insert_with(|| CpuStatistics {
                cpu_id: cpu,
                ..Default::default()
            }).lost_records = count;
        }

        stats
    }
}
