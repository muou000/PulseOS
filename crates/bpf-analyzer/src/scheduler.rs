//! Reconstruct observed blocked and wake-to-switch intervals before filtering.
//!
//! A block event is emitted while its task still owns a CPU. A latency sample
//! therefore needs an observed Blocked switch-out before its successful wake;
//! otherwise a later, unrelated switch-in must not be called wake latency.
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
};

use crate::{EventPayload, NormalizedEvent};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskIdentity {
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub comm: Option<String>,
}
#[derive(Clone)]
struct MetadataObservation {
    cpu: u32,
    sequence: usize,
    identity: TaskIdentity,
}
impl TaskIdentity {
    fn retain_agreement(&mut self, other: &Self) {
        if self.pid != other.pid {
            self.pid = None;
        }
        if self.tid != other.tid {
            self.tid = None;
        }
        if self.comm != other.comm {
            self.comm = None;
        }
    }
}
fn latest_field<T>(
    values: &mut BTreeMap<u32, (usize, Option<T>)>,
    cpu: u32,
    sequence: usize,
    value: Option<T>,
) {
    if values.get(&cpu).is_none_or(|(old, _)| sequence >= *old) {
        values.insert(cpu, (sequence, value));
    }
}
fn agreed_field<T: Clone + PartialEq>(values: BTreeMap<u32, (usize, Option<T>)>) -> Option<T> {
    let mut values = values.into_values();
    let (_, first) = values.next()?;
    if values.all(|(_, value)| value == first) {
        first
    } else {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockedWait {
    pub task_id: u64,
    pub block_sequence: u64,
    pub identity: TaskIdentity,
    pub block_ns: u64,
    pub wake_ns: u64,
    pub duration_ns: u64,
    pub wait_reason: u32,
    pub order_ambiguous: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakeLatency {
    pub task_id: u64,
    pub block_sequence: u64,
    pub identity: TaskIdentity,
    pub block_ns: u64,
    pub wake_ns: u64,
    pub switch_ns: u64,
    pub blocked_wait_ns: u64,
    pub wake_to_switch_ns: u64,
    pub wake_cpu: u32,
    pub run_cpu: u32,
    pub waker_task_id: u64,
    pub wake_source: u32,
    pub enqueue_count: u64,
    pub migration_count: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnfinishedReason {
    LeftCensored,
    RightCensored,
    Exited,
    Superseded,
    UnprovenBlockedSwitchOut,
    AmbiguousOrder,
    InvalidClock,
    MissingWake,
    ExitedTask,
    InvalidSequence,
}
impl UnfinishedReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LeftCensored => "left_censored",
            Self::RightCensored => "right_censored",
            Self::Exited => "exited",
            Self::Superseded => "superseded",
            Self::UnprovenBlockedSwitchOut => "unproven_blocked_switch_out",
            Self::AmbiguousOrder => "ambiguous_order",
            Self::InvalidClock => "invalid_clock",
            Self::MissingWake => "missing_wake",
            Self::ExitedTask => "exited_task",
            Self::InvalidSequence => "invalid_sequence",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnfinishedEpisode {
    pub task_id: u64,
    pub block_sequence: u64,
    pub block_ns: Option<u64>,
    pub wake_ns: Option<u64>,
    pub reason: UnfinishedReason,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SchedulerDiagnostics {
    pub wake_events: u64,
    pub duplicate_wakes: u64,
    pub duplicate_blocks: u64,
    pub left_censored: u64,
    pub right_censored: u64,
    pub exited: u64,
    pub superseded: u64,
    pub ambiguous_wakes: u64,
    pub timestamp_ties: u64,
    pub clock_regressions: u64,
    pub invalid_time_order: u64,
    pub missing_wakes: u64,
    pub exited_task_events: u64,
    pub invalid_sequences: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistogramBucket {
    /// Inclusive upper bound; None is the overflow bucket.
    pub upper_bound_ns: Option<u64>,
    pub count: u64,
}
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LatencySummary {
    pub count: u64,
    pub min_ns: Option<u64>,
    pub max_ns: Option<u64>,
    pub sum_ns: u128,
    pub mean_ns: Option<f64>,
    /// Exact nearest-rank percentiles of the retained observed intervals.
    pub p50_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub p99_ns: Option<u64>,
    pub histogram: Vec<HistogramBucket>,
}
impl LatencySummary {
    fn from_values(mut values: Vec<u64>) -> Self {
        values.sort_unstable();
        let count = values.len();
        let sum_ns = values.iter().map(|&n| n as u128).sum::<u128>();
        let percentile = |percent: usize| {
            if count == 0 {
                None
            } else {
                Some(values[(count as u128 * percent as u128).div_ceil(100) as usize - 1])
            }
        };
        let bounds = [
            Some(1_000),
            Some(10_000),
            Some(100_000),
            Some(1_000_000),
            Some(10_000_000),
            Some(100_000_000),
            Some(1_000_000_000),
            None,
        ];
        let mut histogram: Vec<_> = bounds
            .into_iter()
            .map(|upper_bound_ns| HistogramBucket {
                upper_bound_ns,
                count: 0,
            })
            .collect();
        for &value in &values {
            let index = bounds
                .iter()
                .position(|bound| bound.is_none_or(|limit| value <= limit))
                .unwrap();
            histogram[index].count += 1;
        }
        Self {
            count: count as u64,
            min_ns: values.first().copied(),
            max_ns: values.last().copied(),
            sum_ns,
            mean_ns: if count == 0 {
                None
            } else {
                Some(sum_ns as f64 / count as f64)
            },
            p50_ns: percentile(50),
            p95_ns: percentile(95),
            p99_ns: percentile(99),
            histogram,
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SchedulerReport {
    pub capture_incomplete: bool,
    /// Source/lifecycle coverage is not proven by finding a few paired records.
    /// In particular, incomplete capture statistics cannot certify attribution.
    pub complete_attribution: bool,
    pub wake_latencies: Vec<WakeLatency>,
    pub blocked_waits: Vec<BlockedWait>,
    pub unfinished: Vec<UnfinishedEpisode>,
    pub diagnostics: SchedulerDiagnostics,
    pub summary: LatencySummary,
    pub by_task: BTreeMap<u64, LatencySummary>,
}
#[derive(Clone)]
struct Wake {
    time: u64,
    cpu: u32,
    waker: u64,
    source: u32,
    identity: TaskIdentity,
}
struct Episode {
    task: u64,
    seq: u64,
    block: u64,
    block_cpu: u32,
    reason: u32,
    out: Option<u64>,
    wake: Option<Wake>,
    ambiguous: bool,
    ran_without_wake: bool,
    enqueues: u64,
    migrations: u64,
}
fn subject_roles(event: &NormalizedEvent) -> Vec<(u64, u8)> {
    match event.payload {
        EventPayload::TaskBlock { .. } => vec![(event.task_id, 1)],
        EventPayload::TaskWake { target_task_id, .. } => vec![(target_task_id, 2)],
        EventPayload::SchedSwitch {
            prev_task_id,
            next_task_id,
            ..
        } => vec![(prev_task_id, 3), (next_task_id, 4)],
        EventPayload::TaskExit { exit_task_id, .. } => vec![(exit_task_id, 5)],
        // Enqueue does not decide a wake interval's endpoints.
        _ => Vec::new(),
    }
}
impl SchedulerReport {
    /// `events` must retain each record's original sequence_index. The method
    /// sorts timestamps itself, detects per-CPU clock regressions in original
    /// publication order, and does not use retrospective `event.comm` values.
    pub fn compute(events: &[NormalizedEvent], capture_incomplete: bool) -> Self {
        let mut report = Self {
            capture_incomplete,
            ..Self::default()
        };
        let mut original: Vec<_> = events.iter().collect();
        original.sort_by_key(|e| e.sequence_index);
        let mut clocks = BTreeMap::new();
        let mut bad_cpus = BTreeSet::new();
        for event in &original {
            // Software sampling and other observers can use independent source
            // queues. Their merged transport order does not establish ordering
            // within the scheduler semantic queue.
            if !matches!(
                event.payload,
                EventPayload::TaskMetadata { .. }
                    | EventPayload::TaskBlock { .. }
                    | EventPayload::TaskWake { .. }
                    | EventPayload::SchedSwitch { .. }
                    | EventPayload::TaskExit { .. }
                    | EventPayload::TaskEnqueue { .. }
            ) {
                continue;
            }
            if clocks
                .get(&event.cpu_id)
                .is_some_and(|&previous| previous > event.timestamp_ns)
            {
                report.diagnostics.clock_regressions += 1;
                bad_cpus.insert(event.cpu_id);
            }
            clocks.insert(event.cpu_id, event.timestamp_ns);
        }
        original.sort_by_key(|e| (e.timestamp_ns, e.sequence_index));
        let mut active: BTreeMap<u64, Episode> = BTreeMap::new();
        let mut identities: BTreeMap<u64, TaskIdentity> = BTreeMap::new();
        let mut blocks = BTreeSet::new();
        let mut wakes = BTreeMap::new();
        let mut last_sequences = BTreeMap::new();
        let mut exited = BTreeSet::new();
        let mut offset = 0;
        while offset < original.len() {
            let time = original[offset].timestamp_ns;
            let end = original[offset..]
                .iter()
                .position(|e| e.timestamp_ns != time)
                .map_or(original.len(), |n| offset + n);
            // Metadata equal to a wake timestamp cannot be ordered by the
            // consumer's inter-CPU sequence. Preserve the identity before this
            // timestamp, then apply only proven same-CPU predecessors at wake.
            let mut metadata_updates: BTreeMap<u64, Vec<MetadataObservation>> = BTreeMap::new();
            let mut before_wake: BTreeMap<u64, TaskIdentity> = BTreeMap::new();
            let mut block_facts = Vec::new();
            for event in &original[offset..end] {
                match &event.payload {
                    EventPayload::TaskMetadata {
                        target_task_id,
                        target_pid,
                        target_tid,
                        comm,
                    } => {
                        metadata_updates.entry(*target_task_id).or_default().push(
                            MetadataObservation {
                                cpu: event.cpu_id,
                                sequence: event.sequence_index,
                                identity: TaskIdentity {
                                    pid: (*target_pid != 0).then_some(*target_pid),
                                    tid: (*target_tid != 0).then_some(*target_tid),
                                    comm: (!comm.is_empty()).then(|| comm.clone()),
                                },
                            },
                        );
                    }
                    EventPayload::TaskWake { target_task_id, .. } => {
                        before_wake.entry(*target_task_id).or_insert_with(|| {
                            identities.get(target_task_id).cloned().unwrap_or_default()
                        });
                    }
                    _ => {}
                }
            }
            let mut roles: BTreeMap<u64, BTreeSet<u8>> = BTreeMap::new();
            for event in &original[offset..end] {
                for (task, role) in subject_roles(event) {
                    roles.entry(task).or_default().insert(role);
                }
            }
            let tied: BTreeSet<_> = roles
                .into_iter()
                .filter_map(|(task, roles)| (roles.len() > 1).then_some(task))
                .collect();
            report.diagnostics.timestamp_ties += tied.len() as u64;
            for event in &original[offset..end] {
                for (task, _) in subject_roles(event) {
                    if let Some(episode) = active.get_mut(&task) {
                        episode.ambiguous |= tied.contains(&task);
                    }
                }
                match &event.payload {
                    EventPayload::TaskMetadata {
                        target_task_id,
                        target_pid,
                        target_tid,
                        comm,
                    } => {
                        identities.insert(
                            *target_task_id,
                            TaskIdentity {
                                pid: (*target_pid != 0).then_some(*target_pid),
                                tid: (*target_tid != 0).then_some(*target_tid),
                                comm: (!comm.is_empty()).then(|| comm.clone()),
                            },
                        );
                    }
                    EventPayload::TaskBlock {
                        block_sequence,
                        wait_reason,
                        ..
                    } => {
                        let task = event.task_id;
                        let seq = *block_sequence;
                        if task == 0 || seq == 0 || exited.contains(&task) {
                            report.reject(
                                task,
                                seq,
                                Some(time),
                                None,
                                if exited.contains(&task) {
                                    UnfinishedReason::ExitedTask
                                } else {
                                    UnfinishedReason::InvalidSequence
                                },
                            );
                            continue;
                        }
                        if !blocks.insert((task, seq)) {
                            report.diagnostics.duplicate_blocks += 1;
                            continue;
                        }
                        if let Some(&wake) = wakes.get(&(task, seq)) {
                            report.reject(
                                task,
                                seq,
                                Some(time),
                                Some(wake),
                                if wake == time {
                                    UnfinishedReason::AmbiguousOrder
                                } else {
                                    UnfinishedReason::InvalidClock
                                },
                            );
                            continue;
                        }
                        if last_sequences
                            .get(&task)
                            .is_some_and(|&previous| seq <= previous)
                        {
                            report.reject(
                                task,
                                seq,
                                Some(time),
                                None,
                                UnfinishedReason::InvalidSequence,
                            );
                            continue;
                        }
                        last_sequences.insert(task, seq);
                        if let Some(old) = active.remove(&task) {
                            report.finish_episode(old, UnfinishedReason::Superseded);
                        }
                        let identity = identities.entry(task).or_default();
                        if event.pid != 0 {
                            identity.pid = Some(event.pid);
                        }
                        if event.tid != 0 {
                            identity.tid = Some(event.tid);
                        }
                        block_facts.push((
                            task,
                            event.cpu_id,
                            event.sequence_index,
                            event.pid,
                            event.tid,
                        ));
                        active.insert(
                            task,
                            Episode {
                                task,
                                seq,
                                block: time,
                                block_cpu: event.cpu_id,
                                reason: *wait_reason,
                                out: None,
                                wake: None,
                                ambiguous: tied.contains(&task),
                                ran_without_wake: false,
                                enqueues: 0,
                                migrations: 0,
                            },
                        );
                    }
                    EventPayload::TaskWake {
                        target_task_id,
                        block_sequence,
                        waker_task_id,
                        wake_source,
                        ..
                    } => {
                        report.diagnostics.wake_events += 1;
                        let task = *target_task_id;
                        let seq = *block_sequence;
                        if task == 0 || seq == 0 {
                            report.reject(
                                task,
                                seq,
                                None,
                                Some(time),
                                UnfinishedReason::InvalidSequence,
                            );
                            continue;
                        }
                        if wakes.contains_key(&(task, seq)) {
                            report.diagnostics.duplicate_wakes += 1;
                            continue;
                        }
                        wakes.insert((task, seq), time);
                        if exited.contains(&task) {
                            report.reject(
                                task,
                                seq,
                                None,
                                Some(time),
                                UnfinishedReason::ExitedTask,
                            );
                            continue;
                        }
                        if last_sequences
                            .get(&task)
                            .is_some_and(|&previous| seq < previous)
                        {
                            report.reject(
                                task,
                                seq,
                                None,
                                Some(time),
                                UnfinishedReason::InvalidSequence,
                            );
                            continue;
                        }
                        // Even without its block record, a newer wake proves the
                        // task has advanced beyond any older pending generation.
                        if active.get(&task).is_some_and(|episode| episode.seq < seq) {
                            let old = active.remove(&task).unwrap();
                            report.finish_episode(old, UnfinishedReason::Superseded);
                        }
                        last_sequences.insert(task, seq);
                        if active.get(&task).is_none_or(|episode| episode.seq != seq) {
                            report.reject(
                                task,
                                seq,
                                None,
                                Some(time),
                                UnfinishedReason::LeftCensored,
                            );
                            continue;
                        }
                        let mut episode = active.remove(&task).unwrap();
                        let mut identity = before_wake.get(&task).cloned().unwrap_or_default();
                        if let Some(updates) = metadata_updates.get(&task) {
                            for update in updates {
                                if update.cpu == event.cpu_id
                                    && update.sequence <= event.sequence_index
                                {
                                    identity = update.identity.clone();
                                }
                            }
                            for update in updates {
                                if update.cpu != event.cpu_id {
                                    identity.retain_agreement(&update.identity);
                                }
                            }
                        }

                        let Some(duration) = time.checked_sub(episode.block) else {
                            report.finish_episode(episode, UnfinishedReason::InvalidClock);
                            continue;
                        };
                        episode.wake = Some(Wake {
                            time,
                            cpu: event.cpu_id,
                            waker: *waker_task_id,
                            source: *wake_source,
                            identity: identity.clone(),
                        });
                        let invalid_clock = bad_cpus.contains(&event.cpu_id)
                            || bad_cpus.contains(&episode.block_cpu);
                        if !invalid_clock {
                            report.blocked_waits.push(BlockedWait {
                                task_id: task,
                                block_sequence: seq,
                                identity,
                                block_ns: episode.block,
                                wake_ns: time,
                                duration_ns: duration,
                                wait_reason: episode.reason,
                                order_ambiguous: episode.ambiguous || tied.contains(&task),
                            });
                        }
                        let rejection = if invalid_clock {
                            Some(UnfinishedReason::InvalidClock)
                        } else if episode.ambiguous || tied.contains(&task) {
                            Some(UnfinishedReason::AmbiguousOrder)
                        } else if episode.ran_without_wake {
                            Some(UnfinishedReason::MissingWake)
                        } else if episode.out.is_none_or(|out| out >= time) {
                            Some(UnfinishedReason::UnprovenBlockedSwitchOut)
                        } else {
                            None
                        };
                        if let Some(reason) = rejection {
                            report.finish_episode(episode, reason);
                        } else {
                            active.insert(task, episode);
                        }
                    }
                    EventPayload::SchedSwitch {
                        prev_task_id,
                        next_task_id,
                        prev_state,
                        ..
                    } => {
                        if let Some(episode) = active.get_mut(prev_task_id) {
                            if *prev_state == 3
                                && episode.wake.is_none()
                                && event.cpu_id == episode.block_cpu
                                && time > episode.block
                            {
                                episode.out = Some(time);
                            }
                        }
                        if let Some(mut episode) = active.remove(next_task_id) {
                            if let Some(wake) = episode.wake.take() {
                                let rejection = if bad_cpus.contains(&event.cpu_id) {
                                    Some(UnfinishedReason::InvalidClock)
                                } else if episode.ambiguous
                                    || tied.contains(next_task_id)
                                    || time <= wake.time
                                {
                                    Some(UnfinishedReason::AmbiguousOrder)
                                } else {
                                    None
                                };
                                if let Some(reason) = rejection {
                                    episode.wake = Some(wake);
                                    report.finish_episode(episode, reason);
                                } else {
                                    report.wake_latencies.push(WakeLatency {
                                        task_id: episode.task,
                                        block_sequence: episode.seq,
                                        identity: wake.identity,
                                        block_ns: episode.block,
                                        wake_ns: wake.time,
                                        switch_ns: time,
                                        blocked_wait_ns: wake.time - episode.block,
                                        wake_to_switch_ns: time - wake.time,
                                        wake_cpu: wake.cpu,
                                        run_cpu: event.cpu_id,
                                        waker_task_id: wake.waker,
                                        wake_source: wake.source,
                                        enqueue_count: episode.enqueues,
                                        migration_count: episode.migrations,
                                    });
                                }
                            } else {
                                episode.ran_without_wake = true;
                                active.insert(*next_task_id, episode);
                            }
                        }
                    }
                    EventPayload::TaskEnqueue {
                        enqueue_task_id,
                        enqueue_reason,
                        ..
                    } => {
                        if let Some(episode) = active.get_mut(enqueue_task_id) {
                            episode.enqueues += 1;
                            if matches!(enqueue_reason, 5 | 7) {
                                episode.migrations += 1;
                            }
                        }
                    }
                    EventPayload::TaskExit { exit_task_id, .. } => {
                        exited.insert(*exit_task_id);
                        if let Some(episode) = active.remove(exit_task_id) {
                            report.finish_episode(episode, UnfinishedReason::Exited);
                        }
                        identities.remove(exit_task_id);
                    }
                    _ => {}
                }
            }
            // Once this timestamp is past, each CPU's final metadata update
            // is a possible last update. Conflicting fields remain unknown for
            // later wakes too; actual same-CPU block identity facts retain their
            // sequence relative to metadata instead of being overwritten.
            for (task, updates) in metadata_updates {
                if exited.contains(&task) {
                    continue;
                }
                let mut pids = BTreeMap::new();
                let mut tids = BTreeMap::new();
                let mut names = BTreeMap::new();
                for update in updates {
                    latest_field(&mut pids, update.cpu, update.sequence, update.identity.pid);
                    latest_field(&mut tids, update.cpu, update.sequence, update.identity.tid);
                    latest_field(
                        &mut names,
                        update.cpu,
                        update.sequence,
                        update.identity.comm,
                    );
                }
                for &(subject, cpu, sequence, pid, tid) in &block_facts {
                    if subject == task {
                        if pid != 0 {
                            latest_field(&mut pids, cpu, sequence, Some(pid));
                        }
                        if tid != 0 {
                            latest_field(&mut tids, cpu, sequence, Some(tid));
                        }
                    }
                }
                identities.insert(
                    task,
                    TaskIdentity {
                        pid: agreed_field(pids),
                        tid: agreed_field(tids),
                        comm: agreed_field(names),
                    },
                );
            }
            offset = end;
        }
        for (_, episode) in active {
            let reason = if episode.ran_without_wake {
                UnfinishedReason::MissingWake
            } else {
                UnfinishedReason::RightCensored
            };
            report.finish_episode(episode, reason);
        }
        report.rebuild_summaries();
        report
    }
    fn finish_episode(&mut self, episode: Episode, reason: UnfinishedReason) {
        self.reject(
            episode.task,
            episode.seq,
            Some(episode.block),
            episode.wake.map(|w| w.time),
            reason,
        );
    }
    fn reject(
        &mut self,
        task_id: u64,
        block_sequence: u64,
        block_ns: Option<u64>,
        wake_ns: Option<u64>,
        reason: UnfinishedReason,
    ) {
        match reason {
            UnfinishedReason::LeftCensored => self.diagnostics.left_censored += 1,
            UnfinishedReason::RightCensored => self.diagnostics.right_censored += 1,
            UnfinishedReason::Exited => self.diagnostics.exited += 1,
            UnfinishedReason::Superseded => self.diagnostics.superseded += 1,
            UnfinishedReason::UnprovenBlockedSwitchOut | UnfinishedReason::AmbiguousOrder => {
                self.diagnostics.ambiguous_wakes += 1
            }
            UnfinishedReason::InvalidClock => self.diagnostics.invalid_time_order += 1,
            UnfinishedReason::MissingWake => self.diagnostics.missing_wakes += 1,
            UnfinishedReason::ExitedTask => self.diagnostics.exited_task_events += 1,
            UnfinishedReason::InvalidSequence => self.diagnostics.invalid_sequences += 1,
        }
        self.unfinished.push(UnfinishedEpisode {
            task_id,
            block_sequence,
            block_ns,
            wake_ns,
            reason,
        });
    }
}

fn json_quote(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c < '\u{20}' => {
                write!(&mut out, "\\u{:04x}", c as u32).unwrap();
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn json_number<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "null".into(), |v| v.to_string())
}
fn identity_json(identity: &TaskIdentity) -> String {
    format!(
        "{{\"pid\":{},\"tid\":{},\"comm\":{}}}",
        json_number(identity.pid),
        json_number(identity.tid),
        identity
            .comm
            .as_deref()
            .map_or_else(|| "null".into(), json_quote)
    )
}
impl LatencySummary {
    fn render_json(&self) -> String {
        let histogram = self
            .histogram
            .iter()
            .map(|b| {
                format!(
                    "{{\"upper_bound_ns\":{},\"count\":{}}}",
                    json_number(b.upper_bound_ns),
                    b.count
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            concat!(
                "{{\"count\":{},\"min_ns\":{},\"max_ns\":{},\"sum_ns\":\"{}\",",
                "\"mean_ns\":{},\"p50_ns\":{},\"p95_ns\":{},\"p99_ns\":{},",
                "\"histogram\":[{}]}}",
            ),
            self.count,
            json_number(self.min_ns),
            json_number(self.max_ns),
            self.sum_ns,
            json_number(self.mean_ns),
            json_number(self.p50_ns),
            json_number(self.p95_ns),
            json_number(self.p99_ns),
            histogram
        )
    }
}
impl SchedulerDiagnostics {
    fn entries(&self) -> [(&'static str, u64); 14] {
        [
            ("wake_events", self.wake_events),
            ("duplicate_wakes", self.duplicate_wakes),
            ("duplicate_blocks", self.duplicate_blocks),
            ("left_censored", self.left_censored),
            ("right_censored", self.right_censored),
            ("exited", self.exited),
            ("superseded", self.superseded),
            ("ambiguous_wakes", self.ambiguous_wakes),
            ("timestamp_ties", self.timestamp_ties),
            ("clock_regressions", self.clock_regressions),
            ("invalid_time_order", self.invalid_time_order),
            ("missing_wakes", self.missing_wakes),
            ("exited_task_events", self.exited_task_events),
            ("invalid_sequences", self.invalid_sequences),
        ]
    }
}
impl SchedulerReport {
    /// Rebuild numerical summaries after filtering already reconstructed samples.
    /// Capture-scoped diagnostics and unknown coverage deliberately remain intact.
    pub fn rebuild_summaries(&mut self) {
        self.summary = LatencySummary::from_values(
            self.wake_latencies
                .iter()
                .map(|s| s.wake_to_switch_ns)
                .collect(),
        );
        let mut groups: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for sample in &self.wake_latencies {
            groups
                .entry(sample.task_id)
                .or_default()
                .push(sample.wake_to_switch_ns);
        }
        self.by_task = groups
            .into_iter()
            .map(|(task, values)| (task, LatencySummary::from_values(values)))
            .collect();
    }

    /// Nanoseconds; sum_ns is a decimal string preserving its full u128 range.
    /// Histogram bounds are inclusive; percentiles use exact retained samples.
    pub fn render_json(&self) -> String {
        let mut out = String::new();
        write!(
            &mut out,
            concat!(
                "{{\"report\":\"scheduler\",\"unit\":\"nanoseconds\",",
                "\"scope\":\"observed_intervals\",\"coverage\":\"unknown\",",
                "\"capture_incomplete\":{},\"complete_attribution\":{},\"summary\":{},",
            ),
            self.capture_incomplete,
            self.complete_attribution,
            self.summary.render_json()
        )
        .unwrap();
        out.push_str("\"diagnostics\":{");
        for (index, (name, value)) in self.diagnostics.entries().iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            write!(&mut out, "{}:{}", json_quote(name), value).unwrap();
        }
        out.push_str("},\"by_task\":{");
        for (index, (task, summary)) in self.by_task.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            write!(&mut out, "\"{}\":{}", task, summary.render_json()).unwrap();
        }
        out.push_str("},\"wake_latencies\":[");
        for (index, sample) in self.wake_latencies.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            write!(
                &mut out,
                concat!(
                    "{{\"task_id\":{},\"block_sequence\":{},\"identity\":{},\"block_ns\":{},",
                    "\"wake_ns\":{},\"switch_ns\":{},\"blocked_wait_ns\":{},",
                    "\"wake_to_switch_ns\":{},\"wake_cpu\":{},\"run_cpu\":{},",
                    "\"waker_task_id\":{},\"wake_source\":{},\"enqueue_count\":{},",
                    "\"migration_count\":{}}}",
                ),
                sample.task_id,
                sample.block_sequence,
                identity_json(&sample.identity),
                sample.block_ns,
                sample.wake_ns,
                sample.switch_ns,
                sample.blocked_wait_ns,
                sample.wake_to_switch_ns,
                sample.wake_cpu,
                sample.run_cpu,
                sample.waker_task_id,
                sample.wake_source,
                sample.enqueue_count,
                sample.migration_count
            )
            .unwrap();
        }
        out.push_str("],\"blocked_waits\":[");
        for (index, wait) in self.blocked_waits.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            write!(
                &mut out,
                concat!(
                    "{{\"task_id\":{},\"block_sequence\":{},\"identity\":{},\"block_ns\":{},",
                    "\"wake_ns\":{},\"duration_ns\":{},\"wait_reason\":{},",
                    "\"order_ambiguous\":{}}}",
                ),
                wait.task_id,
                wait.block_sequence,
                identity_json(&wait.identity),
                wait.block_ns,
                wait.wake_ns,
                wait.duration_ns,
                wait.wait_reason,
                wait.order_ambiguous
            )
            .unwrap();
        }
        out.push_str("],\"unfinished\":[");
        for (index, episode) in self.unfinished.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            write!(
                &mut out,
                concat!(
                    "{{\"task_id\":{},\"block_sequence\":{},\"block_ns\":{},\"wake_ns\":{},",
                    "\"reason\":{}}}",
                ),
                episode.task_id,
                episode.block_sequence,
                json_number(episode.block_ns),
                json_number(episode.wake_ns),
                json_quote(episode.reason.as_str())
            )
            .unwrap();
        }
        out.push_str("]}");
        out
    }

    pub fn render_text(&self) -> String {
        let mut out = String::new();
        writeln!(
            &mut out,
            "Observed scheduler wake-to-switch latency (nanoseconds)"
        )
        .unwrap();
        writeln!(
            &mut out,
            "capture_incomplete={} coverage=unknown complete_attribution={}",
            self.capture_incomplete, self.complete_attribution
        )
        .unwrap();
        writeln!(
            &mut out,
            "Successful wake -> selected next task; excludes switch_to function cost and \
             resource-blocked time."
        )
        .unwrap();
        writeln!(
            &mut out,
            "count={} min_ns={} max_ns={} sum_ns={} mean_ns={} p50_ns={} p95_ns={} p99_ns={}",
            self.summary.count,
            display_optional(self.summary.min_ns),
            display_optional(self.summary.max_ns),
            self.summary.sum_ns,
            display_optional(self.summary.mean_ns),
            display_optional(self.summary.p50_ns),
            display_optional(self.summary.p95_ns),
            display_optional(self.summary.p99_ns)
        )
        .unwrap();
        writeln!(
            &mut out,
            "Percentiles: exact nearest rank of observed intervals; histogram upper bounds \
             inclusive."
        )
        .unwrap();
        for bucket in &self.summary.histogram {
            writeln!(
                &mut out,
                "histogram upper_bound_ns={} count={}",
                bucket
                    .upper_bound_ns
                    .map_or_else(|| "overflow".into(), |n| n.to_string()),
                bucket.count
            )
            .unwrap();
        }
        writeln!(
            &mut out,
            "Diagnostics (overlapping categories; do not add as loss):"
        )
        .unwrap();
        for (name, value) in self.diagnostics.entries() {
            writeln!(&mut out, "  {name}={value}").unwrap();
        }
        writeln!(
            &mut out,
            "TASK SEQ PID TID COMM WAKE_CPU RUN_CPU WAKE_NS SWITCH_NS WAKE_TO_SWITCH_NS \
             BLOCKED_WAIT_NS"
        )
        .unwrap();
        for sample in &self.wake_latencies {
            writeln!(
                &mut out,
                "{} {} {} {} {} {} {} {} {} {} {}",
                sample.task_id,
                sample.block_sequence,
                display_optional(sample.identity.pid),
                display_optional(sample.identity.tid),
                sample
                    .identity
                    .comm
                    .as_deref()
                    .map_or_else(|| "unknown".into(), json_quote),
                sample.wake_cpu,
                sample.run_cpu,
                sample.wake_ns,
                sample.switch_ns,
                sample.wake_to_switch_ns,
                sample.blocked_wait_ns
            )
            .unwrap();
        }
        writeln!(
            &mut out,
            "Blocked intervals (block -> wake, not total off-CPU time):"
        )
        .unwrap();
        for wait in &self.blocked_waits {
            writeln!(
                &mut out,
                "  task={} seq={} block_ns={} wake_ns={} duration_ns={} wait_reason={} \
                 order_ambiguous={}",
                wait.task_id,
                wait.block_sequence,
                wait.block_ns,
                wait.wake_ns,
                wait.duration_ns,
                wait.wait_reason,
                wait.order_ambiguous
            )
            .unwrap();
        }
        writeln!(
            &mut out,
            "Unfinished/ambiguous episodes (no invented zero latency):"
        )
        .unwrap();
        for episode in &self.unfinished {
            writeln!(
                &mut out,
                "  task={} seq={} block_ns={} wake_ns={} reason={}",
                episode.task_id,
                episode.block_sequence,
                display_optional(episode.block_ns),
                display_optional(episode.wake_ns),
                episode.reason.as_str()
            )
            .unwrap();
        }
        out
    }
}
fn display_optional<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "unknown".into(), |v| v.to_string())
}
