//! A query selects reports only after whole-capture identity and interval reconstruction.
use std::collections::{BTreeMap, BTreeSet};

use pulse_bpf_schema::PhaseBoundary;

use crate::{
    CaptureAnalyzer, EventPayload, NormalizedEvent, SchedulerReport,
    scheduler::{TaskIdentity, UnfinishedReason},
    stats::{CpuStatistics, OffCpuInterval, SessionStatistics, TaskStatistics},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SampleWeight {
    #[default]
    Samples,
    Period,
}
impl SampleWeight {
    pub fn unit(self) -> &'static str {
        match self {
            Self::Samples => "samples",
            Self::Period => "period_ns",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privilege {
    Kernel,
    User,
}
impl Privilege {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::User => "user",
        }
    }
    fn tag(self) -> u32 {
        match self {
            Self::Kernel => 1,
            Self::User => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseSource {
    RuntimeDiagnostics,
    StreamMarkers,
    Both,
}
impl PhaseSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeDiagnostics => "runtime_diagnostics",
            Self::StreamMarkers => "stream_markers",
            Self::Both => "both",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    pub phase: Option<String>,
    pub mode: Option<Privilege>,
    pub from_ns: Option<u64>,
    pub to_ns: Option<u64>,
    pub task_id: Option<u64>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub cpu: Option<u32>,
    pub weight: SampleWeight,
    pub address_start: Option<u64>,
    pub address_end: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct TimelineInterval {
    pub kind: &'static str,
    pub task_id: u64,
    pub block_sequence: Option<u64>,
    pub start_ns: u64,
    pub end_ns: u64,
    pub visible_start_ns: u64,
    pub visible_end_ns: u64,
    pub start_cpu: Option<u32>,
    pub end_cpu: Option<u32>,
    pub query_clipped: bool,
    pub quality: &'static str,
    pub evidence_records: Vec<usize>,
}
#[derive(Clone, Debug)]
pub struct TimelineUnfinished {
    pub episode: crate::scheduler::UnfinishedEpisode,
    pub visible_start_ns: Option<u64>,
    /// A display/observation bound, never an observed completion endpoint.
    pub observation_limit_ns: Option<u64>,
    pub query_clipped: bool,
    pub evidence_records: Vec<usize>,
}
#[derive(Clone, Debug, Default)]
pub struct Timeline {
    pub intervals: Vec<TimelineInterval>,
    pub unfinished: Vec<TimelineUnfinished>,
    pub context_events: Vec<NormalizedEvent>,
}

#[derive(Clone, Debug)]
pub struct AnalysisResult {
    pub query: Query,
    pub phase_source: Option<PhaseSource>,
    pub from_ns: Option<u64>,
    pub to_ns: Option<u64>,
    pub events: Vec<NormalizedEvent>,
    pub context_records_count: usize,
    pub clipped_intervals: usize,
    pub stats: SessionStatistics,
    pub scheduler: SchedulerReport,
    pub timeline: Timeline,
}

#[derive(Clone)]
struct IdentityPoint {
    time: u64,
    sequence: usize,
    cpu: u32,
    identity: TaskIdentity,
}
struct Identities {
    observations: BTreeMap<u64, Vec<IdentityPoint>>,
    settled: BTreeMap<u64, Vec<(u64, TaskIdentity)>>,
}
impl Identities {
    fn new(events: &[NormalizedEvent]) -> Self {
        let mut result: BTreeMap<u64, Vec<IdentityPoint>> = BTreeMap::new();
        for event in events {
            let (task, identity) = match &event.payload {
                EventPayload::TaskMetadata {
                    target_task_id,
                    target_pid,
                    target_tid,
                    comm,
                } => (
                    *target_task_id,
                    TaskIdentity {
                        pid: (*target_pid != 0).then_some(*target_pid),
                        tid: (*target_tid != 0).then_some(*target_tid),
                        comm: (!comm.is_empty()).then(|| comm.clone()),
                    },
                ),
                EventPayload::TaskExit { exit_task_id, .. } => {
                    (*exit_task_id, TaskIdentity::default())
                }
                _ if event.task_id != 0 && (event.pid != 0 || event.tid != 0) => (
                    event.task_id,
                    TaskIdentity {
                        pid: (event.pid != 0).then_some(event.pid),
                        tid: (event.tid != 0).then_some(event.tid),
                        comm: event.comm.clone(),
                    },
                ),
                _ => continue,
            };
            result.entry(task).or_default().push(IdentityPoint {
                time: event.timestamp_ns,
                sequence: event.sequence_index,
                cpu: event.cpu_id,
                identity,
            });
        }
        let mut settled = BTreeMap::new();
        for (&task, points) in &result {
            let mut history = Vec::new();
            let mut start = 0;
            while start < points.len() {
                let time = points[start].time;
                let end = points[start..]
                    .iter()
                    .position(|p| p.time != time)
                    .map_or(points.len(), |n| start + n);
                // Same-CPU observations are ordered; equal-time observations
                // across CPUs are not. Keep only their agreeing final fields
                // as history for timestamps after this group.
                let mut last_by_cpu = BTreeMap::new();
                for point in &points[start..end] {
                    last_by_cpu.insert(point.cpu, &point.identity);
                }
                let mut values = last_by_cpu.values();
                let mut identity = (*values.next().unwrap()).clone();
                for other in values {
                    if identity.pid != other.pid {
                        identity.pid = None;
                    }
                    if identity.tid != other.tid {
                        identity.tid = None;
                    }
                    if identity.comm != other.comm {
                        identity.comm = None;
                    }
                }
                history.push((time, identity));
                start = end;
            }
            settled.insert(task, history);
        }
        Self {
            observations: result,
            settled,
        }
    }
    fn at(&self, task: u64, time: u64, sequence: usize, cpu: u32) -> TaskIdentity {
        let Some(points) = self.observations.get(&task) else {
            return TaskIdentity::default();
        };
        let begin = points.partition_point(|p| p.time < time);
        let end = points.partition_point(|p| p.time <= time);
        let history = &self.settled[&task];
        let previous = history.partition_point(|(at, _)| *at < time);
        let mut identity = previous
            .checked_sub(1)
            .map(|i| history[i].1.clone())
            .unwrap_or_default();
        for point in &points[begin..end] {
            if point.cpu == cpu && point.sequence <= sequence {
                identity = point.identity.clone();
            }
        }
        // A different CPU's equal timestamp supplies no ordering proof. Retain
        // only fields that agree across the possible identities.
        for point in &points[begin..end] {
            if point.cpu != cpu {
                if point.identity.pid != identity.pid {
                    identity.pid = None;
                }
                if point.identity.tid != identity.tid {
                    identity.tid = None;
                }
                if point.identity.comm != identity.comm {
                    identity.comm = None;
                }
            }
        }
        identity
    }
    fn for_event(&self, event: &NormalizedEvent, task: u64) -> TaskIdentity {
        let mut identity = self.at(task, event.timestamp_ns, event.sequence_index, event.cpu_id);
        if event.task_id == task {
            if event.pid != 0 {
                identity.pid = Some(event.pid);
            }
            if event.tid != 0 {
                identity.tid = Some(event.tid);
            }
            identity.comm = event.comm.clone();
        }
        identity
    }
}
pub(crate) fn subjects(event: &NormalizedEvent) -> Vec<u64> {
    match event.payload {
        EventPayload::TaskMetadata { target_task_id, .. }
        | EventPayload::TaskWake { target_task_id, .. } => vec![target_task_id],
        EventPayload::TaskEnqueue {
            enqueue_task_id, ..
        } => vec![enqueue_task_id],
        EventPayload::TaskExit { exit_task_id, .. } => vec![exit_task_id],
        EventPayload::SchedSwitch {
            prev_task_id,
            next_task_id,
            ..
        } if prev_task_id != next_task_id => vec![prev_task_id, next_task_id],
        _ => vec![event.task_id],
    }
}
impl Query {
    fn task_matches(&self, task: u64, identity: &TaskIdentity) -> bool {
        self.task_id.is_none_or(|value| value == task)
            && self.pid.is_none_or(|value| identity.pid == Some(value))
            && self.tid.is_none_or(|value| identity.tid == Some(value))
    }
    pub fn apply(&self, analyzer: &CaptureAnalyzer) -> Result<AnalysisResult, String> {
        if self.from_ns.zip(self.to_ns).is_some_and(|(a, b)| a >= b) {
            return Err("--from-ns must be smaller than --to-ns".into());
        }
        if self
            .address_start
            .zip(self.address_end)
            .is_some_and(|(a, b)| a >= b)
        {
            return Err("--address-start must be smaller than --address-end".into());
        }
        let all = analyzer.ordered_events();
        let (mut from_ns, mut to_ns) = (self.from_ns, self.to_ns);
        let mut phase_source = None;
        if let Some(phase) = &self.phase {
            let mut starts = Vec::new();
            let mut ends = Vec::new();
            for event in &all {
                if let EventPayload::PhaseMarker {
                    phase_boundary,
                    phase_name,
                } = &event.payload
                {
                    if phase_name == phase {
                        match phase_boundary {
                            PhaseBoundary::Begin => starts.push(event.timestamp_ns),
                            PhaseBoundary::End => ends.push(event.timestamp_ns),
                        }
                    }
                }
            }
            let marker_window = if starts.is_empty() && ends.is_empty() {
                None
            } else {
                if starts.len() != 1 || ends.len() != 1 || starts[0] >= ends[0] {
                    return Err(format!(
                        "phase {phase:?} has ambiguous or incomplete stream markers"
                    ));
                }
                Some((starts[0], ends[0]))
            };
            let definitions: Vec<_> = analyzer
                .data()
                .diagnostics
                .iter()
                .flat_map(|diagnostics| diagnostics.phases.iter())
                .filter(|definition| definition.name == *phase)
                .collect();
            let metadata_window = match definitions.as_slice() {
                [] => None,
                [definition]
                    if definition.start_ns > 0 && definition.start_ns < definition.stop_ns =>
                {
                    Some((definition.start_ns, definition.stop_ns))
                }
                _ => {
                    return Err(format!(
                        "phase {phase:?} has ambiguous or invalid typed metadata"
                    ));
                }
            };
            let (window, source) = match (marker_window, metadata_window) {
                (None, None) => return Err(format!("phase {phase:?} is missing")),
                (Some(window), None) => (window, PhaseSource::StreamMarkers),
                (None, Some(window)) => (window, PhaseSource::RuntimeDiagnostics),
                (Some(markers), Some(metadata)) if markers == metadata => {
                    (metadata, PhaseSource::Both)
                }
                (Some(_), Some(_)) => {
                    return Err(format!(
                        "phase {phase:?} stream markers and typed metadata disagree"
                    ));
                }
            };
            phase_source = Some(source);
            from_ns = Some(from_ns.map_or(window.0, |n| n.max(window.0)));
            to_ns = Some(to_ns.map_or(window.1, |n| n.min(window.1)));
        }

        let time_matches =
            |time: u64| from_ns.is_none_or(|lo| time >= lo) && to_ns.is_none_or(|hi| time < hi);
        let span_matches =
            |start: u64, end: u64| start < end && time_matches(start) && time_matches(end);
        let empty_window = from_ns.zip(to_ns).is_some_and(|(start, end)| start >= end);
        let overlaps = |start: u64, end: u64| {
            !empty_window
                && start < end
                && from_ns.is_none_or(|lo| end > lo)
                && to_ns.is_none_or(|hi| start < hi)
        };
        let identities = Identities::new(&all);
        let address_matches = |event: &NormalizedEvent| {
            if self.address_start.is_none() && self.address_end.is_none() {
                return true;
            }
            match event.payload {
                EventPayload::PageFault { address, .. } => {
                    self.address_start.is_none_or(|start| address >= start)
                        && self.address_end.is_none_or(|end| address < end)
                }
                _ => false,
            }
        };
        let mode_matches = |event: &NormalizedEvent| {
            self.mode.is_none_or(|selected| match event.payload {
                EventPayload::SoftwareSampleV2 { mode, .. } => mode == selected.tag(),
                EventPayload::PageFault { origin, .. } => origin == selected.tag(),
                _ => false,
            })
        };
        let intervals_applicable =
            self.address_start.is_none() && self.address_end.is_none() && self.mode.is_none();
        let events: Vec<_> = all
            .iter()
            .filter(|event| {
                address_matches(event)
                    && mode_matches(event)
                    && time_matches(event.timestamp_ns)
                    && self.cpu.is_none_or(|cpu| event.cpu_id == cpu)
                    && subjects(event)
                        .into_iter()
                        .any(|task| self.task_matches(task, &identities.for_event(event, task)))
            })
            .cloned()
            .collect();
        let mut stats = SessionStatistics::default();
        // Counts concern selected records only; no interval is paired here.
        for event in &events {
            stats.total_events += 1;
            *stats
                .event_counts
                .entry(event.event_name().into())
                .or_default() += 1;
            let cpu = stats
                .cpu_stats
                .entry(event.cpu_id)
                .or_insert_with(|| CpuStatistics {
                    cpu_id: event.cpu_id,
                    lost_records: analyzer.loss_counters().get_cpu_lost(event.cpu_id),
                    ..Default::default()
                });
            cpu.event_count += 1;
            if matches!(event.payload, EventPayload::SchedSwitch { .. }) {
                cpu.context_switches += 1;
            }
            if matches!(
                event.payload,
                EventPayload::SoftwareSample { .. } | EventPayload::SoftwareSampleV2 { .. }
            ) {
                cpu.sample_count += 1;
            }
            for task in subjects(event) {
                let identity = identities.for_event(event, task);
                if !self.task_matches(task, &identity) {
                    continue;
                }
                let row = stats
                    .task_stats
                    .entry(task)
                    .or_insert_with(|| TaskStatistics {
                        task_id: task,
                        ..Default::default()
                    });
                row.pid = identity.pid.unwrap_or(0);
                row.tid = identity.tid.unwrap_or(0);
                row.comm = identity.comm;
                match event.payload {
                    EventPayload::TaskBlock { .. } => row.block_count += 1,
                    EventPayload::TaskWake { .. } => row.wake_count += 1,
                    EventPayload::SoftwareSample { .. } | EventPayload::SoftwareSampleV2 { .. } => {
                        row.sample_count += 1
                    }
                    _ => {}
                }
            }
        }
        // Reconstruct observed closed switch intervals on the whole history;
        // statistics excludes CPUs with scheduler-source clock regressions.
        // Endpoint records below retain their exact publication order/identity.
        let complete = SessionStatistics::compute(&all, analyzer.loss_counters());
        let mut switch_outs = BTreeMap::new();
        let mut blocked_switches: BTreeMap<u64, Vec<&NormalizedEvent>> = BTreeMap::new();
        for event in &all {
            if let EventPayload::SchedSwitch {
                prev_task_id,
                prev_state,
                ..
            } = event.payload
            {
                switch_outs
                    .entry((event.cpu_id, prev_task_id, event.timestamp_ns))
                    .or_insert(event);
                if prev_state == 3 {
                    blocked_switches
                        .entry(prev_task_id)
                        .or_default()
                        .push(event);
                }
            }
        }
        let blocked_out_evidence = |task: u64, start: u64, end: u64| -> Vec<usize> {
            let Some(records) = blocked_switches.get(&task) else {
                return Vec::new();
            };
            let begin = records.partition_point(|event| event.timestamp_ns < start);
            let finish = records.partition_point(|event| event.timestamp_ns < end);
            if begin > finish {
                return Vec::new();
            }
            records[begin..finish]
                .iter()
                .map(|event| event.sequence_index)
                .collect()
        };
        // A positive interval starts at the last same-key switch-in in
        // publication order. Its exact sequence is needed when metadata shares
        // the timestamp but was emitted later on that CPU.
        let switch_ins: BTreeMap<_, _> = all
            .iter()
            .filter_map(|event| match event.payload {
                EventPayload::SchedSwitch { next_task_id, .. } => {
                    Some(((event.cpu_id, next_task_id, event.timestamp_ns), event))
                }
                _ => None,
            })
            .collect();
        let mut clipped_intervals = 0;
        let mut timeline = Timeline::default();
        let closed_bar = |kind,
                          task_id,
                          block_sequence,
                          start_ns,
                          end_ns,
                          start_cpu,
                          end_cpu,
                          quality,
                          evidence_records| TimelineInterval {
            kind,
            task_id,
            block_sequence,
            start_ns,
            end_ns,
            visible_start_ns: from_ns.map_or(start_ns, |start| start.max(start_ns)),
            visible_end_ns: to_ns.map_or(end_ns, |end| end.min(end_ns)),
            start_cpu,
            end_cpu,
            quality,
            evidence_records,
            query_clipped: !span_matches(start_ns, end_ns),
        };
        for mut interval in complete.on_cpu_intervals {
            if !intervals_applicable {
                continue;
            }
            let Some(end_event) =
                switch_outs.get(&(interval.cpu_id, interval.task_id, interval.end_ns))
            else {
                continue;
            };
            let Some(start_event) =
                switch_ins.get(&(interval.cpu_id, interval.task_id, interval.start_ns))
            else {
                continue;
            };
            let identity = identities.for_event(start_event, interval.task_id);
            if !self.task_matches(interval.task_id, &identity)
                || self.cpu.is_some_and(|cpu| cpu != interval.cpu_id)
            {
                continue;
            }
            if overlaps(interval.start_ns, interval.end_ns) {
                timeline.intervals.push(closed_bar(
                    "on_cpu",
                    interval.task_id,
                    None,
                    interval.start_ns,
                    interval.end_ns,
                    Some(interval.cpu_id),
                    Some(interval.cpu_id),
                    "observed_closed",
                    vec![start_event.sequence_index, end_event.sequence_index],
                ));
            }
            if !span_matches(interval.start_ns, interval.end_ns) {
                if overlaps(interval.start_ns, interval.end_ns) {
                    clipped_intervals += 1;
                }
                continue;
            }
            interval.comm = identity.comm.clone();
            let task = stats
                .task_stats
                .entry(interval.task_id)
                .or_insert_with(|| TaskStatistics {
                    task_id: interval.task_id,
                    pid: identity.pid.unwrap_or(0),
                    tid: identity.tid.unwrap_or(0),
                    comm: identity.comm,
                    ..Default::default()
                });
            task.on_cpu_time_ns = task.on_cpu_time_ns.saturating_add(interval.duration_ns);
            let cpu = stats
                .cpu_stats
                .entry(interval.cpu_id)
                .or_insert_with(|| CpuStatistics {
                    cpu_id: interval.cpu_id,
                    ..Default::default()
                });
            cpu.scheduled_time_ns = cpu.scheduled_time_ns.saturating_add(interval.duration_ns);
            stats.on_cpu_intervals.push(interval);
        }
        // Scheduler pairing uses the full unfiltered stream, including remote
        // wake origins and metadata preceding the visible window.
        let mut scheduler = analyzer.scheduler_report();
        let mut blocks = BTreeMap::new();
        let mut wakers = BTreeMap::new();
        for event in &all {
            match event.payload {
                EventPayload::TaskBlock {
                    block_sequence,
                    resource_id,
                    ..
                } => {
                    blocks
                        .entry((event.task_id, block_sequence))
                        .or_insert((event, resource_id));
                }
                EventPayload::TaskWake {
                    target_task_id,
                    block_sequence,
                    waker_task_id,
                    ..
                } => {
                    wakers
                        .entry((target_task_id, block_sequence))
                        .or_insert((event, waker_task_id));
                }
                _ => {}
            }
        }
        scheduler.wake_latencies.retain(|interval| {
            if !intervals_applicable {
                return false;
            }
            let identity = &interval.identity;
            if !self.task_matches(interval.task_id, identity)
                || self.cpu.is_some_and(|cpu| cpu != interval.run_cpu)
            {
                return false;
            }
            if overlaps(interval.wake_ns, interval.switch_ns) {
                let mut evidence = Vec::new();
                if let Some((block, _)) = blocks.get(&(interval.task_id, interval.block_sequence)) {
                    evidence.push(block.sequence_index);
                }
                if let Some((wake, _)) = wakers.get(&(interval.task_id, interval.block_sequence)) {
                    evidence.push(wake.sequence_index);
                }
                if let Some(switch) =
                    switch_ins.get(&(interval.run_cpu, interval.task_id, interval.switch_ns))
                {
                    evidence.push(switch.sequence_index);
                }
                evidence.extend(blocked_out_evidence(
                    interval.task_id,
                    interval.block_ns,
                    interval.wake_ns,
                ));
                timeline.intervals.push(closed_bar(
                    "wake_to_switch",
                    interval.task_id,
                    Some(interval.block_sequence),
                    interval.wake_ns,
                    interval.switch_ns,
                    Some(interval.wake_cpu),
                    Some(interval.run_cpu),
                    "observed_closed",
                    evidence,
                ));
            }
            if !span_matches(interval.wake_ns, interval.switch_ns) {
                if overlaps(interval.wake_ns, interval.switch_ns) {
                    clipped_intervals += 1;
                }
                return false;
            }
            true
        });
        scheduler.blocked_waits.retain(|interval| {
            if !intervals_applicable {
                return false;
            }
            let Some((block, _)) = blocks.get(&(interval.task_id, interval.block_sequence)) else {
                return false;
            };
            if !self.task_matches(interval.task_id, &interval.identity)
                || self.cpu.is_some_and(|cpu| cpu != block.cpu_id)
            {
                return false;
            }
            if overlaps(interval.block_ns, interval.wake_ns) {
                if let Some((wake, _)) = wakers.get(&(interval.task_id, interval.block_sequence)) {
                    timeline.intervals.push(closed_bar(
                        "blocked_wait",
                        interval.task_id,
                        Some(interval.block_sequence),
                        interval.block_ns,
                        interval.wake_ns,
                        Some(block.cpu_id),
                        Some(wake.cpu_id),
                        if interval.order_ambiguous {
                            "ambiguous_order"
                        } else {
                            "observed_closed"
                        },
                        vec![block.sequence_index, wake.sequence_index],
                    ));
                }
            }
            if !span_matches(interval.block_ns, interval.wake_ns) {
                if overlaps(interval.block_ns, interval.wake_ns) {
                    clipped_intervals += 1;
                }
                return false;
            }
            true
        });
        scheduler.unfinished.retain(|interval| {
            if !intervals_applicable {
                return false;
            }
            let time = interval.wake_ns.or(interval.block_ns);
            let block = blocks
                .get(&(interval.task_id, interval.block_sequence))
                .map(|(event, _)| *event);
            // The wake may originate on a different CPU than the block.
            // Reuse that actual event's ordering facts, never a made-up MAX
            // sequence or the block CPU at the wake timestamp.
            let anchor = if let Some(wake_ns) = interval.wake_ns {
                wakers
                    .get(&(interval.task_id, interval.block_sequence))
                    .map(|(event, _)| *event)
                    .filter(|event| event.timestamp_ns == wake_ns)
            } else {
                block.filter(|event| Some(event.timestamp_ns) == interval.block_ns)
            };
            let identity = anchor
                .map(|event| identities.for_event(event, interval.task_id))
                .unwrap_or_default();
            if !self.task_matches(interval.task_id, &identity)
                || self
                    .cpu
                    .is_some_and(|cpu| block.is_none_or(|b| b.cpu_id != cpu))
            {
                return false;
            }
            let Some(time) = time else {
                return false;
            };
            if interval.reason == UnfinishedReason::RightCensored {
                // This episode is still pending in the observed history. Its
                // last event may precede the query, but it remains relevant
                // until capture stop. That horizon is not a switch-in or a
                // completed duration, and must never become a latency sample.
                let stop = analyzer.metadata().stop_ns;
                let spans_window = overlaps(time, stop);
                if !time_matches(time) && !spans_window {
                    return false;
                }
                if spans_window
                    && (from_ns.is_some_and(|lo| lo > time) || to_ns.is_some_and(|hi| hi < stop))
                {
                    clipped_intervals += 1;
                }
                true
            } else {
                time_matches(time)
            }
        });
        for episode in &scheduler.unfinished {
            let start = episode.wake_ns.or(episode.block_ns);
            let right_censored = episode.reason == UnfinishedReason::RightCensored;
            let limit = right_censored.then(|| {
                to_ns.map_or(analyzer.metadata().stop_ns, |end| {
                    end.min(analyzer.metadata().stop_ns)
                })
            });
            let mut evidence = Vec::new();
            if let Some((block, _)) = blocks.get(&(episode.task_id, episode.block_sequence)) {
                evidence.push(block.sequence_index);
            }
            if let Some((wake, _)) = wakers.get(&(episode.task_id, episode.block_sequence)) {
                evidence.push(wake.sequence_index);
            }
            if let Some(block_ns) = episode.block_ns {
                evidence.extend(blocked_out_evidence(
                    episode.task_id,
                    block_ns,
                    episode.wake_ns.unwrap_or(analyzer.metadata().stop_ns),
                ));
            }
            timeline.unfinished.push(TimelineUnfinished {
                episode: episode.clone(),
                visible_start_ns: start.map(|at| from_ns.map_or(at, |begin| begin.max(at))),
                observation_limit_ns: limit,
                query_clipped: right_censored
                    && start.is_some_and(|at| {
                        overlaps(at, analyzer.metadata().stop_ns)
                            && (from_ns.is_some_and(|begin| begin > at)
                                || to_ns.is_some_and(|end| end < analyzer.metadata().stop_ns))
                    }),
                evidence_records: evidence,
            });
        }
        // Fault intervals are self-contained completion records. Reuse the
        // fault module's semantic validator, including elapsed-time consistency.
        for event in &all {
            if let EventPayload::PageFault {
                start_ns,
                classification,
                ..
            } = event.payload
            {
                if !address_matches(event)
                    || !mode_matches(event)
                    || self.cpu.is_some_and(|cpu| cpu != event.cpu_id)
                    || !self
                        .task_matches(event.task_id, &identities.for_event(event, event.task_id))
                    || !overlaps(start_ns, event.timestamp_ns)
                {
                    continue;
                }
                if crate::fault::FaultReport::compute(
                    std::slice::from_ref(event),
                    analyzer.is_complete(),
                )
                .valid_events
                    != 1
                {
                    continue;
                }
                timeline.intervals.push(closed_bar(
                    "page_fault_resolve",
                    event.task_id,
                    None,
                    start_ns,
                    event.timestamp_ns,
                    None,
                    Some(event.cpu_id),
                    if classification == 0 {
                        "observed_closed_unknown_classification"
                    } else {
                        "observed_closed"
                    },
                    vec![event.sequence_index],
                ));
            }
        }
        for interval in &scheduler.blocked_waits {
            if interval.order_ambiguous {
                continue;
            }
            let resource_id = blocks[&(interval.task_id, interval.block_sequence)].1;
            let row = stats
                .task_stats
                .entry(interval.task_id)
                .or_insert_with(|| TaskStatistics {
                    task_id: interval.task_id,
                    pid: interval.identity.pid.unwrap_or(0),
                    tid: interval.identity.tid.unwrap_or(0),
                    comm: interval.identity.comm.clone(),
                    ..Default::default()
                });
            row.off_cpu_wait_ns = row.off_cpu_wait_ns.saturating_add(interval.duration_ns);
            stats.off_cpu_intervals.push(OffCpuInterval {
                task_id: interval.task_id,
                comm: interval.identity.comm.clone(),
                block_sequence: interval.block_sequence,
                wait_reason: interval.wait_reason,
                resource_id,
                start_ns: interval.block_ns,
                end_ns: interval.wake_ns,
                duration_ns: interval.duration_ns,
                waker_task_id: wakers[&(interval.task_id, interval.block_sequence)].1,
            });
        }
        stats.unpaired_blocks = scheduler
            .unfinished
            .iter()
            .filter(|e| e.block_ns.is_some())
            .count() as u64;
        stats.unpaired_wakes = scheduler
            .unfinished
            .iter()
            .filter(|e| e.reason == UnfinishedReason::LeftCensored)
            .count() as u64;
        // Context contains actual supporting records, never synthesized
        // boundary events. Include identity history only for involved tasks.
        let selected_ids: BTreeSet<_> = events.iter().map(|e| e.sequence_index).collect();
        let mut supporting = BTreeSet::new();
        for bar in &timeline.intervals {
            supporting.extend(bar.evidence_records.iter().copied());
        }
        for pending in &timeline.unfinished {
            supporting.extend(pending.evidence_records.iter().copied());
        }
        let mut involved: BTreeMap<u64, u64> = BTreeMap::new();
        for event in &all {
            if selected_ids.contains(&event.sequence_index)
                || supporting.contains(&event.sequence_index)
            {
                for task in subjects(event)
                    .into_iter()
                    .chain(std::iter::once(event.task_id))
                {
                    involved
                        .entry(task)
                        .and_modify(|until| *until = (*until).max(event.timestamp_ns))
                        .or_insert(event.timestamp_ns);
                }
            }
        }
        for event in &all {
            match &event.payload {
                EventPayload::TaskMetadata { target_task_id, .. }
                    if involved
                        .get(target_task_id)
                        .is_some_and(|&until| event.timestamp_ns <= until) =>
                {
                    supporting.insert(event.sequence_index);
                }
                EventPayload::PhaseMarker { phase_name, .. }
                    if self.phase.as_ref() == Some(phase_name) =>
                {
                    supporting.insert(event.sequence_index);
                }
                _ => {}
            }
        }
        timeline.context_events = all
            .iter()
            .filter(|e| {
                supporting.contains(&e.sequence_index) && !selected_ids.contains(&e.sequence_index)
            })
            .cloned()
            .collect();
        timeline
            .intervals
            .sort_by_key(|bar| (bar.start_ns, bar.end_ns, bar.task_id, bar.kind));
        scheduler.rebuild_summaries();
        Ok(AnalysisResult {
            query: self.clone(),
            phase_source,
            from_ns,
            to_ns,
            context_records_count: all.len() - events.len(),
            events,
            clipped_intervals,
            stats,
            scheduler,
            timeline,
        })
    }
}
