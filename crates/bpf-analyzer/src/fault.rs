//! Aggregate selected page-fault completion records without inventing timings.
use std::{collections::BTreeMap, fmt::Write};

use crate::{EventPayload, NormalizedEvent};

/// Address grouping uses fixed 4-KiB reporting bins, not inferred PTE sizes.
pub const ADDRESS_BIN_BYTES: u64 = 4096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FaultGroupKey {
    pub task_id: u64,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub page_address: u64,
    pub access: u32,
    pub origin: u32,
    pub outcome: u32,
    pub classification: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FaultDurations {
    pub count: u64,
    pub sum_ns: u128,
    pub min_ns: Option<u64>,
    pub max_ns: Option<u64>,
    /// Inclusive upper bounds: 0, 1, 2, 4, ... , 2^63, u64::MAX.
    pub histogram_ns: BTreeMap<u64, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultGroup {
    pub key: FaultGroupKey,
    pub record_count: u64,
    pub query_censored: u64,
    pub duration: FaultDurations,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FaultReport {
    pub capture_complete: bool,
    pub is_complete: bool,
    pub invalid_window: bool,
    pub captured_events: u64,
    pub valid_events: u64,
    pub invalid_events: u64,
    pub query_censored: u64,
    /// Disjoint counts of successful resolver completions by measured class.
    pub resolved_minor: u64,
    pub resolved_major: u64,
    pub resolved_unknown: u64,
    /// NotHandled, NoMemory and ResolverError; classification is not applicable.
    pub unsuccessful: u64,
    /// Raw Unknown tags, including unsuccessful completions.
    pub unknown_classification: u64,
    pub unknown_access: u64,
    pub unknown_identity: u64,
    pub duration: FaultDurations,
    pub groups: Vec<FaultGroup>,
}

impl FaultReport {
    pub fn compute(events: &[NormalizedEvent], capture_complete: bool) -> Self {
        Self::compute_in_window(events, capture_complete, None, None)
    }
    /// `events` are the Query's selected completion records. Windows are
    /// half-open; a resolver beginning before the query is counted but its full
    /// duration is excluded, never clipped into a fabricated latency sample.
    pub fn compute_in_window(
        events: &[NormalizedEvent],
        capture_complete: bool,
        from_ns: Option<u64>,
        to_ns: Option<u64>,
    ) -> Self {
        let mut report = Self {
            capture_complete,
            invalid_window: to_ns.is_some_and(|end| from_ns.unwrap_or(0) >= end),
            ..Self::default()
        };
        let mut groups: BTreeMap<FaultGroupKey, FaultGroup> = BTreeMap::new();
        for event in events {
            let EventPayload::PageFault {
                address,
                start_ns,
                elapsed_ns,
                access,
                origin,
                outcome,
                classification,
            } = &event.payload
            else {
                continue;
            };
            report.captured_events += 1;
            if event.event_id != 8
                || event.schema_version != 1
                || event.task_id == 0
                || event.timestamp_ns.checked_sub(*start_ns) != Some(*elapsed_ns)
                || access & !7 != 0
                || !matches!(*origin, 1 | 2)
                || !pulse_bpf_schema::PageFaultClassification::is_valid_pair(*outcome, *classification)
            {
                report.invalid_events += 1;
                continue;
            }
            report.valid_events += 1;
            if *outcome == 1 {
                match classification {
                    0 => report.resolved_unknown += 1,
                    1 => report.resolved_minor += 1,
                    2 => report.resolved_major += 1,
                    _ => unreachable!("validated page-fault classification"),
                }
            } else {
                report.unsuccessful += 1;
            }
            report.unknown_classification += u64::from(*classification == 0);
            report.unknown_access += u64::from(*access == 0);
            report.unknown_identity += u64::from(event.pid == 0 || event.tid == 0);
            let key = FaultGroupKey {
                task_id: event.task_id,
                pid: (event.pid != 0).then_some(event.pid),
                tid: (event.tid != 0).then_some(event.tid),
                page_address: *address & !(ADDRESS_BIN_BYTES - 1),
                access: *access,
                origin: *origin,
                outcome: *outcome,
                classification: *classification,
            };
            let group = groups.entry(key.clone()).or_insert_with(|| FaultGroup {
                key,
                record_count: 0,
                query_censored: 0,
                duration: FaultDurations::default(),
            });
            group.record_count += 1;
            let censored = report.invalid_window
                || from_ns.is_some_and(|from| *start_ns < from || event.timestamp_ns < from)
                || to_ns.is_some_and(|to| event.timestamp_ns >= to);
            if censored {
                group.query_censored += 1;
                report.query_censored += 1;
            } else {
                group.duration.observe(*elapsed_ns);
                report.duration.observe(*elapsed_ns);
            }
        }
        report.groups = groups.into_values().collect();
        report.is_complete = capture_complete
            && report.valid_events > 0
            && report.resolved_unknown == 0
            && report.unknown_access == 0
            && report.unknown_identity == 0
            && report.invalid_events == 0
            && report.query_censored == 0
            && !report.invalid_window;
        report
    }
    pub fn render_text(&self) -> String {
        let mut text = String::new();
        writeln!(
            &mut text,
            "{} Page-fault resolver completions; resolver_wall_ns (not CPU time)",
            if self.is_complete {
                "[OBSERVED]"
            } else {
                "[PARTIAL]"
            }
        )
        .unwrap();
        writeln!(
            &mut text,
            "resolved_minor={} resolved_major={} resolved_unknown={} unsuccessful={}",
            self.resolved_minor, self.resolved_major, self.resolved_unknown, self.unsuccessful
        )
        .unwrap();
        writeln!(
            &mut text,
            "capture_complete={} records={} valid={} invalid={} query_censored={} \
             unknown_classification={} unknown_access={} unknown_identity={} invalid_window={}",
            self.capture_complete,
            self.captured_events,
            self.valid_events,
            self.invalid_events,
            self.query_censored,
            self.unknown_classification,
            self.unknown_access,
            self.unknown_identity,
            self.invalid_window
        )
        .unwrap();
        writeln!(
            &mut text,
            "Address groups are {}-byte reporting bins. Censored durations are not histogram \
             samples.",
            ADDRESS_BIN_BYTES
        )
        .unwrap();
        writeln!(
            &mut text,
            "task pid tid address_bin access origin resolver_outcome classification classification_applicability records timed \
             min_ns max_ns sum_ns"
        )
        .unwrap();
        for group in &self.groups {
            let key = &group.key;
            writeln!(
                &mut text,
                "{} {} {} 0x{:x} {} {} {} {} {} {} {} {} {} {}",
                key.task_id,
                key.pid.map_or_else(|| "unknown".into(), |v| v.to_string()),
                key.tid.map_or_else(|| "unknown".into(), |v| v.to_string()),
                key.page_address,
                access_name(key.access),
                origin_name(key.origin),
                outcome_name(key.outcome),
                classification_name(key.classification),
                classification_applicability(key.outcome),
                group.record_count,
                group.duration.count,
                optional_number(group.duration.min_ns),
                optional_number(group.duration.max_ns),
                group.duration.sum_ns
            )
            .unwrap();
        }
        text
    }
    pub fn render_json(&self) -> String {
        let mut json = String::new();
        write!(
            &mut json,
            "{{\"kind\":\"fault_report\",\"time_unit\":\"ns\",\"duration_semantics\":\"\
             resolver_wall_time\",\"histogram_bounds\":\"inclusive_upper\",\"address_bin_bytes\":\
             {},\"capture_complete\":{},\"is_complete\":{},\"invalid_window\":{},\"\
             captured_events\":{},\"valid_events\":{},\"invalid_events\":{},\"query_censored\":{},\
             \"resolved_minor\":{},\"resolved_major\":{},\"resolved_unknown\":{},\"unsuccessful\":{},\
             \"unknown_classification\":{},\"unknown_access\":{},\"unknown_identity\":{},\"\
             duration\":",
            ADDRESS_BIN_BYTES,
            self.capture_complete,
            self.is_complete,
            self.invalid_window,
            self.captured_events,
            self.valid_events,
            self.invalid_events,
            self.query_censored,
            self.resolved_minor,
            self.resolved_major,
            self.resolved_unknown,
            self.unsuccessful,
            self.unknown_classification,
            self.unknown_access,
            self.unknown_identity
        )
        .unwrap();
        self.duration.write_json(&mut json);
        json.push_str(",\"groups\":[");
        for (index, group) in self.groups.iter().enumerate() {
            if index > 0 {
                json.push(',');
            }
            let key = &group.key;
            write!(
                &mut json,
                "{{\"task_id\":{},\"pid\":{},\"tid\":{},\"page_address\":{},\"access_bits\":{},\"\
                 access\":\"{}\",\"origin_id\":{},\"origin\":\"{}\",\"outcome_id\":{},\"outcome\":\
                 \"{}\",\"classification_id\":{},\"classification\":\"{}\",\"classification_applicability\":\"{}\",\"record_count\":{},\"\
                 query_censored\":{},\"duration\":",
                key.task_id,
                optional_number(key.pid),
                optional_number(key.tid),
                key.page_address,
                key.access,
                access_name(key.access),
                key.origin,
                origin_name(key.origin),
                key.outcome,
                outcome_name(key.outcome),
                key.classification,
                classification_name(key.classification),
                classification_applicability(key.outcome),
                group.record_count,
                group.query_censored
            )
            .unwrap();
            group.duration.write_json(&mut json);
            json.push('}');
        }
        json.push_str("]}");
        json
    }
}

impl FaultDurations {
    fn write_json(&self, json: &mut String) {
        let mean = if self.count == 0 {
            "null".into()
        } else {
            (self.sum_ns as f64 / self.count as f64).to_string()
        };
        write!(
            json,
            "{{\"count\":{},\"sum_ns\":{},\"min_ns\":{},\"max_ns\":{},\"mean_ns\":{},\"\
             histogram_ns\":[",
            self.count,
            self.sum_ns,
            optional_number(self.min_ns),
            optional_number(self.max_ns),
            mean
        )
        .unwrap();
        for (index, (upper, count)) in self.histogram_ns.iter().enumerate() {
            if index > 0 {
                json.push(',');
            }
            write!(json, "{{\"upper_ns\":{},\"count\":{}}}", upper, count).unwrap();
        }
        json.push_str("]}");
    }
    fn observe(&mut self, elapsed: u64) {
        self.count += 1;
        self.sum_ns += u128::from(elapsed);
        self.min_ns = Some(self.min_ns.map_or(elapsed, |old| old.min(elapsed)));
        self.max_ns = Some(self.max_ns.map_or(elapsed, |old| old.max(elapsed)));
        let upper = if elapsed == 0 {
            0
        } else {
            elapsed.checked_next_power_of_two().unwrap_or(u64::MAX)
        };
        *self.histogram_ns.entry(upper).or_default() += 1;
    }
}

fn optional_number<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "null".into(), |v| v.to_string())
}
fn classification_name(value: u32) -> &'static str {
    match value {
        0 => "unknown",
        1 => "minor",
        2 => "major",
        _ => "unsupported",
    }
}
pub(crate) fn classification_applicability(outcome: u32) -> &'static str {
    if outcome == 1 { "applicable" } else { "not_applicable" }
}
fn origin_name(value: u32) -> &'static str {
    match value {
        1 => "kernel",
        2 => "user",
        _ => "unsupported",
    }
}
fn outcome_name(value: u32) -> &'static str {
    match value {
        1 => "resolved",
        2 => "not_handled",
        3 => "no_memory",
        4 => "resolver_error",
        _ => "unsupported",
    }
}
fn access_name(value: u32) -> &'static str {
    match value {
        0 => "unknown",
        1 => "read",
        2 => "write",
        3 => "read|write",
        4 => "execute",
        5 => "read|execute",
        6 => "write|execute",
        7 => "read|write|execute",
        _ => "unsupported",
    }
}
