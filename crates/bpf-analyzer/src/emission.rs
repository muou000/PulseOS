use bpf_capture::framing::SessionStatusCode;
use std::collections::BTreeMap;
use std::fmt::Write;

use crate::analyzer::CaptureAnalyzer;
use crate::event::{EventPayload, NormalizedEvent};
use crate::stats::SessionStatistics;

/// Folded stack output with completeness and session status indicator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldedOutput {
    pub text: String,
    pub is_complete: bool,
    pub status: SessionStatusCode,
}

/// Render a tabular textual overview of all normalized events.
pub fn render_event_table(analyzer: &CaptureAnalyzer, events: &[NormalizedEvent]) -> String {
    let mut out = String::new();

    if !analyzer.is_complete() {
        writeln!(
            &mut out,
            "[WARNING: INCOMPLETE CAPTURE - Attribution claims disallowed (Anchor A3 / #88)]"
        )
        .unwrap();
        writeln!(&mut out).unwrap();
    }

    writeln!(
        &mut out,
        "{:<16} {:<4} {:<6} {:<6} {:<8} {:<16} {:<14} {}",
        "TIMESTAMP (ns)", "CPU", "PID", "TID", "TASK_ID", "COMM", "EVENT", "DETAILS"
    )
    .unwrap();
    writeln!(
        &mut out,
        "{:-<16} {:-<4} {:-<6} {:-<6} {:-<8} {:-<16} {:-<14} {:-<30}",
        "", "", "", "", "", "", "", ""
    )
    .unwrap();

    for ev in events {
        let comm_str = ev.comm.as_deref().unwrap_or("-");
        let details = match &ev.payload {
            EventPayload::TaskMetadata {
                target_task_id,
                target_pid,
                target_tid,
                comm,
            } => {
                format!(
                    "target={} pid={} tid={} comm=\"{}\"",
                    target_task_id, target_pid, target_tid, comm
                )
            }
            EventPayload::SchedSwitch {
                prev_task_id,
                next_task_id,
                prev_state,
                prev_prio,
                next_prio,
            } => {
                format!(
                    "prev={} next={} prev_state={} prio={}/{}",
                    prev_task_id, next_task_id, prev_state, prev_prio, next_prio
                )
            }
            EventPayload::TaskBlock {
                block_sequence,
                wait_reason,
                resource_id,
                resource_detail,
            } => {
                format!(
                    "seq={} wait_reason={} res_id={} detail={}",
                    block_sequence, wait_reason, resource_id, resource_detail
                )
            }
            EventPayload::TaskWake {
                target_task_id,
                block_sequence,
                waker_task_id,
                wake_source,
                source_id,
            } => {
                format!(
                    "target={} seq={} waker={} source={} src_id={}",
                    target_task_id, block_sequence, waker_task_id, wake_source, source_id
                )
            }
            EventPayload::TaskExit {
                exit_task_id,
                exit_code,
            } => {
                format!("exit_task={} code={}", exit_task_id, exit_code)
            }
            EventPayload::TaskEnqueue {
                enqueue_task_id,
                enqueue_cpu,
                target_cpu,
                queue_depth,
                enqueue_reason,
            } => {
                format!(
                    "task={} from_cpu={} to_cpu={} q_depth={} reason={}",
                    enqueue_task_id, enqueue_cpu, target_cpu, queue_depth, enqueue_reason
                )
            }
            EventPayload::PhaseMarker {
                phase_boundary,
                phase_name,
            } => {
                format!("{:?} \"{}\"", phase_boundary, phase_name)
            }
            EventPayload::SoftwareSample { sample_period, pc } => {
                format!("period={} pc=0x{:016x}", sample_period, pc)
            }
            EventPayload::SoftwareSampleV2 { sample_period, addr, pc, mode } => {
                let mode = match mode { 1 => "kernel", 2 => "user", _ => "unknown" };
                format!("period={} pc=0x{:016x} mode={} addr=0x{:016x}", sample_period, pc, mode, addr)
            }
            EventPayload::Raw { bytes } => {
                format!("raw_bytes={}", bytes.len())
            }
        };

        writeln!(
            &mut out,
            "{:<16} {:<4} {:<6} {:<6} {:<8} {:<16} {:<14} {}",
            ev.timestamp_ns,
            ev.cpu_id,
            ev.pid,
            ev.tid,
            ev.task_id,
            comm_str,
            ev.event_name(),
            details
        )
        .unwrap();
    }

    out
}

/// Render a detailed loss and integrity summary report.
pub fn render_loss_report(analyzer: &CaptureAnalyzer) -> String {
    let mut out = String::new();
    let status = analyzer.status_code();
    let is_comp = analyzer.is_complete();
    let counters = analyzer.loss_counters();

    writeln!(&mut out, "================================================================================").unwrap();
    writeln!(&mut out, "PulseOS BPF Capture Loss and Integrity Report").unwrap();
    writeln!(&mut out, "================================================================================").unwrap();
    writeln!(&mut out, "Status: {:?}", status).unwrap();
    writeln!(&mut out, "Target Arch: {}", analyzer.target_arch().as_str()).unwrap();
    writeln!(
        &mut out,
        "Attribution Claim: {}",
        if analyzer.attribution_claim_allowed() {
            "Allowed"
        } else {
            "Disallowed"
        }
    )
    .unwrap();
    writeln!(&mut out).unwrap();

    if let Some(diagnostics) = &analyzer.data().diagnostics {
        writeln!(&mut out, "--- Runtime diagnostics (scopes overlap; do not sum) ---").unwrap();
        for counter in &diagnostics.counters {
            let value = counter.value.map(|v| v.to_string()).unwrap_or_else(|| "unknown".into());
            writeln!(&mut out, "{} {} ({:?}): {}", counter.scope, counter.name, counter.kind, value).unwrap();
        }
        writeln!(&mut out, "--- Build and run identities ---").unwrap();
        for identity in &diagnostics.identities {
            writeln!(&mut out, "{}: {}", identity.name, identity.value.as_deref().unwrap_or("unknown")).unwrap();
        }
        writeln!(&mut out, "--- Measured workload phases ---").unwrap();
        for phase in &diagnostics.phases {
            let wall = phase.stop_ns - phase.start_ns;
            let mapped = phase.mapped_bytes.map(|v| v.to_string()).unwrap_or_else(|| "unknown".into());
            writeln!(&mut out, "{}: start_ns={} stop_ns={} wall_ns={} iterations={} iterations_per_second={:.3} sampler_mapped_bytes={}",
                phase.name, phase.start_ns, phase.stop_ns, wall, phase.iterations,
                phase.iterations as f64 * 1e9 / wall as f64, mapped).unwrap();
        }
        writeln!(&mut out, "Consumer projection: {} normalized records; {} observed PERF_RECORD_LOST notices (counts may overlap sink diagnostics).",
            counters.delivered, counters.lost_records_total).unwrap();
        writeln!(&mut out, "Other legacy counter fields are not runtime measurements; use the scoped diagnostics above.").unwrap();
        writeln!(&mut out, "Complete CPU/off-CPU attribution: unavailable (individual source stream; mappings/callchains/full scheduler evidence absent).").unwrap();
        if is_comp {
            writeln!(&mut out, "Integrity verified; no loss reported by the recorded diagnostics. This is not proof of complete attribution.").unwrap();
        } else {
            writeln!(&mut out, "PARTIAL: loss, error, or unknown runtime evidence prevents a complete capture claim.").unwrap();
        }
        return out;
    }

    writeln!(&mut out, "--- Layered Loss Counters ---").unwrap();
    writeln!(&mut out, "Attempted: {}", counters.attempted).unwrap();
    writeln!(&mut out, "Delivered: {}", counters.delivered).unwrap();
    writeln!(&mut out, "Lost Records: {}", counters.lost_records_total).unwrap();

    if !counters.per_cpu_lost.is_empty() {
        for &(cpu, count) in &counters.per_cpu_lost {
            writeln!(&mut out, "  CPU {}: {} lost", cpu, count).unwrap();
        }
    }

    writeln!(&mut out, "Ringbuf Lost: {}", counters.ringbuf_lost).unwrap();
    writeln!(&mut out, "Discarded Records: {}", counters.discarded_records).unwrap();
    writeln!(&mut out, "Re-entry Drops: {}", counters.re_entry_drops).unwrap();
    writeln!(&mut out, "Helper Failures: {}", counters.helper_failures).unwrap();
    writeln!(&mut out, "Budget Failures: {}", counters.budget_failures).unwrap();
    writeln!(&mut out, "Verifier Failures: {}", counters.verifier_failures).unwrap();
    writeln!(&mut out, "Load Failures: {}", counters.load_failures).unwrap();
    writeln!(&mut out, "Attach Failures: {}", counters.attach_failures).unwrap();
    writeln!(&mut out, "Consumer Corrupt Records: {}", counters.consumer_corrupt_records).unwrap();
    writeln!(&mut out, "Consumer Out-of-Bounds: {}", counters.consumer_out_of_bounds).unwrap();
    writeln!(&mut out).unwrap();

    if !is_comp {
        writeln!(&mut out, "WARNING: Capture is incomplete. Attribution claims cannot be treated as complete or final (Anchor A3 / #88).").unwrap();
    } else {
        writeln!(&mut out, "INTEGRITY CHECK PASSED: Capture is fully complete with zero data loss.").unwrap();
    }

    out
}

/// Render a machine-readable JSON document.
pub fn render_json(
    analyzer: &CaptureAnalyzer,
    stats: &SessionStatistics,
) -> String {
    let mut out = String::new();
    let hdr = analyzer.header();
    let meta = analyzer.metadata();
    let counters = analyzer.loss_counters();
    let is_comp = analyzer.is_complete();
    let status_str = match analyzer.status_code() {
        SessionStatusCode::Complete => "Complete",
        SessionStatusCode::IncompleteLoss => "IncompleteLoss",
        SessionStatusCode::IncompleteTruncated => "IncompleteTruncated",
        SessionStatusCode::IncompleteError => "IncompleteError",
    };

    writeln!(&mut out, "{{").unwrap();
    writeln!(&mut out, "  \"is_complete\": {},", is_comp).unwrap();
    writeln!(&mut out, "  \"status\": \"{}\",", status_str).unwrap();
    writeln!(
        &mut out,
        "  \"attribution_claim_allowed\": {},",
        analyzer.attribution_claim_allowed()
    )
    .unwrap();
    writeln!(&mut out, "  \"arch\": \"{}\",", analyzer.target_arch().as_str()).unwrap();
    writeln!(&mut out, "  \"pulse_commit\": {},", json_string(&meta.config.pulse_commit)).unwrap();
    writeln!(&mut out, "  \"kernel_elf_path\": {},", json_string(&meta.config.kernel_elf_path)).unwrap();
    writeln!(&mut out, "  \"kernel_elf_hash\": {},", json_string(&meta.config.kernel_elf_hash)).unwrap();
    writeln!(&mut out, "  \"image_path\": {},", json_string(&meta.config.image_path)).unwrap();
    writeln!(&mut out, "  \"image_hash\": {},", json_string(&meta.config.image_hash)).unwrap();
    writeln!(&mut out, "  \"clock_name\": {},", json_string(&meta.config.clock_name)).unwrap();
    writeln!(&mut out, "  \"sample_period\": {},", meta.config.sample_period).unwrap();
    writeln!(&mut out, "  \"buffer_pages\": {},", meta.config.buffer_pages).unwrap();
    writeln!(&mut out, "  \"records_count\": {},", hdr.records_count).unwrap();

    if let Some(diagnostics) = &analyzer.data().diagnostics {
        writeln!(&mut out, "  \"statistics_scope\": \"observed records only; per-CPU lost_records contains consumed PERF_RECORD_LOST counts\",").unwrap();
        writeln!(&mut out, "  \"loss_counters\": null,").unwrap();
        writeln!(&mut out, "  \"consumer_projection\": {{\"delivered\": {}, \"observed_perf_lost\": {}}},", counters.delivered, counters.lost_records_total).unwrap();
        write!(&mut out, "  \"runtime_diagnostics\": ").unwrap();
        render_diagnostics_json(&mut out, diagnostics);
        writeln!(&mut out, ",").unwrap();
    } else {
        // loss_counters object
        writeln!(&mut out, "  \"loss_counters\": {{").unwrap();
        writeln!(&mut out, "    \"attempted\": {},", counters.attempted).unwrap();
        writeln!(&mut out, "    \"delivered\": {},", counters.delivered).unwrap();
        writeln!(&mut out, "    \"lost_records_total\": {},", counters.lost_records_total).unwrap();
        writeln!(&mut out, "    \"ringbuf_lost\": {},", counters.ringbuf_lost).unwrap();
        writeln!(&mut out, "    \"discarded_records\": {},", counters.discarded_records).unwrap();
        writeln!(&mut out, "    \"re_entry_drops\": {},", counters.re_entry_drops).unwrap();
        writeln!(&mut out, "    \"helper_failures\": {},", counters.helper_failures).unwrap();
        writeln!(&mut out, "    \"budget_failures\": {},", counters.budget_failures).unwrap();
        writeln!(&mut out, "    \"verifier_failures\": {},", counters.verifier_failures).unwrap();
        writeln!(&mut out, "    \"load_failures\": {},", counters.load_failures).unwrap();
        writeln!(&mut out, "    \"attach_failures\": {},", counters.attach_failures).unwrap();
        writeln!(&mut out, "    \"consumer_corrupt_records\": {},", counters.consumer_corrupt_records).unwrap();
        writeln!(&mut out, "    \"consumer_out_of_bounds\": {},", counters.consumer_out_of_bounds).unwrap();
        writeln!(&mut out, "    \"per_cpu_lost\": [").unwrap();
        for (i, &(cpu, count)) in counters.per_cpu_lost.iter().enumerate() {
            let comma = if i + 1 < counters.per_cpu_lost.len() { "," } else { "" };
            writeln!(&mut out, "      {{\"cpu\": {}, \"lost\": {}}}{}", cpu, count, comma).unwrap();
        }
        writeln!(&mut out, "    ]").unwrap();
        writeln!(&mut out, "  }},").unwrap();

    }

    // cpu_stats array
    writeln!(&mut out, "  \"cpu_stats\": [").unwrap();
    let cpu_keys: Vec<_> = stats.cpu_stats.keys().cloned().collect();
    for (i, cpu_id) in cpu_keys.iter().enumerate() {
        let c = &stats.cpu_stats[cpu_id];
        let comma = if i + 1 < cpu_keys.len() { "," } else { "" };
        writeln!(
            &mut out,
            "    {{\"cpu_id\": {}, \"event_count\": {}, \"sample_count\": {}, \"context_switches\": {}, \"lost_records\": {}, \"busy_time_ns\": {}, \"idle_time_ns\": {}}}{}",
            c.cpu_id, c.event_count, c.sample_count, c.context_switches, c.lost_records, c.busy_time_ns, c.idle_time_ns, comma
        ).unwrap();
    }
    writeln!(&mut out, "  ],").unwrap();

    // task_stats array
    writeln!(&mut out, "  \"task_stats\": [").unwrap();
    let task_keys: Vec<_> = stats.task_stats.keys().cloned().collect();
    for (i, tid) in task_keys.iter().enumerate() {
        let t = &stats.task_stats[tid];
        let comma = if i + 1 < task_keys.len() { "," } else { "" };
        let comm_str = t.comm.as_deref().unwrap_or("");
        writeln!(
            &mut out,
            "    {{\"task_id\": {}, \"comm\": {}, \"pid\": {}, \"tid\": {}, \"on_cpu_time_ns\": {}, \"off_cpu_wait_ns\": {}, \"block_count\": {}, \"wake_count\": {}, \"sample_count\": {}}}{}",
            t.task_id, json_string(comm_str), t.pid, t.tid, t.on_cpu_time_ns, t.off_cpu_wait_ns, t.block_count, t.wake_count, t.sample_count, comma
        ).unwrap();
    }
    writeln!(&mut out, "  ],").unwrap();

    // event_counts
    writeln!(&mut out, "  \"event_counts\": {{").unwrap();
    let event_keys: Vec<_> = stats.event_counts.keys().cloned().collect();
    for (i, k) in event_keys.iter().enumerate() {
        let comma = if i + 1 < event_keys.len() { "," } else { "" };
        writeln!(&mut out, "    \"{}\": {}{}", k, stats.event_counts[k], comma).unwrap();
    }
    writeln!(&mut out, "  }},").unwrap();

    writeln!(&mut out, "  \"unpaired_blocks\": {},", stats.unpaired_blocks).unwrap();
    writeln!(&mut out, "  \"unpaired_wakes\": {}", stats.unpaired_wakes).unwrap();
    write!(&mut out, "}}").unwrap();

    out
}

/// Render on-CPU folded stack frames compatible with FlameGraph.
/// Aggregates identical collapsed stack traces to total counts/durations.
pub fn render_on_cpu_folded(
    analyzer: &CaptureAnalyzer,
    events: &[NormalizedEvent],
    stats: &SessionStatistics,
) -> FoldedOutput {
    let mut out = String::new();
    let mut is_comp = analyzer.is_complete();
    let status = analyzer.status_code();

    let prefix = if is_comp { "" } else { "[INCOMPLETE_CAPTURE];" };

    // Collapsed stacks map: stack_line -> total_value
    let mut collapsed_stacks: BTreeMap<String, u64> = BTreeMap::new();

    // 1. If software samples exist, fold by comm;pc
    let mut has_software_samples = false;
    for ev in events {
        if let EventPayload::SoftwareSample { pc, .. } | EventPayload::SoftwareSampleV2 { pc, .. } = ev.payload {
            has_software_samples = true;
            let fallback = if matches!(ev.payload, EventPayload::SoftwareSampleV2 { mode: 2, .. }) {
                format!("pid:{}:tid:{}", ev.pid, ev.tid)
            } else { "[kernel]".to_string() };
            let comm = ev.comm.as_deref().unwrap_or(&fallback);
            let stack = format!("{}{};pc:0x{:x}", prefix, comm, pc);
            *collapsed_stacks.entry(stack).or_insert(0) += 1;
        }
    }

    if !has_software_samples {
        // Tracepoint based on-CPU intervals
        if !stats.on_cpu_intervals.is_empty() {
            for interval in &stats.on_cpu_intervals {
                let comm = interval.comm.as_deref().unwrap_or("[unknown]");
                let stack = format!("{}{};on_cpu", prefix, comm);
                *collapsed_stacks.entry(stack).or_insert(0) += interval.duration_ns;
            }
        } else {
            // Fallback from task_stats
            for (task_id, t) in &stats.task_stats {
                if t.on_cpu_time_ns > 0 {
                    let comm = t.comm.as_deref().unwrap_or("task");
                    let stack = format!("{}{}_{};on_cpu", prefix, comm, task_id);
                    *collapsed_stacks.entry(stack).or_insert(0) += t.on_cpu_time_ns;
                }
            }
        }
    }

    if collapsed_stacks.is_empty() {
        // Zero evidence capture is marked incomplete
        is_comp = false;
        writeln!(&mut out, "{}[no_on_cpu_evidence] 1", prefix).unwrap();
    } else {
        for (stack, value) in collapsed_stacks {
            writeln!(&mut out, "{} {}", stack, value).unwrap();
        }
    }

    FoldedOutput {
        text: out,
        is_complete: is_comp,
        status,
    }
}

/// Render off-CPU folded stack frames compatible with FlameGraph.
/// Aggregates identical collapsed wait reasons to total durations.
pub fn render_off_cpu_folded(
    analyzer: &CaptureAnalyzer,
    stats: &SessionStatistics,
) -> FoldedOutput {
    let mut out = String::new();
    let mut is_comp = analyzer.attribution_claim_allowed();
    let status = analyzer.status_code();

    let prefix = if is_comp { "" } else { "[INCOMPLETE_CAPTURE];" };

    let mut collapsed_stacks: BTreeMap<String, u64> = BTreeMap::new();

    if !stats.off_cpu_intervals.is_empty() {
        for interval in &stats.off_cpu_intervals {
            let comm = interval.comm.as_deref().unwrap_or("task");
            let stack = format!(
                "{}{};wait_reason_{};res_{}",
                prefix, comm, interval.wait_reason, interval.resource_id
            );
            *collapsed_stacks.entry(stack).or_insert(0) += interval.duration_ns;
        }
    } else {
        for (task_id, t) in &stats.task_stats {
            if t.off_cpu_wait_ns > 0 {
                let comm = t.comm.as_deref().unwrap_or("task");
                let stack = format!("{}{}_{};off_cpu_wait", prefix, comm, task_id);
                *collapsed_stacks.entry(stack).or_insert(0) += t.off_cpu_wait_ns;
            } else if t.block_count > 0 {
                let comm = t.comm.as_deref().unwrap_or("task");
                let stack = format!("{}{}_{};blocked", prefix, comm, task_id);
                *collapsed_stacks.entry(stack).or_insert(0) += t.block_count;
            }
        }
    }

    if collapsed_stacks.is_empty() {
        is_comp = false;
        writeln!(&mut out, "{}[no_off_cpu_evidence] 1", prefix).unwrap();
    } else {
        for (stack, value) in collapsed_stacks {
            writeln!(&mut out, "{} {}", stack, value).unwrap();
        }
    }

    FoldedOutput {
        text: out,
        is_complete: is_comp,
        status,
    }
}


// The capture stores arbitrary UTF-8 strings, including original JSON evidence;
// quote them rather than inserting them into an emitted JSON document verbatim.
fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch < '\u{20}' => { write!(&mut out, "\\u{:04x}", ch as u32).unwrap(); }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn render_diagnostics_json(out: &mut String, diagnostics: &bpf_capture::RuntimeDiagnostics) {
    write!(out, "{{\"counters\":[").unwrap();
    for (i, counter) in diagnostics.counters.iter().enumerate() {
        if i != 0 { out.push(','); }
        let kind = match counter.kind { bpf_capture::CounterKind::Activity => "activity", bpf_capture::CounterKind::Loss => "loss", bpf_capture::CounterKind::Error => "error" };
        write!(out, "{{\"name\":{},\"scope\":{},\"kind\":{},\"value\":{}}}", json_string(&counter.name), json_string(&counter.scope), json_string(kind),
            counter.value.map(|v| v.to_string()).unwrap_or_else(|| "null".into())).unwrap();
    }
    write!(out, "],\"identities\":[").unwrap();
    for (i, identity) in diagnostics.identities.iter().enumerate() {
        if i != 0 { out.push(','); }
        write!(out, "{{\"name\":{},\"value\":{}}}", json_string(&identity.name), identity.value.as_deref().map(json_string).unwrap_or_else(|| "null".into())).unwrap();
    }
    write!(out, "],\"phases\":[").unwrap();
    for (i, phase) in diagnostics.phases.iter().enumerate() {
        if i != 0 { out.push(','); }
        write!(out, "{{\"name\":{},\"start_ns\":{},\"stop_ns\":{},\"iterations\":{},\"sampler_mapped_bytes\":{}}}", json_string(&phase.name), phase.start_ns, phase.stop_ns,
            phase.iterations, phase.mapped_bytes.map(|v| v.to_string()).unwrap_or_else(|| "null".into())).unwrap();
    }
    write!(out, "],\"evidence_json\":{}}}", diagnostics.evidence_json.as_deref().map(json_string).unwrap_or_else(|| "null".into())).unwrap();
}
