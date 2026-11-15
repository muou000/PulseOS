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
            EventPayload::SoftwareSample { sample_period, addr } => {
                format!("period={} addr=0x{:016x} ip=unavailable mode=unavailable", sample_period, addr)
            }
            EventPayload::SoftwareSampleV2 { sample_period, addr, pc, mode } => {
                let mode = match mode { 1 => "kernel", 2 => "user", _ => "unknown" };
                format!("period={} pc=0x{:016x} mode={} addr=0x{:016x}", sample_period, pc, mode, addr)
            }
            EventPayload::SoftwareStackV3 { sample_period, pc, mode, source_id, stack, .. } => {
                let ips = stack.ips[..stack.len as usize].iter().map(|ip| format!("0x{ip:x}")).collect::<Vec<_>>().join(";");
                format!("period={sample_period} pc=0x{pc:016x} mode={mode} source_id={source_id} stack={} termination={} depth={} capture_ns={} ips=[{ips}]",
                    stack.status.classification(), stack.status.as_str(), stack.len, stack.capture_ns)
            }
            EventPayload::PageFault {address,start_ns,elapsed_ns,access,origin,outcome,classification} => {
                let origin=match origin {1=>"kernel",2=>"user",_=>"invalid"};
                let outcome=match outcome {1=>"resolved",2=>"not_handled",3=>"no_memory",4=>"resolver_error",_=>"invalid"};
                let class=match classification {0=>"unknown",1=>"minor",2=>"major",_=>"invalid"};
                format!("address=0x{address:x} start_ns={start_ns} resolver_wall_ns={elapsed_ns} access=0x{access:x} origin={origin} outcome={outcome} classification={class}")
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
        writeln!(&mut out, "Complete CPU/off-CPU attribution: unavailable (mapping/full scheduler evidence absent; stack availability is reported per sample).").unwrap();
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
pub fn render_json(analyzer: &CaptureAnalyzer, stats: &SessionStatistics) -> String {
    render_json_inner(analyzer, stats, None)
}

pub fn render_query_json(analyzer: &CaptureAnalyzer, result: &crate::query::AnalysisResult) -> String {
    render_json_inner(analyzer, &result.stats, Some(result))
}

fn render_json_inner(
    analyzer: &CaptureAnalyzer,
    stats: &SessionStatistics,
    selected: Option<&crate::query::AnalysisResult>,
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
    writeln!(&mut out, "  \"records_count\": {},", selected.map_or(hdr.records_count, |q|q.events.len() as u64)).unwrap();
    if let Some(result) = selected {
        writeln!(&mut out, "  \"capture_records_count\": {},", hdr.records_count).unwrap();
        writeln!(&mut out, "  \"context_records_count\": {},", result.context_records_count).unwrap();
        writeln!(&mut out, "  \"query_clipped_intervals\": {},", result.clipped_intervals).unwrap();
        writeln!(&mut out, "  \"query_has_data\": {},", !result.events.is_empty()).unwrap();
        writeln!(&mut out, "  \"query\": {},", render_query_metadata(result)).unwrap();
    }

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

    // Preserve legacy observations without pretending their data addresses
    // supply usable IPs. Profile weights consume explicit sampled IPs/chains.
    writeln!(&mut out, "  \"software_samples_with_ip\": {},", stats.event_counts.get("perf_sample_v2").copied().unwrap_or(0) + stats.event_counts.get("software_stack_v3").copied().unwrap_or(0)).unwrap();
    writeln!(&mut out, "  \"software_samples_without_ip\": {},", stats.event_counts.get("perf_sample").copied().unwrap_or(0)).unwrap();
    let all_events;
    let events = if let Some(query) = selected { query.events.as_slice() } else {
        all_events = analyzer.ordered_events();
        all_events.as_slice()
    };
    let stack_samples = events.iter().filter(|event| matches!(event.payload, EventPayload::SoftwareStackV3 { .. }))
        .map(|event| format!("{{\"timestamp_ns\":{},\"cpu_id\":{},\"pid\":{},\"tid\":{},\"task_id\":{},\"sample\":{}}}",
            event.timestamp_ns, event.cpu_id, event.pid, event.tid, event.task_id, semantic_json(event)))
        .collect::<Vec<_>>().join(",");
    writeln!(&mut out, "  \"stack_samples\": [{stack_samples}],").unwrap();
    // cpu_stats array
    writeln!(&mut out, "  \"cpu_stats\": [").unwrap();
    let cpu_keys: Vec<_> = stats.cpu_stats.keys().cloned().collect();
    for (i, cpu_id) in cpu_keys.iter().enumerate() {
        let c = &stats.cpu_stats[cpu_id];
        let comma = if i + 1 < cpu_keys.len() { "," } else { "" };
        writeln!(
            &mut out,
            concat!("    {{\"cpu_id\": {}, \"event_count\": {}, \"sample_count\": {}, ",
                "\"context_switches\": {}, \"lost_records\": {}, \"scheduled_time_ns\": {}, ",
                "\"scheduled_time_scope\": \"observed_closed_sched_switch_intervals\", ",
                "\"busy_time_ns\": {}, \"idle_time_ns\": {}, ",
                "\"utilization_status\": \"unsupported_without_execution_and_residency_evidence\"}}{}"),
            c.cpu_id, c.event_count, c.sample_count, c.context_switches, c.lost_records,
            c.scheduled_time_ns, optional_number(c.busy_time_ns), optional_number(c.idle_time_ns), comma
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
    _stats: &SessionStatistics,
) -> FoldedOutput {
    render_on_cpu_folded_weighted(analyzer, events, crate::query::SampleWeight::Samples)
}

pub fn render_on_cpu_folded_weighted(
    analyzer: &CaptureAnalyzer,
    events: &[NormalizedEvent],
    weight: crate::query::SampleWeight,
) -> FoldedOutput {
    let mut out = String::new();
    let prefix = if analyzer.is_complete() {
        ""
    } else {
        "[INCOMPLETE_CAPTURE];"
    };
    let mut stacks: BTreeMap<String, u128> = BTreeMap::new();
    for event in events {
        let (pc, sample_period, mode, stack) = match &event.payload {
            EventPayload::SoftwareSampleV2 { pc, sample_period, mode, .. } => (*pc, *sample_period, *mode, None),
            EventPayload::SoftwareStackV3 { pc, sample_period, mode, stack, .. } => (*pc, *sample_period, *mode, Some(stack)),
            _ => continue,
        };
        let mode = match mode { 1 => "kernel", 2 => "user", _ => "unknown-mode" };
        let fallback = if mode == "user" {
            format!("pid:{}:tid:{}", event.pid, event.tid)
        } else { format!("task:{}", event.task_id) };
        let name = folded_label(event.comm.as_deref().unwrap_or(&fallback));
        let amount = match weight {
            crate::query::SampleWeight::Samples => 1,
            crate::query::SampleWeight::Period => sample_period as u128,
        };
        let mut key = format!("{}{};[{}]", prefix, name, mode);
        if let Some(stack) = stack {
            if stack.status != pulse_bpf_schema::StackStatus::Complete {
                write!(&mut key, ";[{}:{}]", stack.status.classification(), stack.status.as_str()).unwrap();
            }
            // Native frames are leaf first. Folded data is root first, while
            // the status marker preserves the fact that this may be a prefix.
            for ip in stack.ips[..stack.len as usize].iter().rev() {
                write!(&mut key, ";pc:0x{ip:x}").unwrap();
            }
            if stack.len == 0 { continue; }
        } else {
            write!(&mut key, ";pc:0x{pc:x}").unwrap();
        }
        *stacks.entry(key).or_default() += amount;
    }
    let has_data = !stacks.is_empty();
    for (stack, value) in stacks {
        writeln!(&mut out, "{} {}", stack, value).unwrap();
    }
    FoldedOutput {
        text: out,
        is_complete: has_data && analyzer.is_complete() && events.iter().all(|event| {
            !matches!(&event.payload, EventPayload::SoftwareStackV3 { stack, .. }
                if stack.status != pulse_bpf_schema::StackStatus::Complete)
        }),
        status: analyzer.status_code(),
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
            let comm = folded_label(interval.comm.as_deref().unwrap_or("task"));
            let stack = format!(
                "{}{};wait_reason_{};res_{}",
                prefix, comm, interval.wait_reason, interval.resource_id
            );
            *collapsed_stacks.entry(stack).or_insert(0) += interval.duration_ns;
        }
    }

    if collapsed_stacks.is_empty() {
        is_comp = false;
        // No interval means no folded weight, even if a block event was observed.
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


/// One canonical query descriptor accompanies every queried report.
pub fn render_query_metadata(result: &crate::query::AnalysisResult) -> String {
    let q = &result.query;
    let number = |value: Option<u64>| {
        value
            .map(|n| n.to_string())
            .unwrap_or_else(|| "null".into())
    };
    format!(
        concat!(
            "{{\"phase\":{},\"phase_source\":{},\"mode\":{},\"from_ns\":{},\"to_ns\":{},\"empty_window\":{},",
            "\"task_id\":{},\"pid\":{},\"tid\":{},\"cpu\":{},",
            "\"address_start\":{},\"address_end\":{},",
            "\"oncpu_unit\":{},\"offcpu_unit\":\"duration_ns\",",
            "\"association_scope\":\"whole capture before filtering\",",
            "\"diagnostics_scope\":\"capture\",",
            "\"blocked_cpu_filter\":\"block origin\"}}"
        ),
        q.phase
            .as_deref()
            .map(json_string)
            .unwrap_or_else(|| "null".into()),
        result
            .phase_source
            .map(|source| json_string(source.as_str()))
            .unwrap_or_else(|| "null".into()),
        q.mode
            .map(|mode| json_string(mode.as_str()))
            .unwrap_or_else(|| "null".into()),
        number(result.from_ns),
        number(result.to_ns),
        result
            .from_ns
            .zip(result.to_ns)
            .is_some_and(|(a, b)| a >= b),
        number(q.task_id),
        number(q.pid.map(u64::from)),
        number(q.tid.map(u64::from)),
        number(q.cpu.map(u64::from)),
        number(q.address_start),
        number(q.address_end),
        json_string(q.weight.unit())
    )
}

// Escape frame delimiters and line controls before placing task names in the
// folded protocol. Percent itself is escaped to keep the representation unique.
fn folded_label(value: &str) -> String {
    let mut output=String::new();
    for ch in value.chars() {
        match ch {
            '%' => output.push_str("%25"), ';' => output.push_str("%3B"),
            ch if ch.is_ascii_control() => {write!(&mut output,"%{:02X}",ch as u32).unwrap();}
            ch => output.push(ch),
        }
    }
    output
}

fn hex_payload(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}
fn optional_number(value: Option<u64>) -> String {
    value
        .map(|n| n.to_string())
        .unwrap_or_else(|| "null".into())
}
fn record_ids(values: &[usize]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}
fn semantic_json(event: &NormalizedEvent) -> String {
    match &event.payload {
        EventPayload::TaskMetadata {
            target_task_id,
            target_pid,
            target_tid,
            comm,
        } => format!(
            "{{\"target_task_id\":{},\"target_pid\":{},\"target_tid\":{},\"comm_display\":{}}}",
            target_task_id,
            target_pid,
            target_tid,
            json_string(comm)
        ),
        EventPayload::SchedSwitch {
            prev_task_id,
            next_task_id,
            prev_state,
            prev_prio,
            next_prio,
        } => format!(
            concat!(
                "{{\"prev_task_id\":{},\"next_task_id\":{},\"prev_state\":{},",
                "\"prev_prio\":{},\"next_prio\":{}}}"
            ),
            prev_task_id, next_task_id, prev_state, prev_prio, next_prio
        ),
        EventPayload::TaskBlock {
            block_sequence,
            wait_reason,
            resource_id,
            resource_detail,
        } => format!(
            concat!(
                "{{\"block_sequence\":{},\"wait_reason\":{},\"resource_id\":{},",
                "\"resource_detail\":{}}}"
            ),
            block_sequence, wait_reason, resource_id, resource_detail
        ),
        EventPayload::TaskWake {
            target_task_id,
            block_sequence,
            waker_task_id,
            wake_source,
            source_id,
        } => format!(
            concat!(
                "{{\"target_task_id\":{},\"block_sequence\":{},\"waker_task_id\":{},",
                "\"wake_source\":{},\"source_id\":{}}}"
            ),
            target_task_id, block_sequence, waker_task_id, wake_source, source_id
        ),
        EventPayload::TaskExit {
            exit_task_id,
            exit_code,
        } => format!(
            "{{\"exit_task_id\":{},\"exit_code\":{}}}",
            exit_task_id, exit_code
        ),
        EventPayload::TaskEnqueue {
            enqueue_task_id,
            enqueue_cpu,
            target_cpu,
            queue_depth,
            enqueue_reason,
        } => format!(
            concat!(
                "{{\"enqueue_task_id\":{},\"enqueue_cpu\":{},\"target_cpu\":{},",
                "\"queue_depth\":{},\"enqueue_reason\":{}}}"
            ),
            enqueue_task_id, enqueue_cpu, target_cpu, queue_depth, enqueue_reason
        ),
        EventPayload::PhaseMarker {
            phase_boundary,
            phase_name,
        } => format!(
            "{{\"phase_boundary\":{},\"phase_name_display\":{}}}",
            *phase_boundary as u32,
            json_string(phase_name)
        ),
        EventPayload::SoftwareSample { sample_period, addr } => format!(
            "{{\"sample_period\":{},\"addr\":{},\"ip\":null,\"mode\":null}}",
            sample_period, addr
        ),
        EventPayload::SoftwareSampleV2 {
            sample_period,
            addr,
            pc,
            mode,
        } => format!(
            "{{\"sample_period\":{},\"addr\":{},\"ip\":{},\"mode\":{}}}",
            sample_period, addr, pc, mode
        ),
        EventPayload::SoftwareStackV3 { sample_period, addr, pc, mode, source_id, stack } => {
            let ips = stack.ips[..stack.len as usize].iter().map(u64::to_string).collect::<Vec<_>>().join(",");
            format!(concat!("{{\"sample_period\":{},\"addr\":{},\"ip\":{},\"mode\":{},\"source_id\":{},",
                "\"sp\":{},\"fp\":{},\"ra\":{},\"capture_ns\":{},\"depth_limit\":{},\"chain_len\":{},",
                "\"stack_status\":{},\"termination\":{},\"bytes_read\":{},\"byte_limit\":{},\"ips\":[{}]}}"),
                sample_period, addr, pc, mode, source_id, stack.registers.sp, stack.registers.fp,
                stack.registers.ra, stack.capture_ns, stack.depth_limit, stack.len,
                json_string(stack.status.classification()), json_string(stack.status.as_str()),
                stack.bytes_read, stack.byte_limit, ips)
        },
        EventPayload::PageFault {
            address,
            start_ns,
            elapsed_ns,
            access,
            origin,
            outcome,
            classification,
        } => format!(
            concat!(
                "{{\"address\":{},\"start_ns\":{},\"elapsed_ns\":{},\"access\":{},",
                "\"origin\":{},\"outcome\":{},\"classification\":{}}}"
            ),
            address, start_ns, elapsed_ns, access, origin, outcome, classification
        ),
        EventPayload::Raw { .. } => "null".into(),
    }
}
fn timeline_event_json(analyzer: &CaptureAnalyzer, event: &NormalizedEvent) -> String {
    let original = &analyzer.records()[event.sequence_index];
    let privilege = match event.payload {
        EventPayload::SoftwareSampleV2 { mode: 1, .. }
        | EventPayload::SoftwareStackV3 { mode: 1, .. }
        | EventPayload::PageFault { origin: 1, .. } => Some("kernel"),
        EventPayload::SoftwareSampleV2 { mode: 2, .. }
        | EventPayload::SoftwareStackV3 { mode: 2, .. }
        | EventPayload::PageFault { origin: 2, .. } => Some("user"),
        _ => None,
    };
    format!(
        concat!(
            "{{\"sequence_index\":{},\"event_id\":{},\"event_name\":{},",
            "\"schema_version\":{},\"timestamp_ns\":{},\"cpu_id\":{},\"pid\":{},",
            "\"tid\":{},\"task_id\":{},\"subjects\":[{}],\"privilege\":{},",
            "\"resolved_comm\":{},\"payload_hex\":{},\"semantic\":{}}}"
        ),
        event.sequence_index,
        event.event_id,
        json_string(event.event_name()),
        event.schema_version,
        event.timestamp_ns,
        event.cpu_id,
        event.pid,
        event.tid,
        event.task_id,
        crate::query::subjects(event)
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(","),
        privilege.map(json_string).unwrap_or_else(|| "null".into()),
        event
            .comm
            .as_deref()
            .map(json_string)
            .unwrap_or_else(|| "null".into()),
        json_string(&hex_payload(&original.payload)),
        semantic_json(event)
    )
}

/// Timeline v1 keeps observed records separate from derived, possibly clipped
/// intervals. An unfinished observation never receives a fabricated end event.
pub fn render_timeline(
    analyzer: &CaptureAnalyzer,
    result: &crate::query::AnalysisResult,
) -> String {
    let mut out = String::new();
    let header = analyzer.header();
    let meta = analyzer.metadata();
    write!(
        &mut out,
        concat!(
            "{{\"timeline_version\":1,\"query\":{},",
            "\"source\":{{\"format_version\":{},\"arch\":{},\"records_count\":{},",
            "\"start_ns\":{},\"stop_ns\":{},\"trailer_checksum\":{},",
            "\"checksum_algorithm\":{},\"capture_complete\":{},",
            "\"attribution_claim_allowed\":false}},",
            "\"selected_records_count\":{},\"retained_context_records_count\":{},",
            "\"association_context_records_count\":{},\"query_clipped_intervals\":{},",
            "\"ordering\":\"timestamp then source sequence; cross-CPU ties remain unordered\",",
            "\"events\":["
        ),
        render_query_metadata(result),
        header.format_version,
        json_string(analyzer.target_arch().as_str()),
        header.records_count,
        meta.start_ns,
        meta.stop_ns,
        analyzer.data().trailer.checksum,
        json_string(if header.format_version >= 2 {
            "IEEE-CRC32"
        } else {
            "legacy-v1"
        }),
        analyzer.is_complete(),
        result.events.len(),
        result.timeline.context_events.len(),
        result.context_records_count,
        result.clipped_intervals
    )
    .unwrap();
    for (i, event) in result.events.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        out.push_str(&timeline_event_json(analyzer, event));
    }
    out.push_str("],\"context_events\":[");
    for (i, event) in result.timeline.context_events.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        out.push_str(&timeline_event_json(analyzer, event));
    }
    out.push_str("],\"schemas\":[");
    let ids: std::collections::BTreeSet<_> = result
        .events
        .iter()
        .chain(&result.timeline.context_events)
        .map(|e| e.event_id)
        .collect();
    for (i, schema) in analyzer
        .data()
        .registry
        .schemas()
        .iter()
        .filter(|s| ids.contains(&s.event_id))
        .enumerate()
    {
        if i != 0 {
            out.push(',');
        }
        write!(
            &mut out,
            concat!(
                "{{\"event_id\":{},\"version\":{},\"category\":{},\"name\":{},",
                "\"payload_size\":{},\"field_offset_base\":\"normalized payload\",\"fields\":["
            ),
            schema.event_id,
            schema.version,
            json_string(&schema.category),
            json_string(&schema.name),
            schema.payload_size
        )
        .unwrap();
        for (j, field) in schema.fields.iter().enumerate() {
            if j != 0 {
                out.push(',');
            }
            let (type_id, extra) = field.field_type.to_bytes();
            write!(
                &mut out,
                "{{\"name\":{},\"offset\":{},\"size\":{},\"type_id\":{},\"type_width\":{}}}",
                json_string(&field.name),
                field.offset,
                field.size,
                type_id,
                extra
            )
            .unwrap();
        }
        out.push_str("]}");
    }
    out.push_str("],\"intervals\":[");
    for (i, bar) in result.timeline.intervals.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        write!(
            &mut out,
            concat!(
                "{{\"kind\":{},\"task_id\":{},\"block_sequence\":{},",
                "\"start_ns\":{},\"end_ns\":{},\"visible_start_ns\":{},\"visible_end_ns\":{},",
                "\"start_cpu\":{},\"end_cpu\":{},\"query_clipped\":{},\"quality\":{},",
                "\"evidence_records\":{}}}"
            ),
            json_string(bar.kind),
            bar.task_id,
            optional_number(bar.block_sequence),
            bar.start_ns,
            bar.end_ns,
            bar.visible_start_ns,
            bar.visible_end_ns,
            optional_number(bar.start_cpu.map(u64::from)),
            optional_number(bar.end_cpu.map(u64::from)),
            bar.query_clipped,
            json_string(bar.quality),
            record_ids(&bar.evidence_records)
        )
        .unwrap();
    }
    out.push_str("],\"unfinished\":[");
    for (i, pending) in result.timeline.unfinished.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        let episode = &pending.episode;
        write!(&mut out,concat!("{{\"task_id\":{},\"block_sequence\":{},\"reason\":{},",
            "\"block_ns\":{},\"wake_ns\":{},\"start_ns\":{},\"end_ns\":null,",
            "\"visible_start_ns\":{},\"visible_end_ns\":null,\"observation_limit_ns\":{},",
            "\"observation_limit_is_endpoint\":false,\"query_clipped\":{},\"evidence_records\":{}}}"),
            episode.task_id,episode.block_sequence,json_string(episode.reason.as_str()),
            optional_number(episode.block_ns),optional_number(episode.wake_ns),optional_number(episode.wake_ns.or(episode.block_ns)),
            optional_number(pending.visible_start_ns),optional_number(pending.observation_limit_ns),pending.query_clipped,record_ids(&pending.evidence_records)).unwrap();
    }
    write!(
        &mut out,
        "],\"scheduler_diagnostics_scope\":\"capture\",\"scheduler\":{},\"capture_diagnostics\":",
        result.scheduler.render_json()
    )
    .unwrap();
    if let Some(diagnostics) = &analyzer.data().diagnostics {
        render_diagnostics_json(&mut out, diagnostics);
    } else {
        out.push_str("null");
    }
    out.push('}');
    out
}
