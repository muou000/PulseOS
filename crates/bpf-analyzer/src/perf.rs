//! Conservative Linux v6.12 PERFILE2 exporter. Captured CPU addresses and periods
//! are immutable; perf receives only mappings verified against the selected ELF
//! bundle. The original capture and the sidecar retain loss and unwind quality.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use bpf_capture::{
    CaptureArch, CaptureScope, RecorderKind, RecorderSource, SourceClock, SourceConfig, SourceUnit,
    mapping::{MappingEvent, MappingMetadata, TaskClass},
};

use crate::{
    CaptureAnalyzer, EventPayload, NormalizedEvent,
    artifact::{VerifiedElf, sha256},
    emission::{json_string as quote, render_query_metadata},
    mapping::MappingTimeline,
    query::{AnalysisResult, SampleWeight},
};

const SAMPLE_TYPE: u64 = 1 | 2 | 4 | 32 | 128 | 256 | (1 << 16);
const KERNEL: u16 = 1;
const USER: u16 = 2;
const CONTEXT_KERNEL: u64 = (-128i64) as u64;
const CONTEXT_USER: u64 = (-512i64) as u64;

#[derive(Debug)]
pub struct PerfExport {
    pub data: Vec<u8>,
    pub manifest: String,
    pub artifact_paths: Vec<String>,
}
#[derive(Clone)]
struct Source {
    id: u64,
    config: u64,
    period: u64,
    declaration: RecorderSource,
}
impl Source {
    fn json(&self) -> String {
        let s = &self.declaration;
        let (scope, target) = match s.scope {
            CaptureScope::PerCpu(cpu) => ("cpu", u64::from(cpu)),
            CaptureScope::Task(tid) => ("task", tid),
            CaptureScope::AllCpus => unreachable!("reader validates source scope"),
        };
        format!(concat!(
            "{{\"id\":{},\"kernel_event_id\":{},\"program_id\":{},\"link_id\":{},",
            "\"config\":{},\"period\":{},\"scope\":{},\"target\":{},\"task_id\":{},",
            "\"clock\":{},\"requested_config\":{},\"effective_config\":{},",
            "\"requested_sample_period\":{},\"requested_frequency_hz\":{},\"effective_frequency_hz\":{},",
            "\"requested_buffer_pages\":{},\"effective_buffer_pages\":{},\"unit\":{},\"fallback\":{},",
            "\"enable_before_ns\":{},\"enable_after_ns\":{},\"disable_before_ns\":{},\"disable_after_ns\":{}}}"),
            self.id, s.kernel_event_id, s.program_id, s.link_id,
            self.config, self.period, quote(scope), target, s.bound_task_id,
            quote(s.clock.as_str()), quote(s.requested_config.as_str()), quote(s.config.as_str()),
            s.requested_sample_period, s.requested_frequency_hz, s.effective_frequency_hz,
            s.requested_buffer_pages, s.effective_buffer_pages, quote(s.unit.as_str()), quote(s.fallback.as_str()),
            s.enable_before_ns, s.enable_after_ns, s.disable_before_ns, s.disable_after_ns,
        )
    }
}
fn sources(analyzer: &CaptureAnalyzer) -> Result<Vec<Source>, String> {
    let metadata = analyzer.data().recorder.as_ref().ok_or("capture source declarations missing")?;
    metadata.sources.iter().filter(|s| matches!(s.kind, RecorderKind::SoftwareV2 | RecorderKind::SoftwareStackV3))
        .map(|s| {
            let config = match s.config {
                SourceConfig::CpuClock => 0,
                SourceConfig::TaskClock => 1,
                _ => return Err("CPU export requires an explicit software clock config".into()),
            };
            if s.unit != SourceUnit::Nanoseconds {
                return Err("CPU export requires nanosecond periods".into());
            }
            Ok(Source { id: u64::from(s.id), config, period: s.sample_period, declaration: s.clone() })
        }).collect()
}
fn u16le(out: &mut Vec<u8>, n: u16) {
    out.extend_from_slice(&n.to_le_bytes());
}
fn u32le(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}
fn u64le(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_le_bytes());
}
fn string(out: &mut Vec<u8>, value: &str, prefix: usize) -> Result<(), String> {
    if value.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r') {
        return Err("perf string contains unsupported control character".into());
    }
    out.extend_from_slice(value.as_bytes());
    out.push(0);
    while (prefix + out.len()) % 8 != 0 {
        out.push(0);
    }
    Ok(())
}
fn record(kind: u32, misc: u16, payload: Vec<u8>) -> Result<Vec<u8>, String> {
    let size = u16::try_from(payload.len() + 8).map_err(|_| "perf record exceeds u16 length")?;
    if size % 8 != 0 {
        return Err("unaligned perf record".into());
    }
    let mut out = Vec::with_capacity(size as usize);
    u32le(&mut out, kind);
    u16le(&mut out, misc);
    u16le(&mut out, size);
    out.extend(payload);
    Ok(out)
}
fn trailer(out: &mut Vec<u8>, pid: u32, tid: u32, time: u64, cpu: u32, source: u64) {
    u32le(out, pid);
    u32le(out, tid);
    u64le(out, time);
    u32le(out, cpu);
    u32le(out, 0);
    u64le(out, source);
}
fn comm(
    pid: u32,
    tid: u32,
    name: &str,
    time: u64,
    source: u64,
    exec: bool,
) -> Result<Vec<u8>, String> {
    let mut b = Vec::new();
    u32le(&mut b, pid);
    u32le(&mut b, tid);
    string(&mut b, name, 0)?;
    trailer(&mut b, pid, tid, time, u32::MAX, source);
    record(3, USER | if exec { 1 << 13 } else { 0 }, b)
}
fn mmap(
    pid: u32,
    tid: u32,
    start: u64,
    len: u64,
    pgoff: u64,
    path: &str,
    time: u64,
    cpu: u32,
    source: u64,
    mode: u16,
) -> Result<Vec<u8>, String> {
    let mut b = Vec::new();
    u32le(&mut b, pid);
    u32le(&mut b, tid);
    u64le(&mut b, start);
    u64le(&mut b, len);
    u64le(&mut b, pgoff);
    string(&mut b, path, 0)?;
    trailer(&mut b, pid, tid, time, cpu, source);
    record(1, mode, b)
}
fn lifecycle(
    kind: u32,
    pid: u32,
    tid: u32,
    ppid: u32,
    ptid: u32,
    time: u64,
    source: u64,
) -> Result<Vec<u8>, String> {
    let mut b = Vec::new();
    for value in [pid, ppid, tid, ptid] {
        u32le(&mut b, value);
    }
    u64le(&mut b, time);
    trailer(&mut b, pid, tid, time, u32::MAX, source);
    record(kind, USER, b)
}
struct Sample<'a> {
    event: &'a NormalizedEvent,
    source: &'a Source,
    period: u64,
    pc: u64,
    mode: u16,
    ips: Vec<u64>,
    status: &'static str,
}

/// Export exactly the CPU samples in an existing query result. `capture_bytes`
/// must be the original bytes from which `analyzer` was read, never a re-encoding.
/// Missing/ambiguous source or artifact evidence fails before any output write.
pub fn export(
    analyzer: &CaptureAnalyzer,
    selected: &AnalysisResult,
    bundle: &Path,
    capture_bytes: &[u8],
) -> Result<PerfExport, String> {
    if CaptureAnalyzer::from_bytes(capture_bytes).map_err(|e| e.to_string())? != *analyzer {
        return Err("capture bytes do not match analyzer".into());
    }
    let canonical = analyzer.query(&selected.query)?;
    if canonical.events != selected.events
        || canonical.from_ns != selected.from_ns
        || canonical.to_ns != selected.to_ns
        || canonical.phase_source != selected.phase_source
        || canonical.context_records_count != selected.context_records_count
        || canonical.clipped_intervals != selected.clipped_intervals
    {
        return Err("query result differs from canonical capture selection".into());
    }
    let declared = sources(analyzer)?;
    let all = analyzer.ordered_events();
    let mut samples = Vec::new();
    for event in &selected.events {
        let (period, pc, mode, id, ips, status) = match &event.payload {
            EventPayload::SoftwareSampleV2 {
                sample_period,
                pc,
                mode,
                ..
            } => (*sample_period, *pc, *mode, None, vec![*pc], "ip_only"),
            EventPayload::SoftwareStackV3 {
                sample_period,
                pc,
                mode,
                source_id,
                stack,
                ..
            } => (
                *sample_period,
                *pc,
                *mode,
                Some(*source_id),
                stack.ips[..stack.len as usize].to_vec(),
                stack.status.as_str(),
            ),
            _ => continue,
        };
        let logical_id = analyzer.data().recorder.as_ref()
            .and_then(|metadata| metadata.record_sources.get(event.sequence_index))
            .ok_or("sample lacks explicit logical source binding")?;
        let source = declared.iter().find(|source| source.id == u64::from(*logical_id))
            .ok_or("sample references an undeclared CPU source")?;
        if id.is_some_and(|kernel_id| source.declaration.kernel_event_id != kernel_id) {
            return Err("stack kernel source differs from logical source declaration".into());
        }
        if source.period != period {
            return Err("sample period differs from its declared source".into());
        }
        if !matches!(mode, 1 | 2) || pc == 0 || ips.first().is_some_and(|ip| *ip != pc) {
            return Err("invalid captured CPU sample".into());
        }
        samples.push(Sample {
            event,
            source,
            period,
            pc,
            mode: mode as u16,
            ips,
            status,
        });
    }
    let arch = match analyzer.target_arch() {
        CaptureArch::Riscv64 => "riscv64",
        CaptureArch::LoongArch64 => "loongarch64",
        CaptureArch::Unknown => {
            return Err("perf export requires a known target architecture".into());
        }
    };
    let mut records: Vec<(u64, u8, usize, Vec<u8>)> = Vec::new();
    let mut verified: BTreeMap<String, VerifiedElf> = BTreeMap::new();
    let mut kernel_artifact_path = None;
    let mut emitted_kernel_mapping = false;
    let mut metadata_for_manifest = None;
    if !samples.is_empty() {
        let metadata = analyzer
            .data()
            .mappings
            .as_ref()
            .ok_or("CPU export requires mapping metadata")?;
        let timeline = MappingTimeline::new(metadata)?;
        if timeline.journal().dropped != 0 {
            return Err("mapping journal loss prevents safe perf symbolization".into());
        }
        metadata_for_manifest = Some(metadata);
        for s in &samples {
            let e = s.event;
            if e.timestamp_ns < timeline.journal().started_ns
                || e.timestamp_ns >= timeline.journal().snapshot_ns
            {
                return Err("sample outside mapping coverage".into());
            }
            if s.mode == KERNEL && (e.pid != 0 || e.tid != 0) {
                timeline
                    .task_identity(e.task_id, e.pid, e.tid, e.timestamp_ns)
                    .map_err(|why| format!("sample {} task identity: {why}", e.sequence_index))?;
            }
            let mut seen = BTreeSet::new();
            // Even when the unwinder saved no frames, the separately captured
            // SAMPLE_IP still needs artifact and mapping validation. This does
            // not add that IP to the captured callchain below.
            let addresses = if s.ips.is_empty() { std::slice::from_ref(&s.pc) } else { &s.ips };
            for (index, &ip) in addresses.iter().enumerate() {
                // Resolve a return address at its preceding instruction, as perf
                // does, without changing the serialized captured address.
                let address = ip
                    .checked_sub(u64::from(index > 0))
                    .ok_or("invalid zero return address")?;
                if s.mode == USER {
                    let resolved = timeline
                        .lookup(e.task_id, e.pid, e.tid, e.timestamp_ns, address)
                        .map_err(|why| {
                            format!("sample {} frame {index}: {why}", e.sequence_index)
                        })?;
                    let sha = resolved
                        .sha256
                        .as_ref()
                        .ok_or("mapped object SHA unavailable")?;
                    load(metadata, &mut verified, bundle, analyzer.target_arch(), sha)?
                        .address_for_file_offset(resolved.file_offset)?;
                    if seen.insert((resolved.mapping.start, sha.clone())) {
                        records.push((
                            e.timestamp_ns,
                            2,
                            e.sequence_index,
                            mmap(
                                e.pid,
                                e.tid,
                                resolved.mapping.start,
                                resolved.mapping.len,
                                resolved.mapping.pgoff,
                                &format!("/artifacts/{sha}.elf"),
                                e.timestamp_ns,
                                e.cpu_id,
                                s.source.id,
                                USER,
                            )?,
                        ));
                    }
                } else {
                    let link = metadata
                        .kernel
                        .as_ref()
                        .ok_or("kernel artifact identity unavailable")?;
                    let candidates: Vec<_> = timeline
                        .journal()
                        .entries
                        .iter()
                        .filter(|row| row.timestamp_ns <= e.timestamp_ns)
                        .filter_map(|row| {
                            if let MappingEvent::Kernel {
                                start,
                                len,
                                reference,
                                symbol,
                            } = &row.event
                            {
                                Some((row.timestamp_ns, *start, *len, *reference, symbol))
                            } else {
                                None
                            }
                        })
                        .collect();
                    if candidates.len() != 1 || candidates[0].0 == e.timestamp_ns {
                        return Err("kernel mapping identity missing or ambiguous".into());
                    }
                    let (mapping_time, start, len, reference, symbol) = candidates[0];
                    load(
                        metadata,
                        &mut verified,
                        bundle,
                        analyzer.target_arch(),
                        &link.sha256,
                    )?
                    .kernel_address(link, start, len, reference, symbol, address)?;
                    kernel_artifact_path = Some(format!("artifacts/{}.elf", link.sha256));
                    if !emitted_kernel_mapping {
                        emitted_kernel_mapping = true;
                        records.push((
                            mapping_time,
                            2,
                            e.sequence_index,
                            mmap(
                                0,
                                0,
                                start,
                                len,
                                reference,
                                &format!("[kernel.kallsyms]{symbol}"),
                                mapping_time,
                                u32::MAX,
                                s.source.id,
                                KERNEL,
                            )?,
                        ));
                    }
                }
            }
            let mut b = Vec::new();
            u64le(&mut b, s.source.id);
            u64le(&mut b, s.pc);
            u32le(&mut b, e.pid);
            u32le(&mut b, e.tid);
            u64le(&mut b, e.timestamp_ns);
            u32le(&mut b, e.cpu_id);
            u32le(&mut b, 0);
            u64le(&mut b, s.period);
            u64le(&mut b, if s.ips.is_empty() { 0 } else { s.ips.len() as u64 + 1 });
            if !s.ips.is_empty() {
                u64le(
                    &mut b,
                    if s.mode == USER {
                        CONTEXT_USER
                    } else {
                        CONTEXT_KERNEL
                    },
                );
            }
            for &ip in &s.ips {
                u64le(&mut b, ip);
            }
            records.push((e.timestamp_ns, 3, e.sequence_index, record(9, s.mode, b)?));
        }
        append_lifecycle(&mut records, &timeline, samples[0].source.id)?;
    }
    records.sort_by_key(|row| (row.0, row.1, row.2));
    let mut body = Vec::new();
    for (_, _, _, bytes) in records {
        body.extend(bytes);
    }
    let selected_ids: BTreeSet<_> = samples.iter().map(|s| s.source.id).collect();
    let used: Vec<_> = declared
        .iter()
        .filter(|s| selected_ids.contains(&s.id))
        .collect();
    let mut features = Vec::new();
    let mut buildids = Vec::new();
    for (sha, elf) in &verified {
        if let Some(id) = &elf.gnu_build_id {
            if id.len() > 40 {
                return Err(
                    "perf v6.12 export subset supports GNU build-ids up to 20 bytes".into(),
                );
            }
            let kernel = metadata_for_manifest
                .and_then(|m| m.kernel.as_ref())
                .is_some_and(|k| k.sha256 == *sha);
            let path = if kernel {
                "[kernel.kallsyms]".into()
            } else {
                format!("/artifacts/{sha}.elf")
            };
            let mut b = Vec::new();
            u32le(&mut b, u32::MAX);
            for pair in id.as_bytes().chunks_exact(2) {
                b.push(
                    u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
                        .map_err(|_| "invalid build-id")?,
                );
            }
            b.resize(24, 0);
            b.push((id.len() / 2) as u8);
            b.extend([0; 3]);
            string(&mut b, &path, 8)?;
            buildids.extend(record(
                67,
                (if kernel { KERNEL } else { USER }) | (1 << 15),
                b,
            )?);
        }
    }
    if !buildids.is_empty() {
        features.push((2u32, buildids));
    }
    let mut target = Vec::new();
    u32le(&mut target, arch.len() as u32 + 1);
    target.extend(arch.as_bytes());
    target.push(0);
    features.push((6, target));
    let data = container(&used, &body, &features);
    let total_period: u128 = samples.iter().map(|s| u128::from(s.period)).sum();
    let selected_weight = match selected.query.weight {
        SampleWeight::Samples => samples.len() as u128,
        SampleWeight::Period => total_period,
    };
    let partial = samples
        .iter()
        .filter(|s| !s.ips.is_empty() && s.status != "ip_only" && s.status != "complete_at_terminator")
        .count();
    let unavailable = samples.iter().filter(|s| s.ips.is_empty()).count();
    let ip_only = samples.iter().filter(|s| s.status == "ip_only").count();
    let mut attribution_reasons = vec!["scheduler_and_irq_residency_unavailable"];
    if !analyzer.is_complete() {
        attribution_reasons.push("capture_incomplete");
    }
    if partial != 0 {
        attribution_reasons.push("partial_callchain");
    }
    if unavailable != 0 {
        attribution_reasons.push("unavailable_callchain");
    }
    if ip_only != 0 {
        attribution_reasons.push("ip_only");
    }
    if samples.iter().any(|s| s.mode == KERNEL && s.event.pid == 0 && s.event.tid == 0) {
        attribution_reasons.push("unknown_kernel_or_idle_identity");
    }
    let artifact_json = verified
        .keys()
        .map(|sha| {
            let a = metadata_for_manifest
                .unwrap()
                .artifacts
                .iter()
                .find(|a| a.sha256 == *sha)
                .unwrap();
            format!(
                "{{\"sha256\":{},\"path\":{},\"gnu_build_id\":{},\"debug_sha256\":{}}}",
                quote(sha),
                quote(&a.path),
                a.gnu_build_id
                    .as_deref()
                    .map(quote)
                    .unwrap_or("null".into()),
                a.debug_sha256
                    .as_deref()
                    .map(quote)
                    .unwrap_or("null".into())
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let sample_json = samples
        .iter()
        .map(|s| {
            format!(
                "{{\"sequence_index\":{},\"source_id\":{},\"timestamp_ns\":{},\"cpu\":{},\"pid\":\
                 {},\"tid\":{},\"task_id\":{},\"ip\":{},\"mode\":{},\"period_ns\":{},\"\
                 chain_status\":{},\"saved_chain_len\":{},\"task_identity_quality\":{}}}",
                s.event.sequence_index,
                s.source.id,
                s.event.timestamp_ns,
                s.event.cpu_id,
                s.event.pid,
                s.event.tid,
                s.event.task_id,
                s.pc,
                s.mode,
                s.period,
                quote(s.status),
                if s.status == "ip_only" { "null".into() } else { s.ips.len().to_string() },
                quote(
                    if s.mode == KERNEL && s.event.pid == 0 && s.event.tid == 0 {
                        "unknown_kernel_or_idle"
                    } else {
                        "verified_journal"
                    }
                )
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let loss = analyzer.loss_counters();
    let capture_cpu_samples = all
        .iter()
        .filter(|event| {
            matches!(
                event.payload,
                EventPayload::SoftwareSampleV2 { .. }
                    | EventPayload::SoftwareStackV3 { .. }
            )
        })
        .count();
    let artifact_manifest_sha256 = sha256(format!("[{artifact_json}]").as_bytes());
    let manifest = format!(
        r#"{{"version":1,
"exporter_version":"bpf-analyzer/{} perf-export/1",
"capture_cpu_samples":{},
"artifact_manifest_sha256":{},
"artifact_manifest_hash_scope":"UTF-8 exported artifacts JSON array",
"format_baseline":"Linux v6.12",
"capture_sha256":{},"perf_data_sha256":{},"architecture":{},
"sample_count":{},"total_period_ns":{},"selected_weight":{},"weight_unit":{},
"perf_period_unit":"period_ns","capture_complete":{},"attribution_complete":false,
"attribution_incomplete_reasons":[{}],
"partial_chain_count":{},"unavailable_chain_count":{},"ip_only_count":{},"query":{},"artifacts":[{}],
"kernel_artifact_path":{},"sources":[{}],"samples":[{}],
"source_identifier_domain":"recorder_logical_source_id",
"capture_loss":{{"scope":"whole_capture","lost_records_total":{},
"ringbuf_lost":{},"discarded_records":{},"diagnostics":{}}},
"notes":[
"User MMAP records are verified observations at sample timestamps, not creation events",
"The unique immutable kernel MMAP is emitted once at its captured publication time",
"Lifecycle times are captured; trailer CPU is unknown and identifier only selects the attr layout",
"Aggregate loss lacks source/time provenance; never fabricated as PERF_RECORD_LOST",
"Single-domain bounded callchains only; no invented user/kernel transition"]}}
"#,
        env!("CARGO_PKG_VERSION"),
        capture_cpu_samples,
        quote(&artifact_manifest_sha256),
        quote(&sha256(capture_bytes)),
        quote(&sha256(&data)),
        quote(arch),
        samples.len(),
        total_period,
        selected_weight,
        quote(selected.query.weight.unit()),
        analyzer.is_complete(),
        attribution_reasons.iter().map(|reason| quote(reason)).collect::<Vec<_>>().join(","),
        partial,
        unavailable,
        ip_only,
        render_query_metadata(selected),
        artifact_json,
        kernel_artifact_path
            .as_deref()
            .map(quote)
            .unwrap_or("null".into()),
        used.iter().map(|s| s.json()).collect::<Vec<_>>().join(","),
        sample_json,
        loss.lost_records_total,
        loss.ringbuf_lost,
        loss.discarded_records,
        quote(&analyzer.render_loss_report())
    );
    let artifact_paths = verified
        .keys()
        .map(|sha| format!("artifacts/{sha}.elf"))
        .collect();
    Ok(PerfExport {
        data,
        manifest,
        artifact_paths,
    })
}
fn append_lifecycle(
    records: &mut Vec<(u64, u8, usize, Vec<u8>)>,
    timeline: &MappingTimeline,
    source: u64,
) -> Result<(), String> {
    let mut identities = BTreeMap::new();
    let mut parents = BTreeMap::new();
    for row in &timeline.journal().entries {
        if let MappingEvent::Task {
            task,
            pid,
            tid,
            parent,
            kind,
            comm: name,
            class,
            ..
        } = &row.event
        {
            if *parent != 0 {
                parents.insert(*task, *parent);
            }
            let parent_identity = parents
                .get(task)
                .and_then(|parent| identities.get(parent))
                .copied();
            if *class == TaskClass::User {
                if kind == "fork" {
                    let (ppid, ptid) = parent_identity.ok_or("fork parent identity unavailable")?;
                    records.push((
                        row.timestamp_ns,
                        0,
                        row.sequence as usize,
                        lifecycle(7, *pid, *tid, ppid, ptid, row.timestamp_ns, source)?,
                    ));
                }
                if kind == "exit" {
                    let (ppid, ptid) = parent_identity.unwrap_or((0, 0));
                    records.push((
                        row.timestamp_ns,
                        0,
                        row.sequence as usize,
                        lifecycle(4, *pid, *tid, ppid, ptid, row.timestamp_ns, source)?,
                    ));
                } else {
                    records.push((
                        row.timestamp_ns,
                        1,
                        row.sequence as usize,
                        comm(*pid, *tid, name, row.timestamp_ns, source, kind == "exec")?,
                    ));
                }
            }
            if kind == "exit" {
                identities.remove(task);
            } else {
                identities.insert(*task, (*pid, *tid));
            }
        }
    }
    Ok(())
}
fn load<'a>(
    metadata: &MappingMetadata,
    cache: &'a mut BTreeMap<String, VerifiedElf>,
    bundle: &Path,
    arch: CaptureArch,
    sha: &str,
) -> Result<&'a VerifiedElf, String> {
    if !cache.contains_key(sha) {
        let artifact = metadata
            .artifacts
            .iter()
            .find(|a| a.sha256 == sha)
            .ok_or("mapped ELF absent from captured bundle")?;
        if artifact
            .debug_sha256
            .as_ref()
            .is_some_and(|debug| debug != sha)
        {
            return Err(
                "separate debug ELF requires explicit consumer staging; embedded debug is \
                 supported"
                    .into(),
            );
        }
        cache.insert(
            sha.into(),
            VerifiedElf::from_bundle(bundle, artifact, arch)?,
        );
    }
    Ok(&cache[sha])
}
fn container(sources: &[&Source], body: &[u8], features: &[(u32, Vec<u8>)]) -> Vec<u8> {
    // PERF_ATTR_SIZE_VER3 includes clockid. A perf_file_attr appends the
    // 16-byte ID section after these 96 bytes (Linux v6.12 perf_event.h).
    const ATTR_SIZE: u64 = 96;
    const FILE_ATTR_SIZE: u64 = ATTR_SIZE + 16;
    let ids_offset = 104u64;
    let attrs_offset = ids_offset + sources.len() as u64 * 8;
    let attrs_size = sources.len() as u64 * FILE_ATTR_SIZE;
    let data_offset = attrs_offset + attrs_size;
    let mut out = b"PERFILE2".to_vec();
    for value in [
        104,
        FILE_ATTR_SIZE,
        attrs_offset,
        attrs_size,
        data_offset,
        body.len() as u64,
        0,
        0,
        features
            .iter()
            .fold(0, |bits, (bit, _)| bits | (1u64 << bit)),
        0,
        0,
        0,
    ] {
        u64le(&mut out, value);
    }
    for source in sources {
        u64le(&mut out, source.id);
    }
    for (index, source) in sources.iter().enumerate() {
        u32le(&mut out, 1);
        u32le(&mut out, ATTR_SIZE as u32);
        u64le(&mut out, source.config);
        let frequency = source.declaration.effective_frequency_hz;
        u64le(&mut out, if frequency == 0 { source.period } else { frequency });
        u64le(&mut out, SAMPLE_TYPE);
        u64le(&mut out, 0);
        // sample_id_all and use_clockid; freq selects sample_freq in the union.
        u64le(&mut out, (1 << 18) | (1 << 25) | if frequency == 0 { 0 } else { 1 << 10 });
        u32le(&mut out, 0);
        u32le(&mut out, 0);
        u64le(&mut out, 0);
        u64le(&mut out, 0); // config2
        u64le(&mut out, 0); // branch_sample_type
        u64le(&mut out, 0); // sample_regs_user
        u32le(&mut out, 0); // sample_stack_user
        u32le(&mut out, match source.declaration.clock {
            SourceClock::Monotonic => 1, // Linux CLOCK_MONOTONIC
        });
        u64le(&mut out, ids_offset + index as u64 * 8);
        u64le(&mut out, 8);
    }
    out.extend(body);
    let mut offset = data_offset + body.len() as u64 + features.len() as u64 * 16;
    for (_, bytes) in features {
        u64le(&mut out, offset);
        u64le(&mut out, bytes.len() as u64);
        offset += bytes.len() as u64;
    }
    for (_, bytes) in features {
        out.extend(bytes);
    }
    out
}
