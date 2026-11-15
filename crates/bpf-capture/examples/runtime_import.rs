//! Import an actual PBRW0001 ring archive and its verified runtime evidence.
//! This tool never manufactures normalized events. All events enter the same
//! capture writer used by other consumers through explicit RAW context formats.
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

use bpf_capture::{
    CaptureArch, CaptureScope, CaptureWriter, CounterKind, DiagnosticCounter, DiagnosticIdentity,
    PhaseMeasurement, RuntimeDiagnostics, SchemaRegistry, SessionConfig,
    framing::compute_checksum_ieee, writer::NativeContextFormat,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, String>;
fn number(v: &Value, key: &str) -> Result<u64> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing/invalid unsigned {key}"))
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing/invalid string {key}"))
}
fn object(v: &Value) -> Result<&Map<String, Value>> {
    v.as_object().ok_or("expected object".into())
}
fn numeric_string(v: &Value, key: &str) -> Result<u64> {
    string(v, key)?
        .parse()
        .map_err(|_| format!("invalid numeric config {key}"))
}
fn narrow(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| "ID exceeds session u32 field".into())
}
fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    const LIMIT: u64 = 8 * 1024 * 1024;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > LIMIT {
        return Err("input exceeds bound".into());
    }
    Ok(bytes)
}
fn read_json(path: &Path) -> Result<Value> {
    let bytes = read_bounded(path)?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}
fn read32(bytes: &[u8], n: usize) -> u32 {
    u32::from_le_bytes(bytes[n..n + 4].try_into().unwrap())
}
fn read64(bytes: &[u8], n: usize) -> u64 {
    u64::from_le_bytes(bytes[n..n + 8].try_into().unwrap())
}
fn counter(
    d: &mut RuntimeDiagnostics,
    scope: &str,
    name: &str,
    value: Option<u64>,
    kind: CounterKind,
) {
    d.counters.push(DiagnosticCounter {
        name: name.into(),
        scope: scope.into(),
        value,
        kind,
    });
}
fn identity(d: &mut RuntimeDiagnostics, name: &str, value: Option<String>) {
    d.identities.push(DiagnosticIdentity {
        name: name.into(),
        value,
    });
}
fn delta(before: &Value, after: &Value, key: &str) -> Result<u64> {
    number(after, key)?
        .checked_sub(number(before, key)?)
        .ok_or_else(|| format!("counter regressed: {key}"))
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or("counter sum overflow".into())
}
fn kind(name: &str) -> CounterKind {
    match name {
        "timer_full" | "timer_busy" | "trace_full" | "trace_recursive" | "skipped"
        | "cancelled" | "transport_lost" => CounterKind::Loss,
        "invalid" | "reentry" | "helper" | "budget" | "consumer_corrupt" | "consumer_bounds"
        | "errors" | "fault_clock_errors" => CounterKind::Error,
        _ => CounterKind::Activity,
    }
}
fn snapshots(
    d: &mut RuntimeDiagnostics,
    before: &Value,
    after: &Value,
    scope: &str,
    names: &[&str],
) -> Result<()> {
    for name in names {
        counter(
            d,
            &format!("{scope}/before"),
            name,
            Some(number(before, name)?),
            CounterKind::Activity,
        );
        counter(
            d,
            &format!("{scope}/after"),
            name,
            Some(number(after, name)?),
            CounterKind::Activity,
        );
        counter(
            d,
            scope,
            name,
            Some(delta(before, after, name)?),
            kind(name),
        );
    }
    Ok(())
}
/// Native fault probes retain exact first-touch target identities. The verifier
/// consumes the original frames again, independently of the Python log parser.
struct FaultWorkload {
    pid: u32,
    tid: u32,
    reads: std::collections::BTreeSet<u64>,
    writes: std::collections::BTreeSet<u64>,
    expected_read_hits: u64,
    expected_write_hits: u64,
    read_hits: u64,
    write_hits: u64,
}
impl FaultWorkload {
    fn new(archive: &Value, dropped: u32, d: &mut RuntimeDiagnostics) -> Result<Self> {
        if dropped != 0 {
            return Err("native workload requires an untruncated fault export".into());
        }
        let workload = &archive["fault_workload"];
        let pid = narrow(number(workload, "pid")?)?;
        let tid = narrow(number(workload, "tid")?)?;
        if pid == 0
            || tid == 0
            || number(workload, "iterations")? != 128
            || number(&archive["measurements"]["attached_capture"], "iterations")? != 128
        {
            return Err("invalid fault workload identity/iterations".into());
        }
        for point in ["before", "after"] {
            if number(&archive["snapshots"][point], "pid")? != u64::from(pid) {
                return Err("fault workload differs from snapshot process".into());
            }
        }
        let targets = archive["fault_targets"]
            .as_array()
            .ok_or("missing fault targets")?;
        if targets.len() != 128 {
            return Err("incomplete fault targets".into());
        }
        let (mut reads, mut writes) = (
            std::collections::BTreeSet::new(),
            std::collections::BTreeSet::new(),
        );
        for (index, target) in targets.iter().enumerate() {
            let read = number(target, "read")?;
            let write = number(target, "write")?;
            if number(target, "index")? != index as u64
                || read == 0
                || read % 4096 != 0
                || read.checked_add(8192) != Some(write)
            {
                return Err("invalid/reordered fault targets".into());
            }
            reads.insert(read);
            writes.insert(write);
            identity(
                d,
                &format!("fault_target/{index}/read_address"),
                Some(format!("0x{read:x}")),
            );
            identity(
                d,
                &format!("fault_target/{index}/write_address"),
                Some(format!("0x{write:x}")),
            );
        }
        identity(d, "fault_workload/pid", Some(pid.to_string()));
        identity(d, "fault_workload/tid", Some(tid.to_string()));
        counter(
            d,
            "fault_workload",
            "iterations",
            Some(128),
            CounterKind::Activity,
        );
        Ok(Self {
            pid,
            tid,
            reads,
            writes,
            expected_read_hits: number(workload, "read_hits")?,
            expected_write_hits: number(workload, "write_hits")?,
            read_hits: 0,
            write_hits: 0,
        })
    }
    fn observe(&mut self, context: &[u8]) -> Result<()> {
        if context.len() != 80 {
            return Err("invalid native fault completion length".into());
        }
        let end = read64(context, 8);
        let start = read64(context, 48);
        let elapsed = read64(context, 56);
        let address = read64(context, 40);
        let access = read32(context, 64);
        let origin = read32(context, 68);
        let outcome = read32(context, 72);
        if read32(context, 0) != 8
            || read32(context, 4) != 1
            || read32(context, 28) != 0
            || read64(context, 32) == 0
            || end.checked_sub(start) != Some(elapsed)
            || access & !7 != 0
            || !matches!(origin, 1 | 2)
            || !pulse_bpf_schema::PageFaultClassification::is_valid_pair(outcome, read32(context, 76))
        {
            return Err("invalid native fault completion".into());
        }
        if read32(context, 20) == self.pid && read32(context, 24) == self.tid && origin == 2 {
            let read = self.reads.contains(&address) && access & 1 != 0;
            let write = self.writes.contains(&address) && access & 2 != 0;
            if (read || write) && outcome != 1 {
                return Err("fresh fault workload resolver failed".into());
            }
            self.read_hits = add(self.read_hits, u64::from(read))?;
            self.write_hits = add(self.write_hits, u64::from(write))?;
        }
        Ok(())
    }
    fn finish(self, d: &mut RuntimeDiagnostics) -> Result<()> {
        if self.read_hits == 0
            || self.write_hits == 0
            || self.read_hits != self.expected_read_hits
            || self.write_hits != self.expected_write_hits
        {
            return Err("fault workload hits do not match actual RAW records".into());
        }
        counter(
            d,
            "fault_workload",
            "read_hits",
            Some(self.read_hits),
            CounterKind::Activity,
        );
        counter(
            d,
            "fault_workload",
            "write_hits",
            Some(self.write_hits),
            CounterKind::Activity,
        );
        Ok(())
    }
}

fn mapping_evidence(
    dir: &Path,
    input: &Value,
) -> Result<Option<bpf_capture::mapping::MappingMetadata>> {
    use bpf_capture::mapping::{Artifact, KernelArtifact, MappingMetadata};
    if input.get("mapping_journal").is_none() {
        return Ok(None);
    }
    if string(input, "mapping_journal")? != "mappings.txt"
        || string(input, "artifact_bundle")? != "artifacts.json"
    {
        return Err("invalid mapping evidence file names".into());
    }
    let mut journal_bytes = Vec::new();
    fs::File::open(dir.join("mappings.txt"))
        .map_err(|e| e.to_string())?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut journal_bytes)
        .map_err(|e| e.to_string())?;
    if journal_bytes.len() > 16 * 1024 * 1024
        || format!("{:x}", Sha256::digest(&journal_bytes))
            != string(input, "mapping_journal_sha256")?
    {
        return Err("mapping journal SHA mismatch/bound".into());
    }
    let manifest_bytes = read_bounded(&dir.join("artifacts.json"))?;
    if format!("{:x}", Sha256::digest(&manifest_bytes)) != string(input, "artifact_bundle_sha256")?
    {
        return Err("artifact manifest SHA mismatch".into());
    }
    let manifest: Value = serde_json::from_slice(&manifest_bytes).map_err(|e| e.to_string())?;
    if number(&manifest, "version")? != 1 {
        return Err("unsupported artifact manifest".into());
    }
    let optional = |v: &Value, name: &str| -> Result<Option<String>> {
        match v.get(name) {
            Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            _ => Err(format!("invalid optional artifact {name}")),
        }
    };
    let mut artifacts = Vec::new();
    for row in manifest["artifacts"]
        .as_array()
        .ok_or("missing artifacts")?
    {
        artifacts.push(Artifact {
            sha256: string(row, "sha256")?.into(),
            gnu_build_id: optional(row, "gnu_build_id")?,
            path: string(row, "path")?.into(),
            debug_sha256: optional(row, "debug_sha256")?,
            debug_build_id: optional(row, "debug_build_id")?,
        });
    }
    let kernel = if manifest["kernel"].is_null() {
        None
    } else {
        let row = &manifest["kernel"];
        if string(row, "sha256")? != string(input, "kernel_elf_sha256")? {
            return Err("kernel artifact differs from boot ELF".into());
        }
        Some(KernelArtifact {
            sha256: string(row, "sha256")?.into(),
            reference_symbol: string(row, "reference_symbol")?.into(),
            reference_address: number(row, "reference_address")?,
            text_start: number(row, "text_start")?,
            text_end: number(row, "text_end")?,
        })
    };
    let result = MappingMetadata {
        journal: String::from_utf8(journal_bytes).map_err(|_| "non-UTF8 mapping journal")?,
        artifacts,
        kernel,
    };
    result
        .validate()
        .map_err(|e| format!("mapping evidence: {e:?}"))?;
    // Verify every bundled identity against the actual stored bytes. The analyzer
    // independently inspects ELF headers/build-id when it opens a symbol object.
    for a in &result.artifacts {
        let file = fs::File::open(dir.join(&a.path)).map_err(|e| e.to_string())?;
        if file.metadata().map_err(|e| e.to_string())?.len() > 256 * 1024 * 1024 {
            return Err("artifact exceeds bound".into());
        }
        let mut hash = Sha256::new();
        let mut reader = file;
        let mut block = [0u8; 65536];
        loop {
            let len = reader.read(&mut block).map_err(|e| e.to_string())?;
            if len == 0 {
                break;
            }
            hash.update(&block[..len]);
        }
        if format!("{:x}", hash.finalize()) != a.sha256 {
            return Err("artifact ELF SHA mismatch".into());
        }
    }
    Ok(Some(result))
}

fn import(dir: &Path, output: &Path) -> Result<()> {
    let input = read_json(&dir.join("inputs.json"))?;
    let archive = read_json(&dir.join("archive.json"))?;
    let raw = read_bounded(&dir.join("records.pbraw"))?;
    if raw.len() < 64
        || raw.len() > 8 * 1024 * 1024
        || &raw[..8] != b"PBRW0001"
        || raw[48..64] != [0; 16]
    {
        return Err("invalid RAW archive header/size".into());
    }
    let (start, stop, frames, size, crc, dropped) = (
        read64(&raw, 8),
        read64(&raw, 16),
        read64(&raw, 24),
        read64(&raw, 32),
        read32(&raw, 40),
        read32(&raw, 44),
    );
    if start >= stop
        || frames == 0
        || size != (raw.len() - 64) as u64
        || compute_checksum_ieee(&raw[64..]) != crc
    {
        return Err("empty, truncated or corrupt RAW archive".into());
    }
    for (name, expected) in [
        ("start_ns", start),
        ("stop_ns", stop),
        ("frames", frames),
        ("export_dropped", dropped as u64),
    ] {
        if number(&archive, name)? != expected {
            return Err(format!("archive evidence disagrees: {name}"));
        }
    }
    let mode = string(&archive, "mode")?;
    if string(&input, "mode")? != mode {
        return Err("input/archive mode mismatch".into());
    }
    let arch = match string(&input, "arch")? {
        "riscv64" => CaptureArch::Riscv64,
        "loongarch64" => CaptureArch::LoongArch64,
        _ => return Err("unsupported arch".into()),
    };
    if input["kernel_elf_matches_boot"] != true {
        return Err("kernel symbols not matched to boot".into());
    }
    for name in [
        "kernel_sha256",
        "kernel_elf_sha256",
        "boot_image_sha256",
        "payload_sha256",
    ] {
        let hash = string(&input, name)?;
        if hash.len() != 64 || !hash.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("invalid actual artifact hash: {name}"));
        }
    }
    let stacks = match archive.get("context_format").and_then(Value::as_str) {
        Some("software-stack-v3") if matches!(mode, "task" | "cpu") => true,
        Some("software-v2") | Some("tracepoint") | None => false,
        _ => return Err("unknown required context format".into()),
    };
    if let Some(declared) = input.get("context_format") {
        if archive.get("context_format") != Some(declared) {
            return Err("input/archive context format mismatch".into());
        }
    }
    let config = &archive["config"];
    let before = &archive["snapshots"]["before"];
    let after = &archive["snapshots"]["after"];
    let sources = archive["sources"].as_array().ok_or("missing sources")?;
    if sources.len()
        != if mode == "task" {
            1
        } else if mode == "cpu" && stacks {
            16
        } else if mode == "sched" {
            48
        } else {
            8
        }
    {
        return Err("missing source configuration".into());
    }
    let mut bindings = std::collections::BTreeMap::new();
    if mode == "sched" {
        for row in archive["program_bindings"]
            .as_array()
            .ok_or("missing program bindings")?
        {
            let tracepoint = number(row, "tracepoint")?;
            let size = match tracepoint {
                1 | 2 | 3 => 72,
                4 => 80,
                5 => 56,
                6 => 64,
                _ => return Err("unknown scheduler tracepoint".into()),
            };
            if number(row, "context_bytes")? != size
                || number(row, "program_id")? == 0
                || bindings
                    .insert(tracepoint, number(row, "program_id")?)
                    .is_some()
            {
                return Err("invalid scheduler binding".into());
            }
        }
        if bindings.len() != 6
            || bindings
                .values()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != 6
        {
            return Err("incomplete scheduler programs".into());
        }
    }
    let first = &sources[0];
    let source = &before["events"][number(first, "fd")?.to_string()];
    let source_after = &after["events"][number(first, "fd")?.to_string()];
    let format = match mode {
        "task" | "cpu" if stacks => NativeContextFormat::SoftwareStackV3,
        "task" | "cpu" => NativeContextFormat::PerfEventV2,
        "trace" | "block" | "wake" | "sched" | "fault" => NativeContextFormat::Tracepoint,
        _ => return Err("unknown mode".into()),
    };
    let mut d = RuntimeDiagnostics {
        counters: vec![],
        identities: vec![],
        phases: vec![],
        evidence_json: Some(serde_json::json!({"inputs":input,"archive":archive}).to_string()),
    };
    for (name, value) in object(&input)? {
        identity(
            &mut d,
            &format!("build/{name}"),
            if value.is_null() {
                None
            } else {
                Some(
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string()),
                )
            },
        );
    }
    // Old saved runs intentionally do not claim their runtime workspace HEAD
    // as the source of a previously compiled kernel.
    identity(
        &mut d,
        "kernel_source_commit",
        input
            .get("kernel_source_commit")
            .and_then(Value::as_str)
            .map(str::to_owned),
    );
    identity(&mut d, "clock_resolution_ns", None);
    identity(
        &mut d,
        "memory_scope",
        Some("sampler-owned virtual mappings; RSS/kernel allocations unknown".into()),
    );
    identity(
        &mut d,
        "workload",
        Some(format!(
            "{mode}: 128 identical workload iterations in each phase"
        )),
    );
    identity(
        &mut d,
        "attribution_scope",
        Some(match (stacks, input.get("mapping_journal").is_some()) {
            (true, true) => "observed bounded frame-pointer prefixes and temporal mapping evidence; validity is per sample; complete scheduler attribution unavailable",
            (false, true) => "observed records and temporal mapping evidence; validity is per sample; callchain/complete scheduler attribution unavailable",
            (true, false) => "observed bounded frame-pointer prefixes; termination is per sample; mapping/complete scheduler attribution unavailable",
            (false, false) => "observed records only; callchain/mapping/complete scheduler attribution unavailable",
        }.into()),
    );
    snapshots(
        &mut d,
        &before["global"],
        &after["global"],
        "system",
        &[
            "timer_enqueued",
            "timer_dequeued",
            "timer_full",
            "timer_busy",
            "trace_enqueued",
            "trace_full",
            "trace_recursive",
        ],
    )?;
    for name in ["fault_started", "fault_completed", "fault_clock_errors"] {
        if before["global"].get(name).is_some() && after["global"].get(name).is_some() {
            snapshots(
                &mut d,
                &before["global"],
                &after["global"],
                "system",
                &[name],
            )?;
        } else {
            if mode == "fault" {
                return Err("missing mandatory fault diagnostics".into());
            }
            counter(&mut d, "system", name, None, kind(name));
        }
    }
    let mut fault_workload = if mode == "fault" {
        Some(FaultWorkload::new(&archive, dropped, &mut d)?)
    } else {
        None
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut sink_delivered = 0u64;
    let mut sink_lost = 0u64;
    for (fd, event) in object(&before["events"])? {
        let next = &after["events"][fd];
        if number(event, "id")? != number(next, "id")? {
            return Err("event identity changed".into());
        }
        let id = number(event, "id")?;
        if !seen.insert(id) {
            continue;
        }
        let scope = format!("event/{id}");
        snapshots(
            &mut d,
            event,
            next,
            &scope,
            &[
                "observed",
                "delivered",
                "skipped",
                "cancelled",
                "invalid",
                "reentry",
                "helper",
                "budget",
                "transport_lost",
                "consumer_corrupt",
                "consumer_bounds",
            ],
        )?;
        for name in [
            "fd",
            "id",
            "clock",
            "config",
            "scope",
            "target",
            "task_id",
            "period",
            "program_id",
        ] {
            identity(
                &mut d,
                &format!("{scope}/{name}"),
                Some(event[name].to_string()),
            );
        }
        for (point, row) in [("before", event), ("after", next)] {
            for name in ["generation", "enabled", "inflight"] {
                counter(
                    &mut d,
                    &format!("{scope}/{point}"),
                    name,
                    Some(number(row, name)?),
                    CounterKind::Activity,
                );
            }
        }
        if number(event, "clock")? == 10 {
            sink_delivered = add(sink_delivered, delta(event, next, "delivered")?)?;
            sink_lost = add(sink_lost, delta(event, next, "transport_lost")?)?;
        }
    }
    let mut source_delivered = 0u64;
    let mut per_program = std::collections::BTreeMap::<u64, u64>::new();
    let mut source_coverage = std::collections::BTreeSet::new();
    let mut source_ids = std::collections::BTreeSet::new();
    let mut stack_sources = std::collections::BTreeMap::new();
    let mut stack_source_counts = std::collections::BTreeMap::<u64, u64>::new();
    for item in sources {
        let fd = number(item, "fd")?.to_string();
        let old = &before["events"][&fd];
        let new = &after["events"][&fd];
        if number(old, "enabled")? != 0
            || number(new, "enabled")? != 0
            || number(old, "inflight")? != 0
            || number(new, "inflight")? != 0
        {
            return Err("capture sources not quiescent".into());
        }
        if number(old, "id")? != number(new, "id")? {
            return Err("source instance changed across capture".into());
        }
        if !source_ids.insert(number(old, "id")?) {
            return Err("source alias would double count".into());
        }
        let program_id = number(old, "program_id")?;
        let expected = if mode == "sched" {
            *bindings
                .get(&number(old, "config")?)
                .ok_or("undeclared source tracepoint")?
        } else {
            numeric_string(config, "program_id")?
        };
        if program_id != expected || number(new, "program_id")? != expected {
            return Err("source program binding mismatch".into());
        }
        for key in ["clock", "config", "scope", "target", "task_id", "period"] {
            if old[key] != new[key] {
                return Err("source configuration changed".into());
            }
        }
        if matches!(mode, "sched" | "fault") {
            if number(old, "clock")? != 2 || string(old, "scope")? != "cpu" {
                return Err(format!("wrong {mode} source kind"));
            }
            source_coverage.insert((number(old, "config")?, number(old, "target")?));
        }
        let delivered = delta(old, new, "delivered")?;
        if stacks {
            if number(item, "event_id")? != number(old, "id")? {
                return Err("declared source instance differs from diagnostics".into());
            }
            let clock = number(old, "clock")?;
            let scope = string(old, "scope")?;
            if !((mode == "cpu" && clock == 0 && scope == "cpu")
                || (mode == "task" && clock == 1 && scope == "task")) {
                return Err("software stack source kind differs from declared mode".into());
            }
            stack_sources.insert(number(old, "id")?, (scope, number(old, "target")?,
                number(old, "task_id")?, number(old, "period")?, delivered));
        }
        let total = per_program.entry(program_id).or_default();
        *total = add(*total, delivered)?;
        source_delivered = add(source_delivered, delivered)?;
        identity(&mut d, &format!("source/{fd}"), Some(item.to_string()));
    }
    if stacks && mode == "cpu" {
        let mut coverage = std::collections::BTreeMap::<u64, usize>::new();
        for (_, target, _, _, _) in stack_sources.values() {
            *coverage.entry(*target).or_default() += 1;
        }
        if coverage != (0..8).map(|cpu| (cpu, 2)).collect() {
            return Err("software stack CPU coverage requires two instances on every CPU".into());
        }
    }
    for (id, program) in object(&before["programs"])? {
        snapshots(
            &mut d,
            program,
            &after["programs"][id],
            &format!("program/{id}"),
            &["runs", "errors"],
        )?;
    }
    if mode == "sched"
        && source_coverage
            != (1u64..=6)
                .flat_map(|event| (0u64..8).map(move |cpu| (event, cpu)))
                .collect()
    {
        return Err("incomplete scheduler source coverage".into());
    }
    if mode == "fault" && source_coverage != (0u64..8).map(|cpu| (8, cpu)).collect() {
        return Err("incomplete fault source coverage".into());
    }
    for (program_id, delivered) in per_program {
        let id = program_id.to_string();
        let runs = delta(&before["programs"][&id], &after["programs"][&id], "runs")?;
        let errors = delta(&before["programs"][&id], &after["programs"][&id], "errors")?;
        if runs.checked_sub(errors) != Some(delivered) {
            return Err("program counters do not reconcile with source delivery".into());
        }
    }
    for name in [
        "verifier_failures",
        "load_failures",
        "attach_failures",
        "process_rss_bytes",
        "kernel_allocated_bytes",
    ] {
        counter(&mut d, "unavailable", name, None, CounterKind::Activity);
    }
    let dropped_samples = archive
        .get("export_dropped_samples")
        .and_then(Value::as_u64)
        .or(if dropped == 0 { Some(0) } else { None })
        .ok_or("unknown overflow sample count")?;
    counter(
        &mut d,
        "export",
        "dropped_records",
        Some(dropped as u64),
        CounterKind::Loss,
    );
    counter(
        &mut d,
        "export",
        "dropped_samples",
        Some(dropped_samples),
        CounterKind::Loss,
    );
    for name in ["baseline", "loaded_detached", "attached_capture"] {
        let phase = &archive["measurements"][name];
        d.phases.push(PhaseMeasurement {
            name: name.into(),
            start_ns: number(phase, "start_ns")?,
            stop_ns: number(phase, "stop_ns")?,
            iterations: number(phase, "iterations")?,
            mapped_bytes: Some(number(phase, "extra_mapped_bytes")?),
        });
    }
    if let Some(rings) = archive.get("rings").and_then(Value::as_array) {
        for ring in rings {
            let scope = format!("consumer/cpu{}", number(ring, "cpu")?);
            for name in ["head", "tail", "wraps"] {
                counter(
                    &mut d,
                    &scope,
                    name,
                    Some(number(ring, name)?),
                    CounterKind::Activity,
                );
            }
        }
    }
    let cfg = SessionConfig {
        pulse_commit: input
            .get("kernel_source_commit")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .into(),
        target_arch: arch,
        kernel_elf_path: string(&input, "kernel_elf_path")?.into(),
        kernel_elf_hash: string(&input, "kernel_elf_sha256")?.into(),
        image_path: string(&input, "image")?.into(),
        image_hash: string(&input, "boot_image_sha256")?.into(),
        libbpf_fixture_version: if stacks { "native-stack-v3; no libbpf fixture" } else { "native-runtime-v2; no libbpf fixture" }.into(),
        prog_id: narrow(numeric_string(config, "program_id")?)?,
        map_id: narrow(numeric_string(config, "output_map_id")?)?,
        link_id: narrow(number(first, "link_id")?)?,
        perf_event_id: narrow(number(source, "id")?)?,
        output_path: output.display().to_string(),
        scope: if mode == "task" {
            CaptureScope::Task(number(source, "target")?)
        } else {
            CaptureScope::AllCpus
        },
        sample_period: number(source, "period")?,
        buffer_pages: numeric_string(config, "buffer_pages")?,
        clock_name: "guest CLOCK_MONOTONIC nanoseconds".into(),
        clock_res_ns: 0,
    };
    let mut writer = CaptureWriter::new(cfg, SchemaRegistry::default_pulse_registry());
    writer.start(start).map_err(|e| format!("{e:?}"))?;
    let (mut offset, mut sequence, mut samples, mut lost) = (64usize, 0u64, 0u64, 0u64);
    while offset < raw.len() {
        if raw.len() - offset < 24 {
            return Err("truncated envelope".into());
        }
        let envelope = &raw[offset..offset + 24];
        offset += 24;
        let (seq, cpu, length, crc) = (
            read64(envelope, 0),
            read32(envelope, 8),
            read32(envelope, 12) as usize,
            read32(envelope, 16),
        );
        if seq != sequence
            || cpu >= 8
            || read32(envelope, 20) != 0
            || !(8..=if stacks { 656 } else { 96 }).contains(&length)
            || length > raw.len() - offset
        {
            return Err("invalid envelope".into());
        }
        let frame = &raw[offset..offset + length];
        offset += length;
        if compute_checksum_ieee(frame) != crc {
            return Err("corrupt frame".into());
        }
        if read32(frame, 0) == 9 {
            if frame.len() < 12 {
                return Err("truncated sample".into());
            }
            let expected = match mode {
                "task" | "cpu" if stacks => 640,
                "task" | "cpu" => 64,
                "trace" | "block" => 72,
                "wake" | "fault" => 80,
                "sched" if frame.len() >= 16 => match read32(frame, 12) {
                    1 | 2 | 3 => 72,
                    4 => 80,
                    5 => 56,
                    6 => 64,
                    _ => return Err("unknown scheduler record".into()),
                },
                _ => return Err("short scheduler record".into()),
            };
            if read32(frame, 8) != expected || frame.len() < 12 + expected as usize {
                return Err("wrong RAW sample length".into());
            }
            let context = &frame[12..12 + expected as usize];
            let timestamp = read64(
                context,
                if mode == "task" || mode == "cpu" {
                    16
                } else {
                    8
                },
            );
            if timestamp < start || timestamp > stop {
                return Err("record outside runtime window".into());
            }
            if mode == "task" && read64(context, 40) != number(source, "task_id")? {
                return Err("sample belongs to another task".into());
            }
            if stacks {
                let sample = pulse_bpf_schema::PerfStackSampleContext::from_bytes(context)
                    .map_err(|_| "invalid software stack native context")?;
                let (scope, target, task, period, _) = stack_sources.get(&sample.source_id)
                    .ok_or("software stack source instance not declared")?;
                if sample.base.base.sample_period != *period
                    || (*scope == "cpu" && u64::from(cpu) != *target)
                    || (*scope == "task" && (sample.base.base.task_id != *task
                        || u64::from(sample.base.base.tid) != *target)) {
                    return Err("software stack source scope/period mismatch".into());
                }
                let count = stack_source_counts.entry(sample.source_id).or_default();
                *count = add(*count, 1)?;
            }
            if let NativeContextFormat::Tracepoint = format {
                let expected_id = match mode {
                    "trace" => 2,
                    "block" => 3,
                    "fault" => 8,
                    _ => 4,
                };
                if (mode != "sched" && read32(context, 0) != expected_id)
                    || (mode == "sched" && !(1..=6).contains(&read32(context, 0)))
                {
                    return Err("wrong tracepoint".into());
                }
            }
            if let Some(workload) = &mut fault_workload {
                workload.observe(context)?;
            }
            samples += 1;
        } else if read32(frame, 0) == 2 && frame.len() == 24 {
            lost = add(lost, read64(frame, 16))?;
        }
        add(samples, lost)?; // consumer attempted count includes both sample and LOST records
        writer
            .ingest_raw_perf_frame_as(cpu, frame, format)
            .map_err(|e| format!("RAW normalization: {e:?}"))?;
        sequence += 1;
    }
    if sequence != frames
        || samples == 0
        || samples != number(&archive, "samples")?
        || lost != number(&archive, "transport_lost")?
    {
        return Err("RAW record counts do not match evidence".into());
    }
    for (source_id, (_, _, _, _, delivered)) in &stack_sources {
        let recorded = stack_source_counts.get(source_id).copied().unwrap_or(0);
        if recorded > *delivered || (dropped_samples == 0 && sink_lost == 0 && recorded != *delivered) {
            return Err("per-source stack sample count does not reconcile".into());
        }
        counter(&mut d, &format!("source/{source_id}"), "recorded_stack_samples", Some(recorded), CounterKind::Activity);
    }
    if sink_delivered != add(samples, dropped_samples)?
        || source_delivered != add(add(samples, dropped_samples)?, sink_lost)?
        || lost > sink_lost
    {
        return Err("producer/consumer counters do not reconcile".into());
    }
    if let Some(workload) = fault_workload {
        workload.finish(&mut d)?;
    }
    if number(source, "id")? != number(source_after, "id")? {
        return Err("unstable source identity".into());
    }
    counter(
        &mut d,
        "consumer",
        "samples",
        Some(samples),
        CounterKind::Activity,
    );
    counter(
        &mut d,
        "consumer",
        "lost_notices_records",
        Some(lost),
        CounterKind::Loss,
    );
    writer
        .set_diagnostics(d)
        .map_err(|e| format!("diagnostics: {e:?}"))?;
    if let Some(mappings) = mapping_evidence(dir, &input)? {
        writer.set_mappings(mappings).map_err(|e| format!("mappings: {e:?}"))?;
    }
    let bytes = writer.finish(stop).map_err(|e| format!("capture: {e:?}"))?;
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    out.write_all(&bytes).map_err(|e| e.to_string())?;
    println!(
        "Imported {samples} actual records ({frames} RAW frames) into {}",
        output.display()
    );
    Ok(())
}
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        eprintln!("usage: runtime_import <verified-run-directory> <new-output.pbcapture>");
        std::process::exit(2);
    }
    if let Err(error) = import(Path::new(&args[1]), Path::new(&args[2])) {
        eprintln!("runtime import rejected: {error}");
        std::process::exit(1);
    }
}
