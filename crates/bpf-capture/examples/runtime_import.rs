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
    framing::compute_checksum_ieee, writer::SampleFormat,
};
use serde_json::{Map, Value};

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
    u32::try_from(value).map_err(|_| "ID exceeds legacy u32 field".into())
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
        | "errors" => CounterKind::Error,
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
    let config = &archive["config"];
    let before = &archive["snapshots"]["before"];
    let after = &archive["snapshots"]["after"];
    let sources = archive["sources"].as_array().ok_or("missing sources")?;
    if sources.len() != if mode == "task" { 1 } else { 8 } {
        return Err("missing source configuration".into());
    }
    let first = &sources[0];
    let source = &before["events"][number(first, "fd")?.to_string()];
    let source_after = &after["events"][number(first, "fd")?.to_string()];
    let format = match mode {
        "task" | "cpu" => SampleFormat::PerfEventV2,
        "trace" | "block" | "wake" => SampleFormat::Tracepoint,
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
        Some(
            "observed records only; callchain/mapping/complete scheduler attribution unavailable"
                .into(),
        ),
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
        source_delivered = add(source_delivered, delta(old, new, "delivered")?)?;
        identity(&mut d, &format!("source/{fd}"), Some(item.to_string()));
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
    let program_id = numeric_string(config, "program_id")?.to_string();
    let runs = delta(
        &before["programs"][&program_id],
        &after["programs"][&program_id],
        "runs",
    )?;
    let errors = delta(
        &before["programs"][&program_id],
        &after["programs"][&program_id],
        "errors",
    )?;
    if runs.checked_sub(errors) != Some(source_delivered) {
        return Err("program counters do not reconcile with source delivery".into());
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
        libbpf_fixture_version: "native-runtime-v2; no libbpf fixture".into(),
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
            || !(8..=96).contains(&length)
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
                "task" | "cpu" => 64,
                "trace" | "block" => 72,
                "wake" => 80,
                _ => unreachable!(),
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
            if let SampleFormat::Tracepoint = format {
                let expected_id = match mode {
                    "trace" => 2,
                    "block" => 3,
                    _ => 4,
                };
                if read32(context, 0) != expected_id {
                    return Err("wrong tracepoint".into());
                }
            }
            samples += 1;
        } else if read32(frame, 0) == 2 && frame.len() == 24 {
            lost = add(lost, read64(frame, 16))?;
        }
        add(samples, lost)?; // legacy attempted count includes both sample and LOST records
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
    if sink_delivered != add(samples, dropped_samples)?
        || source_delivered != add(add(samples, dropped_samples)?, sink_lost)?
        || lost > sink_lost
    {
        return Err("producer/consumer counters do not reconcile".into());
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
