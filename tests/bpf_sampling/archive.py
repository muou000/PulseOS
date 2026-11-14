"""Verify the guest's actual ring-frame stream before creating any capture.

PBRW0001 has a 64-byte LE header followed by sequence-numbered, CRC32-checked
frames. Diagnostic snapshots remain separate original evidence files. This
archive alone does not assert a complete sampling session.
"""
from __future__ import annotations
import re
import struct
import zlib


def fields(line: str) -> dict[str, str]:
    values = {}
    for token in line.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key in values:
            raise ValueError(f"duplicate field: {key}")
        values[key] = value
    return values


def chunks(lines: list[str], prefix: str, point: str) -> bytes:
    output = bytearray()
    for line in lines:
        if not line.startswith(prefix):
            continue
        data = fields(line)
        if data.get("point") != point:
            continue
        if int(data["offset"]) != len(output):
            raise ValueError("missing, repeated or reordered archive chunk")
        raw = bytes.fromhex(data["hex"])
        if not raw or len(raw) > 256:
            raise ValueError("invalid archive chunk size")
        output.extend(raw)
    return bytes(output)


def parse_stats(raw: bytes) -> dict:
    def number(value: str) -> int:
        if not re.fullmatch(r"[0-9]+", value) or int(value) > (1 << 64) - 1:
            raise ValueError("diagnostic value is not an unsigned 64-bit integer")
        return int(value)
    lines = raw.decode().splitlines()
    if len(lines) < 3 or not lines[0].startswith("PULSE_BPF_STATS ") or not lines[-1].startswith("END "):
        raise ValueError("incomplete diagnostic snapshot")
    header = fields(lines[0])
    if header.get("version") != "1" or header.get("available") != "1":
        raise ValueError("unknown or unavailable diagnostics")
    events, programs = {}, {}
    global_counters = None
    for line in lines[1:-1]:
        values = fields(line)
        kind = line.split()[0]
        if kind == "GLOBAL":
            required = {"timer_enqueued", "timer_dequeued", "timer_full", "timer_busy", "trace_enqueued", "trace_full", "trace_recursive"}
            if global_counters is not None or not required <= values.keys():
                raise ValueError("missing or duplicate global counters")
            global_counters = {key: number(value) for key, value in values.items()}
        elif kind == "EVENT":
            required = {"fd", "id", "clock", "config", "scope", "target", "task_id", "period", "generation", "enabled", "inflight", "observed", "delivered", "skipped", "cancelled", "invalid", "reentry", "helper", "budget", "transport_lost", "consumer_corrupt", "consumer_bounds", "program_id"}
            if not required <= values.keys() or values["scope"] not in ("cpu", "task"):
                raise ValueError("missing event diagnostic fields")
            event = {key: (value if key == "scope" else number(value)) for key, value in values.items()}
            fd = event["fd"]
            if fd in events or event["id"] == 0:
                raise ValueError("duplicate FD or unknown event identity")
            events[fd] = event
        elif kind == "PROGRAM":
            if not {"id", "runs", "errors"} <= values.keys():
                raise ValueError("missing program counters")
            program = {key: number(value) for key, value in values.items()}
            if program["id"] in programs:
                raise ValueError("duplicate program counters")
            programs[program["id"]] = program
        else:
            raise ValueError(f"unknown diagnostic row {kind}")
    end = fields(lines[-1])
    if global_counters is None or int(end["events"]) != len(events) or int(end["programs"]) != len(programs):
        raise ValueError("diagnostic row count mismatch")
    for event in events.values():
        if event["program_id"] and event["program_id"] not in programs:
            raise ValueError("event's attached program is absent")
    return {"pid": int(header["pid"]), "global": global_counters, "events": events, "programs": programs}


def extract(text: str, mode: str) -> tuple[bytes, dict, dict[str, bytes]]:
    lines = [re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line).strip() for line in text.replace("\r", "").splitlines()]
    def one(prefix: str, point: str | None = None) -> dict[str, str]:
        matches = [fields(line) for line in lines if line.startswith(prefix)]
        if point is not None:
            matches = [value for value in matches if value.get("point") == point]
        if len(matches) != 1:
            raise ValueError(f"missing or duplicate {prefix} {point}")
        return matches[0]
    begin, end = one("ARCHIVE BEGIN "), one("ARCHIVE END ")
    if begin.get("version") != "1" or begin.get("mode") != mode:
        raise ValueError("unknown archive format or mode")
    raw = chunks(lines, "ARCHIVE DATA ", "frames")
    for key in ("frames", "bytes", "crc"):
        if begin[key] != end[key]:
            raise ValueError("archive BEGIN/END disagree")
    if len(raw) != int(begin["bytes"]) or zlib.crc32(raw) != int(begin["crc"]):
        raise ValueError("archive byte count or CRC mismatch")
    start, stop = int(begin["start_ns"]), int(begin["stop_ns"])
    if start >= stop or int(begin["frames"]) == 0:
        raise ValueError("empty capture or invalid time window")
    position, frames, samples, lost = 0, 0, 0, 0
    frame_sizes = [[] for _ in range(8)]
    while position < len(raw):
        if len(raw) - position < 24:
            raise ValueError("truncated frame envelope")
        seq, cpu, size, crc, reserved = struct.unpack_from("<QIIII", raw, position)
        position += 24
        if seq != frames or cpu >= 8 or reserved != 0 or size > len(raw) - position or size < 8:
            raise ValueError("invalid frame sequence/cpu/length")
        frame = raw[position:position + size]
        position += size
        kind, _misc, declared = struct.unpack_from("<IHH", frame)
        if declared != size or size % 8 or zlib.crc32(frame) != crc:
            raise ValueError("frame CRC or boundary mismatch")
        if kind == 9:
            if size < 12:
                raise ValueError("short RAW sample")
            n, = struct.unpack_from("<I", frame, 8)
            expected = {"task":64,"cpu":64,"trace":72,"block":72,"wake":80}[mode]
            if n != expected or not 12+n <= size <= 12+n+7:
                raise ValueError("RAW sample length differs from declared program")
            payload = frame[12:12+n]
            if mode in ("task", "cpu"):
                timestamp, = struct.unpack_from("<Q", payload, 16)
                source_cpu, = struct.unpack_from("<I", payload, 24)
                version, = struct.unpack_from("<I", payload, 60)
                if version != 2:
                    raise ValueError("not a v2 software sample")
            else:
                event, version, timestamp, source_cpu = struct.unpack_from("<IIQI", payload)
                if event != {"trace":2,"block":3,"wake":4}[mode] or version != 1:
                    raise ValueError("not the declared tracepoint")
            if source_cpu != cpu or not start <= timestamp <= stop:
                raise ValueError("sample source CPU/time outside capture")
            samples += 1
        elif kind == 2 and size == 24:
            lost += struct.unpack_from("<Q", frame, 16)[0]
        else:
            raise ValueError("unsupported perf record")
        frame_sizes[cpu].append(size)
        frames += 1
    if frames != int(begin["frames"]) or samples == 0:
        raise ValueError("frame count mismatch or no real samples")
    stats_raw, snapshots = {}, {}
    for point in ("before", "after"):
        header = one("ARCHIVE STATS_BEGIN ", point)
        one("ARCHIVE STATS_END ", point)
        data = chunks(lines, "ARCHIVE STATS_DATA ", point)
        if len(data) != int(header["bytes"]) or zlib.crc32(data) != int(header["crc"]):
            raise ValueError("diagnostics truncated or corrupt")
        stats_raw[point] = data
        snapshots[point] = parse_stats(data)
    config = one("ARCHIVE CONFIG ")
    if config.get("mode") != mode or any(int(config[key]) == 0 for key in ("program_id", "output_map_id", "scratch_map_id", "buffer_pages")):
        raise ValueError("invalid program/map identity or mode")
    sources = []
    for line in lines:
        if not line.startswith("ARCHIVE SOURCE "):
            continue
        source = {key: int(value) for key, value in fields(line).items()}
        fd = source["fd"]
        before = snapshots["before"]["events"].get(fd)
        after = snapshots["after"]["events"].get(fd)
        if before is None or after is None or before["id"] != after["id"] or source["link_id"] == 0:
            raise ValueError("source event or link identity changed")
        if before["program_id"] != int(config["program_id"]) or after["program_id"] != int(config["program_id"]):
            raise ValueError("source attached to a different program")
        if before["enabled"] or after["enabled"] or before["inflight"] or after["inflight"]:
            raise ValueError("non-quiescent capture boundary")
        if not start <= source["enable_before"] <= source["enable_after"] <= source["disable_before"] <= source["disable_after"] <= stop:
            raise ValueError("invalid per-source control window")
        source["event_id"] = before["id"]
        sources.append(source)
    if len(sources) != (1 if mode == "task" else 8) or len({s["fd"] for s in sources}) != len(sources):
        raise ValueError("missing or duplicate source configuration")
    if len({source["event_id"] for source in sources}) != len(sources):
        raise ValueError("source aliases would double-count one event")
    before, after = snapshots["before"], snapshots["after"]
    def delta(old: dict, new: dict, key: str) -> int:
        difference = new[key] - old[key]
        if difference < 0:
            raise ValueError(f"counter regressed: {key}")
        return difference
    vm_delivered = sum(delta(before["events"][s["fd"]], after["events"][s["fd"]], "delivered") for s in sources)
    program_id = int(config["program_id"])
    program_runs = delta(before["programs"][program_id], after["programs"][program_id], "runs")
    program_errors = delta(before["programs"][program_id], after["programs"][program_id], "errors")
    if program_runs < program_errors or program_runs - program_errors != vm_delivered:
        raise ValueError("program execution counters do not reconcile with source delivery")
    sink_delivered = sink_lost = 0
    seen_sinks = set()
    for fd, old in before["events"].items():
        if old["clock"] != 10 or old["id"] in seen_sinks:
            continue
        new = after["events"].get(fd)
        if new is None or new["id"] != old["id"]:
            raise ValueError("output sink disappeared or changed identity")
        seen_sinks.add(old["id"])
        sink_delivered += delta(old, new, "delivered")
        sink_lost += delta(old, new, "transport_lost")
    sink_cpus = {event["target"] for event in before["events"].values() if event["clock"] == 10 and event["scope"] == "cpu"}
    if len(seen_sinks) != 8 or sink_cpus != set(range(8)):
        raise ValueError("incomplete output sink coverage")
    dropped = int(begin["dropped"])
    # When the reported total is zero, both nonnegative sub-counts are known to
    # be zero even for the first archive protocol revision, which omitted them.
    dropped_samples = int(begin.get("dropped_samples", "0")) if dropped == 0 else int(begin["dropped_samples"])
    dropped_notices = int(begin.get("dropped_notices", "0")) if dropped == 0 else int(begin["dropped_notices"])
    if dropped < 0 or dropped > (1 << 32)-1 or dropped != dropped_samples + dropped_notices:
        raise ValueError("inconsistent export overflow counters")
    if vm_delivered != samples + sink_lost + dropped_samples or sink_delivered != samples + dropped_samples or lost > sink_lost:
        raise ValueError("actual ring frames do not reconcile with producer/sink counters")
    observed_issues = []
    for name in ("timer_full", "timer_busy", "trace_full", "trace_recursive"):
        value = delta(before["global"], after["global"], name)
        if value:
            observed_issues.append({"scope":"global", "counter":name, "delta":value})
    for source in sources:
        old, new = before["events"][source["fd"]], after["events"][source["fd"]]
        for name in ("skipped", "cancelled", "invalid", "reentry", "helper", "budget"):
            value = delta(old, new, name)
            if value:
                observed_issues.append({"scope":"event", "id":source["event_id"], "counter":name, "delta":value})
    for fd, old in before["events"].items():
        for name in ("consumer_corrupt", "consumer_bounds"):
            value = delta(old, after["events"][fd], name)
            if value:
                observed_issues.append({"scope":"event", "id":old["id"], "counter":name, "delta":value})
    if program_errors:
        observed_issues.append({"scope":"program", "id":program_id, "counter":"errors", "delta":program_errors})
    if sink_lost:
        observed_issues.append({"scope":"transport", "counter":"lost", "delta":sink_lost})
    if dropped:
        observed_issues.append({"scope":"consumer", "counter":"export_overflow", "delta":dropped})
    measurements = {}
    for line in lines:
        if line.startswith("ARCHIVE MEASURE "):
            measure = fields(line)
            phase = measure["phase"]
            if phase in measurements or measure.get("memory_scope") != "sampler_mappings":
                raise ValueError("duplicate measurement or unknown memory scope")
            numeric = {key: int(measure[key]) for key in ("start_ns", "stop_ns", "wall_ns", "iterations", "extra_mapped_bytes")}
            if numeric["wall_ns"] <= 0 or numeric["wall_ns"] != numeric["stop_ns"] - numeric["start_ns"] or numeric["iterations"] != 128:
                raise ValueError("invalid actual workload measurement")
            measurements[phase] = numeric
    if set(measurements) != {"baseline", "loaded_detached", "attached_capture"}:
        raise ValueError("missing workload phase")
    rings = []
    for line in lines:
        if line.startswith("ARCHIVE RING "):
            row = {key: int(value) for key, value in fields(line).items()}
            if row["head"] != row["tail"] or row["wraps"] < 0 or row["tail"] < 0:
                raise ValueError("ring not fully consumed at capture boundary")
            rings.append(row)
    if rings and (len(rings) != 8 or {row["cpu"] for row in rings} != set(range(8))):
        raise ValueError("incomplete ring boundary evidence")
    if config.get("ring_diagnostics") == "1":
        if not rings:
            raise ValueError("missing ring consumption evidence")
        quiescent = one("ARCHIVE QUIESCENT ")
        if int(quiescent["polls"]) < 1 or int(quiescent["waited_ns"]) < 0:
            raise ValueError("invalid source quiescence observation")
    for ring in rings:
        position = wraps = 0
        capacity = int(config["buffer_pages"]) * 4096
        if capacity == 0 or capacity & (capacity-1):
            raise ValueError("invalid ring capacity")
        for size in frame_sizes[ring["cpu"]]:
            if (position & (capacity-1)) + size > capacity:
                wraps += 1
            position += size
        if (dropped == 0 and (position != ring["tail"] or wraps != ring["wraps"])) or position > ring["tail"]:
            raise ValueError("RAW frames do not match ring positions/wraps")
    binary = struct.pack("<8sQQQQII16x", b"PBRW0001", start, stop, frames, len(raw), zlib.crc32(raw), int(begin["dropped"])) + raw
    return binary, {"version":1, "mode":mode, "start_ns":start, "stop_ns":stop,
        "frames":frames,"samples":samples,"transport_lost":lost,"export_dropped":int(begin["dropped"]),
        "known_archive_mapped_bytes":int(begin["mapped_bytes"]),"snapshots":snapshots,
        "config":config,"sources":sources,"measurements":measurements,"rings":rings,
        "export_dropped_samples":dropped_samples,"export_dropped_notices":dropped_notices,
        "observed_issues":observed_issues,"quality":"partial" if observed_issues else "no_observed_loss"}, stats_raw
