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


def source_context(frame: bytes) -> tuple[int, int, bytes]:
    """Read the current stamped RAW envelope; no source/layout inference."""
    if len(frame) < 36:
        raise ValueError("missing logical source envelope")
    record_type, _, declared, raw_size = struct.unpack_from('<IHHI', frame)
    magic, version, kind, length, logical_id, reserved = struct.unpack_from('<IHHIIQ', frame, 12)
    if (record_type != 9 or declared != len(frame) or raw_size != length + 24
        or len(frame) != (12 + raw_size + 7) & ~7 or magic != 0x31524250
        or version != 1 or kind not in (1, 2, 3) or not logical_id or reserved):
        raise ValueError("invalid logical source envelope")
    return logical_id, kind, frame[36:36 + length]


def extract(text: str, mode: str) -> tuple[bytes, dict, dict[str, bytes]]:
    lines = [re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line).strip() for line in text.replace("\r", "").splitlines()]
    def one(prefix: str, point: str | None = None) -> dict[str, str]:
        matches = [fields(line) for line in lines if line.startswith(prefix)]
        if point is not None:
            matches = [value for value in matches if value.get("point") == point]
        if len(matches) != 1:
            raise ValueError(f"missing or duplicate {prefix} {point}")
        return matches[0]
    if mode not in ("task", "cpu", "trace", "block", "wake", "sched", "fault"):
        raise ValueError("unknown requested archive mode")
    trace_sizes = {1:72, 2:72, 3:72, 4:80, 5:56, 6:64}
    context_rows = [fields(line) for line in lines if line.startswith("ARCHIVE CONTEXT ")]
    if len(context_rows) != 1 or context_rows[0].get("format") not in (("software-v2", "software-stack-v3") if mode in ("task", "cpu") else ("tracepoint",)):
        raise ValueError("unknown or duplicate required context format")
    stacks = context_rows[0]["format"] == "software-stack-v3"
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
    fault_records = []
    stack_records = []
    bound_records = []
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
            logical_id, source_kind, payload = source_context(frame)
            if source_kind != (3 if stacks else 1 if mode in ("task", "cpu") else 2):
                raise ValueError("source kind differs from declared context")
            if mode == "sched":
                event = struct.unpack_from("<I", payload)[0] if len(payload) >= 4 else 0
                expected = trace_sizes.get(event)
            else:
                expected = 640 if stacks else {"task":64,"cpu":64,"trace":72,"block":72,"wake":80,"fault":80}[mode]
            if len(payload) != expected:
                raise ValueError("RAW sample length differs from declared program")
            if mode in ("task", "cpu"):
                timestamp, = struct.unpack_from("<Q", payload, 16)
                source_cpu, = struct.unpack_from("<I", payload, 24)
                version, = struct.unpack_from("<I", payload, 60)
                if version != 2:
                    raise ValueError("not a v2 software sample")
                if stacks:
                    source_id, sp, fp, ra, capture_ns, extension, depth, length, status, read_bytes, byte_limit, flags = struct.unpack_from("<QQQQQHHHHIIQ", payload, 64)
                    chain = struct.unpack_from("<64Q", payload, 128)
                    if source_id == 0 or extension != 3 or not 1 <= depth <= 64 or length > depth or status > 13 or flags or read_bytes > byte_limit or read_bytes % 16 or any(chain[length:]) or (length == 0 and (status not in (9, 13) or read_bytes != 0)) or (length != 0 and chain[0] != struct.unpack_from("<Q", payload, 48)[0]) or any(ip == 0 for ip in chain[:length]):
                        raise ValueError("invalid software stack extension")
                    period, = struct.unpack_from("<Q", payload, 0)
                    task_id, = struct.unpack_from("<Q", payload, 40)
                    stack_records.append((source_id, source_cpu, task_id, period))
            else:
                event, version, timestamp, source_cpu = struct.unpack_from("<IIQI", payload)
                if (mode != "sched" and event != {"trace":2,"block":3,"wake":4,"fault":8}[mode]) or version != 1:
                    raise ValueError("not the declared tracepoint")
            if source_cpu != cpu or not start <= timestamp <= stop:
                raise ValueError("sample source CPU/time outside capture")
            if mode == "fault":
                address, fault_start, elapsed, access, origin, outcome, classification = struct.unpack_from("<QQQIIII",payload,40)
                pid,tid,reserved,task=struct.unpack_from("<IIIQ",payload,20)
                if reserved or task == 0 or fault_start > timestamp or elapsed != timestamp-fault_start or access & ~7 or origin not in (1,2) or outcome not in (1,2,3,4) or classification not in (0,1,2) or (outcome != 1 and classification != 0):
                    raise ValueError("invalid native fault completion")
                fault_records.append((pid,tid,address,access,origin,outcome))
            bound_records.append((logical_id, source_kind, payload))
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
        if mode == "fault" and not {"fault_started","fault_completed","fault_clock_errors"} <= snapshots[point]["global"].keys():
            raise ValueError("missing mandatory fault diagnostics")
    stack_target = None
    if stacks:
        target = one("SAMPLING START ")
        if target.get("version") != "2" or target.get("mode") != mode or target.get("cpus") != "8":
            raise ValueError("invalid stack workload identity declaration")
        stack_target = {key: int(target[key]) for key in ("pid", "tid")}
        if any(not 0 < value < (1 << 32) for value in stack_target.values()) or any(snapshots[point]["pid"] != stack_target["pid"] for point in ("before", "after")):
            raise ValueError("stack workload identity differs from proc snapshots")
    config = one("ARCHIVE CONFIG ")
    if config.get("mode") != mode or any(int(config[key]) == 0 for key in ("program_id", "output_map_id", "scratch_map_id", "buffer_pages")):
        raise ValueError("invalid program/map identity or mode")
    program_bindings = []
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
        required = {"logical_id", "event_id", "schema_event_id", "schema_version", "kind", "clock", "config", "requested_config", "scope", "target", "bound_task_id", "period", "requested_period", "requested_frequency", "effective_frequency", "requested_buffer_pages", "effective_buffer_pages", "unit", "fallback", "program_id"}
        if not required <= source.keys():
            raise ValueError("missing typed source declaration")
        expected_program = source["program_id"]
        expected_clock = {1:0, 2:1, 3:2}.get(source["config"])
        if (source["event_id"] != before["id"] or source["bound_task_id"] != before["task_id"]
            or source["scope"] != {"cpu":1,"task":2}[before["scope"]] or source["target"] != before["target"]
            or expected_clock != before["clock"] or source["clock"] != 1
            or source["schema_event_id"] != (before["config"] if source["kind"] == 2 else 0x1002 if source["kind"] == 3 else 0x1001)
            or (source["kind"] != 2 and source["period"] != before["period"])):
            raise ValueError("typed source declaration differs from kernel facts")
        if mode == "sched":
            binding = {"tracepoint": source["schema_event_id"], "program_id": expected_program, "context_bytes": trace_sizes[source["schema_event_id"]]}
            if binding not in program_bindings:
                program_bindings.append(binding)
        if any(before[key] != after[key] for key in ("clock","config","scope","target","task_id","period")):
            raise ValueError("source configuration changed during capture")
        if before["program_id"] != expected_program or after["program_id"] != expected_program:
            raise ValueError("source attached to a different program")
        if before["enabled"] or after["enabled"] or before["inflight"] or after["inflight"]:
            raise ValueError("non-quiescent capture boundary")
        if not start <= source["enable_before"] <= source["enable_after"] <= source["disable_before"] <= source["disable_after"] <= stop:
            raise ValueError("invalid per-source control window")
        sources.append(source)
    if len(sources) != (1 if mode == "task" else 48 if mode == "sched" else 16 if stacks else 8) or len({s["fd"] for s in sources}) != len(sources):
        raise ValueError("missing or duplicate source configuration")
    if len({source["event_id"] for source in sources}) != len(sources):
        raise ValueError("source aliases would double-count one event")
    by_logical = {row["logical_id"]: row for row in sources}
    if len(by_logical) != len(sources) or 0 in by_logical:
        raise ValueError("duplicate or zero logical source ID")
    for logical_id, kind, payload in bound_records:
        row = by_logical.get(logical_id)
        if row is None or row["kind"] != kind:
            raise ValueError("unknown or mismatched logical source binding")
        cpu = struct.unpack_from("<I", payload, 16 if kind == 2 else 24)[0]
        task = struct.unpack_from("<Q", payload, 32 if kind == 2 else 40)[0]
        timestamp = struct.unpack_from("<Q", payload, 8 if kind == 2 else 16)[0]
        if ((row["scope"] == 1 and row["target"] != cpu) or (row["scope"] == 2 and row["bound_task_id"] != task)
            or not row["enable_before"] <= timestamp <= row["disable_after"]
            or (kind != 2 and row["period"] != struct.unpack_from("<Q", payload)[0])
            or (kind == 2 and row["schema_event_id"] != struct.unpack_from("<I", payload)[0])
            or (kind == 3 and row["event_id"] != struct.unpack_from("<Q", payload, 64)[0])):
            raise ValueError("record differs from logical source declaration")
    source_rows = [snapshots["before"]["events"][item["fd"]] for item in sources]
    stack_source_counts = {}
    if stacks:
        by_id = {row["id"]: row for row in source_rows}
        for source_id, cpu, task_id, period in stack_records:
            row = by_id.get(source_id)
            if row is None or row["period"] != period or (row["scope"] == "cpu" and row["target"] != cpu) or (row["scope"] == "task" and row["task_id"] != task_id):
                raise ValueError("stack record source/period/scope differs from authoritative event")
            stack_source_counts[source_id] = stack_source_counts.get(source_id, 0) + 1
        if mode == "cpu":
            coverage = {(row["target"], row["period"]) for row in source_rows if row["clock"] == 0 and row["scope"] == "cpu"}
            if coverage != {(cpu, period) for cpu in range(8) for period in (10_000_000, 20_000_000)}:
                raise ValueError("missing same-CPU software source instances")
    if mode == "sched":
        coverage = {(row["config"], row["target"]) for row in source_rows if row["clock"] == 2 and row["scope"] == "cpu"}
        if coverage != {(event,cpu) for event in trace_sizes for cpu in range(8)}:
            raise ValueError("scheduler source CPU/event coverage incomplete")
    if mode == "fault":
        coverage = {(row["config"], row["target"]) for row in source_rows if row["clock"] == 2 and row["scope"] == "cpu"}
        if coverage != {(8,cpu) for cpu in range(8)}:
            raise ValueError("fault source CPU/event coverage incomplete")
    before, after = snapshots["before"], snapshots["after"]
    def delta(old: dict, new: dict, key: str) -> int:
        difference = new[key] - old[key]
        if difference < 0:
            raise ValueError(f"counter regressed: {key}")
        return difference
    vm_delivered = sum(delta(before["events"][s["fd"]], after["events"][s["fd"]], "delivered") for s in sources)
    program_errors = {}
    for program_id in {row["program_id"] for row in source_rows}:
        runs = delta(before["programs"][program_id], after["programs"][program_id], "runs")
        errors = delta(before["programs"][program_id], after["programs"][program_id], "errors")
        delivered = sum(delta(before["events"][row["fd"]], after["events"][row["fd"]], "delivered")
                        for row in source_rows if row["program_id"] == program_id)
        if runs < errors or runs - errors != delivered:
            raise ValueError("program execution counters do not reconcile with source delivery")
        program_errors[program_id] = errors
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
    if stacks and sink_lost == 0 and dropped_samples == 0:
        for row in source_rows:
            if stack_source_counts.get(row["id"], 0) != delta(row, after["events"][row["fd"]], "delivered"):
                raise ValueError("stack source records do not reconcile individually")
    fault_workload = None
    fault_targets = []
    if mode == "fault":
        if dropped:
            raise ValueError("fault workload reconciliation requires an untruncated export")
        def unsigned_fields(values):
            if any(not value.isdecimal() or int(value) > (1 << 64)-1 for value in values.values()):
                raise ValueError("invalid unsigned fault workload field")
            return {key:int(value) for key,value in values.items()}
        fault_workload = unsigned_fields(one("ARCHIVE FAULT_WORKLOAD "))
        if not {"pid","tid","iterations","read_hits","write_hits"} <= fault_workload.keys() or not 0 < fault_workload["pid"] < (1 << 32) or not 0 < fault_workload["tid"] < (1 << 32) or fault_workload["iterations"] != 128:
            raise ValueError("invalid fault workload identity/iterations")
        if before["pid"] != fault_workload["pid"] or after["pid"] != fault_workload["pid"]:
            raise ValueError("fault workload differs from snapshot process")
        for line in lines:
            if not line.startswith("ARCHIVE FAULT_TARGET "):
                continue
            target=unsigned_fields(fields(line))
            if not {"index","read","write"} <= target.keys() or target["index"] != len(fault_targets) or target["read"] == 0 or target["read"] % 4096 or target["write"] != target["read"] + 8192:
                raise ValueError("missing/reordered/invalid fault target")
            fault_targets.append(target)
        if len(fault_targets) != 128:
            raise ValueError("fault workload does not preserve all iteration targets")
        reads={target["read"] for target in fault_targets}
        writes={target["write"] for target in fault_targets}
        actual_read_hits=actual_write_hits=0
        for pid,tid,address,access,origin,outcome in fault_records:
            if (pid,tid,origin) != (fault_workload["pid"],fault_workload["tid"],2):
                continue
            read_match=address in reads and bool(access & 1)
            write_match=address in writes and bool(access & 2)
            if (read_match or write_match) and outcome != 1:
                raise ValueError("fresh fault workload resolver failed")
            actual_read_hits+=int(read_match)
            actual_write_hits+=int(write_match)
        if min(actual_read_hits,actual_write_hits) == 0 or (actual_read_hits,actual_write_hits) != (fault_workload["read_hits"],fault_workload["write_hits"]):
            raise ValueError("fault workload hits do not match actual RAW records")
        # System observer counters can include unrelated/in-flight resolver
        # calls; preserve monotonic deltas without equating them to FD delivery.
        for name in ("fault_started","fault_completed","fault_clock_errors"):
            delta(before["global"],after["global"],name)
    observed_issues = []
    for name in ("timer_full", "timer_busy", "trace_full", "trace_recursive"):
        value = delta(before["global"], after["global"], name)
        if value:
            observed_issues.append({"scope":"global", "counter":name, "delta":value})
    if "fault_clock_errors" in before["global"] and "fault_clock_errors" in after["global"]:
        value = delta(before["global"], after["global"], "fault_clock_errors")
        if value:
            observed_issues.append({"scope":"global", "counter":"fault_clock_errors", "delta":value})
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
    for program_id, errors in program_errors.items():
        if errors:
            observed_issues.append({"scope":"program", "id":program_id, "counter":"errors", "delta":errors})
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
    return binary, {"context_format":context_rows[0]["format"], **({"stack_source_counts":stack_source_counts, "stack_target":stack_target} if stacks else {}), "version":1, "mode":mode, "start_ns":start, "stop_ns":stop,
        "frames":frames,"samples":samples,"transport_lost":lost,"export_dropped":int(begin["dropped"]),
        "known_archive_mapped_bytes":int(begin["mapped_bytes"]),"snapshots":snapshots,
        "config":config,"sources":sources,"measurements":measurements,"rings":rings,"program_bindings":program_bindings,
        **({"fault_workload":fault_workload,"fault_targets":fault_targets} if mode == "fault" else {}),
        "export_dropped_samples":dropped_samples,"export_dropped_notices":dropped_notices,
        "observed_issues":observed_issues,"quality":"partial" if observed_issues else "no_observed_loss"}, stats_raw
