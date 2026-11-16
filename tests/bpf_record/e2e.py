#!/usr/bin/env python3
"""Compare original production-recorder bytes with Query, native perf and SVG.

The wire oracle reads capture v6 directly, independently of the Rust decoder
and exporter. The original guest file, mapping journal and symbols remain the
diagnostic source; every derived negative is explicitly a modified copy.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "tests/bpf_sampling"))
from perf_evidence import native_samples, verify_named_chain
from stack_evidence import elf_symbols
from verify_observation_evidence import decode_capture, check


class Cursor:
    """Bounded little-endian reader for the public v6 metadata layout."""

    def __init__(self, data):
        self.data, self.position = data, 0

    def take(self, length):
        check(0 <= length <= len(self.data) - self.position, "truncated metadata")
        result = self.data[self.position:self.position + length]
        self.position += length
        return result

    def number(self, fmt):
        return struct.unpack("<" + fmt, self.take(struct.calcsize("<" + fmt)))[0]

    def blob(self):
        return self.take(self.number("I"))

    def string(self):
        return self.blob().decode("utf-8")

    def finished(self):
        check(self.position == len(self.data), "metadata has trailing bytes")


def source_metadata(data, count):
    cursor = Cursor(data)
    check(cursor.take(8) == b"PBSRC003", "unsupported typed source schema")
    size, reserved, bindings = cursor.number("I"), cursor.number("I"), cursor.number("Q")
    check(0 < size <= 512 and reserved == 0 and bindings == count, "invalid source/binding count")
    sources = {}
    for _ in range(size):
        row = cursor.take(160)
        logical, kind, event, schema, scope, reserved = struct.unpack_from("<6I", row)
        target, period, kernel = struct.unpack_from("<3Q", row, 24)
        program, link = struct.unpack_from("<2I", row, 48)
        before, after, disable_before, disable_after, task = struct.unpack_from("<5Q", row, 56)
        clock, requested, config, unit, fallback, padding = struct.unpack_from("<6I", row, 96)
        request_period, frequency, effective_frequency, pages, effective_pages = struct.unpack_from("<5Q", row, 120)
        check(logical > 0 and logical not in sources and reserved == padding == 0,
              "duplicate or invalid typed source")
        check(kind in (1, 2, 3, 4) and scope in (1, 2) and clock == 1,
              "unknown typed source kind/scope/clock")
        configs = {1: "cpu-clock", 2: "task-clock", 3: "tracepoint", 4: "hardware-cycles", 5: "custom"}
        check(config in configs and requested in configs, "unknown typed source config")
        sources[logical] = {
            "logical_source": logical, "kind": {1: "software-v2", 2: "tracepoint", 3: "software-stack-v3", 4: "normalized"}[kind],
            "event_id": event, "schema_version": schema, "cpu": target if scope == 1 else None,
            "tid": target if scope == 2 else None, "bound_task_id": task or None,
            "period": period, "kernel_event_id": kernel, "program_id": program, "link_id": link,
            "enable_before_ns": before, "enable_after_ns": after,
            "disable_before_ns": disable_before, "disable_after_ns": disable_after,
            "clock": "monotonic", "requested_config": configs[requested], "config": configs[config],
            "unit": {1: "nanoseconds", 2: "events"}.get(unit),
            "fallback": {0: "none", 1: "hardware-unavailable"}.get(fallback),
            "requested_sample_period": request_period, "requested_frequency_hz": frequency,
            "effective_frequency_hz": effective_frequency, "requested_buffer_pages": pages,
            "effective_buffer_pages": effective_pages,
        }
    record_sources = [cursor.number("I") for _ in range(bindings)]
    cursor.finished()
    check(all(source in sources for source in record_sources), "unknown source binding")
    return sources, record_sources


def mapping_metadata(data):
    cursor = Cursor(data)
    check(cursor.take(8) == b"PBMAP001", "missing original mapping metadata")
    journal = cursor.string()
    artifacts = []
    for _ in range(cursor.number("I")):
        sha, build, path, debug_sha, debug_build = [cursor.string() for _ in range(5)]
        artifacts.append({"sha256": sha, "gnu_build_id": build or None, "path": path,
                          "debug_sha256": debug_sha or None, "debug_build_id": debug_build or None})
    flag = cursor.number("B")
    check(flag in (0, 1), "invalid kernel artifact presence")
    kernel = None
    if flag:
        kernel = {"sha256": cursor.string(), "reference_symbol": cursor.string(),
                  "reference_address": cursor.number("Q"), "text_start": cursor.number("Q"), "text_end": cursor.number("Q")}
    cursor.finished()
    return {"journal": journal, "artifacts": artifacts, "kernel": kernel}


def capture_facts(data, arch):
    records, status = decode_capture(data, arch)
    metadata_offset, metadata_size = struct.unpack_from("<QQ", data, 24)
    cursor = Cursor(data[metadata_offset:metadata_offset + metadata_size])
    # Skip the self-describing registry, using declared lengths, not a magic
    # search: arbitrary strings could contain a metadata marker.
    for _ in range(cursor.number("I")):
        cursor.take(12)
        cursor.string()
        cursor.string()
        for _ in range(cursor.number("I")):
            cursor.string()
            cursor.take(16)
    cursor.string()  # build commit label
    check(cursor.number("I") == {"riscv64": 1, "loongarch64": 2}[arch], "session arch mismatch")
    for _ in range(5):
        cursor.string()
    cursor.take(16)
    cursor.string()
    cursor.take(28)
    cursor.string()
    cursor.take(8)
    start, stop, session_status = cursor.number("Q"), cursor.number("Q"), cursor.number("I")
    counters = [cursor.number("Q") for _ in range(13)]
    cursor.take(cursor.number("I") * 12)
    diagnostics, mappings, source_bytes = cursor.blob(), cursor.blob(), cursor.blob()
    required = cursor.number("Q")
    cursor.finished()
    check(required & 4 and required & ~7 == 0, "unknown/missing required capability")
    check(session_status == status and 0 < start < stop, "session status/window mismatch")
    sources, bindings = source_metadata(source_bytes, len(records))
    for index, record in enumerate(records):
        source = sources[bindings[index]]
        check(record.event == source["event_id"] and record.version == source["schema_version"], "source binding schema mismatch")
        check(source["enable_before_ns"] <= record.time <= source["disable_after_ns"], "source binding time mismatch")
        check(source["cpu"] is None or source["cpu"] == record.cpu, "source binding CPU mismatch")
        check(source["bound_task_id"] is None or source["bound_task_id"] == record.task, "source binding stable task mismatch")
        if record.event in (0x1001, 0x1002):
            check(struct.unpack_from("<Q", record.payload)[0] == source["period"], "source binding period mismatch")
        if record.event == 0x1002:
            check(struct.unpack_from("<Q", record.payload, 32)[0] == source["kernel_event_id"], "source binding kernel ID mismatch")
    return {"records": records, "sources": sources, "bindings": bindings,
            "status": {0: "Complete", 1: "IncompleteLoss", 2: "IncompleteTruncated", 3: "IncompleteError"}[status],
            "start_ns": start, "stop_ns": stop, "counters": counters,
            "diagnostics_sha256": hashlib.sha256(diagnostics).hexdigest(),
            "mappings": mapping_metadata(mappings) if required & 2 else None}


def selected_samples(facts, query):
    selected = []
    for index, record in enumerate(facts["records"]):
        if record.event not in (0x1001, 0x1002):
            continue
        period = struct.unpack_from("<Q", record.payload)[0]
        ip, mode = struct.unpack_from("<QI", record.payload, 16)
        values = {"pid": record.pid, "tid": record.tid, "task": record.task,
                  "cpu": record.cpu, "mode": {1: "kernel", 2: "user"}.get(mode)}
        if any(key in query and values[key] != query[key] for key in values):
            continue
        if not query.get("from_ns", 0) <= record.time < query.get("to_ns", 1 << 64):
            continue
        length, termination = (1, None)
        ips = (ip,)
        if record.event == 0x1002:
            length, termination = struct.unpack_from("<HH", record.payload, 76)
            check(length <= 64 and len(record.payload) == 608, "invalid stack payload")
            ips = struct.unpack_from(f"<{length}Q", record.payload, 96)
        check(mode in (1, 2), "unknown sample mode")
        chain = (((1 << 64) - (128 if mode == 1 else 512)), *ips) if ips else ()
        semantic = None
        if record.event == 0x1002:
            source_id, sp, fp, ra, capture_ns = struct.unpack_from("<5Q", record.payload, 32)
            depth = struct.unpack_from("<H", record.payload, 74)[0]
            read, limit = struct.unpack_from("<II", record.payload, 80)
            reasons = ("complete_at_terminator", "no_frame_pointer", "invalid_frame", "nonmonotonic_frame",
                       "read_fault", "invalid_return_address", "depth_limit", "byte_limit", "address_overflow",
                       "invalid_instruction_pointer", "unavailable", "busy", "unsupported_abi", "invalid_limit")
            check(termination < len(reasons), "unknown stack termination")
            semantic = {"sample_period": period, "addr": struct.unpack_from("<Q", record.payload, 8)[0],
                "ip": ip, "mode": mode, "source_id": source_id, "sp": sp, "fp": fp, "ra": ra,
                "capture_ns": capture_ns, "depth_limit": depth, "chain_len": length,
                "stack_status": "complete" if termination == 0 else "unavailable" if termination in (1, 9, 10, 11, 12, 13) else "partial",
                "termination": reasons[termination], "bytes_read": read, "byte_limit": limit, "ips": list(ips)}
        selected.append({"sequence_index": index, "task_id": record.task, "semantic": semantic,
            "termination": termination, "payload_sha256": hashlib.sha256(record.payload).hexdigest(),
            "fields": (facts["bindings"][index], ip, record.pid, record.tid,
                       record.time, record.cpu, period, mode, chain)})
    return sorted(selected, key=lambda item: (item["fields"][4], item["sequence_index"]))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_chain(path, expected_sha, selected):
    """Bind the known workload functions to its actual ELF and recorded PCs."""
    check(digest(path) == expected_sha, "known workload ELF SHA differs from the executed fixture")
    _, functions = elf_symbols(path)
    result = []
    for name in ("sample_leaf", "sample_middle", "sample_outer"):
        suffix = f"7fixture{len(name)}{name}"
        matches = [(start, end, symbol) for start, end, symbol in functions
                   if symbol.startswith("_RNvC") and symbol.endswith(suffix)]
        check(len(matches) == 1, f"original fixture lacks unique Rust-v0 function {name}")
        start, end, symbol = matches[0]
        result.append({"function": "fixture::" + name, "symbol": symbol, "start": start, "end": end})
    check(any(len(sample["fields"][8]) >= 4 and sample["fields"][7] == 2 and
              all(row["start"] <= pc - int(index != 0) < row["end"]
                  for index, (pc, row) in enumerate(zip(sample["fields"][8][1:4], result)))
              for sample in selected), "original capture lacks the known three-function user chain")
    return result


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def command(directory, name, argv):
    argv = [str(arg) for arg in argv]
    result = subprocess.run(argv, text=True, capture_output=True,
                            env={**os.environ, "LC_ALL": "C", "DEBUGINFOD_URLS": ""})
    (directory / f"{name}.stdout").write_text(result.stdout)
    (directory / f"{name}.stderr").write_text(result.stderr)
    save(directory / f"{name}.command.json", {"argv": argv, "returncode": result.returncode})
    return result


def succeeded(result, label):
    check(result.returncode == 0, f"{label}: {result.stderr.strip()}")
    return result.stdout


def compare_query(selected, report, table, folded, weight):
    fields = [sample["fields"] for sample in selected]
    total = len(fields) if weight == "samples" else sum(row[6] for row in fields)
    unit = "samples" if weight == "samples" else "period_ns"
    check(report["sample_weight"] == {"samples": len(fields), "total": total, "unit": unit}, "JSON Query weight mismatch")
    expected = [{"sequence_index": sample["sequence_index"], "logical_source": row[0],
        "weight": 1 if weight == "samples" else row[6], "timestamp_ns": row[4], "cpu_id": row[5],
        "pid": row[2], "tid": row[3], "task_id": sample["task_id"],
        "sample_period": row[6], "ip": row[1], "mode": row[7]} for sample, row in zip(selected, fields)]
    check(report["cpu_samples"] == expected, "JSON Query records differ from original capture")
    stacks = [{"logical_source": row[0], "timestamp_ns": row[4], "cpu_id": row[5],
               "pid": row[2], "tid": row[3], "task_id": sample["task_id"], "sample": sample["semantic"]}
              for sample, row in zip(selected, fields) if sample["semantic"] is not None]
    check(report["stack_samples"] == stacks, "JSON stack fields differ from original capture")
    check(f"CPU samples: {len(fields)}; weight: {total} {unit}" in table, "table Query weight mismatch")
    # User-origin faults share the public --mode user Query, but carry no CPU
    # sample weight. Preserve their table rows and compare only CPU event rows.
    rows = [tuple(map(int, row)) for row in re.findall(
        r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+.*?\s(?:perf_event_v2|software_stack_v3)\s+period=",
        table, re.M)]
    expected_rows = [(sample["sequence_index"], row[0], row[4], row[5], row[2], row[3], sample["task_id"])
                     for sample, row in zip(selected, fields)]
    check(rows == expected_rows, "table Query record/source identities mismatch")
    check(sum(int(line.rsplit(" ", 1)[1]) for line in folded.splitlines()) == total, "folded Query weight mismatch")


def kernel_chain_proof(native, bundle, kernel):
    """Require three actual symbolized frames in one saved kernel callchain."""
    script = (native / "script.stdout").read_text()
    calltree = (native / "calltree.stdout").read_text()
    path = bundle / "artifacts" / f"{kernel['sha256']}.elf"
    check(digest(path) == kernel["sha256"], "kernel function oracle ELF SHA mismatch")
    symbols, functions = elf_symbols(path)
    check(kernel["reference_symbol"] in symbols, "original kernel lacks reference function")
    relocation = kernel["reference_address"] - symbols[kernel["reference_symbol"]]
    titles = [node.text or "" for node in ET.fromstring((native / "flamegraph.svg").read_text()).iter("{http://www.w3.org/2000/svg}title")]
    for block in re.split(r"\n\s*\n", script):
        frames = re.findall(r"^\s+([0-9a-f]+)\s+(.+?)\s+\(.*\)\s*$", block, re.M)[:3]
        chain = [name for _, name in frames]
        if len(chain) < 3 or len(set(chain)) < 3 or any(name.startswith(("[", ".L", "$")) for name in chain):
            continue
        if not all(any(symbol == name and start <= int(address, 16) - relocation - int(index != 0) < end
                       for start, end, symbol in functions)
                   for index, (address, name) in enumerate(frames)):
            continue
        try:
            verify_named_chain(script, calltree, chain)
        except ValueError:
            continue
        if all(any(title.startswith(name + " (") for title in titles) for name in chain):
            return chain
    raise ValueError("no three-function saved kernel chain agrees across script/calltree/SVG")


def negative_exports(directory, analyzer, capture, filters, artifacts):
    results = []
    for name in ("missing-symbol-bundle", "wrong-symbol-bundle"):
        target = directory / name
        target.mkdir()
        if name == "wrong-symbol-bundle":
            for artifact in artifacts:
                path = target / artifact["path"]
                check(path.resolve().is_relative_to(target), "artifact escapes negative bundle")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"deliberately wrong ELF for negative oracle\n")
        output = target / "rejected.perf.data"
        result = command(target, "export", [analyzer, capture, "--bundle", target, *filters, "--perf-data", output])
        check(result.returncode != 0 and not output.exists() and not Path(str(output) + ".json").exists(),
              f"{name}: expected strict export rejection without success output")
        results.append({"case": name, "diagnostic": result.stderr.strip(), "passed": True})
    original = capture.read_bytes()
    record_start = struct.unpack_from("<Q", original, 40)[0]
    first_size = 48 + struct.unpack_from("<I", original, record_start + 40)[0]
    corrupt = bytearray(original)
    corrupt[record_start + 48] ^= 1
    for name, changed in (("missing-trailer", original[:-40]),
                          ("corrupt-trailer", original[:-40] + b"BADMAGIC" + original[-32:]),
                          ("corrupt-record", bytes(corrupt)),
                          ("removed-record", original[:record_start] + original[record_start + first_size:])):
        target = directory / name
        target.mkdir()
        path = target / "derived-negative.pbcapture"
        path.write_bytes(changed)
        result = command(target, "read", [analyzer, path, "--json"])
        check(result.returncode != 0, f"{name}: invalid derived capture accepted")
        results.append({"case": name, "derived_from_sha256": digest(capture),
                        "modified_sha256": digest(path), "diagnostic": result.stderr.strip(), "passed": True})
    return results


def run(args):
    from capture import extract
    # Import runner helpers only for the independently emitted guest-file SHA
    # witness; none of its parsed reports provide the expected perf records.
    from run import parse_cases, verify_saved_hash

    source = args.run.resolve()
    capture = source / f"{args.capture}.pbcapture"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    inputs = json.loads((source / "inputs.json").read_text())
    build = inputs.get("recorder_build", {})
    check(build.get("variant") == "guest" and build.get("arch") == inputs["arch"],
          "end-to-end gate requires identified production recorder build")
    check(build.get("sha256") == inputs.get("recorder_sha256") == digest(source / "bpf-record.elf"),
          "production recorder ELF differs from run/build identity")
    check(inputs.get("guest_capture_sha_witness"), "run lacks guest file SHA witness")
    check(not args.require_kernel_chain or args.mode == "kernel", "kernel chain proof requires explicit --mode kernel")
    raw = capture.read_bytes()
    log = (source / "guest.log").read_text()
    check(extract(log, args.capture) == raw, "host capture differs from guest file transfer")
    verify_saved_hash(parse_cases(log)[args.capture], raw)
    facts = capture_facts(raw, inputs["arch"])
    query = {key: getattr(args, key) for key in ("mode", "pid", "tid", "task", "cpu", "from_ns", "to_ns") if getattr(args, key) is not None}
    selected = selected_samples(facts, query)
    check(selected, "Query has zero consumed CPU samples")
    check(facts["mappings"] is not None, "capture lacks original mapping/symbol facts")
    analyzer = args.analyzer.resolve()
    filters = [part for key, value in query.items() for part in ("--" + key.replace("_", "-"), str(value))]
    original_sha = digest(capture)
    symbols = args.expect_symbol[:]
    known_chain = []
    if args.require_chain and not symbols:
        known_chain = fixture_chain(source / "record-fixture.elf", inputs["fixture_sha256"], selected)
        symbols = [row["symbol"] for row in known_chain]
    result = {"run": str(source), "capture": capture.name, "capture_sha256": original_sha,
        "inputs_sha256": digest(source / "inputs.json"), "guest_log_sha256": digest(source / "guest.log"),
        "analyzer_sha256": digest(analyzer), "oracle_sha256": digest(Path(__file__)),
        "recorder_build": build,
        "known_fixture_chain": known_chain,
        "architecture": inputs["arch"], "query": query, "original_status": facts["status"],
        "diagnostics_sha256": facts["diagnostics_sha256"], "capture_counters": facts["counters"],
        "original_cpu_samples": len(selected_samples(facts, {})), "selected_samples": len(selected),
        "original_records": len(facts["records"]), "selected_records": selected,
        "source_counts": dict(Counter(row["fields"][0] for row in selected)),
        "source_period_ns": {key: sum(row["fields"][6] for row in selected if row["fields"][0] == key) for key in sorted({row["fields"][0] for row in selected})},
        "typed_sources": list(facts["sources"].values()), "queries": [], "passed": False}
    save(output / "e2e.json", result)
    manifest = json.loads(succeeded(command(output, "artifact-manifest", [analyzer, capture, "--artifact-manifest"]), "artifact manifest"))
    for key, expected in facts["mappings"].items():
        check(manifest[key] == expected, f"artifact manifest {key} differs from original capture bytes")
    if known_chain:
        check(any(artifact["sha256"] == inputs["fixture_sha256"] for artifact in manifest["artifacts"]),
              "known fixture ELF identity is absent from original capture")
    for artifact in manifest["artifacts"]:
        check((source / artifact["path"]).resolve().is_relative_to(source), "original artifact path escapes bundle")
    artifact_hashes = {artifact["path"]: digest(source / artifact["path"])
                       for artifact in manifest["artifacts"] if (source / artifact["path"]).is_file()}
    for artifact in manifest["artifacts"]:
        if artifact["path"] in artifact_hashes:
            check(artifact_hashes[artifact["path"]] == artifact["sha256"], "collected ELF SHA mismatch")
    for weight in ("samples", "period"):
        target = output / weight
        target.mkdir()
        selection = [*filters, "--weight", weight]
        exported = command(target, "query", [analyzer, capture, "--bundle", source, *selection,
            "--json", "--oncpu", target / "query.folded", "--perf-data", target / "perf.data"])
        report = json.loads(succeeded(exported, "export"))
        table = succeeded(command(target, "table", [analyzer, capture, *selection]), "table")
        compare_query(selected, report, table, (target / "query.folded").read_text(), weight)
        check(report["status"] == facts["status"] and report["is_complete"] is False, "Query promoted partial capture")
        check(report["recorder"]["record_sources"] == facts["bindings"], "report changed original source bindings")
        check({row["logical_source"] for row in report["recorder"]["sources"]} == set(facts["sources"]), "report omitted typed sources")
        for declared in report["recorder"]["sources"]:
            original = facts["sources"][declared["logical_source"]]
            check(all(declared[key] == value for key, value in original.items()), "typed source report differs from original")
        argv = [sys.executable, ROOT / "scripts/perf_pipeline.py", target / "perf.data",
                "--bundle", source, "--perf", args.perf.resolve(), "--flamegraph", args.flamegraph.resolve(), "--output", target / "native"]
        for symbol in symbols:
            argv += ["--expect-symbol", symbol]
        pipeline = json.loads(succeeded(command(target, "pipeline", argv), "perf pipeline"))
        actual = native_samples((target / "native/dump.stdout").read_text())
        check(Counter(sample["fields"] for sample in selected) == Counter(actual), "native perf differs from original source/IP/identity/time/CPU/period/mode/callchain")
        native_report = (target / "native/report.stdout").read_text()
        rows = re.findall(r"^\s*\d+(?:\.\d+)?%\s+(\d+)\s+(\d+)\s+.*?\s+\[[k.u]\]\s+(.+)$", native_report, re.M)
        period = sum(sample["fields"][6] for sample in selected)
        check(sum(int(row[0]) for row in rows) == len(selected) and sum(int(row[1]) for row in rows) == period, "native perf function rows omit samples/periods")
        if args.require_chain:
            verify_named_chain((target / "native/script.stdout").read_text(), (target / "native/calltree.stdout").read_text(), symbols)
        kernel_chain = kernel_chain_proof(target / "native", source, facts["mappings"]["kernel"]) if args.require_kernel_chain else None
        export_manifest = json.loads((target / "perf.data.json").read_text())
        result["queries"].append({"weight": weight, "samples": len(actual), "period_ns": period,
            "capture_status": report["status"], "attribution_complete": export_manifest["attribution_complete"],
            "attribution_incomplete_reasons": export_manifest["attribution_incomplete_reasons"],
            "partial_chain_count": export_manifest["partial_chain_count"], "pipeline": pipeline,
            "observed_kernel_chain": kernel_chain,
            "function_rows": [{"samples": int(n), "period_ns": int(p), "symbol": symbol} for n, p, symbol in rows],
            "perf_data_sha256": digest(target / "perf.data")})
        save(output / "e2e.json", result)
    result["negatives"] = negative_exports(output, analyzer, capture, filters, manifest["artifacts"])
    check(digest(capture) == original_sha, "host analysis changed original capture")
    check(digest(analyzer) == result["analyzer_sha256"], "analyzer changed during qualification")
    check(all(digest(source / path) == sha for path, sha in artifact_hashes.items()), "host analysis changed original ELF")
    result.update(passed=True, original_unchanged=True, original_artifact_sha256=artifact_hashes,
                  fields_verified=["record_sequence", "logical_source", "typed_sources", "ip", "pid", "tid", "stable_task", "timestamp_ns", "cpu", "period_ns", "mode", "callchain", "mapping_journal", "artifact_identities"])
    save(output / "e2e.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--capture", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--analyzer", required=True, type=Path)
    parser.add_argument("--perf", required=True, type=Path)
    parser.add_argument("--flamegraph", required=True, type=Path)
    parser.add_argument("--mode", choices=("user", "kernel"))
    for key in ("pid", "tid", "task", "cpu", "from-ns", "to-ns"):
        parser.add_argument("--" + key, type=int)
    parser.add_argument("--expect-symbol", action="append", default=[])
    parser.add_argument("--require-chain", action="store_true")
    parser.add_argument("--require-kernel-chain", action="store_true")
    args = parser.parse_args()
    try:
        result = run(args)
    except (OSError, ValueError, KeyError, struct.error) as error:
        parser.exit(1, f"recorder e2e: {error}\n")
    print(json.dumps({"passed": result["passed"], "samples": result["selected_samples"], "output": str(args.output)}))


if __name__ == "__main__":
    main()
