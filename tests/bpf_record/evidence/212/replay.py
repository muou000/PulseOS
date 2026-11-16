#!/usr/bin/env python3
"""Replay immutable #211 captures through #212 and independently check perf.

Inputs are extracted #211 archives. Expected source IDs, record identities and
CPU fields come from their original, hash-checked timelines and raw payloads,
never from the newly generated exporter manifest.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tests/bpf_sampling"))
from perf_evidence import native_samples


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


def original_samples(timeline, tid=None):
    sources = {source["logical_source"]: source for source in timeline["recorder"]["sources"]}
    selected = []
    for event in timeline["events"]:
        if event["event_id"] not in (0x1001, 0x1002):
            continue
        payload = bytes.fromhex(event["payload_hex"])
        period, = struct.unpack_from("<Q", payload)
        ip, mode = struct.unpack_from("<QI", payload, 16)
        if mode != 2 or (tid is not None and event["tid"] != tid):
            continue
        logical = timeline["recorder"]["record_sources"][event["sequence_index"]]
        assert logical == event["logical_source"]
        source = sources[logical]
        assert period == source["period"]
        assert source["enable_before_ns"] <= event["timestamp_ns"] <= source["disable_after_ns"]
        if source["bound_task_id"] is not None:
            assert source["bound_task_id"] == event["task_id"]
        if event["event_id"] == 0x1002:
            kernel, = struct.unpack_from("<Q", payload, 32)
            length, = struct.unpack_from("<H", payload, 76)
            ips = struct.unpack_from(f"<{length}Q", payload, 96)
            assert kernel == source["kernel_event_id"]
            assert list(ips) == event["semantic"]["ips"]
        else:
            ips = (ip,)
        chain = ((1 << 64) - 512, *ips) if ips else ()
        fields = (logical, ip, event["pid"], event["tid"], event["timestamp_ns"],
                  event["cpu_id"], period, mode, chain)
        selected.append((event, fields))
    return sorted(selected, key=lambda pair: (pair[0]["timestamp_ns"], pair[0]["sequence_index"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new output directory")
    parser.add_argument("--analyzer", required=True, type=Path)
    parser.add_argument("--perf", required=True, type=Path)
    parser.add_argument("--flamegraph", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    analyzer = output / "bpf-analyzer"
    shutil.copy2(args.analyzer.resolve(), analyzer)
    index_path = ROOT / "tests/bpf_record/evidence/211/index.json"
    index = json.loads(index_path.read_text())
    result = {
        "date": "2026-11-16", "source_issue": 211, "consumer_issue": 212,
        "evidence_scope": "host replay of unchanged archived QEMU captures; no new guest run",
        "original_index_sha256": digest(index_path),
        "analyzer_sha256": digest(analyzer), "replay_sha256": digest(Path(__file__)),
        "cases": [],
    }

    def command(directory, name, argv):
        argv = [str(item) for item in argv]
        completed = subprocess.run(argv, capture_output=True, text=True,
                                   env={**os.environ, "LC_ALL": "C", "DEBUGINFOD_URLS": ""})
        (directory / f"{name}.stdout").write_text(completed.stdout)
        (directory / f"{name}.stderr").write_text(completed.stderr)
        save(directory / f"{name}.command.json", {"argv": argv, "returncode": completed.returncode})
        return completed

    for arch in ("riscv64", "loongarch64"):
        archive = index["archives"][f"{arch}.tar.gz"]
        for suite, name in (("stacks-mixed", "mixed"), ("recovery", "nonleader-exec")):
            bundle = (args.inputs / arch / suite).resolve()
            capture = bundle / f"{name}.pbcapture"
            timeline_path = bundle / f"{name}-timeline.json"
            for path in (capture, timeline_path):
                member = f"{arch}/{suite}/{path.name}"
                assert digest(path) == archive["members"][member]["sha256"], member
            timeline = json.loads(timeline_path.read_text())
            tids = sorted({event["tid"] for event, _ in original_samples(timeline)})
            queries = [("samples", None), ("period", None)]
            if name == "nonleader-exec":
                assert len(tids) == 2, "nonleader exec must preserve observations on both TIDs"
                assert len({event["task_id"] for event, _ in original_samples(timeline)}) == 1
                queries += [("samples", tid) for tid in tids]
            for weight, tid in queries:
                label = f"{arch}-{name}-{weight}" + (f"-tid{tid}" if tid is not None else "")
                directory = output / label
                directory.mkdir()
                selected = original_samples(timeline, tid)
                expected = [fields for _, fields in selected]
                period = sum(fields[6] for fields in expected)
                total = len(expected) if weight == "samples" else period
                filters = ["--mode", "user", "--weight", weight]
                if tid is not None:
                    filters += ["--tid", str(tid)]
                row = {
                    "label": label, "architecture": arch, "archive": f"../211/{arch}.tar.gz",
                    "archive_sha256": archive["sha256"], "capture_member": f"{arch}/{suite}/{capture.name}",
                    "capture_sha256": digest(capture), "original_timeline_sha256": digest(timeline_path),
                    "query_argv": filters, "selected_record_indices": [event["sequence_index"] for event, _ in selected],
                    "samples": len(expected), "period_ns": period,
                    "weight_unit": "samples" if weight == "samples" else "period_ns", "selected_weight": total,
                    "logical_sources": sorted({fields[0] for fields in expected}),
                    "stable_task_ids": sorted({event["task_id"] for event, _ in selected}),
                    "numeric_tids": sorted({fields[3] for fields in expected}),
                    "original_fields_sha256": fingerprint(sorted(expected)),
                }
                exported = command(directory, "export", [analyzer, capture, "--bundle", bundle, *filters,
                    "--json", "--oncpu", directory / "query.folded", "--perf-data", directory / "perf.data"])
                if exported.returncode:
                    row.update(status="rejected", rejection=exported.stderr.strip())
                    result["cases"].append(row)
                    save(output / "replay.json", result)
                    continue
                report = json.loads(exported.stdout)
                assert report["sample_weight"] == {"unit": row["weight_unit"], "total": total, "samples": len(expected)}
                rows = report["cpu_samples"]
                assert [entry["sequence_index"] for entry in rows] == row["selected_record_indices"]
                assert [entry["logical_source"] for entry in rows] == [fields[0] for fields in expected]
                assert sum(int(line.rsplit(" ", 1)[1]) for line in (directory / "query.folded").read_text().splitlines()) == total
                piped = command(directory, "pipeline", [sys.executable, ROOT / "scripts/perf_pipeline.py",
                    directory / "perf.data", "--bundle", bundle, "--perf", args.perf.resolve(),
                    "--flamegraph", args.flamegraph.resolve(), "--output", directory / "native",
                    "--expect-symbol", "_start"])
                if piped.returncode:
                    raise ValueError(f"{label}: {piped.stderr}")
                native = json.loads(piped.stdout)
                actual = native_samples((directory / "native/dump.stdout").read_text())
                assert Counter(expected) == Counter(actual), "native perf differs from original archived fields"
                native_report = (directory / "native/report.stdout").read_text()
                function_rows = re.findall(r"^\s*\d+(?:\.\d+)?%\s+(\d+)\s+(\d+)\s+.*?\s+\[[k.u]\]\s+(.+)$", native_report, re.M)
                assert sum(int(entry[0]) for entry in function_rows) == len(expected)
                assert sum(int(entry[1]) for entry in function_rows) == period
                manifest = json.loads((directory / "perf.data.json").read_text())
                assert digest(capture) == row["capture_sha256"], "export changed its input"
                row.update(status="passed", capture_status=report["status"],
                    capture_complete=report["is_complete"], attribution_complete=False,
                    attribution_incomplete_reasons=manifest["attribution_incomplete_reasons"],
                    partial_chain_count=manifest["partial_chain_count"],
                    unavailable_chain_count=manifest.get("unavailable_chain_count", 0),
                    native_fields_sha256=fingerprint(sorted(actual)),
                    native_fields_verified=["logical_source", "ip", "pid", "tid", "time", "cpu", "period", "mode", "context_markers", "callchain"],
                    native_function_rows=[{"samples": int(n), "period_ns": int(p), "symbol": symbol} for n, p, symbol in function_rows],
                    native_observed=native["observed"],
                    perf_version=native["perf_version"], perf_sha256=native["perf_sha256"],
                    format_baseline=manifest["format_baseline"], flamegraph=native["flamegraph"],
                    svg_sha256=native["svg_sha256"], perf_data_sha256=digest(directory / "perf.data"))
                result["cases"].append(row)
                save(output / "replay.json", result)
                print(f"{label}: {len(expected)} samples, {period} ns; native fields and SVG pass", flush=True)
    assert digest(analyzer) == result["analyzer_sha256"]
    if any(row["status"] != "passed" for row in result["cases"]):
        raise SystemExit("some exports were rejected; see replay.json")


if __name__ == "__main__":
    main()
