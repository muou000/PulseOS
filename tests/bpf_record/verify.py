#!/usr/bin/env python3
"""Replay recorder acceptance from original guest bytes using a host analyzer."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from capture import clean_console, extract
from run import (REPO, benchmark, cases_script, helpers, parse_cases, collection,
                 validate_case, validate_report, verify_exec_identity, verify_existing_workload,
                 verify_saved_hash, stack_proof, mapping_lifecycle_proof)


def verify(run: Path, analyzer: Path, *, functional_only: bool = False) -> dict:
    inputs = json.loads((run / "inputs.json").read_text())
    log = (run / "guest.log").read_text()
    _, captures, failures = cases_script("/unused", inputs["suite"], inputs["duration_ms"])
    cases = parse_cases(log)
    errors, reports, proofs = [], {}, {}
    if not re.search(r"(?m)^BPF_HOST_EXIT \S+ 0\s*$", clean_console(log)):
        errors.append("missing successful harness exit")
    if helpers.digest(run / "cases.sh") != inputs["script_sha256"]:
        errors.append("guest script hash mismatch")
    for filename, key in (("bpf-record.elf", "recorder_sha256"), ("record-fixture.elf", "fixture_sha256"),
                          ("kernel", "kernel_sha256")):
        if (run / filename).exists() and helpers.digest(run / filename) != inputs[key]:
            errors.append(f"archived artifact hash mismatch: {filename}")
    labels = captures + failures
    if inputs["suite"] in ("benchmark", "full"):
        labels += ["loaded-detached"]
    for label in dict.fromkeys(labels):
        if label not in cases:
            errors.append(f"missing case: {label}")
        else:
            errors += validate_case(label, cases[label], label in failures)
    for label in captures:
        path = run / f"{label}.pbcapture"
        if path.read_bytes() != extract(log, label):
            errors.append(f"{label}: saved capture differs from original guest file transfer")
        if inputs.get("guest_capture_sha_witness"):
            verify_saved_hash(cases[label], path.read_bytes())
            candidates = list((run / "artifacts").glob("*.elf"))
            collected = collection.collect(path, run, candidates, analyzer)
        report = json.loads(helpers.command([str(analyzer), str(path), "--json"], cwd=REPO))
        reports[label] = report
        errors += validate_report(label, report)
        if inputs["suite"].startswith("stacks-") and label != "journal-failure":
            timeline = run / f"{label}-replay-timeline.json"
            helpers.command([str(analyzer), str(path), "--timeline", str(timeline)], cwd=REPO)
            proofs[label] = stack_proof(json.loads(timeline.read_text()), report, collected,
                                       require_depth=label in ("stack-task", "stack-cpu"), require_kernel=label == "mixed")
        if label == "mapping-lifecycle":
            proofs[label] = mapping_lifecycle_proof(log, collected["captured_manifest"])
        if label == "nonleader-exec":
            # Regenerate the timeline through the same authoritative input.
            timeline = run / "nonleader-exec-replay-timeline.json"
            helpers.command([str(analyzer), str(path), "--timeline", str(timeline)], cwd=REPO)
            proofs[label] = verify_exec_identity(log, report, json.loads(timeline.read_text()))
        if label in ("existing-cpu", "existing-sched", "existing-fault"):
            timeline = run / f"{label}-replay-timeline.json"
            helpers.command([str(analyzer), str(path), "--timeline", str(timeline)], cwd=REPO)
            proofs[label] = verify_existing_workload(log, json.loads(timeline.read_text()), label)
        if inputs.get("guest_capture_sha_witness"):
            verify_saved_hash(cases[label], path.read_bytes())
    if "write-failure" in failures:
        path = run / "write-failure.pbcapture"
        if path.read_bytes() != extract(log, "write-failure") or path.stat().st_size != 1024:
            errors.append("failed-write original prefix differs")
        try:
            helpers.command([str(analyzer), str(path), "--json"], cwd=REPO)
        except RuntimeError:
            pass
        else:
            errors.append("missing-trailer file was accepted")
    measurements = {} if functional_only else benchmark(log, cases, reports)
    return {"arch": inputs["arch"], "suite": inputs["suite"], "passed": not errors, "errors": errors,
            "analyzer_sha256": helpers.digest(analyzer), "functional_only": functional_only,
            "captures": {label: {"records_count": report["records_count"], "status": report["status"],
                                  "sources": len(report["recorder"]["sources"])} for label, report in reports.items()},
            "benchmark": measurements, "proofs": proofs}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--analyzer", type=Path, default=REPO / "target/debug/bpf-analyzer")
    parser.add_argument("--functional-only", action="store_true",
                        help="replay lifecycle/capture checks without qualifying older benchmark measurements")
    args = parser.parse_args()
    result = verify(args.run.resolve(), args.analyzer.resolve(), functional_only=args.functional_only)
    print(json.dumps(result, indent=2))
    return int(not result["passed"])


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
