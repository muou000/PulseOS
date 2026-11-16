#!/usr/bin/env python3
"""Qualify the complete #213 guest matrix through fixed perf/SVG Queries."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from acceptance import ARCHES, CONTROL_SUITES, PRODUCTION_SUITES
from capture import clean_console
from e2e import capture_facts, command, digest, save, selected_samples


def validate_matrix(directory):
    required = {(arch, suite): "guest" if suite in PRODUCTION_SUITES else "acceptance"
                for arch in ARCHES for suite in PRODUCTION_SUITES + CONTROL_SUITES}
    prefix = "requires the complete dual-architecture guest matrix"
    try:
        index = json.loads((directory / "index.json").read_text())
        plan = json.loads((directory / "plan.json").read_text())
    except FileNotFoundError as error:
        raise ValueError(prefix + ": index.json and plan.json are required") from error
    actual = {(row["arch"], row["suite"]): row for row in index["runs"]}
    planned = {(row["arch"], row["suite"]): row.get("variant") for row in plan["runs"]}
    if (index.get("guest_passed") is not True or not actual or len(index["runs"]) != len(actual)
            or len(plan["runs"]) != len(planned) or set(actual) != set(planned)
            or any(key not in required or variant != required[key] for key, variant in planned.items())):
        raise ValueError(prefix + ": each original plan must exactly match its completed indexed runs")
    supplements = []
    for key, variant in planned.items():
        row = actual[key]
        if row.get("passed") is not True or row.get("variant") != variant:
            raise ValueError(f"guest suite failed or has wrong recorder variant: {key}")
        run = (directory / row["path"]).resolve()
        if not run.is_relative_to(directory) or row["path"] != f"{key[0]}/{key[1]}":
            raise ValueError("guest run path does not match matrix identity")
        files = row["files"]
        if not {"inputs.json", "result.json", "guest.log", "cases.sh", "bpf-record.elf", "kernel", "kernel.elf"} <= set(files):
            raise ValueError(f"guest inventory omits required originals: {key}")
        for name, expected in files.items():
            path = (run / name).resolve()
            if not path.is_relative_to(run) or digest(path) != expected:
                raise ValueError(f"original run file hash mismatch: {key}/{name}")
        console = (directory / row["console"]).resolve()
        if not console.is_relative_to(directory) or digest(console) != row["console_sha256"]:
            raise ValueError(f"guest harness console hash mismatch: {key}")
        inputs = json.loads((run / "inputs.json").read_text())
        result = json.loads((run / "result.json").read_text())
        for evidence in (inputs, result):
            build = evidence.get("recorder_build", {})
            if ((evidence.get("arch"), evidence.get("suite")) != key
                    or build.get("variant") != variant or build.get("arch") != key[0]
                    or build.get("sha256") != evidence.get("recorder_sha256")
                    or build.get("sha256") != files["bpf-record.elf"]):
                raise ValueError(f"guest recorder identity differs from its planned executable: {key}")
        if result.get("passed") is not True or result.get("errors"):
            raise ValueError(f"guest result did not pass: {key}")
        if result.get("captures") != row["captures"]:
            raise ValueError(f"guest capture index differs from result: {key}")
        if key[1] == "benchmark" and not result.get("benchmark"):
            raise ValueError(f"three-phase benchmark measurements missing: {key}")
        supplement_path = run / "supplemental-collection.json"
        if supplement_path.exists():
            supplement = json.loads(supplement_path.read_text())
            artifact = supplement["captured_artifact"]
            captured = capture_facts((run / supplement["capture"]).read_bytes(), key[0])
            if (artifact not in captured["mappings"]["artifacts"]
                    or supplement["capture_sha256"] != digest(run / supplement["capture"])
                    or supplement["original_collection_sha256"] != digest(run / supplement["original_collection"])
                    or supplement["candidate_sha256"] != artifact["sha256"]
                    or digest(run / supplement["candidate"]) != artifact["sha256"]
                    or digest(run / artifact["path"]) != artifact["sha256"]
                    or any(supplement[field] != inputs["boot_image_sha256"] for field in
                           ("recorded_boot_image_sha256", "disk_sha256_before", "disk_sha256_after"))):
                raise ValueError("supplement changed original facts or lacks matching captured ELF identity")
            supplements.append({"path": str(supplement_path.relative_to(directory)), "sha256": digest(supplement_path),
                                "capture_sha256": supplement["capture_sha256"], "artifact_sha256": artifact["sha256"]})
    index["verified_supplemental_collections"] = supplements
    return index


def queries(locations, arch):
    # This fixed list is the destination contract. There is deliberately no
    # option to drop a failing architecture, source mode or external workload.
    mapping = capture_facts((locations[arch, "mapping"] / "mapping-lifecycle.pbcapture").read_bytes(), arch)
    task_sources = [source for source in mapping["sources"].values() if source["tid"] is not None]
    if len(task_sources) != 1 or task_sources[0]["bound_task_id"] is None:
        raise ValueError("mapping Query requires the unique explicitly bound fixture task source")
    mapping_task = str(task_sources[0]["bound_task_id"])
    cases = [
        ("stacks-cpu", "stack-cpu", "cpu-user", ["--mode", "user", "--require-chain"]),
        ("stacks-cpu", "stack-cpu", "cpu-kernel", ["--mode", "kernel", "--require-kernel-chain"]),
        ("stacks-task", "stack-task", "task-user", ["--mode", "user", "--require-chain"]),
        ("stacks-mixed", "mixed", "mixed-user", ["--mode", "user", "--require-chain"]),
        ("stacks-mixed", "mixed", "mixed-kernel", ["--mode", "kernel", "--require-kernel-chain"]),
        ("stacks-existing", "existing-shell", "installed-program-user", ["--mode", "user"]),
        ("mapping", "mapping-lifecycle", "mapping-user", ["--mode", "user", "--task", mapping_task]),
        ("installed-io", "installed-io", "installed-program-kernel", ["--mode", "kernel", "--require-kernel-chain"]),
        ("nonleader-exec", "nonleader-exec", "nonleader-exec-user", ["--mode", "user"]),
    ]
    path = locations[arch, "nonleader-exec"] / "nonleader-exec.pbcapture"
    samples = selected_samples(capture_facts(path.read_bytes(), arch), {"mode": "user"})
    tids = sorted({sample["fields"].tid for sample in samples})
    if len(tids) != 2 or len({sample["task_id"] for sample in samples}) != 1:
        raise ValueError("nonleader exec lacks two observed numeric TIDs on one stable task")
    for tid in tids:
        cases.append(("nonleader-exec", "nonleader-exec", f"nonleader-exec-tid-{tid}", ["--mode", "user", "--tid", str(tid)]))
    return cases


def installed_kernel_witness(locations, arch):
    """Require every sample to belong to the one already-running installed dd."""
    run = locations[arch, "installed-io"]
    text = clean_console((run / "guest.log").read_text())
    ready = re.findall(r"(?m)^INSTALLED_IO READY pid=(\d+) command=dd if=/dev/zero of=/dev/null bs=65536$", text)
    alive = re.findall(r"(?m)^INSTALLED_IO ALIVE_AFTER_RECORD pid=(\d+)$", text)
    stopped = re.findall(r"(?m)^INSTALLED_IO STOPPED pid=(\d+) wait_rc=\d+$", text)
    dd_tids = {int(match[1]) for match in re.finditer(
        r'\[\s*[\d.]+\s+\d+:(\d+)\s+[^\]]+\]\s+sys_execve: path="(?:/usr)?/bin/dd"', text)}
    if len(ready) != 1 or alive != ready or stopped != ready or int(ready[0]) not in dd_tids:
        raise ValueError("installed-program Query lacks its actual dd exec/live/stop witnesses")
    target = int(ready[0])
    facts = capture_facts((run / "installed-io.pbcapture").read_bytes(), arch)
    sources = list(facts["sources"].values())
    if (len(sources) != 1 or sources[0]["tid"] != target or sources[0]["bound_task_id"] is None
            or sources[0]["config"] != "task-clock"):
        raise ValueError("installed-program capture is not bound to the one existing dd task")
    task = sources[0]["bound_task_id"]
    if any(record.task != task or record.tid != target or record.pid != target for record in facts["records"]):
        raise ValueError("installed-program capture contains idle, recorder or unrelated task samples")
    selected = selected_samples(facts, {"mode": "kernel"})
    if not selected:
        raise ValueError("installed-program kernel Query has no target kernel samples")
    return {"target_tid": target, "bound_task_id": task, "logical_source": sources[0]["logical_source"],
            "record_indices": [row["sequence_index"] for row in selected], "kernel_samples": len(selected),
            "all_capture_records": len(facts["records"]),
            "scope": "all saved kernel samples from the one already-running installed dd task"}


def qualify(args):
    directories = [args.matrix.resolve(), *(path.resolve() for path in args.additional)]
    locations, matrix_facts, supplements = {}, [], []
    for directory in directories:
        original = validate_matrix(directory)
        for row in original["runs"]:
            key = row["arch"], row["suite"]
            if key in locations:
                raise ValueError(f"duplicate guest suite across original matrices: {key}")
            locations[key] = directory / row["path"]
        matrix_facts.append({"path": str(directory), "index_sha256": digest(directory / "index.json"),
                             "plan_sha256": digest(directory / "plan.json"), "runs": len(original["runs"])})
        supplements += [{"matrix": str(directory), **item} for item in original["verified_supplemental_collections"]]
    required = {(arch, suite) for arch in ARCHES for suite in PRODUCTION_SUITES + CONTROL_SUITES}
    if set(locations) != required:
        raise ValueError("requires the complete dual-architecture guest matrix: union omits required suites")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"format": 1, "scope": "complete fresh guest matrix, fixed supported CPU Queries and explicit strict attribution boundary",
              "matrices": matrix_facts,
              "guest_runs": len(locations), "guest_passed": True, "passed": False,
              "supplemental_collections": supplements,
              "queries": [], "strict_negatives": [], "installed_kernel_witnesses": {},
              "known_boundaries": ["LoongArch installed dynamic-library user mappings lack guest-recorded SHA; strict user export must reject",
                                   "Mapping user Query selects the fixture's explicit stable task binding; other captured contexts retain unknown/partial diagnostics"],
              "complete_dynamic_executable_symbolization": False}
    save(output / "qualification.json", report)
    for arch in ARCHES:
        report["installed_kernel_witnesses"][arch] = installed_kernel_witness(locations, arch)
        for suite, capture, label, filters in queries(locations, arch):
            target = output / f"{arch}-{label}"
            run = locations[arch, suite]
            argv = [sys.executable, Path(__file__).with_name("e2e.py"), run,
                    "--capture", capture, "--analyzer", args.analyzer.resolve(), "--perf", args.perf.resolve(),
                    "--flamegraph", args.flamegraph.resolve(), "--output", target, *filters]
            capture_path = run / f"{capture}.pbcapture"
            original_sha = digest(capture_path)
            completed = command(output, f"{arch}-{label}", argv)
            result_path = target / "e2e.json"
            result = json.loads(result_path.read_text()) if result_path.exists() else {}
            expected_rejection = arch == "loongarch64" and label == "installed-program-user"
            if expected_rejection:
                passed = (completed.returncode == 1 and completed.stderr.strip() == "recorder e2e: export: Error: mapped object SHA unavailable"
                          and result.get("passed") is False and digest(capture_path) == original_sha
                          and not list(target.glob("*/perf.data*")) and not list(target.glob("*/native")))
            else:
                passed = completed.returncode == 0 and result.get("passed") is True
            entries = report["strict_negatives"] if expected_rejection else report["queries"]
            entries.append({"arch": arch, "suite": suite, "capture": capture, "label": label, "run": str(run),
                "query_argv": filters, "passed": passed, "report": str(result_path.relative_to(output)),
                "outcome": "expected strict rejection; no native export" if expected_rejection else "native perf/SVG verification",
                "report_sha256": digest(result_path) if result_path.exists() else None,
                "selected_samples": result.get("selected_samples"), "original_cpu_samples": result.get("original_cpu_samples"),
                "source_counts": result.get("source_counts"), "source_period_ns": result.get("source_period_ns"),
                "capture_sha256": result.get("capture_sha256"), "capture_status": result.get("original_status"),
                "original_unchanged": digest(capture_path) == original_sha,
                "diagnostic": completed.stderr.strip()})
            save(output / "qualification.json", report)
            outcome = "PASS strict rejection" if passed and expected_rejection else "PASS native export" if passed else "FAIL"
            print(f"{outcome} {arch} {label}", flush=True)
            if not passed:
                return 1
    if any(digest(Path(matrix["path"]) / "index.json") != matrix["index_sha256"]
           or digest(Path(matrix["path"]) / "plan.json") != matrix["plan_sha256"] for matrix in matrix_facts):
        raise ValueError("guest matrix index changed during qualification")
    report["passed"] = True
    report["successful_native_queries"] = len(report["queries"])
    report["verified_strict_negatives"] = len(report["strict_negatives"])
    save(output / "qualification.json", report)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix", type=Path)
    parser.add_argument("--additional", type=Path, action="append", default=[],
                        help="additional unchanged original matrix; the union must contain each required suite exactly once")
    parser.add_argument("--analyzer", type=Path, required=True)
    parser.add_argument("--perf", type=Path, required=True)
    parser.add_argument("--flamegraph", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        return qualify(args)
    except (OSError, ValueError, KeyError) as error:
        print(f"recorder qualification: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
