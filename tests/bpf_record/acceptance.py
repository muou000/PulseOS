#!/usr/bin/env python3
"""Run the #213 guest matrix serially and retain its original inputs and files.

This gate produces fresh capture/lifecycle evidence. Run e2e.py on its production
captures to qualify the independent perf and FlameGraph consumer stage.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from run import ACCEPTANCE_SUITES, ARCHES, BASE, REPO, helpers


PRODUCTION_SUITES = (
    "smoke", "stacks-cpu", "stacks-task", "stacks-mixed", "stacks-existing",
    "mapping", "nonleader-exec", "stacks-sigint", "stacks-sigterm",
    "stacks-exit", "stacks-overflow", "existing", "installed-io",
)
CONTROL_SUITES = ("lifecycle", "negative", "stacks-observation", "recovery", "benchmark")


def plan(arches: list[str], suites: list[str] | None) -> dict:
    selected = suites or list(PRODUCTION_SUITES + CONTROL_SUITES)
    # Benchmarks run after the functional matrix, never beside another guest.
    selected = [suite for suite in selected if suite != "benchmark"] + (["benchmark"] if "benchmark" in selected else [])
    runs = [{"arch": arch, "suite": suite,
             "variant": "acceptance" if suite in ACCEPTANCE_SUITES else "guest"}
            for suite in selected for arch in arches]
    return {"format": 1, "scope": "fresh guest capture and control lifecycle; perf/SVG qualified by e2e.py",
            "execution": "serial, including baseline/loaded-detached/attached benchmark phases",
            "runs": runs}


def inventory(directory: Path) -> dict:
    """Hash replay files; large rebuildable inputs retain their input identities."""
    omitted = {"disk.img", "bpf-analyzer"}
    return {str(path.relative_to(directory)): helpers.digest(path)
            for path in sorted(directory.rglob("*"))
            if path.is_file() and path.name not in omitted}


def execute(args: argparse.Namespace, matrix: dict) -> int:
    output = helpers.scoped(args.output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "plan.json").write_text(json.dumps(matrix, indent=2) + "\n")
    index = {"format": 1, "scope": matrix["scope"], "guest_passed": False,
             "omitted_rebuildable_inputs": ["disk.img (boot_image_sha256 in inputs.json)",
                                             "bpf-analyzer (analyzer_sha256 in inputs.json)"],
             "runs": []}
    for item in matrix["runs"]:
        arch, suite = item["arch"], item["suite"]
        directory = output / arch / suite
        command = [sys.executable, str(BASE / "run.py"), "guest", "--arch", arch,
                   "--suite", suite, "--duration-ms", str(args.duration_ms),
                   "--run-dir", str(directory), "--timeout", str(args.timeout)]
        if args.analyzer:
            command += ["--analyzer", str(args.analyzer.resolve(strict=True))]
        image = getattr(args, "image_" + arch)
        if image:
            command += ["--image", str(image.resolve(strict=True))]
        print(f"RUN {arch} {suite} recorder={item['variant']}", flush=True)
        console = output / f"{arch}-{suite}.log"
        with console.open("w") as stream:
            completed = subprocess.run(command, cwd=REPO, stdout=stream, stderr=subprocess.STDOUT)
        helpers.permission_check(console.read_text())
        result_path = directory / "result.json"
        result = json.loads(result_path.read_text()) if result_path.exists() else {}
        passed = (completed.returncode == 0 and result.get("passed") is True
                  and result.get("recorder_build", {}).get("variant") == item["variant"])
        index["runs"].append({**item, "path": str(directory.relative_to(output)),
                              "command": command, "passed": passed,
                              "captures": result.get("captures", {}),
                              "files": inventory(directory) if directory.exists() else {},
                              "console": console.name, "console_sha256": helpers.digest(console)})
        (output / "index.json").write_text(json.dumps(index, indent=2) + "\n")
        print(f"{'PASS' if passed else 'FAIL'} {arch} {suite}: {directory}", flush=True)
        if not passed:
            return 1
    index["guest_passed"] = True
    (output / "index.json").write_text(json.dumps(index, indent=2) + "\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true", help="print the matrix without building or running guests")
    parser.add_argument("--arch", choices=tuple(ARCHES), action="append")
    parser.add_argument("--suite", choices=PRODUCTION_SUITES + CONTROL_SUITES, action="append")
    parser.add_argument("--output", type=Path, help="new evidence directory under tests/bpf_record")
    parser.add_argument("--analyzer", type=Path)
    parser.add_argument("--image-riscv64", type=Path)
    parser.add_argument("--image-loongarch64", type=Path)
    parser.add_argument("--duration-ms", type=int, default=1000)
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    if not 100 <= args.duration_ms <= 30_000:
        parser.error("--duration-ms must be 100..30000")
    if len(args.arch or []) != len(set(args.arch or [])) or len(args.suite or []) != len(set(args.suite or [])):
        parser.error("duplicate architecture or suite")
    matrix = plan(args.arch or list(ARCHES), args.suite)
    if args.plan:
        print(json.dumps(matrix, indent=2))
        return 0
    if args.output is None:
        parser.error("--output is required to retain fresh evidence")
    return execute(args, matrix)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
