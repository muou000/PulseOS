#!/usr/bin/env python3
"""Run explicitly installed perf and pinned FlameGraph on a CPU capture export.

The original perf stdout/stderr is retained. No tool is downloaded, no runtime
paths select artifacts, and the source capture remains the diagnostic authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET
import importlib.util

FLAMEGRAPH_REVISION = "41fee1f99f9276008b7cd112fca19dc3ea84ac32"
FLAMEGRAPH_SHA256 = {
    "flamegraph.pl": "088f82e6848a4f12a56e1e8e8170ee6761fccf12e5615cd64630f6b087c99ea7",
    "stackcollapse-perf.pl": "74faa47a29d8df07cb06731dfd8bb94dc4c165b9d811ac6b4c9449eea2ac25d8",
}
HEADER = re.compile(r"^(.+?)\s+(\d+)/(\d+)\s+\[(\d+)\]\s+(\d+\.\d+):\s+(\d+)\s+(\S+):\s*$")
FRAME = re.compile(r"^\s+([0-9a-fA-F]+)\s+(.+)\s+\((.*)\)\s*$")


def inspect_perf_script(text: str) -> dict:
    """Read unmodified explicit-field perf output, rejecting missing payloads."""
    samples, periods, symbols, events, in_sample, frames = 0, 0, set(), set(), False, 0
    for line in text.splitlines() + [""]:
        if not line.strip():
            if in_sample and not frames:
                raise ValueError("perf script sample has no decoded IP/callchain")
            in_sample, frames = False, 0
            continue
        header = HEADER.fullmatch(line)
        if header:
            if in_sample:
                raise ValueError("perf script sample missing separator")
            period = int(header[6])
            if period <= 0:
                raise ValueError("perf script has zero period; cannot invent weight one")
            samples += 1
            periods += period
            events.add(header[7])
            in_sample = True
            continue
        frame = FRAME.fullmatch(line)
        if not in_sample or not frame:
            raise ValueError(f"unrecognized perf script line: {line!r}")
        frames += 1
        symbols.add(frame[2])
    return {"sample_count": samples, "total_period_ns": periods,
            "symbols": sorted(symbols), "event_names": sorted(events)}


def inspect_folded(text: str) -> int:
    total = 0
    for line in text.splitlines():
        stack, separator, weight = line.rpartition(" ")
        if not separator or not stack or not weight.isdecimal() or int(weight) <= 0:
            raise ValueError("invalid folded stack or nonpositive weight")
        total += int(weight)
    return total


def inspect_svg(text: str, total: int, unit: str, expected_symbols: list[str]) -> None:
    root = ET.fromstring(text)
    if root.tag != "{http://www.w3.org/2000/svg}svg":
        raise ValueError("FlameGraph output is not an SVG document")
    countname = {"samples": "samples", "period_ns": "nanoseconds"}[unit]
    titles = [element.text or "" for element in root.iter("{http://www.w3.org/2000/svg}title")]
    totals = [re.fullmatch(r"all \(([\d,]+) " + countname + r", 100(?:\.0+)?%\)", title) for title in titles]
    totals = [int(match[1].replace(",", "")) for match in totals if match]
    if totals != [total]:
        raise ValueError("SVG total weight or count unit differs from captured samples")
    for symbol in expected_symbols:
        if not any(title.startswith(symbol + " (") for title in titles):
            raise ValueError(f"SVG lacks expected function {symbol}")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_flamegraph(directory: Path) -> dict:
    for name, expected in FLAMEGRAPH_SHA256.items():
        if digest(directory / name) != expected:
            raise ValueError(f"FlameGraph {name} SHA-256 differs from pinned {FLAMEGRAPH_REVISION}")
    return {"revision": FLAMEGRAPH_REVISION, "sha256": FLAMEGRAPH_SHA256.copy()}


def bundle_file(bundle: Path, relative: str) -> Path:
    path = (bundle / relative).resolve(strict=True)
    if Path(relative).is_absolute() or not path.is_relative_to(bundle):
        raise ValueError("artifact path escapes explicit bundle")
    return path


def inspect_buildids(text: str, manifest: dict) -> None:
    expected = {}
    for artifact in manifest["artifacts"]:
        name = "[kernel.kallsyms]" if artifact["path"] == manifest.get("kernel_artifact_path") else "/" + artifact["path"]
        expected[name] = artifact.get("gnu_build_id")
    actual = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) == 1:
            identifier, name = None, fields[0]
        elif len(fields) == 2 and re.fullmatch(r"[0-9a-f]+", fields[0]):
            identifier, name = fields
        else:
            raise ValueError("unrecognized native perf buildid-list row")
        if name in actual:
            raise ValueError("duplicate native perf buildid-list artifact")
        actual[name] = identifier
    if actual != expected:
        raise ValueError("native perf buildid-list differs from actual bundled GNU notes")


def run_pipeline(args: argparse.Namespace) -> dict:
    data = args.data.resolve(strict=True)
    manifest_path = (args.manifest or Path(str(data) + ".json")).resolve(strict=True)
    manifest = json.loads(manifest_path.read_text())
    if digest(data) != manifest["perf_data_sha256"]:
        raise ValueError("perf.data does not match its export manifest")
    unit = manifest["weight_unit"]
    if unit not in ("samples", "period_ns"):
        raise ValueError("unsupported CPU sample weight unit")
    sample_count, period = manifest["sample_count"], manifest["total_period_ns"]
    if any(type(value) is not int or value < 0 for value in (sample_count, period, manifest["selected_weight"])):
        raise ValueError("invalid manifest sample/period totals")
    expected_weight = sample_count if unit == "samples" else period
    if manifest["selected_weight"] != expected_weight or bool(sample_count) != bool(period):
        raise ValueError("manifest weight differs from sample/period totals")
    pinned = verify_flamegraph(args.flamegraph.resolve(strict=True))
    bundle = args.bundle.resolve(strict=True)
    for artifact in manifest["artifacts"]:
        if digest(bundle_file(bundle, artifact["path"])) != artifact["sha256"]:
            raise ValueError("artifact SHA-256 differs from capture export identity")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    cache = output / "buildid-cache"
    cache.mkdir()
    perf = args.perf.resolve(strict=True)
    commands = {}

    def command(name: str, argv: list[str | Path]) -> str:
        argv = [str(value) for value in argv]
        completed = subprocess.run(argv, capture_output=True, text=True,
                                   env={**os.environ, "LC_ALL": "C", "DEBUGINFOD_URLS": ""})
        (output / f"{name}.stdout").write_text(completed.stdout)
        (output / f"{name}.stderr").write_text(completed.stderr)
        commands[name] = {"argv": argv, "returncode": completed.returncode}
        (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        if completed.returncode:
            raise ValueError(f"{name} exited {completed.returncode}; original output in {output}")
        return completed.stdout

    version = command("perf-version", [perf, "version"]).strip()
    result = {"pipeline_sha256": digest(Path(__file__)), "perf_version": version, "perf_sha256": digest(perf), "flamegraph": pinned,
              "manifest_sha256": digest(manifest_path), "perf_data_sha256": digest(data),
              "sample_count": sample_count, "total_period_ns": period, "selected_weight": expected_weight,
              "weight_unit": unit, "capture_complete": manifest["capture_complete"],
              "attribution_complete": False, "partial_chain_count": manifest.get("partial_chain_count"),
              "ip_only_count": manifest.get("ip_only_count"), "query": manifest.get("query"),
              "diagnostic_authority": "original capture and export manifest", "svg": None}
    if not sample_count:
        # Neither the renderer nor stackcollapse's absent-period fallback may
        # create one sample for an empty selection.
        (output / "flamegraph.folded").write_text("")
        result["empty"] = True
    else:
        prefix = [perf, "--buildid-dir", cache]
        common = ["-i", data, "--symfs", bundle]
        kernel = manifest.get("kernel_artifact_path")
        if kernel is not None:
            # A deterministic auxiliary ELF view hides only local assembler
            # labels that perf otherwise prefers over enclosing STT_FUNC names.
            # Full executed ELF identity and all load bytes remain authoritative.
            spec = importlib.util.spec_from_file_location("perf_symbols", Path(__file__).with_name("perf_symbols.py"))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            symbols_path = output / "kernel-symbols.elf"
            result["kernel_symbol_view"] = module.prepare_kernel_symbols(bundle_file(bundle, kernel), symbols_path)
            expected_kernel = next(entry["sha256"] for entry in manifest["artifacts"] if entry["path"] == kernel)
            if result["kernel_symbol_view"]["original_sha256"] != expected_kernel:
                raise ValueError("kernel ELF changed after captured artifact verification")
            common += ["--vmlinux", symbols_path]
        command("report", prefix + ["report", *common, "--stdio", "--no-children", "--show-nr-samples", "--show-total-period", "--percent-limit", "0"])
        command("calltree", prefix + ["report", *common, "--stdio", "--children", "--call-graph", "graph,0,caller",
                                      "--show-nr-samples", "--show-total-period", "--percent-limit", "0"])
        script = command("script", prefix + ["script", *common, "--ns", "-F", "comm,pid,tid,cpu,time,period,event,ip,sym,dso"])
        command("dump", prefix + ["script", *common, "-D"])
        buildids = command("buildid-list", prefix + ["buildid-list", "-i", data])
        observed = inspect_perf_script(script)
        if observed["sample_count"] != sample_count or observed["total_period_ns"] != period:
            raise ValueError("native perf script sample count/period differs from capture export")
        if len(observed["event_names"]) != 1:
            raise ValueError("select one CPU event kind before combining FlameGraph weights")
        inspect_buildids(buildids, manifest)
        for symbol in args.expect_symbol:
            if symbol not in observed["symbols"]:
                raise ValueError(f"native perf script lacks expected function {symbol}")
        script_name = "script"
        if unit == "samples":
            # Ask unmodified perf to omit period. Pinned stackcollapse then
            # assigns one to each actual decoded sample, without rewriting it.
            command("script-samples", prefix + ["script", *common, "--ns", "-F", "comm,pid,tid,cpu,time,event,ip,sym,dso"])
            script_name = "script-samples"
        folded = command("stackcollapse", ["perl", args.flamegraph / "stackcollapse-perf.pl", "--tid", output / f"{script_name}.stdout"])
        if inspect_folded(folded) != expected_weight:
            raise ValueError("FlameGraph folded weights differ from selected capture weight")
        (output / "flamegraph.folded").write_text(folded)
        svg = command("flamegraph", ["perl", args.flamegraph / "flamegraph.pl", "--minwidth", "0",
            "--countname", "samples" if unit == "samples" else "nanoseconds",
            "--title", "PulseOS recorded CPU samples (see capture diagnostics)", output / "flamegraph.folded"])
        inspect_svg(svg, expected_weight, unit, args.expect_symbol)
        (output / "flamegraph.svg").write_text(svg)
        result.update(empty=False, svg="flamegraph.svg", svg_sha256=digest(output / "flamegraph.svg"),
                      observed=observed, commands=commands)
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--perf", required=True, type=Path)
    parser.add_argument("--flamegraph", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new output directory")
    parser.add_argument("--expect-symbol", action="append", default=[])
    args = parser.parse_args()
    try:
        result = run_pipeline(args)
    except (ValueError, OSError, KeyError, ET.ParseError) as error:
        parser.exit(1, f"perf pipeline: {error}\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
