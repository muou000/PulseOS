#!/usr/bin/env python3
"""Compare successful SG benchmarks with identical guest and QEMU settings."""
import argparse
import json
from pathlib import Path


def normalized_qemu(command):
    result = []
    skip = False
    for word in command:
        if skip:
            skip = False
            continue
        if word in ("-kernel", "-drive"):
            result.append(word)
            skip = True
        else:
            result.append(word)
    return result


def compare(before, after):
    for name, data in (("before", before), ("after", after)):
        if data["errors"]:
            raise ValueError(f"{name} run failed: {data['errors']}")
    for key in ("arch", "suite", "guest_sha256", "source_image_sha256", "qemu_version"):
        if before[key] != after[key]:
            raise ValueError(f"unmatched {key}")
    if normalized_qemu(before["qemu"]) != normalized_qemu(after["qemu"]):
        raise ValueError("QEMU configurations differ")
    key = lambda row: (row["layout"], row["operation"], row["bytes"])
    old, new = ({key(row): row for row in data["summary"]} for data in (before, after))
    if old.keys() != new.keys():
        raise ValueError("benchmark cases differ")
    text = [
        f"# {before['arch']} {before['suite']} comparison", "",
        f"Guest SHA-256: {before['guest_sha256']}",
        f"Before kernel: {before['kernel_sha256']}",
        f"After kernel: {after['kernel_sha256']}", "",
        "Latency is the median per-operation sample; throughput is cached guest I/O.",
        "Natural allocations can have different physical layouts. Such rows remain",
        "visible but are marked unmatched and must not support a controlled speedup claim.", "",
        "| Layout | Operation | KiB | Before µs | After µs | Speedup | Before MiB/s | After MiB/s | PFN breaks |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for case in sorted(old):
        b, a = old[case], new[case]
        if b["samples"] != a["samples"]:
            raise ValueError(f"sample count differs: {case}")
        # Equal counts alone do not identify the distribution of partial runs.
        matched = (b["discontinuities"] == a["discontinuities"] and
                   b["discontinuities"] in ([0], [case[2] // 4096 - 1]))
        speedup = b["median_latency_ns"] / a["median_latency_ns"]
        text.append(
            f"| {case[0]} | {case[1]} | {case[2] // 1024} | "
            f"{b['median_latency_ns'] / 1000:.2f} | {a['median_latency_ns'] / 1000:.2f} | "
            f"{speedup:.3f}×{' (unmatched)' if not matched else ''} | "
            f"{b['median_mib_per_second']:.2f} | {a['median_mib_per_second']:.2f} | "
            f"{b['discontinuities']} → {a['discontinuities']} |"
        )
    return "\n".join(text) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = compare(json.loads(args.before.read_text()), json.loads(args.after.read_text()))
    if args.output:
        args.output.write_text(result)
    print(result, end="")


if __name__ == "__main__":
    main()
