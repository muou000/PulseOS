#!/usr/bin/env python3
"""Run lmbench pipe benchmarks in PulseOS under QEMU and collect quantitative metrics.

Supports single-kernel evaluation or dual-kernel before-vs-after comparison.
"""

import argparse
from datetime import datetime
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[1]
FAULT = re.compile(r"Illegal instruction!|panicked at|Failed to (?:load shell ELF|resolve shell path)")
PROMPT = re.compile(r"(?:^|[\r\n])[^\r\n]*[#$] ?$")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

BENCH_COMMANDS = [
    ("lat_pipe", "/bin/lat_pipe -W 0 -N 3"),
    ("bw_pipe_512B", "/bin/bw_pipe -m 512 -M 2m -W 0 -N 3"),
    ("bw_pipe_4KB", "/bin/bw_pipe -m 4096 -M 2m -W 0 -N 3"),
    ("bw_pipe_16KB", "/bin/bw_pipe -m 16384 -M 2m -W 0 -N 3"),
    ("bw_pipe_64KB", "/bin/bw_pipe -m 65536 -M 2m -W 0 -N 3"),
]


def run_benchmarks(kernel: Path, image: Path, timeout: float = 300) -> dict:
    qemu = shutil.which("qemu-system-riscv64")
    if not qemu:
        raise RuntimeError("qemu-system-riscv64 executable missing")

    log_dir = REPO / "records" / ("lmbench-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "guest.log"

    command = [
        qemu,
        "-machine", "virt",
        "-kernel", str(kernel),
        "-m", "8G",
        "-nographic",
        "-smp", "8",
        "-bios", "default",
        "-drive", f"file={image},if=none,format=raw,id=x0,snapshot=on",
        "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0",
        "-no-reboot",
        "-device", "virtio-net-device,netdev=net",
        "-netdev", "user,id=net",
        "-rtc", "base=utc",
        "-monitor", "none",
        "-serial", "stdio"
    ]

    print(f"\n========================================================")
    print(f"Starting QEMU with kernel: {kernel.name}")
    print(f"========================================================")
    proc = subprocess.Popen(
        command,
        cwd=REPO,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0
    )

    results = {}
    current_idx = 0
    waiting_for_name = None
    last_sent_pos = 0
    deadline = time.monotonic() + timeout
    text = ""
    shell_ready = False

    try:
        with selectors.DefaultSelector() as selector, log_path.open("wb") as log:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                events = selector.select(timeout=min(0.2, max(0, deadline - time.monotonic())))
                if not events:
                    if proc.poll() is not None:
                        break
                    continue
                chunk = proc.stdout.read(65536)
                if not chunk:
                    break
                log.write(chunk)
                log.flush()
                chunk_str = chunk.decode("utf-8", errors="replace")
                text += chunk_str
                normalized = ANSI.sub("", text).replace("\x08", "")

                fault = FAULT.search(normalized)
                if fault:
                    err = normalized[fault.start():].splitlines()[0]
                    print(f"Fault detected: {err}")
                    break

                # Wait for initial shell prompt
                if not shell_ready:
                    if PROMPT.search(normalized):
                        shell_ready = True
                        print("Guest interactive shell ready.")
                    else:
                        continue

                # If not currently waiting for a command to finish, send the next command
                if waiting_for_name is None and current_idx < len(BENCH_COMMANDS):
                    name, cmd = BENCH_COMMANDS[current_idx]
                    print(f"Running benchmark [{current_idx + 1}/{len(BENCH_COMMANDS)}]: {name} ({cmd})")
                    last_sent_pos = len(normalized)
                    waiting_for_name = name
                    payload = f"{cmd}; echo '__BM_DONE__'\n"
                    proc.stdin.write(payload.encode())
                    proc.stdin.flush()
                    continue

                # If waiting for current command, check if standalone __BM_DONE__ appears
                if waiting_for_name is not None:
                    name, _ = BENCH_COMMANDS[current_idx]
                    sub = normalized[last_sent_pos:]
                    done_match = re.search(r"[\r\n]__BM_DONE__[\r\n]", sub)
                    if done_match:
                        block = sub[:done_match.start()].strip()
                        results[name] = block
                        print(f"  -> Completed {name}:")
                        for line in block.splitlines():
                            if "Pipe" in line or "latency" in line or "bandwidth" in line:
                                print(f"     {line}")
                        waiting_for_name = None
                        current_idx += 1
                        if current_idx >= len(BENCH_COMMANDS):
                            print(f"All benchmarks finished for {kernel.name}.")
                            break
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        if proc.stdin:
            proc.stdin.close()
        if proc.stdout:
            proc.stdout.close()

    print(f"Log written to {log_path}")
    return results


def parse_results(raw_results: dict) -> dict:
    parsed = {}
    for name, raw in raw_results.items():
        # Pipe latency: 12.3456 microseconds
        lat_match = re.search(r"Pipe latency:\s*([\d\.]+)\s*microseconds", raw, re.I)
        if lat_match:
            parsed[name] = {"value": float(lat_match.group(1)), "unit": "us", "raw": raw}
            continue
        # Pipe bandwidth: 123.45 MB/sec
        bw_match = re.search(r"Pipe bandwidth:\s*([\d\.]+)\s*MB/sec", raw, re.I)
        if bw_match:
            parsed[name] = {"value": float(bw_match.group(1)), "unit": "MB/s", "raw": raw}
            continue
        parsed[name] = {"value": None, "unit": None, "raw": raw}
    return parsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, default=REPO / "kernel-rv")
    parser.add_argument("--image", type=Path, default=REPO / "disk.img")
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--compare", nargs=2, metavar=("BEFORE_KERNEL", "AFTER_KERNEL"),
                        help="Run comparison between two kernels")
    args = parser.parse_args()

    if args.compare:
        k_before = Path(args.compare[0]).resolve()
        k_after = Path(args.compare[1]).resolve()
        for k in (k_before, k_after):
            if not k.is_file():
                parser.error(f"Kernel file not found: {k}")

        print("=== Step 1/2: Running BEFORE kernel benchmark ===")
        raw_before = run_benchmarks(k_before, args.image.resolve(), args.timeout)
        parsed_before = parse_results(raw_before)

        print("\n=== Step 2/2: Running AFTER kernel benchmark ===")
        raw_after = run_benchmarks(k_after, args.image.resolve(), args.timeout)
        parsed_after = parse_results(raw_after)

        print("\n" + "=" * 70)
        print("          LMbench Pipe Performance Quantitative Comparison")
        print("=" * 70)
        print(f"{'Benchmark':<16} | {'Before (#main)':<16} | {'After (#137)':<16} | {'Diff (%)':<12}")
        print("-" * 70)

        for name, _ in BENCH_COMMANDS:
            b_data = parsed_before.get(name, {})
            a_data = parsed_after.get(name, {})
            b_val = b_data.get("value")
            a_val = a_data.get("value")
            unit = b_data.get("unit") or a_data.get("unit") or ""

            if b_val is not None and a_val is not None:
                b_str = f"{b_val:.2f} {unit}"
                a_str = f"{a_val:.2f} {unit}"
                diff = (a_val - b_val) / b_val * 100.0
                if "lat" in name:
                    diff_str = f"{diff:+.2f}% ({'better' if diff < 0 else 'worse'})"
                else:
                    diff_str = f"{diff:+.2f}% ({'better' if diff > 0 else 'worse'})"
            elif b_val is not None:
                b_str = f"{b_val:.2f} {unit}"
                a_str = "N/A"
                diff_str = "N/A"
            elif a_val is not None:
                b_str = "N/A"
                a_str = f"{a_val:.2f} {unit}"
                diff_str = "N/A"
            else:
                b_str = "N/A"
                a_str = "N/A"
                diff_str = "N/A"

            print(f"{name:<16} | {b_str:<16} | {a_str:<16} | {diff_str:<12}")

        print("=" * 70)
    else:
        raw = run_benchmarks(args.kernel.resolve(), args.image.resolve(), args.timeout)
        parsed = parse_results(raw)

        print("\n--- Parsed Benchmark Results ---")
        for name, data in parsed.items():
            val = data["value"]
            unit = data["unit"]
            if val is not None:
                print(f"  {name:15s}: {val:10.2f} {unit}")
            else:
                print(f"  {name:15s}: FAILED or NOT FOUND (raw: {data['raw']!r})")


if __name__ == "__main__":
    main()
