#!/usr/bin/env python3
"""Run file SG syscall probes and matched microbenchmarks in a private guest."""
import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import selectors
import shutil
import statistics
import subprocess
import sys
import time
from zoneinfo import ZoneInfo

BASE = Path(__file__).resolve().parent
REPO = BASE.parents[1]
SUITES = {"bench": 1, "append": 2, "semantics": 3, "mappings": 4, "counts": 5,
          "small-bench": 6, "unmap-race": 7, "shared-position": 8}
spec = importlib.util.spec_from_file_location("shutdown_runner", REPO / "tests/init_shutdown/run.py")
shutdown = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shutdown)


def check_permissions(output):
    if re.search(r"permission denied|read-only file system|operation not permitted", output, re.I):
        raise PermissionError(output[-2000:])


def command(argv):
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check_permissions(result.stdout)
    if result.returncode:
        raise RuntimeError(f"command failed: {argv}\n{result.stdout[-4000:]}")
    return result.stdout


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def compile_guest(args, output):
    elf = output / "guest.elf"
    if args.guest_elf:
        shutil.copyfile(args.guest_elf, elf)
        return elf
    sysroot = Path(command(["rustc", "--print", "sysroot"]).strip())
    host = next(line[6:] for line in command(["rustc", "-vV"]).splitlines()
                if line.startswith("host: "))
    linker = sysroot / "lib/rustlib" / host / "bin/rust-lld"
    obj = output / "guest.o"
    compile_cmd = [
        "clang", f"--target={args.arch}-unknown-linux-gnu", "-O2", "-Wall", "-Wextra",
        "-Werror", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic",
        f"-DSG_SUITE={SUITES[args.suite]}", f"-DSG_SAMPLES={args.samples}",
        f"-DSG_ITERATIONS={args.iterations}", "-c", str(BASE / "guest.c"), "-o", str(obj),
    ]
    if args.arch == "riscv64":
        compile_cmd.append("-mno-relax")
    link_cmd = [str(linker), "-flavor", "gnu", "-static", "--no-relax",
                "-T", str(BASE / "guest.ld"), str(obj), "-o", str(elf)]
    command(compile_cmd)
    command(link_cmd)
    (output / "build.json").write_text(json.dumps({
        "compile": compile_cmd, "link": link_cmd,
        "source_sha256": sha256(BASE / "guest.c"),
        "linker_script_sha256": sha256(BASE / "guest.ld"),
        "clang": command(["clang", "--version"]).splitlines()[0],
    }, indent=2) + "\n")
    return elf


def prepare_image(image, elf, output, suite):
    private_image = output / "rootfs.img"
    command(["cp", "--reflink=auto", "--sparse=always", "--", str(image), str(private_image)])
    try:
        for request in (f'write "{elf}" /file-sg-probe', "set_inode_field /file-sg-probe mode 0100755"):
            result = command(["debugfs", "-w", "-R", request, str(private_image)])
            if re.search(r"not found|error|already exists", result, re.I):
                raise RuntimeError(result)
        if suite == "counts":
            seed = output / "cold.data"
            seed.write_bytes(bytes((i * 37 + 11) & 255 for i in range(262144)))
            for index in range(16):
                result = command(["debugfs", "-w", "-R",
                                  f'write "{seed}" /sg-cold-{index:02d}', str(private_image)])
                if re.search(r"not found|error|already exists", result, re.I):
                    raise RuntimeError(result)
    except Exception:
        private_image.unlink()
        raise
    return private_image


def benchmark_rows(lines):
    rows = []
    for line in lines:
        if not line.startswith("SG_BENCH "):
            continue
        row = dict(word.split("=", 1) for word in line.split()[1:])
        for name in ("bytes", "sample", "iterations", "elapsed_ns", "discontinuities"):
            row[name] = int(row[name])
        if row["elapsed_ns"] <= 0:
            raise ValueError(f"nonpositive benchmark interval: {line}")
        row["latency_ns"] = row["elapsed_ns"] / row["iterations"]
        row["mib_per_second"] = row["bytes"] / row["latency_ns"] * 1e9 / (1024 * 1024)
        rows.append(row)
    return rows


def summarize(rows):
    groups = {}
    for row in rows:
        groups.setdefault((row["layout"], row["operation"], row["bytes"]), []).append(row)
    summaries = []
    for (layout, operation, size), samples in sorted(groups.items()):
        latency = [row["latency_ns"] for row in samples]
        summaries.append({
            "layout": layout, "operation": operation, "bytes": size, "samples": len(samples),
            "median_latency_ns": statistics.median(latency),
            "min_latency_ns": min(latency), "max_latency_ns": max(latency),
            "median_mib_per_second": statistics.median(row["mib_per_second"] for row in samples),
            "discontinuities": sorted(set(row["discontinuities"] for row in samples)),
        })
    return summaries


def run(args, output, kernel, image, elf):
    source_hash, kernel_hash, guest_hash = sha256(image), sha256(kernel), sha256(elf)
    private_image = prepare_image(image, elf, output, args.suite)
    qemu = shutdown.qemu_command(args.arch, kernel, private_image)
    qemu = qemu[:qemu.index("-monitor")]
    if args.arch == "riscv64":
        qemu += ["-cpu", "max"]
    payload = b"exec /file-sg-probe\n"
    manifest = {
        "arch": args.arch, "suite": args.suite, "qemu": qemu,
        "qemu_version": command([qemu[0], "--version"]).splitlines()[0],
        "kernel_sha256": kernel_hash, "guest_sha256": guest_hash,
        "source_image_sha256": source_hash, "shell": payload.decode(),
    }
    (output / "command.json").write_text(json.dumps(manifest, indent=2) + "\n")
    proc = None
    text, sent, failed = "", False, False
    errors = []
    deadline = time.monotonic() + args.timeout
    try:
        proc = subprocess.Popen(qemu, cwd=REPO, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        with selectors.DefaultSelector() as selector, (output / "guest.log").open("wb") as log:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if not selector.select(timeout=0.2):
                    if proc.poll() is not None:
                        break
                    continue
                chunk = proc.stdout.read(65536)
                if not chunk:
                    proc.wait(timeout=5)
                    break
                log.write(chunk)
                log.flush()
                text += chunk.decode("utf-8", errors="replace")
                check_permissions(text)
                normalized = shutdown.ANSI.sub("", text).replace("\x08", "")
                if not failed and (shutdown.FAULT.search(normalized) or "SG_FAIL " in normalized):
                    errors.append("kernel fault or guest assertion failed")
                    failed = True
                    deadline = min(deadline, time.monotonic() + 1)
                if not sent and shutdown.PROMPT.search(normalized):
                    proc.stdin.write(payload)
                    proc.stdin.flush()
                    sent = True
            if proc.poll() is None:
                errors.append("QEMU did not exit normally before deadline")
            elif proc.returncode != 0:
                errors.append(f"QEMU exited {proc.returncode}")
    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            proc.stdin.close()
            proc.stdout.close()
        private_image.unlink()
    lines = shutdown.ANSI.sub("", text).replace("\r", "").splitlines()
    if "SG_PASS" not in lines:
        errors.append("missing final assertion marker")
    if not any("filesystem writeback complete; system power transition: PowerOff" in line
               for line in lines):
        errors.append("missing completed shutdown")
    if sha256(image) != source_hash:
        errors.append("source image changed")
    rows = benchmark_rows(lines)
    cases = {"bench": 16, "small-bench": 4}.get(args.suite)
    if cases and len(rows) != cases * args.samples:
        errors.append(f"benchmark matrix incomplete: {len(rows)} rows")
    result = {
        **manifest, "passed_assertions": sum(line.startswith("SG_OK ") for line in lines),
        "errors": errors, "measurements": rows, "summary": summarize(rows),
        "counts": [dict(word.split("=", 1) for word in line.split()[1:])
                   for line in lines if line.startswith("SG_COUNT ")],
    }
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"{'FAIL' if errors else 'PASS'} {args.arch} {args.suite}: {output / 'result.json'}")
    for line in lines:
        if line.startswith(("SG_FAIL ", "SG_LAYOUT ", "SG_OK ")):
            print(line)
    for error in errors:
        print(error)
    return bool(errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=SUITES, default="bench")
    parser.add_argument("--arch", choices=("riscv64", "loongarch64"), default="riscv64")
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--guest-elf", type=Path, help="reuse the exact saved baseline probe")
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--iterations", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()
    if args.samples < 1 or args.iterations < 1:
        parser.error("samples and iterations must be positive")
    stamp = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y%m%d-%H%M%S-%f")
    output = (args.log_dir or REPO / "records" /
              f"file-sg-136-{args.arch}-{args.suite}-{stamp}").resolve()
    output.mkdir(parents=True, exist_ok=False)
    elf = compile_guest(args, output)
    if args.build_only:
        print(elf)
        return 0
    kernel = (args.kernel or REPO / ("kernel-rv" if args.arch == "riscv64" else "kernel-la")).resolve()
    image = (args.image or REPO / ("disk.img" if args.arch == "riscv64" else "disk-la.img")).resolve()
    return run(args, output, kernel, image, elf)


if __name__ == "__main__":
    sys.exit(main())
