#!/usr/bin/env python3
"""Synthetic perf.data reader experiment for #181; does not record guest samples.

Requires Python 3, clang with target backends, GNU readelf, LLD, and Linux perf.
All generated ELF/data/log files go into --output-dir (a new temp dir by default).
Wire layout follows Linux v6.12 include/uapi/linux/perf_event.h and
 tools/perf/{util/header.h,util/header.c}; actual reader version is recorded.
"""

import argparse
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile


EVENT_ID = 1
SAMPLE_TYPE = 1 | 2 | 4 | 32 | 128 | 256 | (1 << 16)
KERNEL, USER = 1, 2
CONTEXT_KERNEL = (1 << 64) - 128
CONTEXT_USER = (1 << 64) - 512
PERIOD = 10_000_000
TARGETS = {
    "x86_64": ("x86_64-linux-gnu", 0xFFFFFFFF81000000),
    "riscv64": ("riscv64-linux-gnu", 0xFFFFFFFF80200000),
    "loongarch64": ("loongarch64-linux-gnu", 0x9000000090000000),
}


def pack(fmt, *values):
    return struct.pack("<" + fmt, *values)


def run(command, *, cwd=None):
    completed = subprocess.run([str(x) for x in command], cwd=cwd, text=True,
                               capture_output=True, env={**os.environ, "LC_ALL": "C",
                                                         "DEBUGINFOD_URLS": ""})
    if completed.returncode:
        raise RuntimeError(f"{' '.join(map(str, command))}: {completed.returncode}\n"
                           + completed.stdout + completed.stderr)
    return completed.stdout, completed.stderr


def record(kind, misc, payload):
    size = 8 + len(payload)
    if size > 65535 or size % 8:
        raise ValueError(f"invalid record size {size}")
    return pack("IHH", kind, misc, size) + payload


def padded_string(text, prefix_size=0):
    value = text.encode() + b"\0"
    return value + bytes(-(prefix_size + len(value)) % 8)


def trailer(pid, time, cpu=0):
    # Unlike SAMPLE, IDENTIFIER is last in sample_id_all trailers.
    return pack("IIQIIQ", pid, pid, time, cpu, 0, EVENT_ID)


def build_elf(args, directory, arch, kernel=False):
    target, kernel_base = TARGETS[arch]
    name = "kernel" if kernel else "user"
    source = directory / (name + ".c")
    source.write_text(
        f"__attribute__((noinline)) int {name}_leaf(int n) {{ return n + 1; }}\n"
        f"__attribute__((noinline)) int {name}_parent(int n) {{ return {name}_leaf(n) + 2; }}\n"
        f"int _start(void) {{ return {name}_parent(1); }}\n")
    obj = directory / (name + ".o")
    command = [args.clang, "--target=" + target, "-O1", "-g", "-ffreestanding",
               "-fno-pic", "-fno-pie", "-fno-stack-protector", "-c", source, "-o", obj]
    if arch == "riscv64":
        command += ["-mcmodel=medany"]
    run(command)
    elf = directory / "symfs" / ("boot/vmlinux" if kernel else "usr/bin/fixture")
    elf.parent.mkdir(parents=True, exist_ok=True)
    link = [args.linker]
    if Path(args.linker).name == "rust-lld":
        link += ["-flavor", "gnu"]
    base = kernel_base if kernel else 0x400000
    run(link + ["--build-id=sha1", "-e", "_start", "-Ttext=" + hex(base),
                "--defsym=_text=" + hex(base), obj, "-o", elf])
    symbols, _ = run([args.readelf, "-Ws", elf])
    table = {}
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].endswith(":"):
            try:
                table[fields[7]] = int(fields[1], 16)
            except ValueError:
                pass
    notes, _ = run([args.readelf, "-n", elf])
    build_id = bytes.fromhex(re.search(r"Build ID: ([0-9a-f]+)", notes).group(1))
    raw = elf.read_bytes()
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", raw, 54)
    for i in range(phnum):
        ptype, flags, offset, vaddr, _, _, memsz, _ = struct.unpack_from(
            "<IIQQQQQQ", raw, phoff + i * phentsize)
        if ptype == 1 and flags & 1:
            return {"path": elf, "symbols": table, "build_id": build_id,
                    "addr": vaddr, "length": memsz, "pgoff": offset}
    raise RuntimeError("no executable ELF segment")


def make_data(path, arch, user, kernel):
    events = []
    timestamp = 1_000_000_000

    def emit(kind, misc, payload, pid=100, cpu=0):
        nonlocal timestamp
        events.append(record(kind, misc, payload + trailer(pid, timestamp, cpu)))
        timestamp += 1_000_000

    def comm(pid, text):
        emit(3, USER, pack("II", pid, pid) + padded_string(text), pid)

    # Existing task and kernel mappings precede samples. Kernel pgoff is a
    # runtime reference-symbol address, unlike the user file-byte offset.
    comm(100, "parent")
    emit(1, USER, pack("IIQQQ", 100, 100, user["addr"], user["length"], user["pgoff"])
         + padded_string("/usr/bin/fixture"))
    emit(1, KERNEL, pack("IIQQQ", 0, 0, kernel["addr"], kernel["length"],
                         kernel["symbols"]["_text"])
         + padded_string("[kernel.kallsyms]_text"), 0)
    # Child inherits its executable mapping through FORK; no duplicate MMAP.
    emit(7, USER, pack("IIIIQ", 101, 100, 101, 100, timestamp), 101)
    comm(101, "child")

    def sample(pid, mode, cpu, chain):
        nonlocal timestamp
        # IDENTIFIER, IP, TID, TIME, CPU, PERIOD, CALLCHAIN in ABI order.
        ip = chain[1]
        payload = pack("QQIIQIIQQ", EVENT_ID, ip, pid, pid, timestamp,
                       cpu, 0, PERIOD, len(chain)) + pack("Q" * len(chain), *chain)
        events.append(record(9, mode, payload))
        timestamp += PERIOD

    us = user["symbols"]
    ks = kernel["symbols"]
    sample(100, USER, 0, [CONTEXT_USER, us["user_leaf"], us["user_parent"]])
    sample(101, USER, 1, [CONTEXT_USER, us["user_leaf"], us["user_parent"]])
    sample(101, KERNEL, 1, [CONTEXT_KERNEL, ks["kernel_leaf"], ks["kernel_parent"],
                          CONTEXT_USER, us["user_parent"]])
    emit(2, USER, pack("QQ", EVENT_ID, 2), 101, 1)
    emit(4, USER, pack("IIIIQ", 101, 100, 101, 100, timestamp), 101, 1)
    data = b"".join(events)

    # PERF_ATTR_SIZE_VER0=64 suffices: flags, sample_type, period, no regs dump.
    attr = pack("IIQQQQQIIQ", 1, 64, 0, PERIOD, SAMPLE_TYPE, 0,
                (1 << 18), 0, 0, 0)
    assert len(attr) == 64
    ids_offset = 104
    attrs_offset = ids_offset + 8
    data_offset = attrs_offset + len(attr) + 16
    attrs = attr + pack("QQ", ids_offset, 8)

    def build_id_record(image, misc, filename):
        # HEADER_BUILD_ID's 24B union: data[20],size,reserved; MMAP2 differs.
        payload = pack("I", 0xFFFFFFFF) + image["build_id"] + pack("BBH", 20, 0, 0)
        payload += padded_string(filename, prefix_size=8 + len(payload))
        return record(67, misc | (1 << 15), payload)

    build_ids = build_id_record(user, USER, "/usr/bin/fixture")
    build_ids += build_id_record(kernel, KERNEL, "[kernel.kallsyms]")
    arch_bytes = arch.encode() + b"\0"
    features = [(2, build_ids), (6, pack("I", len(arch_bytes)) + arch_bytes)]
    feature_offset = data_offset + len(data) + len(features) * 16
    sections = b""
    for _, content in features:
        sections += pack("QQ", feature_offset, len(content))
        feature_offset += len(content)
    header = b"PERFILE2" + pack("QQQQQQQQQQQQ", 104, len(attrs), attrs_offset,
                               len(attrs), data_offset, len(data), 0, 0,
                               sum(1 << bit for bit, _ in features), 0, 0, 0)
    assert len(header) == 104
    path.write_bytes(header + pack("Q", EVENT_ID) + attrs + data + sections
                     + b"".join(content for _, content in features))
    return {"samples": 3, "lost": 2, "period_total": 3 * PERIOD,
            "user_pgoff": user["pgoff"], "data_bytes": len(data)}


def check_arch(args, root, arch):
    directory = root / arch
    directory.mkdir(parents=True, exist_ok=True)
    user = build_elf(args, directory, arch)
    kernel = build_elf(args, directory, arch, kernel=True)
    path = directory / "perf.data"
    result = make_data(path, arch, user, kernel)
    common = ["-i", path, "--symfs", directory / "symfs", "--vmlinux", kernel["path"]]
    cache = directory / "buildid-cache"
    cache.mkdir(exist_ok=True)
    perf = [args.perf, "--buildid-dir", cache]
    commands = {
        "script": [*perf, "script", *common],
        "report": [*perf, "report", *common, "--stdio", "--no-children",
                   "--show-nr-samples", "--show-total-period", "--percent-limit", "0"],
        "buildid": [*perf, "buildid-list", "-i", path],
        "dump": [*perf, "script", *common, "-D"],
    }
    outputs = {}
    for name, command in commands.items():
        stdout, stderr = run(command)
        (directory / (name + ".stdout")).write_text(stdout)
        (directory / (name + ".stderr")).write_text(stderr)
        outputs[name] = stdout
    for symbol in ("user_leaf", "user_parent", "kernel_leaf", "kernel_parent"):
        assert symbol in outputs["script"], f"{arch}: missing symbol {symbol}"
    assert "parent" in outputs["script"] and "child" in outputs["script"]
    assert outputs["script"].count("cpu-clock:") == 3, f"{arch}: incorrect sample count"
    assert "[unknown]" not in outputs["script"], f"{arch}: unresolved symbols"
    assert "Samples: 3" in outputs["report"], f"{arch}: wrong report sample count"
    assert "30000000" in outputs["report"], f"{arch}: wrong total period"
    for image in (user, kernel):
        assert image["build_id"].hex() in outputs["buildid"]
    for name in ("PERF_RECORD_MMAP", "PERF_RECORD_COMM", "PERF_RECORD_FORK",
                 "PERF_RECORD_EXIT", "PERF_RECORD_LOST"):
        assert name in outputs["dump"], f"{arch}: missing record {name}"
    assert "lost:2" in outputs["dump"].lower(), f"{arch}: wrong lost count"
    assert user["pgoff"] > 0
    # Missing user ELF must remain unresolved, even with a known build-id.
    # Isolate the cache and disable debuginfod so this cannot reuse host data.
    empty_symfs = directory / "empty-symfs"
    empty_symfs.mkdir(exist_ok=True)
    negative = [*perf, "script", "-i", path, "--symfs", empty_symfs,
                "--vmlinux", kernel["path"]]
    stdout, stderr = run(negative)
    (directory / "missing-elf.stdout").write_text(stdout)
    (directory / "missing-elf.stderr").write_text(stderr)
    assert "user_leaf" not in stdout and "user_parent" not in stdout
    assert "[unknown]" in stdout and "kernel_leaf" in stdout
    commands["missing_elf"] = negative
    result["missing_elf"] = "PASS: user addresses stay unresolved"
    result["status"] = "PASS"
    result["commands"] = {k: [str(x) for x in v] for k, v in commands.items()}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--perf", default="perf")
    parser.add_argument("--clang", default="clang-18")
    parser.add_argument("--linker", default="rust-lld")
    parser.add_argument("--readelf", default="readelf")
    parser.add_argument("--arch", action="append", choices=TARGETS)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    root = (args.output_dir or Path(tempfile.mkdtemp(prefix="pulse-perf-data-"))).resolve()
    root.mkdir(parents=True, exist_ok=True)
    version, _ = run([args.perf, "version"])
    linker_version = [args.linker]
    if Path(args.linker).name == "rust-lld":
        linker_version += ["-flavor", "gnu"]
    toolchain = {}
    for name, command in {"clang": [args.clang, "--version"],
                          "readelf": [args.readelf, "--version"],
                          "linker": [*linker_version, "--version"]}.items():
        stdout, _ = run(command)
        toolchain[name] = stdout.splitlines()[0]
    results = {"reader": version.strip(), "specification": "Linux v6.12",
               "toolchain": toolchain,
               "kind": "synthetic reader experiment, not guest sampling", "architectures": {}}
    print(f"Output: {root}\nReader: {version.strip()}", flush=True)
    for arch in args.arch or TARGETS:
        results["architectures"][arch] = check_arch(args, root, arch)
        print(f"{arch}: PASS", flush=True)
    (root / "results.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
