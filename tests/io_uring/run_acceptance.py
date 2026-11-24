#!/usr/bin/env python3
"""Dual-architecture acceptance runner for PulseOS io_uring (#240).

Modes:
  guest-checks : Verify boot-time io_uring frame refcount & teardown probes.
  functional   : Verify LTP io_uring01..04, 54/54 liburing-2.9, smp_stress, meminfo.
  sqpoll       : Verify the shared-ring SQPOLL protocol and pinned sqpoll-sleep.t.
  sqpoll-reserved : Observe SQ consumption on a reserved CPU (guest-checks kernel).
  dedicated-ring : Exercise SQPOLL, inline reads, native poll and worker I/O on one reserved CPU.
  future-cpu   : Check native poll placement and ordinary-ring progress (guest-checks kernel).
  worker-cpu   : Check Path 3 placement (guest-checks kernel with worker-scheduler.patch).
  worker-limits: Saturate the shared pool and verify quotas and cross-ring ordering (guest-checks).
  fio          : Verify syscall-count reduction and ext4 O_DIRECT/cached fio-3.39.
  bpf          : Capture paired cpu+sched bpf-record sessions, run bpf-analyzer
                 and scripts/perf_pipeline.py (native perf + FlameGraph SVG).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parent
REPO = BASE.parents[1]

sys.path.insert(0, str(REPO / "tests/bpf_record"))


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helpers = _load_module("bpf_smoke_helpers", REPO / "tests/bpf_smoke/run.py")
helpers.BASE = REPO / "tests/bpf_record"
bpf_rec = _load_module("bpf_record_runner", REPO / "tests/bpf_record/run.py")
ARCHES = helpers.ARCHES

READY_REGEX = r"(?:^|[\r\n])[^\r\n]*[#$] ?$"
PANIC_RE = re.compile(r"panicked at|kernel panic|panic:|fatal trap", re.I)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

GUEST_CHECK_MARKERS = (
    "[IO_URING_RSRC_GUEST] PinnedUserBuffers balance & direct copy: PASS",
    "[IO_URING_RSRC_GUEST] FixedBufferRegistry pin/inflight/memlock accounting: PASS",
    "[IO_URING_RSRC_GUEST] FixedFileRegistry sparse slots & partial update: PASS",
    "[IO_URING_RSRC_GUEST] Inflight munmap + close five-step teardown frame balance: PASS",
    "[IO_URING_RSRC_GUEST] Fixed resources & frame refcount checks: PASS",
    "WORKER_OVERLAPPING_FINISH_PASS",
)

BPF_WORKLOADS: dict[str, dict[str, str | int]] = {
    "cached_psync": {
        "warm": 1,
        "file": "/root/fio-uring-cached",
        "size": "4m",
        "args": "--direct=0 --rw=read --ioengine=psync --iodepth=1",
    },
    "cached_uring_qd32": {
        "warm": 1,
        "file": "/root/fio-uring-cached",
        "size": "4m",
        "args": "--direct=0 --rw=read --ioengine=io_uring --iodepth=32 --iodepth_batch_submit=32 --iodepth_batch_complete_min=1 --iodepth_batch_complete_max=32 --fixedbufs=1 --registerfiles=1",
    },
    "direct_psync": {
        "warm": 0,
        "file": "/root/fio-uring-bench",
        "size": "64m",
        "args": "--direct=1 --rw=randread --ioengine=psync --iodepth=1",
    },
    "direct_uring_qd16": {
        "warm": 0,
        "file": "/root/fio-uring-bench",
        "size": "64m",
        "args": "--direct=1 --rw=randread --ioengine=io_uring --iodepth=16 --iodepth_batch_submit=8 --iodepth_batch_complete_min=1 --iodepth_batch_complete_max=8 --fixedbufs=1 --registerfiles=1",
    },
}


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text).replace("\r", "")


def create_run_dir(mode: str, arch: str, run_dir: Path | None) -> Path:
    if run_dir is not None:
        run = helpers.scoped(run_dir)
        if run.exists():
            raise ValueError(f"run directory already exists: {run}")
        run.mkdir(parents=True, exist_ok=False)
        return run
    stamp = time.strftime("%Y%m%d-%H%M%S")
    token = os.urandom(3).hex()
    run = helpers.scoped(helpers.BASE / "runs" / f"issue-240-{mode}-{arch}-{stamp}-{token}")
    run.mkdir(parents=True, exist_ok=False)
    return run


def stage_dir_for(arch: str) -> Path:
    return REPO / "target/iouring-tests" / arch


def install_tree_to_image(image_copy: Path, source: Path, dest: str) -> None:
    # Diagnostics also call these helpers directly. Only inject into a run copy.
    helpers.scoped(image_copy)
    installer = REPO / "scripts/install_to_rootfs.sh"
    subprocess.run(
        [str(installer), str(image_copy), str(source), dest],
        cwd=REPO,
        check=True,
    )


def install_verified_file(image_copy: Path, source: Path, dest: str, run: Path) -> None:
    install_tree_to_image(image_copy, source, dest)
    dumped = run / f".verify-{os.getpid()}-{source.name}"
    if dumped.exists():
        dumped.unlink()
    helpers.debugfs(image_copy, f'dump {dest} "{dumped}"')
    try:
        if helpers.digest(dumped) != helpers.digest(source):
            raise ValueError(f"injected artifact bytes differ at {dest}")
    finally:
        if dumped.exists():
            dumped.unlink()


def install_script(image_copy: Path, script_text: str, run: Path, dest: str = "/opt/io_uring/guest_job.sh") -> Path:
    local = run / Path(dest).name
    local.write_text(script_text, encoding="utf-8")
    os.chmod(local, 0o755)
    install_tree_to_image(image_copy, local, dest)
    return local


def run_guest_job(
    *,
    arch: str,
    kernel: Path,
    image_copy: Path,
    run: Path,
    script_text: str,
    boot_timeout: float,
    timeout: float,
    on_output=None,
) -> tuple[str, int]:
    install_script(image_copy, script_text, run)
    token = run.name.rsplit("-", 1)[-1]
    shell_cmd = (
        f"ulimit -c 0; sh /opt/io_uring/guest_job.sh; "
        f"status=$?; printf '\\nBPF_HOST_EXIT {token} %s\\n' \"$status\""
    )
    argv = bpf_rec.qemu_command(arch, kernel, image_copy)
    print(f"QEMU: {shlex.join(argv)}", flush=True)
    raw_text, qemu_exit, reason = helpers.drive_guest(
        argv,
        shell_cmd,
        token,
        run / "guest.log",
        READY_REGEX,
        boot_timeout,
        timeout,
        on_output=on_output,
    )
    clean = strip_ansi(raw_text)
    if PANIC_RE.search(clean):
        raise RuntimeError(f"Kernel panic or fatal trap detected in {run / 'guest.log'}")
    if reason:
        raise RuntimeError(f"Guest session aborted ({reason}); see {run / 'guest.log'}")
    matches = re.findall(rf"(?m)^BPF_HOST_EXIT {re.escape(token)} ([0-9]+)\s*$", clean)
    if len(matches) != 1 or int(matches[0]) != 0:
        raise RuntimeError(
            f"Unexpected guest shell exit marker matches={matches!r} qemu_exit={qemu_exit}"
        )
    return clean, qemu_exit


def extract_block(text: str, begin_marker: str, end_marker: str) -> str:
    begin = text.find(begin_marker)
    if begin < 0:
        raise ValueError(f"Missing begin marker: {begin_marker}")
    after = begin + len(begin_marker)
    end = text.find(end_marker, after)
    if end < 0:
        raise ValueError(f"Missing end marker: {end_marker}")
    return text[after:end].strip()


def parse_meminfo(block: str) -> dict[str, int]:
    parsed: dict[str, int] = {}
    for line in block.splitlines():
        m = re.match(r"^([A-Za-z0-9_()]+):\s+(\d+)\s*kB", line.strip())
        if m:
            parsed[m.group(1)] = int(m.group(2))
    return parsed


def run_guest_checks(args: argparse.Namespace, run: Path, kernel: Path, image_copy: Path) -> dict:
    clean, qemu_exit = run_guest_job(
        arch=args.arch,
        kernel=kernel,
        image_copy=image_copy,
        run=run,
        script_text="true\n",
        boot_timeout=args.boot_timeout,
        timeout=args.timeout,
    )
    missing = [m for m in GUEST_CHECK_MARKERS if m not in clean]
    if missing:
        raise RuntimeError(f"Missing guest-checks markers: {missing}")
    summary = {
        "mode": "guest-checks",
        "arch": args.arch,
        "qemu_exit": qemu_exit,
        "markers": list(GUEST_CHECK_MARKERS),
        "passed": True,
    }
    (run / f"guest-checks-{args.arch}.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def run_sqpoll(args: argparse.Namespace, run: Path, kernel: Path, image_copy: Path) -> dict:
    stage = stage_dir_for(args.arch)
    install_verified_file(image_copy, stage / "bin/sqpoll", "/opt/io_uring/sqpoll", run)
    install_verified_file(
        image_copy, stage / "liburing-tests/sqpoll-sleep.t", "/opt/io_uring/sqpoll-sleep.t", run
    )
    clean, qemu_exit = run_guest_job(
        arch=args.arch,
        kernel=kernel,
        image_copy=image_copy,
        run=run,
        script_text="""#!/bin/sh
set -e
/opt/io_uring/sqpoll
/opt/io_uring/sqpoll-sleep.t
echo 'SQPOLL liburing-2.9 sqpoll-sleep.t PASS'
""",
        boot_timeout=args.boot_timeout,
        timeout=args.timeout,
    )
    markers = [
        "SQPOLL affinity requested=1 running=1",
        "SQPOLL active batches=8 unique=32 ordinary_reads=16 fixed_reads=16 enters=0",
        "SQPOLL_RESULT PASS",
        "SQPOLL liburing-2.9 sqpoll-sleep.t PASS",
    ]
    for marker in markers:
        if marker not in clean:
            raise RuntimeError(f"Missing SQPOLL evidence: {marker}")
    summary = {"mode": "sqpoll", "arch": args.arch, "qemu_exit": qemu_exit, "markers": markers, "passed": True}
    (run / f"sqpoll-{args.arch}.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def run_reserved_probe(args: argparse.Namespace, run: Path, kernel: Path, image_copy: Path,
                       option: str, on_output=None, service_cpus: str = "7",
                       reserved_cpus: str = "6-7") -> tuple[str, int]:
    for name, cpus in (("pulse-kernel-cpus", reserved_cpus), ("pulse-sqpoll-cpus", service_cpus)):
        config = run / name
        config.write_text(cpus + "\n")
        install_verified_file(image_copy, config, f"/etc/{name}", run)
    probe = stage_dir_for(args.arch) / "bin/sqpoll"
    install_verified_file(image_copy, probe, "/opt/io_uring/sqpoll", run)
    return run_guest_job(
        arch=args.arch, kernel=kernel, image_copy=image_copy, run=run,
        script_text=f"#!/bin/sh\nexec /opt/io_uring/sqpoll {option}\n",
        boot_timeout=args.boot_timeout, timeout=args.timeout, on_output=on_output,
    )


def run_dedicated_ring(args: argparse.Namespace, run: Path, kernel: Path, image_copy: Path) -> dict:
    from dedicated_ring import PendingPoll, check_dedicated_ring

    provenance = _load_module("build_provenance", REPO / "scripts/build_provenance.py")
    manifest = kernel.with_suffix(".elf.provenance.json")
    build = provenance.verify_manifest(manifest, kernel.with_suffix(".elf"), kernel)
    shutil.copyfile(manifest, run / "kernel.provenance.json")
    gate = PendingPoll()
    clean, qemu_exit = run_reserved_probe(
        args, run, kernel, image_copy, "--dedicated-ring",
        lambda text, stdin: gate(strip_ansi(text), stdin), reserved_cpus="7",
    )
    summary = {
        "mode": "dedicated-ring", "arch": args.arch, "qemu_exit": qemu_exit,
        "kernel_commit": build["source"]["commit"],
        "kernel_tree_sha256": build["source"]["tree_sha256"],
        "boot_sha256": helpers.digest(kernel),
        "build": build["configuration"]["values"],
        "qemu": bpf_rec.qemu_command(args.arch, kernel, image_copy),
        "guest": "/opt/io_uring/sqpoll --dedicated-ring",
        **check_dedicated_ring(clean),
    }
    (run / f"dedicated-ring-{args.arch}.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def run_worker_cpu(args: argparse.Namespace, run: Path, kernel: Path, image_copy: Path) -> dict:
    from worker_cpu import WorkerGates, check_worker_cpu

    gates = WorkerGates()
    clean, qemu_exit = run_reserved_probe(args, run, kernel, image_copy, "--reserved-workers",
                                         lambda text, stdin: gates(strip_ansi(text), stdin))
    return {"mode": "worker-cpu", "arch": args.arch, "qemu_exit": qemu_exit, **check_worker_cpu(clean)}


def run_worker_limits(args: argparse.Namespace, run: Path, kernel: Path, image_copy: Path) -> dict:
    from worker_cpu import JOB, check_worker_limits

    released = False

    def signal_full(log, stdin):
        nonlocal released
        trace = log.partition("WORKER_LIMITS_BEGIN")[2]
        if not released and sum(m["phase"] == "start" for m in JOB.finditer(trace)) >= 16:
            stdin.write(b"full\n")
            stdin.flush()
            released = True

    clean, qemu_exit = run_reserved_probe(args, run, kernel, image_copy, "--worker-limits",
                                          signal_full, service_cpus="6-7")
    return {"mode": "worker-limits", "arch": args.arch, "qemu_exit": qemu_exit, **check_worker_limits(clean)}


def run_sqpoll_reserved(args: argparse.Namespace, run: Path, kernel: Path, image_copy: Path) -> dict:
    clean, qemu_exit = run_reserved_probe(args, run, kernel, image_copy, "--reserved-cpu")
    trace = extract_block(clean, "SQPOLL user mask=0x3f bind7=EINVAL producer=0",
                          "SQPOLL reserved NEED_WAKEUP resumed user_data=33")
    active, marker, resumed = trace.partition("SQPOLL reserved active batches=8 unique=32 enters=0")
    if not marker:
        raise ValueError("Missing active NOP completion and enter count")
    consumes = re.findall(r"SQPOLL consume ring=(\d+) user_data=(\d+) cpu=(\d+)", trace)
    if not consumes:
        raise ValueError("Missing SQE consumption trace (build with guest-checks)")
    ring = consumes[0][0]
    if consumes != [(ring, str(i), "7") for i in range(34)]:
        raise ValueError(f"Expected NOPs 0..33 on one ring on CPU 7, saw {consumes}")

    # Warmup is the last enter before active NOPs. The next wake acknowledges
    # NEED_WAKEUP on an empty SQ, before the producer publishes ID 33.
    enter = f"SQPOLL enter ring={ring} wakeup=true wait=false"
    first_active = active.index(f"SQPOLL consume ring={ring} user_data=1 cpu=7")
    if active.count("SQPOLL enter ring=") != 1 or enter not in active[:first_active]:
        raise ValueError("Expected only the warmup enter before the active NOPs")
    last_nop = resumed.index(f"SQPOLL consume ring={ring} user_data=33 cpu=7")
    if enter not in resumed[:last_nop]:
        raise ValueError("Expected a wakeup before consuming the resumed NOP")
    return {"mode": "sqpoll-reserved", "arch": args.arch, "qemu_exit": qemu_exit,
            "ring": int(ring), "cpu": 7, "active_nops": 32, "active_enters": 0,
            "resumed_user_data": 33, "passed": True}


def run_future_cpu(args: argparse.Namespace, run: Path, kernel: Path, image_copy: Path) -> dict:
    clean, qemu_exit = run_reserved_probe(args, run, kernel, image_copy, "--reserved-futures")
    return {**check_future_cpu(clean), "arch": args.arch, "qemu_exit": qemu_exit}


def check_future_cpu(clean: str) -> dict:
    remote = re.findall(r"\[IO_URING_CPU_GUEST\] first poll submit=(\d+) target=(\d+) cpu=(\d+) task=(\S+)", clean)
    if remote != [("0", "7", "7", "async-exec-cpu-7")]:
        raise ValueError(f"Expected one first poll dispatched from CPU 0 to the CPU 7 driver: {remote}")
    _, begin, workload = clean.partition("FUTURE_CPU_BEGIN")
    trace, _, native_io = workload.partition("FUTURE_CPU_NATIVE_IO_BEGIN")
    if not begin or "FUTURE_CPU CQ order, unique completions, close and writer release PASS" not in trace:
        raise ValueError("Missing guest completion checks")
    competition = re.search(r"FUTURE_CPU wake_cpu=0 GETEVENTS_cpu=1 calls=([1-9]\d*)", trace)
    if not competition:
        raise ValueError("Missing cross-CPU wake and ordinary GETEVENTS")
    reserved = re.search(r"SQPOLL consume ring=(\d+) user_data=1 cpu=7\b", trace)
    if not reserved:
        raise ValueError("Missing reserved SQ consumption (build with guest-checks)")
    io_ring = re.search(r"SQPOLL consume ring=(\d+) user_data=203 cpu=7\b", native_io)
    if not io_ring or "FUTURE_CPU socket recv, timeout and shared offset write/read PASS" not in native_io:
        raise ValueError("Missing native socket, timer or file results")
    ring = reserved[1]
    polls = re.findall(r"io_uring poll ring=(\d+) req=(\d+) phase=(first|resume) cpu=(\d+) "
                       r"result=(pending|ready) task=(\S+)", workload)
    reserved_ids = {ring, io_ring[1]}
    outside = [record for record in polls if record[0] in reserved_ids and
               (record[3] != "7" or record[5] != "async-exec-cpu-7")]
    if outside:
        raise ValueError(f"Reserved request polled outside its CPU 7 driver: {outside}")
    dedicated = [(req, phase, cpu, result) for rid, req, phase, cpu, result, _ in polls if rid == ring]
    # User data on this ring equals the request ordinal. 3 and 5 run on Path 3,
    # 9 cancels 7 synchronously, and every other request must receive one first poll.
    first = [int(req) for req, phase, _, _ in dedicated if phase == "first"]
    if sorted(first) != [1, 2, 4, 6, 7, 8, 10, 11]:
        raise ValueError(f"Missing or duplicate first polls on ring {ring}: {first}")
    for req in ("1", "7", "10"):
        if (req, "first", "7", "pending") not in dedicated:
            raise ValueError(f"Reserved request {req} did not wait before wake/cancel/close")
    if ("1", "resume", "7", "ready") not in dedicated:
        raise ValueError("Reserved request 1 did not resume after the CPU 0 pipe write")

    workers = re.findall(rf"io_uring native submit ring={ring} req=(4|6) cpu=(\d+) task=(io-uring-wk-\d+)", trace)
    if sorted((req, cpu) for req, cpu, _ in workers) != [("4", "7"), ("6", "7")]:
        raise ValueError(f"Expected link/drain predecessors to dispatch successors from CPU 7: {workers}")
    ordinary = {rid for rid, *_ in polls} - reserved_ids
    if len(ordinary) != 1:
        raise ValueError(f"Expected one ordinary ring alongside reserved ring {ring}, got {ordinary}")
    ordinary_id = ordinary.pop()
    for req in ("1", "2"):
        events = [(phase, result, task) for rid, r, phase, _, result, task in polls
                  if rid == ordinary_id and r == req]
        if not any(p == "first" and res == "pending" for p, res, _ in events):
            raise ValueError(f"Ordinary request {req} did not wait")
        if not any(p == "resume" and res == "ready" and (req == "1" or re.fullmatch(r"async-exec-\d+", task))
                   for p, res, task in events):
            raise ValueError(f"Missing ordinary request {req} progress: {events}")
    io_polls = [(req, phase, cpu, result) for rid, req, phase, cpu, result, _ in polls if rid == io_ring[1]]
    if not any(req == "3" and phase == "first" for req, phase, _, _ in io_polls):
        raise ValueError("Missing shared-offset native write poll")
    for req in ("1", "2"):
        if (req, "first", "7", "pending") not in io_polls or (req, "resume", "7", "ready") not in io_polls:
            raise ValueError(f"Native RECV/TIMEOUT did not wait and resume: {io_polls}")
    return {"mode": "future-cpu",
            "ring": int(ring), "target": 7, "first": len(first), "resume": len(dedicated) - len(first),
            "polls": dedicated, "outside": len(outside), "worker_submissions": workers, "ordinary_ring": int(ordinary_id),
            "remote_first_poll": {"submit_cpu": int(remote[0][0]), "poll_cpu": int(remote[0][2])},
            "getevents_calls": int(competition[1]), "io_ring": int(io_ring[1]),
            "io_polls": io_polls, "passed": True}


def run_functional(args: argparse.Namespace, run: Path, kernel: Path, image_copy: Path) -> dict:
    stage = stage_dir_for(args.arch)
    liburing_dir = stage / "liburing-tests"
    runner_sh = stage / "run_all.sh"
    smp_stress = stage / "bin/smp_stress"
    fio_bin = stage / "bin/fio"
    for p in (liburing_dir, runner_sh, smp_stress, fio_bin):
        if not p.exists():
            raise FileNotFoundError(f"Missing staged artifact {p}; build tests & probes first")

    install_tree_to_image(image_copy, liburing_dir, "/opt/io_uring/liburing-tests")
    install_tree_to_image(image_copy, runner_sh, "/opt/io_uring/run_all.sh")
    install_verified_file(image_copy, smp_stress, "/opt/io_uring/smp_stress", run)
    install_verified_file(image_copy, fio_bin, "/usr/bin/fio", run)

    guest_script = """#!/bin/sh
echo "=== MEMINFO_BEFORE_START ==="
cat /proc/meminfo
echo "=== MEMINFO_BEFORE_END ==="

overall=0
for t in io_uring01 io_uring02 io_uring03; do
    echo "=== LTP_START ${t} ==="
    /opt/ltp/testcases/bin/${t}
    rc=$?
    echo "LTP_RC ${t} ${rc}"
    [ "${rc}" -eq 0 ] || overall=1
done

echo "=== LTP_START io_uring04 ==="
KCONFIG_SKIP_CHECK=1 /opt/ltp/testcases/bin/io_uring04
rc04=$?
echo "LTP_RC io_uring04 ${rc04}"
if [ "${rc04}" -ne 0 ] && [ "${rc04}" -ne 32 ]; then
    overall=1
fi

echo "=== LIBURING_START ==="
/opt/io_uring/run_all.sh
rc_lib=$?
echo "LIBURING_RC ${rc_lib}"
[ "${rc_lib}" -eq 0 ] || overall=1

echo "=== SMP_STRESS_START ==="
/opt/io_uring/smp_stress
rc_smp=$?
echo "SMP_STRESS_RC ${rc_smp}"
[ "${rc_smp}" -eq 0 ] || overall=1

echo "=== MEMINFO_AFTER_START ==="
cat /proc/meminfo
echo "=== MEMINFO_AFTER_END ==="
exit "${overall}"
"""
    clean, qemu_exit = run_guest_job(
        arch=args.arch,
        kernel=kernel,
        image_copy=image_copy,
        run=run,
        script_text=guest_script,
        boot_timeout=args.boot_timeout,
        timeout=args.timeout,
    )

    ltp_rcs = {name: int(rc) for name, rc in re.findall(r"(?m)^LTP_RC (\S+) (\d+)\s*$", clean)}
    for req in ("io_uring01", "io_uring02", "io_uring03"):
        if ltp_rcs.get(req) != 0:
            raise RuntimeError(f"LTP {req} failed: rc={ltp_rcs.get(req)}")
        block = extract_block(
            clean,
            f"=== LTP_START {req} ===",
            f"LTP_RC {req} {ltp_rcs[req]}",
        )
        if "TPASS" not in block or "TFAIL" in block or "TBROK" in block:
            raise RuntimeError(f"LTP {req} output did not cleanly TPASS")
    if ltp_rcs.get("io_uring04") not in (0, 32):
        raise RuntimeError(f"LTP io_uring04 unexpected rc={ltp_rcs.get('io_uring04')}")

    lib_m = re.search(
        r"(?m)^IO_URING_LIBURING_SUMMARY passed=(\d+) skipped=(\d+) failed=(\d+) total=(\d+)\s*$",
        clean,
    )
    if not lib_m:
        raise RuntimeError("Missing liburing run_all.sh IO_URING_LIBURING_SUMMARY line")
    skip_m = re.search(r"(?m)^SKIPPED_TESTS:\s*(.+?)\s*$", clean)
    lib_summary = {
        "passed": int(lib_m.group(1)),
        "skipped": int(lib_m.group(2)),
        "failed": int(lib_m.group(3)),
        "total": int(lib_m.group(4)),
        "skipped_tests": skip_m.group(1).split() if skip_m else [],
    }
    allowed_skip = lib_summary["skipped"] == 0 or (
        lib_summary["skipped"] == 1
        and lib_summary["skipped_tests"] == ["ooo-file-unreg.t(rc=77)"]
    )
    if (
        lib_summary["failed"] != 0
        or lib_summary["total"] != 54
        or lib_summary["passed"] + lib_summary["skipped"] != 54
        or not allowed_skip
    ):
        raise RuntimeError(f"liburing regression incomplete: {lib_summary}")

    if "SMP_STRESS_RESULT PASS" not in clean:
        raise RuntimeError("Missing SMP_STRESS_RESULT PASS")

    mem_before = parse_meminfo(extract_block(clean, "=== MEMINFO_BEFORE_START ===", "=== MEMINFO_BEFORE_END ==="))
    mem_after = parse_meminfo(extract_block(clean, "=== MEMINFO_AFTER_START ===", "=== MEMINFO_AFTER_END ==="))
    mem_delta = {
        k: mem_after[k] - mem_before[k]
        for k in mem_before
        if k in mem_after
    }

    summary = {
        "mode": "functional",
        "arch": args.arch,
        "qemu_exit": qemu_exit,
        "ltp_rc": ltp_rcs,
        "liburing": lib_summary,
        "smp_stress": "PASS",
        "meminfo_before_kb": mem_before,
        "meminfo_after_kb": mem_after,
        "meminfo_delta_kb": mem_delta,
        "passed": True,
    }
    (run / f"functional-{args.arch}.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def parse_fio_json(raw_block: str) -> dict:
    start = raw_block.find("{")
    end = raw_block.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("Missing JSON object in fio output")
    return json.loads(raw_block[start : end + 1])


def summarize_fio_job(doc: dict) -> dict:
    job = doc["jobs"][0]
    read = job["read"]
    lat = read.get("clat_ns", {}).get("percentile", {})
    iodepth = job.get("iodepth_level", {})
    ge8_pct = sum(float(iodepth.get(k, 0.0)) for k in ("8", "16", "32", ">=64"))
    return {
        "jobname": job["jobname"],
        "io_kbytes": read.get("io_kbytes", 0),
        "bw_bytes": read.get("bw_bytes", 0),
        "bw_mib_s": round(read.get("bw_bytes", 0) / (1024.0 * 1024.0), 3),
        "iops": round(float(read.get("iops", 0.0)), 2),
        "total_ios": read.get("total_ios", 0),
        "runtime_ms": read.get("runtime", 0),
        "clat_p50_ns": lat.get("50.000000"),
        "clat_p95_ns": lat.get("95.000000"),
        "clat_p99_ns": lat.get("99.000000"),
        "iodepth_level": iodepth,
        "iodepth_ge8_pct": round(ge8_pct, 2),
    }


def run_fio(args: argparse.Namespace, run: Path, kernel: Path, image_copy: Path) -> dict:
    stage = stage_dir_for(args.arch)
    fio_bin = stage / "bin/fio"
    sc_bench = stage / "bin/syscall_count_bench"
    for p in (fio_bin, sc_bench):
        if not p.exists():
            raise FileNotFoundError(f"Missing staged benchmark binary {p}")

    install_verified_file(image_copy, fio_bin, "/usr/bin/fio", run)
    install_verified_file(image_copy, sc_bench, "/opt/io_uring/syscall_count_bench", run)

    runtime_s = args.fio_runtime
    guest_script = f"""#!/bin/sh
set -e
echo "Preparing 64 MiB direct file (/root/fio-uring-bench) and 4 MiB cached file (/root/fio-uring-cached)..."
dd if=/dev/zero of=/root/fio-uring-bench bs=1M count=64
dd if=/dev/zero of=/root/fio-uring-cached bs=1M count=4
sync

echo "=== SYSCALL_BENCH_START ==="
/opt/io_uring/syscall_count_bench /root/fio-uring-bench /root/fio-uring-cached
echo "=== SYSCALL_BENCH_END ==="

run_fio_case() {{
    name="$1"
    fpath="$2"
    fsize="$3"
    shift 3
    echo "=== FIO_JSON_BEGIN ${{name}} ==="
    /usr/bin/fio --name="${{name}}" --filename="${{fpath}}" --size="${{fsize}}" --bs=4k --numjobs=1 --thread=1 --time_based --runtime={runtime_s} --output-format=json "$@"
    echo "=== FIO_JSON_END ${{name}} ==="
}}

run_fio_case direct_psync /root/fio-uring-bench 64m --ioengine=psync --direct=1 --rw=randread --iodepth=1
run_fio_case direct_uring_qd1 /root/fio-uring-bench 64m --ioengine=io_uring --direct=1 --rw=randread --iodepth=1
run_fio_case direct_uring_qd16 /root/fio-uring-bench 64m --ioengine=io_uring --direct=1 --rw=randread --iodepth=16 --iodepth_batch_submit=8 --iodepth_batch_complete_min=1 --iodepth_batch_complete_max=8 --fixedbufs=1 --registerfiles=1

echo "Warming 4 MiB page cache file (within axfs 1024-page soft limit)..."
dd if=/root/fio-uring-cached of=/dev/null bs=1M

run_fio_case cached_psync /root/fio-uring-cached 4m --ioengine=psync --direct=0 --rw=read --iodepth=1
run_fio_case cached_uring_qd32 /root/fio-uring-cached 4m --ioengine=io_uring --direct=0 --rw=read --iodepth=32 --iodepth_batch_submit=32 --iodepth_batch_complete_min=1 --iodepth_batch_complete_max=32 --fixedbufs=1 --registerfiles=1
"""
    clean, qemu_exit = run_guest_job(
        arch=args.arch,
        kernel=kernel,
        image_copy=image_copy,
        run=run,
        script_text=guest_script,
        boot_timeout=args.boot_timeout,
        timeout=args.timeout,
    )

    if "SYSCALL_BENCH_RESULT PASS" not in clean:
        raise RuntimeError("syscall_count_bench failed or missing PASS marker")

    syscall_cases: dict[str, dict] = {}
    for m in re.finditer(
        r"(?m)^SYSCALL_BENCH case=(\S+) ios=(\d+) syscalls=(\d+) io_per_syscall=([0-9.]+) wall_ms=([0-9.]+) bw_mib_s=([0-9.]+)\s*$",
        clean,
    ):
        syscall_cases[m.group(1)] = {
            "ios": int(m.group(2)),
            "syscalls": int(m.group(3)),
            "io_per_syscall": float(m.group(4)),
            "wall_ms": float(m.group(5)),
            "bw_mib_s": float(m.group(6)),
        }

    red_m = re.search(
        r"(?m)^SYSCALL_REDUCTION direct_qd16_vs_psync=([0-9.]+)x direct_qd16_vs_qd1=([0-9.]+)x cached_qd32_vs_psync=([0-9.]+)x\s*$",
        clean,
    )
    if not red_m:
        raise RuntimeError("Missing SYSCALL_REDUCTION summary line")
    reduction = {
        "direct_qd16_vs_psync": float(red_m.group(1)),
        "direct_qd16_vs_qd1": float(red_m.group(2)),
        "cached_qd32_vs_psync": float(red_m.group(3)),
    }
    if min(reduction.values()) < 4.0:
        raise RuntimeError(f"Syscall reduction below 4.0x target: {reduction}")

    fio_results: dict[str, dict] = {}
    for name in ("direct_psync", "direct_uring_qd1", "direct_uring_qd16", "cached_psync", "cached_uring_qd32"):
        block = extract_block(clean, f"=== FIO_JSON_BEGIN {name} ===", f"=== FIO_JSON_END {name} ===")
        doc = parse_fio_json(block)
        (run / f"fio-{name}.json").write_text(json.dumps(doc, indent=2) + "\n")
        fio_results[name] = summarize_fio_job(doc)

    ge8 = fio_results["direct_uring_qd16"]["iodepth_ge8_pct"]
    if ge8 <= 80.0:
        raise RuntimeError(f"O_DIRECT qd16 IO depths >= 8 share {ge8}% <= 80%")

    cached_base = fio_results["cached_psync"]["bw_bytes"]
    cached_uring = fio_results["cached_uring_qd32"]["bw_bytes"]
    cached_speedup_pct = ((cached_uring - cached_base) / cached_base) * 100.0 if cached_base else 0.0
    if cached_speedup_pct < 20.0:
        raise RuntimeError(f"Cached qd32 throughput gain {cached_speedup_pct:.2f}% < 20%")

    summary = {
        "mode": "fio",
        "arch": args.arch,
        "qemu_exit": qemu_exit,
        "syscall_bench": syscall_cases,
        "syscall_reduction": reduction,
        "fio": fio_results,
        "cached_qd32_speedup_pct": round(cached_speedup_pct, 2),
        "passed": True,
    }
    (run / f"fio-{args.arch}.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def run_host(cmd: list[str], *, cwd: Path = REPO) -> str:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"host command failed rc={proc.returncode}: {shlex.join(cmd)}\n"
            f"stderr: {proc.stderr.strip()[-2000:]}"
        )
    return proc.stdout


def extract_b64_capture(clean: str, case_name: str, out_path: Path) -> dict:
    saved_re = re.compile(
        rf"(?m)^RECORD SAVED output=/root/{re.escape(case_name)}\.pbcapture bytes=(\d+) sha256=([0-9a-f]{{64}})\s*$"
    )
    m = saved_re.search(clean)
    if not m:
        raise RuntimeError(f"Missing RECORD SAVED confirmation for {case_name}")
    expected_len = int(m.group(1))
    expected_sha = m.group(2)

    block = extract_block(clean, f"=== PULSE_B64_BEGIN {case_name} ===", f"=== PULSE_B64_END {case_name} ===")
    b64_lines = [line[4:].strip() for line in block.splitlines() if line.startswith("B64:")]
    raw = base64.b64decode("".join(b64_lines), validate=True)
    actual_sha = hashlib.sha256(raw).hexdigest()
    if len(raw) != expected_len or actual_sha != expected_sha:
        raise RuntimeError(
            f"Capture {case_name} corrupt: got len={len(raw)} sha={actual_sha}, "
            f"expected len={expected_len} sha={expected_sha}"
        )
    out_path.write_bytes(raw)
    return {"bytes": len(raw), "sha256": actual_sha}


def analyze_bpf_case(
    *,
    case_name: str,
    cap_path: Path,
    run: Path,
    kernel_elf: Path,
    analyzer: Path,
    flamegraph_dir: Path,
) -> dict:
    case_dir = run / case_name
    bundle_dir = case_dir / "bundle"
    case_dir.mkdir(parents=True, exist_ok=True)

    collection_json = run_host(
        [
            sys.executable,
            str(REPO / "tools/bpf-record/collect.py"),
            str(cap_path),
            "--bundle",
            str(bundle_dir),
            "--candidate",
            str(kernel_elf),
            "--analyzer",
            str(analyzer),
        ]
    )
    (case_dir / "collect-stdout.json").write_text(collection_json)

    loss_txt = run_host([str(analyzer), str(cap_path), "--loss"])
    (case_dir / "loss.txt").write_text(loss_txt)

    summary_txt = run_host([str(analyzer), str(cap_path), "--json"])
    (case_dir / "analyzer-summary.json").write_text(summary_txt)

    sched_txt = run_host([str(analyzer), str(cap_path), "--sched-report", "--json"])
    (case_dir / "sched-report.json").write_text(sched_txt)

    mapping_txt = run_host(
        [str(analyzer), str(cap_path), "--mapping-report", "--bundle", str(bundle_dir)]
    )
    (case_dir / "mapping-report.json").write_text(mapping_txt)

    # The analyzer rejects a selection containing any sample inside a task
    # mutation gap (exec/thread-creation transitions of short-lived helpers).
    # Select the dominant non-idle workload thread so only a stable task is exported.
    tid_counts: dict[tuple[int, int], int] = {}
    for sample in json.loads(summary_txt)["cpu_samples"]:
        if sample["pid"] != 0:
            key = (sample["pid"], sample["tid"])
            tid_counts[key] = tid_counts.get(key, 0) + 1
    if not tid_counts:
        raise RuntimeError(f"{case_name}: capture has no non-idle CPU samples")
    (sel_pid, sel_tid), sel_samples = max(tid_counts.items(), key=lambda kv: kv[1])
    selected_task = {
        "pid": sel_pid,
        "tid": sel_tid,
        "samples": sel_samples,
        "non_idle_samples": sum(tid_counts.values()),
    }

    weights_out: dict[str, dict] = {}
    for weight in ("period", "samples"):
        table_path = case_dir / f"kernel-hotspots-{weight}.txt"
        folded_path = case_dir / f"oncpu-{weight}.folded"
        perf_data_path = case_dir / f"{case_name}-{weight}.perf.data"
        perf_out_dir = case_dir / f"perf-pipeline-{weight}"

        table_text = run_host(
            [
                str(analyzer),
                str(cap_path),
                "--mode",
                "kernel",
                "--pid",
                str(sel_pid),
                "--tid",
                str(sel_tid),
                "--weight",
                weight,
                "--bundle",
                str(bundle_dir),
                "--table",
                "--oncpu",
                str(folded_path),
                "--perf-data",
                str(perf_data_path),
            ]
        )
        table_path.write_text(table_text)
        run_host(
            [
                sys.executable,
                str(REPO / "scripts/perf_pipeline.py"),
                str(perf_data_path),
                "--manifest",
                str(perf_data_path) + ".json",
                "--bundle",
                str(bundle_dir),
                "--perf",
                shutil.which("perf") or "/usr/local/bin/perf",
                "--flamegraph",
                str(flamegraph_dir),
                "--output",
                str(perf_out_dir),
            ]
        )
        weights_out[weight] = {
            "table": str(table_path.relative_to(run)),
            "folded": str(folded_path.relative_to(run)),
            "perf_data": str(perf_data_path.relative_to(run)),
            "perf_pipeline_dir": str(perf_out_dir.relative_to(run)),
        }

    return {
        "capture": str(cap_path.relative_to(run)),
        "capture_bytes": cap_path.stat().st_size,
        "loss": loss_txt.strip().splitlines(),
        "selected_task": selected_task,
        "analyzer_summary": json.loads(summary_txt),
        "sched_report": json.loads(sched_txt),
        "weights": weights_out,
    }


def run_bpf(args: argparse.Namespace, run: Path, kernel: Path, image_copy: Path) -> dict:
    analyzer = (REPO / "target/debug/bpf-analyzer").resolve(strict=True)
    recorder = (REPO / f"tools/bpf-record/build/{args.arch}/guest/bpf-record").resolve(strict=True)
    fio_bin = (stage_dir_for(args.arch) / "bin/fio").resolve(strict=True)
    flamegraph_dir = (REPO / ".tools/FlameGraph").resolve(strict=True)

    kernel_elf = bpf_rec.kernel_identity(kernel, run)
    prov_dst = run / "kernel.provenance.json"
    if not prov_dst.exists():
        prov_src = kernel.with_suffix(".elf.provenance.json")
        prov_facts = json.loads(prov_src.read_text())["artifacts"]
        if prov_facts["elf"]["sha256"] != helpers.digest(kernel_elf):
            raise ValueError(f"kernel provenance mismatch for {kernel_elf}")
        shutil.copyfile(prov_src, prov_dst)
    install_verified_file(image_copy, recorder, "/usr/bin/bpf-record", run)
    install_verified_file(image_copy, fio_bin, "/usr/bin/fio", run)
    install_verified_file(image_copy, kernel_elf, "/boot/kernel.elf", run)

    selected_cases = args.cases or list(BPF_WORKLOADS.keys())
    case_cmds: list[str] = [
        "#!/bin/sh",
        "set -e",
        "dd if=/dev/zero of=/root/fio-uring-bench bs=1M count=64",
        "dd if=/dev/zero of=/root/fio-uring-cached bs=1M count=4",
        "sync",
    ]
    runtime_s = args.fio_runtime
    for name in selected_cases:
        cfg = BPF_WORKLOADS[name]
        if cfg["warm"]:
            case_cmds.append(f'echo "Warming 4 MiB page cache before {name}..."')
            case_cmds.append("dd if=/root/fio-uring-cached of=/dev/null bs=1M")
        cap = f"/root/{name}.pbcapture"
        case_cmds.extend(
            [
                f'echo "=== BPF_CASE_BEGIN {name} ==="',
                f"/usr/bin/bpf-record --events cpu,sched --callchain fp --frequency {args.sample_freq} "
                f"--buffer-pages {args.buffer_pages} --record-bytes 33554432 --duration-ms 30000 "
                f"--kernel-elf /boot/kernel.elf --output {cap} &",
                "rec_pid=$!",
                "sleep 1",
                f'echo "=== FIO_JSON_BEGIN {name} ==="',
                f"/usr/bin/fio --name={name} --filename={cfg['file']} --size={cfg['size']} --bs=4k "
                f"--numjobs=1 --thread=1 --time_based --runtime={runtime_s} --output-format=json {cfg['args']}",
                f'echo "=== FIO_JSON_END {name} ==="',
                "kill -INT $rec_pid",
                "wait $rec_pid",
                f'echo "=== PULSE_B64_BEGIN {name} ==="',
                f"base64 {cap} | sed 's/^/B64:/'",
                f'echo "=== PULSE_B64_END {name} ==="',
                f"sha256sum {cap}",
                f"rm -f {cap}",
                f'echo "=== BPF_CASE_END {name} ==="',
            ]
        )

    clean, qemu_exit = run_guest_job(
        arch=args.arch,
        kernel=kernel,
        image_copy=image_copy,
        run=run,
        script_text="\n".join(case_cmds) + "\n",
        boot_timeout=args.boot_timeout,
        timeout=args.timeout,
    )

    analyzed: dict[str, dict] = {}
    for name in selected_cases:
        cap_path = run / f"{name}.pbcapture"
        cap_meta = extract_b64_capture(clean, name, cap_path)
        fio_doc = parse_fio_json(
            extract_block(clean, f"=== FIO_JSON_BEGIN {name} ===", f"=== FIO_JSON_END {name} ===")
        )
        (run / f"fio-{name}.json").write_text(json.dumps(fio_doc, indent=2) + "\n")
        report = analyze_bpf_case(
            case_name=name,
            cap_path=cap_path,
            run=run,
            kernel_elf=kernel_elf,
            analyzer=analyzer,
            flamegraph_dir=flamegraph_dir,
        )
        report["capture_sha256"] = cap_meta["sha256"]
        report["fio"] = summarize_fio_job(fio_doc)
        analyzed[name] = report

    summary = {
        "mode": "bpf",
        "arch": args.arch,
        "qemu_exit": qemu_exit,
        "kernel_elf": str(kernel_elf),
        "kernel_elf_sha256": helpers.digest(kernel_elf),
        "kernel_provenance_sha256": helpers.digest(run / "kernel.provenance.json"),
        "flamegraph_commit": helpers.command(["git", "-C", str(flamegraph_dir), "rev-parse", "HEAD"]).strip(),
        "cases": analyzed,
        "passed": True,
    }
    (run / f"bpf-{args.arch}-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("guest-checks", "functional", "sqpoll", "sqpoll-reserved", "dedicated-ring", "future-cpu", "worker-cpu", "worker-limits", "fio", "bpf"))
    parser.add_argument("--arch", required=True, choices=tuple(ARCHES))
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--boot-timeout", type=float, default=60.0)
    parser.add_argument("--timeout", type=float, default=600.0)
    parser.add_argument("--fio-runtime", type=int, default=5)
    parser.add_argument("--sample-freq", type=int, default=100)
    parser.add_argument("--buffer-pages", type=int, default=64)
    parser.add_argument("--cases", nargs="+", choices=tuple(BPF_WORKLOADS.keys()))
    args = parser.parse_args()

    cfg = ARCHES[args.arch]
    kernel = (REPO / cfg["kernel"]).resolve(strict=True)
    orig_image = helpers.check_image(REPO / cfg["secondary"])
    orig_sha = helpers.digest(orig_image)

    run = create_run_dir(args.mode, args.arch, args.run_dir)
    image_copy = helpers.copy_image(orig_image, run, "disk.img")

    handlers = {
        "guest-checks": run_guest_checks,
        "functional": run_functional,
        "sqpoll": run_sqpoll,
        "sqpoll-reserved": run_sqpoll_reserved,
        "dedicated-ring": run_dedicated_ring,
        "future-cpu": run_future_cpu,
        "worker-cpu": run_worker_cpu,
        "worker-limits": run_worker_limits,
        "fio": run_fio,
        "bpf": run_bpf,
    }
    summary = handlers[args.mode](args, run, kernel, image_copy)
    if helpers.digest(orig_image) != orig_sha:
        raise RuntimeError(f"Original image mutated unexpectedly: {orig_image}")
    print(json.dumps({"run_dir": str(run), **summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
