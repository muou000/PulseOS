#!/usr/bin/env python3
"""Build and run real timer/IP BPF regression (#190), with no synthetic capture.

Reuse only image/tool/process helpers from bpf_smoke. Its payload, validators,
fixed capture and PASS markers are deliberately not part of this regression.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import shlex
import shutil
import sys

BASE = Path(__file__).resolve().parent
REPO = BASE.parent.parent
spec = importlib.util.spec_from_file_location("bpf_smoke_transport", BASE.parent / "bpf_smoke/run.py")
assert spec and spec.loader
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
# Helpers' output guard is intentionally scoped to this regression's tree.
helpers.BASE = BASE
SOURCE = BASE / "guest.rs"
LINKER_SCRIPT = BASE / "guest.ld"
ARCHES = helpers.ARCHES


def build(arch: str, mode: str = "task") -> Path:
    sysroot = Path(helpers.command(["rustc", "+nightly", "--print", "sysroot"]).strip())
    version = helpers.command(["rustc", "+nightly", "-vV"])
    host = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
    linker = sysroot / "lib/rustlib" / host / "bin/rust-lld"
    output = BASE / "build" / arch / mode / "sampling.elf"
    output.parent.mkdir(parents=True, exist_ok=True)
    command = ["rustc", "+nightly", "--edition=2024", "--crate-type=bin", "--target", ARCHES[arch]["target"],
               "-C", "panic=abort", "-C", "opt-level=2", "-C", "relocation-model=static",
               "-C", f"linker={linker}", "-C", f"link-arg=-T{LINKER_SCRIPT}",
               "-C", "link-arg=--no-relax", "-o", str(output), str(SOURCE)]
    if mode == "cpu":
        command += ["--cfg", "cpu_clock_test"]
    if mode in ("trace", "block", "wake"):
        command += ["--cfg", "tracepoint_test"]
    if mode in ("block", "wake"):
        command += ["--cfg", f"trace_{mode}"]
    helpers.command(command, timeout=120)
    helpers.check_elf(output, arch)
    (output.parent / "build.json").write_text(json.dumps({"command": command, "rustc": version, "mode": mode,
        "source_sha256": helpers.digest(SOURCE), "linker_script_sha256": helpers.digest(LINKER_SCRIPT),
        "payload_sha256": helpers.digest(output)}, indent=2) + "\n")
    print(f"Built {output}", flush=True)
    return output


def validate_log(text: str, token: str, mode: str = "task") -> list[str]:
    lines = [re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line).strip()
             for line in text.replace("\r", "").splitlines()]
    errors = []
    if mode not in ("task", "cpu", "trace", "block", "wake"):
        return ["invalid expected sampling mode"]
    if sum(line.startswith(f"SAMPLING START version=2 mode={mode} cpus=8 ") for line in lines) != 1:
        errors.append("missing, duplicate or wrong-mode real sampler START")
    if any(line.startswith("SAMPLING FAIL ") for line in lines):
        errors.append("guest sampler emitted FAIL")
    if lines.count(f"SAMPLING SINK_REJECT mode={mode} source_errno=-22 cpu_errno=-22 preserved=1") != 1:
        errors.append("missing invalid output binding rejection or preserved sink evidence")
    if mode in ("trace", "block", "wake"):
        prefix, count_name = {"trace": ("TRACE", "sched"), "block": ("BLOCK", "blocks"), "wake": ("WAKE", "wakes")}[mode]
        observed = [re.fullmatch(rf"SAMPLING {prefix}_OBSERVED {count_name}=(\d+) subjects=(\d+) subjects_capped=([01]) target_contexts=(\d+) lost=(\d+) cpu_mask=0x([0-9a-f]+)", line)
                    for line in lines]
        observed = [match for match in observed if match]
        final = [re.fullmatch(rf"SAMPLING {prefix}_RESULT PASS {count_name}=(\d+) subjects=(\d+) subjects_capped=([01]) target_contexts=(\d+) lost=(\d+) source=kernel_ring", line)
                 for line in lines]
        final = [match for match in final if match]
        if len(observed) != 1 or len(final) != 1:
            errors.append("expected exactly one trace OBSERVED and kernel_ring RESULT")
        else:
            values = tuple(map(int, final[0].groups()))
            sched, subjects, capped, target_contexts, lost = values
            min_subjects = 2 if mode == "trace" else 1
            max_subjects_per_record = 1 if mode == "block" else 2
            if sched < 2 or not min_subjects <= subjects <= 64 or subjects > max_subjects_per_record * sched or target_contexts > sched or lost:
                errors.append("missing real scheduler subjects/events or invalid trace counters")
            if capped and subjects != 64:
                errors.append("trace subject cap inconsistent")
            if values != tuple(map(int, observed[0].groups()[:5])):
                errors.append("trace output grew after disable/detach")
            if int(observed[0].group(6), 16) not in range(1, 1 << 8):
                errors.append("invalid trace CPU mask")
            for stage in ("disabled", "detached"):
                if lines.count(f"SAMPLING PASS {stage} mode={mode} records={sched}") != 1:
                    errors.append(f"missing or inconsistent trace {stage} check")
    else:
        observed = [re.fullmatch(rf"SAMPLING OBSERVED mode={mode} samples=(\d+) foreign=(\d+) a=(\d+) b=(\d+) lost=(\d+) cpu_mask=0x([0-9a-f]+)", line)
                    for line in lines]
        observed = [match for match in observed if match]
        final = [re.fullmatch(rf"SAMPLING RESULT PASS mode={mode} samples=(\d+) foreign=(\d+) a=(\d+) b=(\d+) lost=(\d+) source=kernel_ring", line)
                 for line in lines]
        final = [match for match in final if match]
        if len(observed) != 1 or len(final) != 1:
            errors.append("expected exactly one same-mode OBSERVED and kernel_ring RESULT")
        else:
            values = tuple(map(int, final[0].groups()))
            samples, foreign, a, b, lost = values
            if samples < a + b or a < 2 or b < 2 or lost != 0:
                errors.append("missing real samples in both loops or nonzero loss")
            if mode == "task" and foreign:
                errors.append("task-clock delivered another task's sample")
            if values != tuple(map(int, observed[0].groups()[:5])):
                errors.append("output grew after disable/detach or final counters differ")
            if int(observed[0].group(6), 16) not in range(1, 1 << 8):
                errors.append("invalid observed CPU mask")
            for stage in ("disabled", "detached"):
                expected = f"SAMPLING PASS {stage} mode={mode} records={samples + foreign}"
                if lines.count(expected) != 1:
                    errors.append(f"missing or inconsistent {stage} lifecycle check")
    if mode == "task":
        sleeps = [re.fullmatch(r"SAMPLING TASK_SLEEP before_ns=(\d+) after_ns=(\d+) wall_ns=(\d+)", line)
                  for line in lines]
        sleeps = [match for match in sleeps if match]
        if len(sleeps) != 1:
            errors.append("missing or duplicate task-clock sleep evidence")
        else:
            before, after, wall = map(int, sleeps[0].groups())
            if wall < 80_000_000 or after < before or after - before > wall // 5 + 2_000_000:
                errors.append("task clock counted sleeping time or sleep interval invalid")
    if mode == "task":
        for kind in ("link_target_close", "ioctl_dup_final_close"):
            lifecycle = [re.fullmatch(rf"SAMPLING FD_LIFECYCLE kind={kind} alive=(\d+) loop_a=(\d+) settled=(\d+) after_stop=(\d+) lost=(\d+)", line)
                         for line in lines]
            lifecycle = [match for match in lifecycle if match]
            if len(lifecycle) != 1:
                errors.append(f"missing or duplicate FD lifecycle evidence: {kind}")
                continue
            alive, loop_a, settled, after_stop, lost = map(int, lifecycle[0].groups())
            if loop_a < 2 or alive < loop_a or settled < alive or after_stop != settled or lost:
                errors.append(f"FD retention or final-close sampling failed: {kind}")
    exits = [line for line in lines if line.startswith(f"BPF_HOST_EXIT {token} ")]
    if exits != [f"BPF_HOST_EXIT {token} 0"]:
        errors.append("missing, duplicate or unsuccessful guest exit")
    if re.search(r"panicked at|kernel panic|panic:|fatal trap", text, re.I):
        errors.append("kernel panic or fatal trap")
    return errors


def qemu_command(arch: str, kernel: Path, image: Path) -> list[str]:
    qemu = shutil.which(ARCHES[arch]["qemu"])
    if not qemu:
        raise ValueError(f"missing {ARCHES[arch]['qemu']}")
    command = [qemu, "-machine", "virt", "-kernel", str(kernel), "-m", "8G", "-nographic", "-smp", "8"]
    if arch == "riscv64":
        command += ["-bios", "default"]
    command += ["-drive", f"file={image},if=none,format=raw,id=x0,snapshot=on"]
    if arch == "riscv64":
        command += ["-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0", "-no-reboot",
                    "-device", "virtio-net-device,netdev=net", "-netdev", "user,id=net"]
    else:
        command += ["-device", "virtio-blk-pci,drive=x0", "-no-reboot",
                    "-device", "virtio-net-pci,netdev=net0", "-netdev", "user,id=net0"]
    return command + ["-rtc", "base=utc"]


def guest(args: argparse.Namespace) -> int:
    # Always rebuild from source, so stale payloads cannot turn a missing v2 ABI
    # into a legacy PASS. Kernels/images are copied before QEMU starts.
    payload = build(args.arch, args.mode)
    kernel = (args.kernel or REPO / ARCHES[args.arch]["kernel"]).resolve(strict=True)
    image = helpers.check_image(args.image or REPO / ARCHES[args.arch]["primary"])
    run = helpers.new_run(f"{args.arch}-{args.mode}")
    kernel_copy = run / "kernel"
    shutil.copyfile(kernel, kernel_copy)
    image_copy = helpers.copy_image(image, run, "disk.img")
    binary, guest_dir = helpers.inject(image_copy, payload, run)
    token = run.name.rsplit("-", 1)[-1]
    shell = (f"ulimit -c 0; cd {shlex.quote(guest_dir)} && {binary}; "
             f"status=$?; printf '\\nBPF_HOST_EXIT {token} %s\\n' \"$status\"")
    command = qemu_command(args.arch, kernel_copy, image_copy)
    metadata = {"kind": "real BPF timer and PC regression, no capture synthesis", "arch": args.arch, "mode": args.mode,
                "command": command, "guest_command": shell, "kernel": str(kernel), "image": str(image),
                "kernel_sha256": helpers.digest(kernel_copy), "image_sha256": helpers.digest(image),
                "payload_sha256": helpers.digest(payload), "source_sha256": helpers.digest(SOURCE)}
    (run / "inputs.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(shlex.join(command), flush=True)
    print(f"Logs: {run}", flush=True)
    text, qemu_exit, reason = helpers.drive_guest(command, shell, token, run / "guest.log",
        r"(?:^|[\r\n])[^\r\n]*[#$] ?$", args.boot_timeout, args.timeout)
    errors = validate_log(text, token, args.mode)
    if reason:
        errors.append(reason)
    if helpers.digest(image) != metadata["image_sha256"]:
        errors.append("original image changed during snapshot run")
    (run / "result.json").write_text(json.dumps({**metadata, "errors": errors, "qemu_exit": qemu_exit,
                                                "passed": not errors}, indent=2) + "\n")
    for line in text.replace("\r", "").splitlines():
        if line.startswith(("SAMPLING ", "BPF_HOST_EXIT ")):
            print(line)
    for error in errors:
        print(f"FAIL: {error}", file=sys.stderr)
    print(f"Result: {'FAIL' if errors else 'PASS'}; {run}", flush=True)
    return int(bool(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "guest"))
    parser.add_argument("--arch", required=True, choices=ARCHES)
    parser.add_argument("--mode", choices=("task", "cpu", "trace", "block", "wake"), default="task")
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--boot-timeout", type=float, default=90)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    if args.action == "build":
        build(args.arch, args.mode)
        return 0
    return guest(args)


if __name__ == "__main__":
    raise SystemExit(main())
