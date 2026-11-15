#!/usr/bin/env python3
"""Build and run real timer/IP BPF regression (#190), with no synthetic capture.

Reuse only image/tool/process helpers from bpf_smoke. Its payload, validators,
fixed capture and PASS markers are deliberately not part of this regression.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import archive as raw_archive
import capture as runtime_capture
import stack_evidence
import artifacts
import mapping_evidence
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


def build(arch: str, mode: str = "task", archive: bool = False, fault: str = "none", ring_pages: int = 16, stacks: bool = False, mappings: bool = False) -> Path:
    if stacks and mode not in ("task", "cpu"):
        raise ValueError("--stacks requires task or cpu mode")
    if mappings and (mode != "cpu" or not archive):
        raise ValueError("--mappings requires --mode cpu --archive")
    linker_script = BASE / "mapping_guest.ld" if mappings else LINKER_SCRIPT
    source_inputs = {str(path): helpers.digest(path) for path in (SOURCE, linker_script, BASE / "archive.rs", *([BASE / "mapping_workload.rs"] if mappings else []), *([BASE / "stack_workload.rs"] if stacks else []), *([BASE / "fault_workload.rs"] if mode == "fault" else []))}
    sysroot = Path(helpers.command(["rustc", "+nightly", "--print", "sysroot"]).strip())
    version = helpers.command(["rustc", "+nightly", "-vV"])
    host = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
    linker = sysroot / "lib/rustlib" / host / "bin/rust-lld"
    output = BASE / "build" / arch / (mode + ("-mappings" if mappings else "") + ("-stacks" if stacks else "") + ("-archive" if archive else "") + ("-" + fault if fault != "none" else "") + ("-ring1" if ring_pages == 1 else "")) / "sampling.elf"
    output.parent.mkdir(parents=True, exist_ok=True)
    command = ["rustc", "+nightly", "--edition=2024", "--crate-type=bin", "--target", ARCHES[arch]["target"],
               "-C", "panic=abort", "-C", "opt-level=2", "-C", "relocation-model=static",
               "-C", f"linker={linker}", "-C", f"link-arg=-T{linker_script}",
               "-C", "link-arg=--no-relax", "-o", str(output), str(SOURCE)]
    if stacks:
        command += ["--cfg", "stack_test", "-C", "force-frame-pointers=yes"]
    if mappings:
        command += ["--cfg", "mapping_test", "-C", "debuginfo=2"]
    if mode == "cpu":
        command += ["--cfg", "cpu_clock_test"]
    if mode in ("trace", "block", "wake", "sched", "fault"):
        command += ["--cfg", "tracepoint_test"]
    if mode in ("block", "wake"):
        command += ["--cfg", f"trace_{mode}"]
    if mode == "sched":
        command += ["--cfg", "sched_trace_test"]
    if mode == "fault":
        command += ["--cfg", "trace_fault"]
    if archive:
        command += ["--cfg", "capture_export"]
    if ring_pages == 1:
        command += ["--cfg", "perf_ring_one_page"]
    if fault != "none":
        if not archive:
            raise ValueError("fault injection requires --archive")
        command += ["--cfg", "fault_" + fault.replace("-", "_")]
    helpers.command(command, timeout=120)
    helpers.check_elf(output, arch)
    child_command = None
    if mappings:
        child_command = command.copy()
        child_command[child_command.index("-o") + 1] = str(output.parent / "mapping-child.elf")
        child_command += ["--cfg", "mapping_exec_child", "-C", "link-arg=--build-id=sha1"]
        helpers.command(child_command, timeout=120)
        helpers.check_elf(output.parent / "mapping-child.elf", arch)
        mapping_evidence.check_loop_artifact(output)
        mapping_evidence.check_loop_artifact(output.parent / "mapping-child.elf")
    if any(helpers.digest(Path(path)) != expected for path, expected in source_inputs.items()):
        raise ValueError("payload source changed while compiling")
    (output.parent / "build.json").write_text(json.dumps({"command": command, "rustc": version, "mode": mode,
        "source_sha256": helpers.digest(SOURCE), "linker_script_sha256": helpers.digest(linker_script), "child_command": child_command,
        "payload_sha256": helpers.digest(output), "source_inputs": source_inputs}, indent=2) + "\n")
    print(f"Built {output}", flush=True)
    return output


def validate_log(text: str, token: str, mode: str = "task", stacks: bool = False) -> list[str]:
    lines = [re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line).strip()
             for line in text.replace("\r", "").splitlines()]
    errors = []
    if mode not in ("task", "cpu", "trace", "block", "wake", "sched", "fault"):
        return ["invalid expected sampling mode"]
    if sum(line.startswith(f"SAMPLING START version=2 mode={mode} cpus=8 ") for line in lines) != 1:
        errors.append("missing, duplicate or wrong-mode real sampler START")
    if any(line.startswith("SAMPLING FAIL ") for line in lines):
        errors.append("guest sampler emitted FAIL")
    if lines.count(f"SAMPLING SINK_REJECT mode={mode} source_errno=-22 cpu_errno=-22 preserved=1") != 1:
        errors.append("missing invalid output binding rejection or preserved sink evidence")
    if mode in ("trace", "block", "wake", "sched", "fault"):
        prefix, count_name = {"trace": ("TRACE", "sched"), "block": ("BLOCK", "blocks"), "wake": ("WAKE", "wakes"), "sched": ("SCHED", "events"), "fault": ("FAULT", "faults")}[mode]
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
            min_subjects = 2 if mode in ("trace", "sched") else 1
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
    if mode == "sched":
        counts = [re.fullmatch(r"SAMPLING SCHED_EVENTS metadata=(\d+) switches=(\d+) blocks=(\d+) wakes=(\d+) exits=(\d+) enqueues=(\d+)", line) for line in lines]
        counts = [match for match in counts if match]
        if len(counts) != 1 or any(int(counts[0].group(i)) < 2 for i in (2,3,4)) or int(counts[0].group(6)) == 0:
            errors.append("mixed scheduler session lacks wake/block/switch/enqueue evidence")
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
    if stacks:
        evidence = [re.fullmatch(r"SAMPLING STACKS user_a=(\d+) user_b=(\d+) kernel=(\d+) partial=(\d+) sources=(\d+) context=software-stack-v3", line) for line in lines]
        evidence = [match for match in evidence if match]
        if len(evidence) != 1 or min(map(int, evidence[0].groups()[:3])) < 2 or int(evidence[0].group(5)) != (16 if mode == "cpu" else 1):
            errors.append("missing real three-frame user/kernel chains or source instances")
        probes = [re.fullmatch(r"SAMPLING STACK_PROBES no_fp=(\d+) read_fault=(\d+) cycle=(\d+) bad_ra=(\d+) misaligned=(\d+) depth_limit=(\d+)", line) for line in lines]
        probes = [match for match in probes if match]
        if len(probes) != 1 or min(map(int, probes[0].groups())) == 0:
            errors.append("missing actual negative stack probe diagnostics")
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
    payload = build(args.arch, args.mode, args.archive, args.fault, args.ring_pages, args.stacks, args.mappings)
    kernel = (args.kernel or REPO / ARCHES[args.arch]["kernel"]).resolve(strict=True)
    image = helpers.check_image(args.image or REPO / ARCHES[args.arch]["primary"])
    run = helpers.new_run(f"{args.arch}-{args.mode}")
    payload_copy = run / "payload.elf"
    shutil.copyfile(payload, payload_copy)
    payload_build = json.loads((payload.parent / "build.json").read_text())
    for source, expected in payload_build["source_inputs"].items():
        destination = run / Path(source).name
        shutil.copyfile(source, destination)
        if helpers.digest(destination) != expected:
            raise ValueError("payload source changed before archival")
    (run / "payload-build.json").write_text(json.dumps(payload_build, indent=2) + "\n")
    kernel_copy = run / "kernel"
    shutil.copyfile(kernel, kernel_copy)
    symbol_identity = {}
    if args.archive:
        with kernel.open("rb") as stream:
            boot_is_elf = stream.read(6) == b"\x7fELF\x02\x01"
        elf = (args.kernel_elf or (kernel if boot_is_elf else kernel.with_suffix(".elf"))).resolve(strict=True)
        with elf.open("rb") as stream:
            header = stream.read(64)
        if len(header) < 64 or header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != ARCHES[args.arch]["machine"]:
            raise ValueError("kernel symbols must be the target's LE ELF64")
        elf_copy = run / "kernel.elf"
        shutil.copyfile(elf, elf_copy)
        if boot_is_elf:
            matched = helpers.digest(elf_copy) == helpers.digest(kernel_copy)
        else:
            reproduced = run / "kernel-from-elf.bin"
            helpers.command(["rust-objcopy", f"--binary-architecture={args.arch}", str(elf_copy),
                             "--strip-all", "-O", "binary", str(reproduced)], cwd=REPO)
            matched = helpers.digest(reproduced) == helpers.digest(kernel_copy)
        if not matched:
            raise ValueError("kernel ELF does not match the actual boot image")
        symbol_identity = {"kernel_elf_path": str(elf), "kernel_elf_sha256": helpers.digest(elf_copy),
                           "kernel_elf_matches_boot": True}
        provenance_path = args.kernel_provenance or Path(str(elf) + ".provenance.json")
        if args.kernel_provenance is not None or provenance_path.exists():
            prov_spec = importlib.util.spec_from_file_location("kernel_provenance", REPO / "scripts/build_provenance.py")
            assert prov_spec and prov_spec.loader
            provenance = importlib.util.module_from_spec(prov_spec)
            prov_spec.loader.exec_module(provenance)
            manifest = provenance.verify_manifest(provenance_path, elf_copy, kernel_copy)
            if manifest["configuration"]["values"]["arch"] != args.arch:
                raise ValueError("kernel build provenance architecture mismatch")
            shutil.copyfile(provenance_path, run / "kernel.provenance.json")
            symbol_identity.update({"kernel_source_commit": manifest["source"]["commit"],
                                   "kernel_build_provenance": manifest,
                                   "kernel_provenance_sha256": helpers.digest(run / "kernel.provenance.json")})
    image_copy = helpers.copy_image(image, run, "disk.img")
    binary, guest_dir = helpers.inject(image_copy, payload_copy, run)
    if args.mappings:
        child_copy = run / "mapping-child.elf"
        shutil.copyfile(payload.parent / "mapping-child.elf", child_copy)
        for source, name in [(child_copy, "mapping-child.elf")]:
            if any(c in str(source) for c in '\\"\n\r'):
                raise ValueError("mapping artifact path contains unsupported characters")
            target = guest_dir + "/" + name
            helpers.debugfs(image_copy, f'write "{source}" {target}', write=True)
            helpers.debugfs(image_copy, f"set_inode_field {target} mode 0100755", write=True)
            dumped = run / ("injected-" + name)
            helpers.debugfs(image_copy, f'dump {target} "{dumped}"')
            if helpers.digest(dumped) != helpers.digest(source):
                raise ValueError("injected mapping artifact differs from bundled bytes")
            dumped.unlink()
        artifacts.bundle(run, [run / "kernel.elf", payload_copy, child_copy])
    token = run.name.rsplit("-", 1)[-1]
    shell = (f"ulimit -c 0; cd {shlex.quote(guest_dir)} && {binary}; "
             f"status=$?; printf '\\nBPF_HOST_EXIT {token} %s\\n' \"$status\"")
    command = qemu_command(args.arch, kernel_copy, image_copy)
    helpers.command(["git", "diff", "--binary", "HEAD", "--output", str(run / "worktree.patch")], cwd=REPO)
    metadata = {"kind": "real BPF timer and PC regression, no capture synthesis", "arch": args.arch, "mode": args.mode,
                **({"context_format": "software-stack-v3"} if args.stacks else {}),
                "command": command, "guest_command": shell, "kernel": str(kernel), "image": str(image),
                "kernel_sha256": helpers.digest(kernel_copy), "image_sha256": helpers.digest(image),
                "boot_image_sha256": helpers.digest(image_copy), "archive_requested": args.archive, "fault": args.fault, "ring_pages": args.ring_pages,
                "archive_source_sha256": helpers.digest(BASE / "archive.rs") if args.archive else None,
                "workspace_commit": helpers.command(["git", "rev-parse", "HEAD"], cwd=REPO).strip(),
                "kernel_source_commit": None,
                "worktree_diff_sha256": helpers.digest(run / "worktree.patch"),
                "payload_sha256": helpers.digest(payload_copy), "source_sha256": helpers.digest(SOURCE)}
    metadata.update(symbol_identity)
    if args.mappings:
        metadata.update(mapping_journal="mappings.txt", artifact_bundle="artifacts.json",
                        artifact_bundle_sha256=helpers.digest(run / "artifacts.json"))
    (run / "inputs.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(shlex.join(command), flush=True)
    print(f"Logs: {run}", flush=True)
    text, qemu_exit, reason = helpers.drive_guest(command, shell, token, run / "guest.log",
        r"(?:^|[\r\n])[^\r\n]*[#$] ?$", args.boot_timeout, args.timeout)
    errors = validate_log(text, token, args.mode, args.stacks)
    if reason:
        errors.append(reason)
    if args.archive:
        try:
            binary, archive_metadata, snapshots = raw_archive.extract(text, args.mode)
            (run / "records.pbraw").write_bytes(binary)
            (run / "archive.json").write_text(json.dumps(archive_metadata, indent=2) + "\n")
            for point, raw in snapshots.items():
                (run / f"stats-{point}.txt").write_bytes(raw)
            if args.mappings:
                metadata["mappings"] = mapping_evidence.extract_and_verify(run, text)
                metadata["mapping_journal_sha256"] = helpers.digest(run / "mappings.txt")
                (run / "inputs.json").write_text(json.dumps(metadata, indent=2) + "\n")
            if args.stacks:
                metadata["stacks"] = stack_evidence.verify(run)
            metadata["capture"] = runtime_capture.convert(run)
            print(f"Verified RAW archive: {archive_metadata['samples']} samples, {len(binary)} bytes; quality={archive_metadata['quality']}", flush=True)
        except (ValueError, KeyError, OverflowError) as error:
            errors.append(f"invalid RAW archive: {error}")
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
    parser.add_argument("--mode", choices=("task", "cpu", "trace", "block", "wake", "sched", "fault"), default="task")
    parser.add_argument("--archive", action="store_true")
    parser.add_argument("--stacks", action="store_true", help="verify frozen v3 user/kernel callchains; task/cpu only")
    parser.add_argument("--mappings", action="store_true", help="verify dynamic mapping journal and content-addressed ELF artifacts; cpu/archive only")
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--kernel-elf", type=Path)
    parser.add_argument("--kernel-provenance", type=Path)
    parser.add_argument("--ring-pages", type=int, choices=(1,16), default=16)
    parser.add_argument("--fault", choices=("none", "zero-producer", "zero-consumer", "export-overflow", "ring-overflow", "aborted"), default="none")
    parser.add_argument("--boot-timeout", type=float, default=90)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    if args.stacks and (args.mode not in ("task", "cpu") or not args.archive):
        parser.error("--stacks requires --mode task|cpu --archive to verify RAW bytes against ELF")
    if args.mappings and (args.mode != "cpu" or not args.archive):
        parser.error("--mappings requires --mode cpu --archive")
    if args.fault == "ring-overflow":
        args.ring_pages = 1
    if args.action == "build":
        build(args.arch, args.mode, args.archive, args.fault, args.ring_pages, args.stacks, args.mappings)
        return 0
    return guest(args)


if __name__ == "__main__":
    raise SystemExit(main())
