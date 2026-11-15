#!/usr/bin/env python3
"""Compatibility CLI for real PulseOS BPF capture (#191).

Runtime commands delegate to bpf_sampling/run.py --archive. The helpers below are
shared image/process transport, not a separate sampling or evidence implementation.
Only fixture-check consumes the retained, explicitly static format fixture.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time

BASE = Path(__file__).resolve().parent
REPO = BASE.parent.parent
SAMPLING_DRIVER = BASE.parent / "bpf_sampling" / "run.py"
FORMAT_FIXTURE = BASE / "fixtures" / "format-v1.bin"
MODES = ("task", "cpu", "trace", "block", "wake", "sched", "fault")

ARCHES = {
    "riscv64": {
        "machine": 243,
        "kernel": "kernel-rv",
        "primary": "rootfs-riscv64.img",
        "secondary": "disk.img",
        "qemu": "qemu-system-riscv64",
        "target": "riscv64gc-unknown-none-elf",
    },
    "loongarch64": {
        "machine": 258,
        "kernel": "kernel-la",
        "primary": "rootfs-loongarch64.img",
        "secondary": "disk-la.img",
        "qemu": "qemu-system-loongarch64",
        "target": "loongarch64-unknown-none-softfloat",
    },
}



def scoped(path: Path) -> Path:
    path = path.resolve()
    if not path.is_relative_to(BASE):
        raise ValueError(f"output must be under {BASE}: {path}")
    return path



def new_run(label: str) -> Path:
    parent = scoped(BASE / "runs")
    parent.mkdir(exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=f"{label}-{time.strftime('%Y%m%d-%H%M%S')}-", dir=parent))



def permission_check(text: str) -> None:
    if re.search(r"permission denied|read-only file system|operation not permitted", text, re.I):
        raise PermissionError(
            "tool reported a permission or read-only filesystem error; "
            "fix permissions before retrying\n" + text[-2000:]
        )



def command(argv: list[str], *, cwd: Path = BASE, timeout: float = 60) -> str:
    result = subprocess.run(
        argv,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    permission_check(result.stdout)
    if result.returncode:
        raise RuntimeError(
            f"command exited {result.returncode}: {shlex.join(argv)}\n"
            f"{result.stdout[-4000:]}"
        )
    return result.stdout



def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()



def check_elf(path: Path, arch: str) -> None:
    """Validate that payload is a static LE ELF64 without PT_INTERP for target arch."""
    with path.open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01":
            raise ValueError(f"payload must be little-endian ELF64: {path}")
        machine = struct.unpack_from("<H", header, 18)[0]
        if machine != ARCHES[arch]["machine"]:
            raise ValueError(f"wrong payload architecture for {arch}: e_machine={machine}")
        phoff = struct.unpack_from("<Q", header, 32)[0]
        entsize, count = struct.unpack_from("<HH", header, 54)
        if entsize < 56 or count == 0 or phoff + entsize * count > path.stat().st_size:
            raise ValueError(f"invalid ELF program headers: {path}")
        program_headers = []
        for i in range(count):
            stream.seek(phoff + i * entsize)
            program_headers.append(struct.unpack("<IIQQQQQQ", stream.read(56)))
        if any(ph[0] == 3 for ph in program_headers):
            raise ValueError("guest payload has PT_INTERP; use a static build")
        if not any(
            ph[0] == 1 and ph[2] <= phoff and phoff + entsize * count <= ph[2] + ph[5]
            for ph in program_headers
        ):
            raise ValueError("program headers must be within PT_LOAD for the PulseOS ELF parser")



def check_image(path: Path) -> Path:
    path = path.resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"image is not a regular file: {path}")
    with path.open("rb") as stream:
        stream.seek(1024 + 56)
        if stream.read(2) != b"\x53\xef":
            raise ValueError(f"debugfs needs a raw unpartitioned ext2/3/4 image: {path}")
    if any(char in str(path) for char in ",\n\r"):
        raise ValueError("QEMU image paths cannot contain commas or newlines")
    return path



def copy_image(source: Path, run: Path, name: str) -> Path:
    dest = scoped(run / name)
    if dest.exists() or dest == source:
        raise ValueError(f"refusing to overwrite image: {dest}")
    command(["cp", "--reflink=auto", "--sparse=always", "--", str(source), str(dest)], timeout=300)
    dest.chmod(dest.stat().st_mode | 0o600)
    return dest



def debugfs(image: Path, request: str, *, write: bool = False) -> str:
    if write:
        scoped(image)
    tool = shutil.which("debugfs")
    if not tool:
        raise ValueError("debugfs unavailable; install e2fsprogs before running")
    argv = [tool, *(["-w"] if write else []), "-R", request, str(image)]
    text = command(argv)
    if re.search(
        r"not found|no such file|file exists|usage:|invalid|short read|"
        r"filesystem not open|could not|while (?:opening|writing|reading|looking)|"
        r"no space|error",
        text,
        re.I,
    ):
        raise ValueError(f"debugfs request failed: {request}\n{text}")
    return text



def inject(image: Path, payload: Path, run: Path) -> tuple[str, str]:
    guest_dir = f"/bpf-smoke-{run.name.rsplit('-', 1)[-1]}"
    guest_binary = guest_dir + "/payload"
    debugfs(image, "stat /")
    debugfs(image, "mkdir " + guest_dir, write=True)
    debugfs(image, f"set_inode_field {guest_dir} mode 040755", write=True)
    if any(c in str(payload) for c in '\\"\n\r'):
        raise ValueError("payload path cannot contain quotes, backslashes or newlines")
    debugfs(image, f'write "{payload}" {guest_binary}', write=True)
    debugfs(image, f"set_inode_field {guest_binary} mode 0100755", write=True)
    dump = scoped(run / "injected-payload")
    debugfs(image, f'dump {guest_binary} "{dump}"')
    if digest(dump) != digest(payload):
        raise ValueError("injected payload hash differs from source")
    dump.unlink()
    return guest_binary, guest_dir



def stop_process(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=3)



def drive_guest(
    argv: list[str],
    shell: str,
    token: str,
    log_path: Path,
    ready: str,
    boot_timeout: float,
    timeout: float,
) -> tuple[str, int, str]:
    ready_re = re.compile(ready.encode())
    output = bytearray()
    reason = ""
    sent = False
    completed = False
    start = time.monotonic()
    deadline = start + boot_timeout

    with log_path.open("wb") as log:
        process = subprocess.Popen(
            argv,
            cwd=BASE,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        assert process.stdout is not None and process.stdin is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            try:
                while time.monotonic() < deadline:
                    if not selector.select(
                        timeout=min(0.25, max(0, deadline - time.monotonic()))
                    ):
                        if process.poll() is not None:
                            reason = "QEMU exited before shell exit marker"
                            break
                        continue
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        reason = "QEMU closed output before shell exit marker"
                        break
                    log.write(chunk)
                    log.flush()
                    output.extend(chunk)
                    permission_check(chunk.decode(errors="replace"))
                    if not sent and ready_re.search(output[-65536:]):
                        process.stdin.write((shell + "\n").encode())
                        process.stdin.flush()
                        sent = True
                        deadline = time.monotonic() + timeout
                    text = output.decode(errors="replace").replace("\r", "")
                    if re.search(
                        rf"(?m)^BPF_HOST_EXIT {re.escape(token)} [0-9]+\s*$", text
                    ):
                        completed = True
                        break
                    if re.search(r"panicked at|kernel panic|panic:|fatal trap", text, re.I):
                        reason = "kernel panic/fatal trap"
                        break
                if not completed and not reason:
                    reason = "payload timeout" if sent else "boot/shell prompt timeout"
            finally:
                stop_process(process)
                process.stdin.close()
                process.stdout.close()

    return output.decode(errors="replace"), process.returncode, reason



def probe_toolchain(arch: str | None = None) -> dict[str, bool | str]:
    """Probe host tools and guest compiler target capabilities."""
    status: dict[str, bool | str] = {}
    debugfs_bin = shutil.which("debugfs")
    status["debugfs"] = bool(debugfs_bin)

    # Check rustc nightly targets
    try:
        targets_out = command(["rustup", "+nightly", "target", "list", "--installed"])
        installed_targets = set(targets_out.splitlines())
    except PermissionError:
        raise
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        installed_targets = set()

    for a in ([arch] if arch else ARCHES):
        t = ARCHES[a]["target"]
        status[f"target_{a}"] = t in installed_targets
        q = shutil.which(ARCHES[a]["qemu"])
        status[f"qemu_{a}"] = bool(q)

    return status



def feed_analyzer(capture_path: Path) -> tuple[bool, str]:
    """Check format fixtures using the current analyzer, never a stale binary."""
    argv = ["cargo", "run", "--quiet", "-p", "bpf-analyzer", "--", str(capture_path), "--loss", "--table"]
    try:
        return True, command(argv, cwd=REPO, timeout=120)
    except PermissionError:
        raise
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        return False, str(error)


def sampling_command(action: str, arch: str, mode: str, args: argparse.Namespace) -> list[str]:
    """Route every runtime invocation through the actual consumer and exporter."""
    argv = [sys.executable, str(SAMPLING_DRIVER), action, "--arch", arch, "--mode", mode, "--archive"]
    if action == "guest":
        for option in ("kernel", "kernel_elf", "kernel_provenance", "image", "boot_timeout", "timeout", "fault", "ring_pages"):
            value = getattr(args, option, None)
            if value is not None:
                argv.extend(["--" + option.replace("_", "-"), str(value)])
    return argv


def run_sampling(action: str, arch: str, mode: str, args: argparse.Namespace) -> int:
    argv = sampling_command(action, arch, mode, args)
    print(shlex.join(argv), flush=True)
    # Keep live output and the child's status. In particular, missing tools,
    # missing samples and skipped runs cannot become a successful smoke run.
    return subprocess.run(argv, cwd=REPO).returncode


def gate(args: argparse.Namespace) -> int:
    if args.arch is None and any(getattr(args, key, None) is not None for key in ("kernel", "kernel_elf", "kernel_provenance", "image")):
        raise ValueError("--arch is required when overriding a kernel, symbols or image")
    arches = [args.arch] if args.arch else list(ARCHES)
    modes = [args.mode] if args.mode else ["task", "trace", "sched", "fault"]
    for arch in arches:
        for mode in modes:
            if run_sampling("guest", arch, mode, args) != 0:
                print(f"BPF capture gate failed: arch={arch} mode={mode}", file=sys.stderr)
                return 1
    print("BPF capture gate passed for the requested runs; no off-CPU parity claim")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    probe = sub.add_parser("probe", help="Probe host tools and guest compiler targets")
    probe.add_argument("--arch", choices=ARCHES)
    for name in ("build", "build-raw"):
        build = sub.add_parser(name, help="Build the real sampler with RAW archive export")
        build.add_argument("--arch", choices=ARCHES, required=True)
        build.add_argument("--mode", choices=MODES, default="task")
    for name in ("guest", "smoke", "gate"):
        runtime = sub.add_parser(name, help="Run real capture; gate/smoke default to task+trace+sched+fault on both architectures")
        runtime.add_argument("--arch", choices=ARCHES, required=name == "guest")
        runtime.add_argument("--mode", choices=MODES, default="task" if name == "guest" else None)
        runtime.add_argument("--kernel", type=Path)
        runtime.add_argument("--kernel-elf", type=Path)
        runtime.add_argument("--kernel-provenance", type=Path)
        runtime.add_argument("--ring-pages", type=int, choices=(1, 16), default=16)
        runtime.add_argument("--fault", choices=("none", "zero-producer", "zero-consumer", "export-overflow", "ring-overflow", "aborted"), default="none")
        runtime.add_argument("--image", "--primary", dest="image", type=Path)
        runtime.add_argument("--boot-timeout", type=float, default=90)
        runtime.add_argument("--timeout", type=float, default=120)
    sub.add_parser("fixture-check", help="Validate the static v1 format fixture offline, with no runtime claim")
    sub.add_parser("parity", help="Retired legacy gate; exits unsuccessfully with migration guidance")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "probe":
            print(json.dumps(probe_toolchain(args.arch), indent=2))
            return 0
        if args.command in ("build", "build-raw"):
            return run_sampling("build", args.arch, args.mode, args)
        if args.command == "guest":
            return run_sampling("guest", args.arch, args.mode, args)
        if args.command in ("smoke", "gate"):
            return gate(args)
        if args.command == "fixture-check":
            print("STATIC FORMAT FIXTURE: parser validation only; no runtime evidence")
            ok, report = feed_analyzer(FORMAT_FIXTURE)
            print(report)
            return int(not ok)
        if args.command == "parity":
            print("Legacy parity gate retired: its fixed records and default-zero counters were not runtime evidence. "
                  "Use 'gate' for real captures; complete off-CPU attribution/parity remains a separate gate.", file=sys.stderr)
            return 2
    except (OSError, ValueError, RuntimeError) as error:
        print(f"BPF capture command failed: {error}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
