#!/usr/bin/env python3
"""BPF guest sampler smoke harness and dual-architecture driver (#104).

Builds/injects a static BPF guest sampler payload, boots a PulseOS guest on
RISC-V64 and LoongArch64, collects session markers and exported capture artifacts,
preserves input image/hash integrity under snapshot semantics, and feeds the resulting
capture to bpf-analyzer (T13).
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
RAW_SOURCE = BASE / "guest_sampler.rs"
LINK_SCRIPT = BASE / "guest.ld"

LIFECYCLE_STAGES = (
    "fixture_open_load_attach",
    "workload_and_consume",
    "fixture_detach_close",
)

ARCHES = {
    "riscv64": {
        "machine": 243,
        "kernel": "kernel-rv",
        "primary": "rootfs-riscv64.img",
        "secondary": "disk.img",
        "qemu": "qemu-system-riscv64",
        "target": "riscv64gc-unknown-none-elf",
        "cc": (
            "riscv64-linux-musl-gcc",
            "riscv64-unknown-linux-musl-gcc",
            "riscv64-linux-gnu-gcc",
            "riscv64-unknown-linux-gnu-gcc",
        ),
    },
    "loongarch64": {
        "machine": 258,
        "kernel": "kernel-la",
        "primary": "rootfs-loongarch64.img",
        "secondary": "disk-la.img",
        "qemu": "qemu-system-loongarch64",
        "target": "loongarch64-unknown-none-softfloat",
        "cc": (
            "loongarch64-linux-musl-gcc",
            "loongarch64-unknown-linux-musl-gcc",
            "loongarch64-linux-gnu-gcc",
            "loongarch64-unknown-linux-gnu-gcc",
        ),
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


def check_payload_exists(path: Path) -> Path:
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(f"guest payload binary not found: {path}")
    return path


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


def extract_capture_artifact(text: str) -> tuple[bytes, str] | None:
    """Extract encoded binary capture artifact from guest output lines."""
    begin_match = re.search(r"BPF_CAPTURE_BEGIN bytes=(\d+) sha256=([0-9a-fA-F]{64})", text)
    if not begin_match:
        return None
    expected_len = int(begin_match.group(1))
    expected_sha = begin_match.group(2).lower()

    data_lines = []
    in_capture = False
    for line in text.splitlines():
        if "BPF_CAPTURE_BEGIN" in line:
            in_capture = True
            continue
        if "BPF_CAPTURE_END" in line:
            in_capture = False
            break
        if in_capture and line.startswith("BPF_CAPTURE_DATA "):
            data_lines.append(line.removeprefix("BPF_CAPTURE_DATA ").strip())

    hex_data = "".join(data_lines)
    try:
        raw_bytes = bytes.fromhex(hex_data)
    except Exception as e:
        raise ValueError(f"corrupted BPF_CAPTURE_DATA hex encoding: {e}") from e

    if len(raw_bytes) != expected_len:
        raise ValueError(
            f"extracted capture length mismatch: got {len(raw_bytes)}, expected {expected_len}"
        )
    actual_sha = hashlib.sha256(raw_bytes).hexdigest().lower()
    if actual_sha != expected_sha:
        raise ValueError(
            f"extracted capture SHA-256 mismatch: got {actual_sha}, expected {expected_sha}"
        )

    return raw_bytes, actual_sha


def validate_log(text: str, *, shell_token: str | None = None) -> list[str]:
    """Validate guest session lifecycle markers, capture framing, and shell status."""
    lines = [
        re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line).strip()
        for line in text.replace("\r", "").splitlines()
    ]
    errors = []

    if sum(line.startswith("BPF_SESSION_START ") for line in lines) != 1:
        errors.append("expected exactly one BPF_SESSION_START marker")

    if sum(line.startswith("BPF_SESSION_STOP ") for line in lines) != 1:
        errors.append("expected exactly one BPF_SESSION_STOP marker")

    for stage in LIFECYCLE_STAGES:
        if lines.count(f"BPF BEGIN {stage}") != 1:
            errors.append(f"missing or duplicate BEGIN marker: {stage}")
        if lines.count(f"BPF PASS {stage}") != 1:
            errors.append(f"missing or duplicate PASS marker: {stage}")

    if any(line.startswith("BPF FAIL ") for line in lines):
        errors.append("payload emitted BPF FAIL")

    if f"BPF SUMMARY pass={len(LIFECYCLE_STAGES)} fail=0 skip=0" not in lines:
        errors.append("missing functional BPF SUMMARY marker")

    if "BPF RESULT PASS functional_only=1" not in lines:
        errors.append("missing final functional BPF RESULT PASS marker")

    if shell_token:
        exits = [line for line in lines if line.startswith(f"BPF_HOST_EXIT {shell_token} ")]
        if exits != [f"BPF_HOST_EXIT {shell_token} 0"]:
            errors.append(f"missing, duplicate, or nonzero shell exit marker for token {shell_token}")

    if re.search(r"panicked at|kernel panic|panic:|fatal trap", text, re.I):
        errors.append("kernel panic or fatal trap detected in log")

    return errors


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


def qemu_command(
    arch: str, qemu: str, kernel: Path, primary: Path, secondary: Path
) -> list[str]:
    argv = [
        qemu,
        "-machine",
        "virt",
        "-kernel",
        str(kernel),
        "-m",
        "8G",
        "-nographic",
        "-smp",
        "8",
    ]
    if arch == "riscv64":
        argv += ["-bios", "default"]
    argv += ["-drive", f"file={primary},if=none,format=raw,id=x0,snapshot=on"]
    if arch == "riscv64":
        argv += [
            "-device",
            "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0",
            "-no-reboot",
            "-device",
            "virtio-net-device,netdev=net",
            "-netdev",
            "user,id=net",
        ]
    else:
        argv += [
            "-device",
            "virtio-blk-pci,drive=x0",
            "-no-reboot",
            "-device",
            "virtio-net-pci,netdev=net0",
            "-netdev",
            "user,id=net0",
        ]
    argv += [
        "-rtc",
        "base=utc",
        "-drive",
        f"file={secondary},if=none,format=raw,id=x1,snapshot=on",
        "-device",
    ]
    argv += (
        ["virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1"]
        if arch == "riscv64"
        else ["virtio-blk-pci,drive=x1"]
    )
    return argv + ["-monitor", "none", "-serial", "stdio"]


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


def feed_analyzer(capture_path: Path) -> tuple[bool, str]:
    """Feed capture artifact to T13 bpf-analyzer and verify loss report / event table."""
    analyzer_bin = REPO / "target" / "release" / "bpf-analyzer"
    if not analyzer_bin.is_file():
        # Fallback to cargo run if release binary not built
        cmd = ["cargo", "run", "--quiet", "-p", "bpf-analyzer", "--", str(capture_path), "--loss", "--table"]
    else:
        cmd = [str(analyzer_bin), str(capture_path), "--loss", "--table"]

    try:
        out = command(cmd, cwd=REPO, timeout=30)
        return True, out
    except Exception as e:
        return False, str(e)


def build_raw(arch: str) -> Path:
    target = ARCHES[arch]["target"]
    sysroot = Path(command(["rustc", "+nightly", "--print", "sysroot"]).strip())
    host = next(
        line.removeprefix("host: ")
        for line in command(["rustc", "+nightly", "-vV"]).splitlines()
        if line.startswith("host: ")
    )
    linker = sysroot / "lib" / "rustlib" / host / "bin" / "rust-lld"
    if not linker.is_file():
        raise ValueError(f"toolchain rust-lld unavailable: {linker}")

    out = scoped(BASE / "build" / arch / "guest_sampler.elf")
    out.parent.mkdir(parents=True, exist_ok=True)
    argv = [
        "rustc",
        "+nightly",
        "--edition=2024",
        "--crate-type=bin",
        "--target",
        target,
        "-C",
        "panic=abort",
        "-C",
        "opt-level=2",
        "-C",
        "relocation-model=static",
        "-C",
        "linker=" + str(linker),
        "-C",
        "link-arg=-T" + str(LINK_SCRIPT),
        "-C",
        "link-arg=--no-relax",
        "-o",
        str(out),
        str(RAW_SOURCE),
    ]
    print(shlex.join(argv), flush=True)
    text = command(argv, timeout=120)
    if text:
        print(text, end="")
    check_elf(out, arch)
    (out.parent / "build.json").write_text(
        json.dumps(
            {
                "command": argv,
                "source_sha256": digest(RAW_SOURCE),
                "link_script_sha256": digest(LINK_SCRIPT),
                "binary_sha256": digest(out),
            },
            indent=2,
        )
        + "\n"
    )
    print(f"Built BPF guest sampler: {out}")
    return out


def probe_toolchain(arch: str | None = None) -> dict[str, bool | str]:
    """Probe host tools and guest compiler target capabilities."""
    status: dict[str, bool | str] = {}
    clang = shutil.which("clang")
    status["clang"] = bool(clang)
    llvm_objdump = shutil.which("llvm-objdump")
    status["llvm_objdump"] = bool(llvm_objdump)
    debugfs_bin = shutil.which("debugfs")
    status["debugfs"] = bool(debugfs_bin)

    # Check rustc nightly targets
    try:
        targets_out = command(["rustup", "+nightly", "target", "list", "--installed"])
        installed_targets = set(targets_out.splitlines())
    except Exception:
        installed_targets = set()

    for a in ([arch] if arch else ARCHES):
        t = ARCHES[a]["target"]
        status[f"target_{a}"] = t in installed_targets
        q = shutil.which(ARCHES[a]["qemu"])
        status[f"qemu_{a}"] = bool(q)

    return status


def guest(args: argparse.Namespace) -> int:
    config = ARCHES[args.arch]
    tool_status = probe_toolchain(args.arch)
    if not tool_status[f"target_{args.arch}"]:
        print(
            f"SKIP: missing Rust nightly target {config['target']} for {args.arch}. "
            f"Install with: rustup +nightly target add {config['target']}",
            file=sys.stderr,
        )
        return 77

    qemu = args.qemu or shutil.which(config["qemu"])
    if not qemu:
        print(f"SKIP: {config['qemu']} unavailable", file=sys.stderr)
        return 77

    if not shutil.which("debugfs"):
        raise ValueError("debugfs unavailable; install e2fsprogs")

    kernel = (args.kernel or REPO / config["kernel"]).resolve(strict=True)
    paths = [
        args.primary or REPO / config["primary"],
        args.secondary or REPO / config["secondary"],
    ]
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        raise ValueError(f"missing guest image(s): {', '.join(missing)}")
    primary, secondary = map(check_image, paths)

    payload = (
        args.payload or BASE / "build" / args.arch / "guest_sampler.elf"
    ).resolve()
    if not payload.is_file():
        payload = build_raw(args.arch)
    check_elf(payload, args.arch)

    run = new_run(args.arch)
    inputs = {
        "kernel": kernel,
        "payload": payload,
        "primary": primary,
        "secondary": secondary,
    }
    before = {name: digest(path) for name, path in inputs.items()}

    kernel_copy = scoped(run / "kernel")
    shutil.copyfile(kernel, kernel_copy)
    if digest(kernel_copy) != before["kernel"]:
        raise ValueError("kernel changed while copying")

    pcopy = copy_image(primary, run, "primary.img")
    scopy = copy_image(secondary, run, "secondary.img")
    binary, guest_dir = inject(pcopy, payload, run)

    argv = qemu_command(args.arch, str(qemu), kernel_copy, pcopy, scopy)
    token = run.name.rsplit("-", 1)[-1]
    shell = (
        f"ulimit -c 0; cd {shlex.quote(guest_dir)} && {binary}; "
        f"status=$?; printf '\\nBPF_HOST_EXIT {token} %s\\n' \"$status\""
    )

    metadata = {
        "kind": "PulseOS BPF guest smoke",
        "arch": args.arch,
        "qemu_command": argv,
        "guest_command": shell,
        "inputs": {k: str(v) for k, v in inputs.items()},
        "input_sha256": before,
        "source_sha256": digest(RAW_SOURCE),
    }
    (run / "inputs.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(shlex.join(argv), flush=True)
    print(f"Guest shell command: {shell}\nLogs: {run / 'guest.log'}", flush=True)

    text, qemu_exit, reason = drive_guest(
        argv,
        shell,
        token,
        run / "guest.log",
        args.ready_regex,
        args.boot_timeout,
        args.timeout,
    )

    errors = validate_log(text, shell_token=token)
    if reason:
        errors.append(reason)

    capture_result = extract_capture_artifact(text)
    analyzer_output = ""
    if capture_result:
        raw_capture, cap_sha = capture_result
        capture_path = scoped(run / "capture.bin")
        capture_path.write_bytes(raw_capture)
        print(f"Exported BPF capture: {capture_path} ({len(raw_capture)} bytes, sha256={cap_sha})")
        ok, report = feed_analyzer(capture_path)
        analyzer_output = report
        if not ok:
            errors.append(f"bpf-analyzer validation failed: {report}")
        else:
            print("=== bpf-analyzer report ===")
            print(report)
    else:
        errors.append("missing or corrupted capture artifact in guest output")

    after = {name: digest(path) for name, path in inputs.items()}
    input_changes = [name for name in inputs if after[name] != before[name]]
    if any(name != "kernel" for name in input_changes) or digest(kernel_copy) != before["kernel"]:
        errors.append("non-kernel input hash changed during run or saved kernel hash mismatch")

    result = {
        **metadata,
        "qemu_exit": qemu_exit,
        "driver_reason": reason,
        "errors": errors,
        "input_sha256_after": after,
        "original_input_changes": input_changes,
        "functional_pass": not errors,
        "analyzer_output": analyzer_output,
    }
    (run / "result.json").write_text(json.dumps(result, indent=2) + "\n")

    for error in errors:
        print(f"Driver FAIL: {error}", file=sys.stderr)
    print(f"Guest result: {'FAIL' if errors else 'PASS'}; logs: {run}")
    return int(bool(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_probe = sub.add_parser("probe", help="Probe toolchain dependencies")
    p_probe.add_argument("--arch", choices=("riscv64", "loongarch64"))

    p_build = sub.add_parser("build-raw", help="Build raw freestanding guest sampler")
    p_build.add_argument("--arch", choices=("riscv64", "loongarch64"), required=True)

    p_guest = sub.add_parser("guest", help="Run BPF guest smoke under QEMU")
    p_guest.add_argument("--arch", choices=("riscv64", "loongarch64"), required=True)
    p_guest.add_argument("--kernel", type=Path)
    p_guest.add_argument("--primary", type=Path)
    p_guest.add_argument("--secondary", type=Path)
    p_guest.add_argument("--payload", type=Path)
    p_guest.add_argument("--qemu")
    p_guest.add_argument("--ready-regex", default=r"(?:^|[\r\n])[^\r\n]*[#$] ?$")
    p_guest.add_argument("--boot-timeout", type=float, default=60)
    p_guest.add_argument("--timeout", type=float, default=90)

    p_smoke = sub.add_parser("smoke", help="Run full dual-architecture BPF smoke")
    p_smoke.add_argument("--boot-timeout", type=float, default=60)
    p_smoke.add_argument("--timeout", type=float, default=90)

    args = parser.parse_args()

    if args.command == "probe":
        status = probe_toolchain(args.arch)
        print(json.dumps(status, indent=2))
        return 0
    elif args.command == "build-raw":
        build_raw(args.arch)
        return 0
    elif args.command == "guest":
        return guest(args)
    elif args.command == "smoke":
        failures = 0
        for arch in ("riscv64", "loongarch64"):
            print(f"\n================ Running BPF Smoke for {arch} ================")
            g_args = argparse.Namespace(
                arch=arch,
                kernel=None,
                primary=None,
                secondary=None,
                payload=None,
                qemu=None,
                ready_regex=r"(?:^|[\r\n])[^\r\n]*[#$] ?$",
                boot_timeout=args.boot_timeout,
                timeout=args.timeout,
            )
            res = guest(g_args)
            if res != 0 and res != 77:
                failures += 1
        return failures

    return 0


if __name__ == "__main__":
    sys.exit(main())

