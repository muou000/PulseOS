#!/usr/bin/env python3
"""Issue #178 AT_HWCAP regression test harness.

Injects a bare-metal Linux-ABI guest binary into an isolated copy of disk-la.img,
boots QEMU LoongArch, reads AT_HWCAP from initial stack auxv, compares with CPUCFG1.UAL,
and verifies correct capability reporting.
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
SOURCE = BASE / "guest.rs"
LINKER_SCRIPT = BASE / "guest.ld"

LOONGARCH_MACHINE = 258
LOONGARCH_TARGET = "loongarch64-unknown-none-softfloat"
LOONGARCH_KERNEL = "kernel-la"
LOONGARCH_PRIMARY = "disk-la.img"
LOONGARCH_QEMU = "qemu-system-loongarch64"


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


def command(argv: list[str], *, timeout: float = 60) -> str:
    result = subprocess.run(
        argv, cwd=BASE, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout
    )
    permission_check(result.stdout)
    if result.returncode:
        raise RuntimeError(
            f"command exited {result.returncode}: {shlex.join(argv)}\n{result.stdout[-4000:]}"
        )
    return result.stdout


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


def check_elf(path: Path) -> None:
    path = path.resolve(strict=True)
    with path.open("rb") as stream:
        header = stream.read(64)
    if len(header) < 64 or header[:4] != b"\x7fELF":
        raise ValueError(f"not an ELF binary: {path}")
    if header[4] != 2 or header[5] != 1:
        raise ValueError("payload must be 64-bit little-endian ELF")
    machine = struct.unpack_from("<H", header, 18)[0]
    if machine != LOONGARCH_MACHINE:
        raise ValueError(f"ELF e_machine={machine} expected {LOONGARCH_MACHINE} for loongarch64")


def discover_rust_lld() -> Path:
    sysroot = Path(command(["rustc", "+nightly", "--print", "sysroot"]).strip())
    host = next(
        line.removeprefix("host: ")
        for line in command(["rustc", "+nightly", "-vV"]).splitlines()
        if line.startswith("host: ")
    )
    linker = sysroot / "lib" / "rustlib" / host / "bin" / "rust-lld"
    if not linker.is_file():
        raise ValueError(f"toolchain rust-lld unavailable: {linker}")
    return linker


def build_raw() -> Path:
    out_dir = scoped(BASE / "build" / "loongarch64")
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / "guest-raw.elf"
    linker = discover_rust_lld()
    argv = [
        "rustc",
        "+nightly",
        "--edition=2024",
        "--crate-type=bin",
        "--target",
        LOONGARCH_TARGET,
        "-C",
        "panic=abort",
        "-C",
        "opt-level=2",
        "-C",
        "relocation-model=static",
        "-C",
        f"linker={linker}",
        "-C",
        f"link-arg=-T{LINKER_SCRIPT}",
        "-C",
        "link-arg=--no-relax",
        "-o",
        str(binary),
        str(SOURCE),
    ]
    command(argv, timeout=60)
    check_elf(binary)
    return binary


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
    guest_dir = f"/hwcap-{run.name.rsplit('-', 1)[-1]}"
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


def qemu_command(qemu: str, kernel: Path, primary: Path) -> list[str]:
    return [
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
        "-drive",
        f"file={primary},if=none,format=raw,id=x0,snapshot=on",
        "-device",
        "virtio-blk-pci,drive=x0",
        "-no-reboot",
        "-device",
        "virtio-net-pci,netdev=net0",
        "-netdev",
        "user,id=net0",
        "-rtc",
        "base=utc",
        "-monitor",
        "none",
        "-serial",
        "stdio",
    ]


def validate_log(text: str, shell_token: str | None = None) -> list[str]:
    lines = [
        re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line).strip() for line in text.replace("\r", "").splitlines()
    ]
    errors: list[str] = []
    if "HWCAP START version=1" not in lines:
        errors.append("missing start banner")
    if "HWCAP BEGIN check_auxv_hwcap" not in lines:
        errors.append("missing case begin marker")
    if "HWCAP PASS check_auxv_hwcap" not in lines:
        errors.append("missing case pass marker")
    if "HWCAP RESULT PASS" not in lines:
        errors.append("missing suite pass marker")
    if any(line.startswith("HWCAP FAIL") for line in lines):
        errors.append("explicit failure marker in output")
    if shell_token:
        exits = [line for line in lines if line.startswith(f"HWCAP_HOST_EXIT {shell_token} ")]
        if exits != [f"HWCAP_HOST_EXIT {shell_token} 0"]:
            errors.append("missing/duplicate/nonzero shell exit marker")
    if re.search(r"panicked at|kernel panic|panic:|fatal trap", text, re.I):
        errors.append("kernel panic/fatal trap in log")
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
                    if not selector.select(timeout=min(0.25, max(0, deadline - time.monotonic()))):
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
                    if re.search(rf"(?m)^HWCAP_HOST_EXIT {re.escape(token)} [0-9]+\s*$", text):
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


def guest(args: argparse.Namespace) -> int:
    kernel = (args.kernel or REPO / LOONGARCH_KERNEL).resolve(strict=True)
    primary_path = args.primary or REPO / LOONGARCH_PRIMARY
    if not primary_path.is_file():
        raise ValueError(f"missing guest primary image: {primary_path}")
    primary = check_image(primary_path)

    payload = build_raw()

    qemu = args.qemu or shutil.which(LOONGARCH_QEMU)
    if not qemu:
        raise ValueError(f"{LOONGARCH_QEMU} unavailable")
    if not shutil.which("debugfs"):
        raise ValueError("debugfs unavailable")

    run = new_run("loongarch64")
    inputs = {"kernel": kernel, "payload": payload, "primary": primary}
    before = {name: digest(path) for name, path in inputs.items()}

    kernel_copy = scoped(run / "kernel")
    shutil.copyfile(kernel, kernel_copy)
    pcopy = copy_image(primary, run, "primary.img")

    binary, guest_dir = inject(pcopy, payload, run)
    argv = qemu_command(str(qemu), kernel_copy, pcopy)
    token = run.name.rsplit("-", 1)[-1]

    payload_argv = [binary]
    shell = (
        "ulimit -c 0; cd "
        + shlex.quote(guest_dir)
        + " && "
        + shlex.join(payload_argv)
        + f"; hwcap_status=$?; printf '\\nHWCAP_HOST_EXIT {token} %s\\n' \"$hwcap_status\""
    )

    metadata = {
        "kind": "PulseOS HWCAP guest check",
        "arch": "loongarch64",
        "qemu_command": argv,
        "guest_command": shell,
        "inputs": {k: str(v) for k, v in inputs.items()},
        "input_sha256": before,
        "source_sha256": digest(SOURCE),
        "qemu_version": command([str(qemu), "--version"]).splitlines()[0],
    }
    (run / "inputs.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(shlex.join(argv), flush=True)
    print(f"Guest shell command: {shell}\nLogs: {run / 'guest.log'}", flush=True)

    text, qemu_exit, reason = drive_guest(
        argv, shell, token, run / "guest.log", args.ready_regex, args.boot_timeout, args.timeout
    )
    errors = validate_log(text, shell_token=token)
    if reason:
        errors.append(reason)

    result = {
        **metadata,
        "qemu_exit": qemu_exit,
        "driver_reason": reason,
        "errors": errors,
        "functional_pass": not errors,
    }
    (run / "result.json").write_text(json.dumps(result, indent=2) + "\n")

    for line in text.replace("\r", "").splitlines():
        if line.startswith("HWCAP ") or line.startswith("HWCAP_HOST_EXIT "):
            print(line, flush=True)

    print(f"Guest result: {'FAIL: ' + '; '.join(errors) if errors else 'PASS'}; logs: {run}")
    return int(bool(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("build-raw", help="compile raw LoongArch guest ELF")

    g = sub.add_parser("guest", help="run guest check under QEMU LoongArch")
    g.add_argument("--kernel", type=Path)
    g.add_argument("--primary", type=Path)
    g.add_argument("--qemu")
    g.add_argument("--boot-timeout", type=float, default=60)
    g.add_argument("--timeout", type=float, default=30)
    g.add_argument("--ready-regex", default=r"(?:^|[\r\n])[^\r\n]*[#$] ?$")

    args = parser.parse_args()
    if args.command == "build-raw":
        out = build_raw()
        print(f"Built loongarch64 guest binary: {out}")
        return 0
    elif args.command == "guest":
        return guest(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
