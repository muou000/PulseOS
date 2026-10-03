#!/usr/bin/env python3
"""Issue #67 payload builder, Linux smoke, and isolated-image QEMU driver.

All generated files live under this directory. No mounts, sudo, kernel builds,
rootfs overlay edits, or original-image writes. Run --help for commands.
Guest input images must be raw, unpartitioned ext2/3/4 filesystems for debugfs.
The primary device is the rootfs. Use --bootstrap with raw6 when its archived
/bin/sh cannot boot; only the run image copy receives the minimal console.
Build-raw uses installed nightly bare-metal targets and no libc/cross-gcc.
Fault injection is an explicit SKIP, optionally a hard failure with
--require-fault-injection. A zero result proves only the functional payload.
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
SOURCE = BASE / "mapped_lifecycle.c"
RAW_SOURCE = BASE / "guest.rs"
RAW_CASES = (
    "raw_shared_alias_readback", "raw_private_cow_isolation",
    "raw_fork_pipe_shared_private", "raw_partial_unmap_sigsegv",
    "raw_fixed_replace_noreplace", "raw_msync_readonly_errors",
)
CASES = (
    "shared_visibility_readback", "private_file_isolation",
    "fork_shared_private_cow", "partial_munmap", "process_exit_writeback",
    "map_fixed_tlb_visibility", "fault_replacement_race",
    "mapped_write_checkpoint_race",
)
ARCHES = {
    "riscv64": {
        "machine": 243, "kernel": "kernel-rv", "primary": "sdcard-rv-pub.img",
        "secondary": "disk.img", "qemu": "qemu-system-riscv64",
        "cc": ("riscv64-linux-musl-gcc", "riscv64-unknown-linux-musl-gcc",
               "riscv64-linux-gnu-gcc", "riscv64-unknown-linux-gnu-gcc"),
    },
    "loongarch64": {
        "machine": 258, "kernel": "kernel-la", "primary": "sdcard-la-pub.img",
        "secondary": "disk-la.img", "qemu": "qemu-system-loongarch64",
        "cc": ("loongarch64-linux-musl-gcc", "loongarch64-unknown-linux-musl-gcc",
               "loongarch64-linux-gnu-gcc", "loongarch64-unknown-linux-gnu-gcc"),
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
    return Path(tempfile.mkdtemp(prefix=f"{label}-{time.strftime('%Y%m%d-%H%M%S')}-",
                                 dir=parent))


def permission_check(text: str) -> None:
    if re.search(r"permission denied|read-only file system|operation not permitted", text, re.I):
        raise PermissionError("tool reported a permission or read-only filesystem error; "
                              "fix permissions before retrying\n" + text[-2000:])


def command(argv: list[str], *, timeout: float = 60) -> str:
    result = subprocess.run(argv, cwd=BASE, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout)
    permission_check(result.stdout)
    if result.returncode:
        raise RuntimeError(f"command exited {result.returncode}: {shlex.join(argv)}\n"
                           f"{result.stdout[-4000:]}")
    return result.stdout


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


def check_elf(path: Path, arch: str) -> None:
    """Reject wrong ABI/arch and PT_INTERP; guests get a static ELF payload."""
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
            raise ValueError("guest payload has PT_INTERP; use a static C build or build-raw")
        if not any(ph[0] == 1 and ph[2] <= phoff and
                   phoff + entsize * count <= ph[2] + ph[5] for ph in program_headers):
            raise ValueError("program headers must be within PT_LOAD for the PulseOS ELF parser")


def build(arch: str, cc: str | None = None) -> Path:
    candidates = ("cc", "gcc") if arch == "host" else ARCHES[arch]["cc"]
    compiler = shlex.split(cc) if cc else next(
        ([path] for name in candidates if (path := shutil.which(name))), None)
    if not compiler:
        raise ValueError(f"no {arch} C compiler in PATH; use --cc /absolute/path/to/cross-gcc")
    out = scoped(BASE / "build" / arch / "payload")
    out.parent.mkdir(parents=True, exist_ok=True)
    argv = [*compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread"]
    if arch != "host":
        argv.append("-static")
    argv += [str(SOURCE), "-o", str(out)]
    print(shlex.join(argv), flush=True)
    text = command(argv, timeout=120)
    if text:
        print(text, end="")
    if arch != "host":
        check_elf(out, arch)
    print(f"Built {out}")
    return out


def build_raw(arch: str, bootstrap: bool = False) -> Path:
    target = {"riscv64": "riscv64gc-unknown-none-elf",
              "loongarch64": "loongarch64-unknown-none-softfloat"}[arch]
    sysroot = Path(command(["rustc", "+nightly", "--print", "sysroot"]).strip())
    host = next(line.removeprefix("host: ") for line in
                command(["rustc", "+nightly", "-vV"]).splitlines() if line.startswith("host: "))
    linker = sysroot / "lib" / "rustlib" / host / "bin" / "rust-lld"
    if not linker.is_file():
        raise ValueError(f"toolchain rust-lld unavailable: {linker}")
    out = scoped(BASE / "build" / arch / ("bootstrap.elf" if bootstrap else "guest-raw.elf"))
    out.parent.mkdir(parents=True, exist_ok=True)
    argv = ["rustc", "+nightly", "--edition=2024", "--crate-type=bin", "--target", target,
            "-C", "panic=abort", "-C", "opt-level=2", "-C", "relocation-model=static",
            "-C", "linker=" + str(linker), "-C", "link-arg=-T" + str(BASE / "guest.ld"),
            "-C", "link-arg=--no-relax", "-o", str(out), str(RAW_SOURCE)]
    if bootstrap:
        argv += ["--cfg", "bootstrap", "-A", "dead_code"]
    print(shlex.join(argv), flush=True)
    text = command(argv, timeout=120)
    if text:
        print(text, end="")
    check_elf(out, arch)
    (out.parent / ("bootstrap-build.json" if bootstrap else "raw-build.json")).write_text(json.dumps(
        {"command": argv, "source_sha256": digest(RAW_SOURCE),
         "link_script_sha256": digest(BASE / "guest.ld"), "binary_sha256": digest(out)},
        indent=2) + "\n")
    print(f"Built raw Linux-syscall guest ELF: {out}")
    return out


def validate_log(text: str, *, shell_token: str | None = None,
                 require_faults: bool = False, suite: str = "c8") -> list[str]:
    """Only entire, emitted lines count; shell input echo is never evidence."""
    lines = [re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line).strip()
             for line in text.replace("\r", "").splitlines()]
    errors = []
    cases = RAW_CASES if suite == "raw6" else CASES
    start = "MLC START version=2 suite=raw6 " if suite == "raw6" else "MLC START version=1 "
    if sum(line.startswith(start) for line in lines) != 1:
        errors.append("expected exactly one matching payload START marker")
    for case in cases:
        if lines.count(f"MLC BEGIN {case}") != 1:
            errors.append(f"missing/duplicate BEGIN marker: {case}")
        if lines.count(f"MLC PASS {case}") != 1:
            errors.append(f"missing/duplicate PASS marker: {case}")
    if any(line.startswith("MLC FAIL ") for line in lines):
        errors.append("payload emitted FAIL")
    skips = 2 if suite == "raw6" else 1
    if f"MLC SUMMARY pass={len(cases)} fail=0 skip={skips}" not in lines:
        errors.append(f"missing functional summary ({len(cases)} passes, {skips} unsupported seams)")
    result_marker = "MLC RESULT PASS functional_only=1" + (" suite=raw6" if suite == "raw6" else "")
    if result_marker not in lines:
        errors.append("missing final functional PASS")
    if suite == "raw6" and "MLC SKIP raw_mlocked_ebusy optional mlock semantics not exercised" not in lines:
        errors.append("missing optional mlock SKIP marker")
    if "MLC SKIP sync_failure_reset_refusal no integration FileNode fault/power hook" not in lines:
        errors.append("missing honest fault-injection SKIP marker")
    if require_faults:
        errors.append("sync failure/reset refusal require integration FileNode and power mocks")
    if shell_token:
        exits = [line for line in lines if line.startswith(f"MLC_HOST_EXIT {shell_token} ")]
        if exits != [f"MLC_HOST_EXIT {shell_token} 0"]:
            errors.append("missing/duplicate/nonzero shell exit marker")
    if re.search(r"panicked at|kernel panic|panic:|fatal trap", text, re.I):
        errors.append("kernel panic/fatal trap in log")
    return errors


def stop_process(process: subprocess.Popen) -> None:
    # Dedicated process group: also reap a hung host payload's fork children.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    # The group can outlive its leader after a failed fork assertion/watchdog.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=3)


def host(args: argparse.Namespace) -> int:
    payload = build("host", args.cc)
    run = new_run("linux-host")
    argv = [str(payload), "--dir", str(run), "--iterations", str(args.iterations),
            "--timeout", str(args.case_timeout)]
    if args.require_fault_injection:
        argv.append("--require-fault-injection")
    print("Linux-host smoke only; this is not PulseOS guest evidence.", flush=True)
    print(shlex.join(argv), flush=True)
    timed_out = False
    with (run / "host.log").open("wb") as log:
        process = subprocess.Popen(argv, cwd=run, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            stop_process(process)
    text = (run / "host.log").read_text(errors="replace")
    print(text, end="")
    errors = validate_log(text, require_faults=args.require_fault_injection)
    if timed_out or process.returncode != 0:
        errors.append(f"host payload exit={process.returncode} timed_out={timed_out}")
    result = {"kind": "Linux-host smoke only", "command": argv,
              "exit": process.returncode, "timed_out": timed_out, "errors": errors,
              "unsupported": ["sync_failure_reset_refusal"],
              "source_sha256": digest(SOURCE), "payload_sha256": digest(payload)}
    (run / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Host result: {'FAIL' if errors else 'PASS functional_only=1'}; logs: {run}")
    return int(bool(errors))


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
    # Sparse/reflink copy; subsequent debugfs writes affect only the copy.
    command(["cp", "--reflink=auto", "--sparse=always", "--", str(source), str(dest)],
            timeout=300)
    # A read-only original can safely produce a writable copy owned by this user.
    dest.chmod(dest.stat().st_mode | 0o600)
    return dest


def debugfs(image: Path, request: str, *, write: bool = False) -> str:
    if write:
        scoped(image)
    tool = shutil.which("debugfs")
    if not tool:
        raise ValueError("debugfs unavailable; install e2fsprogs before running")
    argv = [tool, *( ["-w"] if write else []), "-R", request, str(image)]
    text = command(argv)
    # debugfs often exits 0 even when a request failed.
    if re.search(r"not found|no such file|file exists|usage:|invalid|short read|"
                 r"filesystem not open|could not|while (?:opening|writing|reading|looking)|"
                 r"no space|error", text, re.I):
        raise ValueError(f"debugfs request failed: {request}\n{text}")
    return text


def inject(image: Path, payload: Path, run: Path) -> tuple[str, str]:
    guest_dir = f"/mapped-lifecycle-{run.name.rsplit('-', 1)[-1]}"
    guest_binary = guest_dir + "/payload"
    # debugfs does not follow merged-usr symlink components (/bin -> usr/bin).
    # The actual /bin/sh is resolved by the guest; the prompt deadline verifies boot.
    debugfs(image, "stat /")
    debugfs(image, "mkdir " + guest_dir, write=True)
    debugfs(image, f'set_inode_field {guest_dir} mode 040755', write=True)
    # debugfs uses double quotes, not shell quoting. Reject characters it cannot quote.
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


def install_bootstrap(image: Path, bootstrap: Path, run: Path) -> None:
    """Change /bin/sh only on the fresh run copy; archived shell stays untouched."""
    guest_path = "/mapped-lifecycle-bootstrap"
    debugfs(image, f'write "{bootstrap}" {guest_path}', write=True)
    debugfs(image, f"set_inode_field {guest_path} mode 0100755", write=True)
    # Both local rootfs archives use /bin -> usr/bin and /usr/bin/sh is a symlink.
    debugfs(image, "rm /usr/bin/sh", write=True)
    debugfs(image, "symlink /usr/bin/sh /mapped-lifecycle-bootstrap", write=True)
    dumped = scoped(run / "injected-bootstrap")
    debugfs(image, f'dump {guest_path} "{dumped}"')
    if digest(dumped) != digest(bootstrap):
        raise ValueError("injected bootstrap hash differs from source")
    dumped.unlink()


def qemu_command(arch: str, qemu: str, kernel: Path,
                 primary: Path, secondary: Path) -> list[str]:
    argv = [qemu, "-machine", "virt", "-kernel", str(kernel), "-m", "8G",
            "-nographic", "-smp", "8"]
    if arch == "riscv64":
        argv += ["-bios", "default"]
    argv += ["-drive", f"file={primary},if=none,format=raw,id=x0,snapshot=on"]
    if arch == "riscv64":
        argv += ["-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0",
                 "-no-reboot", "-device", "virtio-net-device,netdev=net",
                 "-netdev", "user,id=net"]
    else:
        argv += ["-device", "virtio-blk-pci,drive=x0", "-no-reboot",
                 "-device", "virtio-net-pci,netdev=net0", "-netdev", "user,id=net0"]
    argv += ["-rtc", "base=utc", "-drive",
             f"file={secondary},if=none,format=raw,id=x1,snapshot=on", "-device"]
    argv += (["virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1"] if arch == "riscv64"
             else ["virtio-blk-pci,drive=x1"])
    # Keep prescribed devices/resources. Disable monitor multiplexing for shell stdio.
    return argv + ["-monitor", "none", "-serial", "stdio"]


def drive_guest(argv: list[str], shell: str, token: str, log_path: Path,
                ready: str, boot_timeout: float, timeout: float) -> tuple[str, int, str]:
    ready_re = re.compile(ready.encode())
    output = bytearray()
    reason = ""
    sent = False
    completed = False
    start = time.monotonic()
    deadline = start + boot_timeout
    with log_path.open("wb") as log:
        process = subprocess.Popen(argv, cwd=BASE, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)
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
                    # Anchored: an echoed command containing printf is not an exit marker.
                    if re.search(rf"(?m)^MLC_HOST_EXIT {re.escape(token)} [0-9]+\s*$", text):
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
    config = ARCHES[args.arch]
    kernel = (args.kernel or REPO / config["kernel"]).resolve(strict=True)
    paths = [args.primary or REPO / config["primary"],
             args.secondary or REPO / config["secondary"]]
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        raise ValueError("missing guest image(s): " + ", ".join(missing) +
                         "\nUse discover to list availability. Supply existing compatible raw ext4 "
                         "images with --primary /path/to/rootfs.img --secondary /path/to/data.img; "
                         "the driver copies both. No automatic image fallback or original-image edits.")
    primary, secondary = map(check_image, paths)
    default_binary = "guest-raw.elf" if args.suite == "raw6" else "payload"
    payload = (args.payload or BASE / "build" / args.arch / default_binary).resolve(strict=True)
    check_elf(payload, args.arch)
    qemu = args.qemu or shutil.which(config["qemu"])
    if not qemu:
        raise ValueError(f"{config['qemu']} unavailable")
    if not shutil.which("debugfs"):
        raise ValueError("debugfs unavailable")
    re.compile(args.ready_regex)
    bootstrap = args.bootstrap.resolve(strict=True) if args.bootstrap else None
    if bootstrap:
        if args.suite != "raw6":
            raise ValueError("minimal bootstrap protocol is supported only for raw6")
        check_elf(bootstrap, args.arch)
    run = new_run(args.arch)
    inputs = {"kernel": kernel, "payload": payload, "primary": primary, "secondary": secondary}
    if bootstrap:
        inputs["bootstrap"] = bootstrap
    before = {name: digest(path) for name, path in inputs.items()}
    kernel_copy = scoped(run / "kernel")
    shutil.copyfile(kernel, kernel_copy)
    if digest(kernel_copy) != before["kernel"]:
        raise ValueError("kernel changed while copying; retry once its build completes")
    pcopy = copy_image(primary, run, "primary.img")
    scopy = copy_image(secondary, run, "secondary.img")
    binary, guest_dir = inject(pcopy, payload, run)
    if bootstrap:
        install_bootstrap(pcopy, bootstrap, run)
    argv = qemu_command(args.arch, str(qemu), kernel_copy, pcopy, scopy)
    token = run.name.rsplit("-", 1)[-1]
    if args.suite == "raw6":
        payload_argv = [binary]
    else:
        payload_argv = [binary, "--dir", guest_dir, "--iterations", str(args.iterations),
                        "--timeout", str(args.case_timeout)]
        if args.require_fault_injection:
            payload_argv.append("--require-fault-injection")
    shell = ("ulimit -c 0; cd " + shlex.quote(guest_dir) + " && " + shlex.join(payload_argv) +
             f"; mlc_status=$?; printf '\\nMLC_HOST_EXIT {token} %s\\n' \"$mlc_status\"")
    if bootstrap:
        shell = f"MLC_RUN {binary} {guest_dir} {token}"
    metadata = {"kind": "PulseOS guest", "arch": args.arch, "suite": args.suite, "qemu_command": argv,
                "guest_command": shell, "inputs": {k: str(v) for k, v in inputs.items()},
                "input_sha256": before,
                "source_sha256": digest(RAW_SOURCE if args.suite == "raw6" else SOURCE),
                "qemu_version": command([str(qemu), "--version"]).splitlines()[0],
                "unsupported": (["sync_failure_reset_refusal", "raw_mlocked_ebusy",
                                 "concurrent_checkpoint_preparation", "remote_cpu_tlb"]
                                if args.suite == "raw6" else ["sync_failure_reset_refusal"]),
                "note": "snapshot=on; runtime writes not persisted to copies; readback is cache-visible"}
    (run / "inputs.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(shlex.join(argv), flush=True)
    print(f"Guest shell command: {shell}\nLogs: {run / 'guest.log'}", flush=True)
    text, qemu_exit, reason = drive_guest(
        argv, shell, token, run / "guest.log", args.ready_regex, args.boot_timeout, args.timeout)
    errors = validate_log(text, shell_token=token, require_faults=args.require_fault_injection,
                          suite=args.suite)
    if reason:
        errors.append(reason)
    # QEMU was intentionally terminated after collecting a complete shell exit marker.
    after = {name: digest(path) for name, path in inputs.items()}
    input_changes = [name for name in inputs if after[name] != before[name]]
    # A parent can rebuild its original kernel; execution used the saved matching copy.
    if any(name != "kernel" for name in input_changes) or digest(kernel_copy) != before["kernel"]:
        errors.append("non-kernel input hash changed during run or saved kernel hash mismatch")
    result = {**metadata, "qemu_exit": qemu_exit, "driver_reason": reason,
              "errors": errors, "input_sha256_after": after, "original_input_changes": input_changes,
              "functional_pass": not errors, "issue67_complete": False}
    (run / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    for line in text.replace("\r", "").splitlines():
        if line.startswith("MLC ") or line.startswith("MLC_HOST_EXIT "):
            print(line)
    for error in errors:
        print("Driver FAIL: " + error, file=sys.stderr)
    print(f"Guest result: {'FAIL' if errors else 'PASS functional_only=1'}; logs: {run}")
    return int(bool(errors))


def safe_image_commands(arch: str) -> str:
    """Print an exact unprivileged fallback; never run or overwrite it implicitly."""
    archives = [REPO / "rootfs" / "base" / f"base-rootfs-{arch}.tar.{ext}"
                for ext in ("gz", "xz")]
    archive = next((p for p in archives if p.is_file()), None)
    if archive is None:
        return "No local rootfs archive; supply existing compatible images explicitly."
    root = BASE / "images" / arch
    lines = [
        "# Unexecuted archive fallback; all outputs under tests/mapped_lifecycle.",
        "# Extraction may carry restrictive modes. Stop on permission failure; do not bypass it.",
        "set -euo pipefail",
        "mkdir -p " + shlex.quote(str(root.parent)),
        "mkdir " + shlex.quote(str(root)) + " # fail if already present; never overwrite",
        "mkdir " + shlex.quote(str(root / "stage")),
        shlex.join(["tar", "--no-same-owner", "-xf", str(archive), "-C", str(root / "stage")]),
        shlex.join(["truncate", "-s", "512M", str(root / "primary.img")]),
        shlex.join(["mke2fs", "-q", "-F", "-t", "ext4", "-O", "^has_journal,^metadata_csum",
                    "-d", str(root / "stage"), str(root / "primary.img")]),
        shlex.join(["truncate", "-s", "128M", str(root / "secondary.img")]),
        shlex.join(["mke2fs", "-q", "-F", "-t", "ext4", "-O", "^has_journal,^metadata_csum",
                    str(root / "secondary.img")]),
        "# Archive shell/libc compatibility still requires a real guest boot.",
        shlex.join(["python3", str(BASE / "run.py"), "guest", "--arch", arch,
                    "--primary", str(root / "primary.img"), "--secondary", str(root / "secondary.img")]),
    ]
    return "\n".join(lines)


def discover() -> int:
    print(f"Repository: {REPO}\nOutputs stay under: {BASE}")
    for tool in ("cc", "gcc", "python3", "debugfs", "mke2fs",
                 "qemu-system-riscv64", "qemu-system-loongarch64"):
        print(f"Tool {tool}: {shutil.which(tool) or 'MISSING'}")
    for arch, config in ARCHES.items():
        print(f"\n{arch}:")
        for name in (config["kernel"], config["primary"], config["secondary"],
                     "sdcard-rv.img" if arch == "riscv64" else "sdcard-la.img",
                     f"arceos/{config['secondary']}"):
            path = REPO / name
            print(f"  {'available' if path.is_file() else 'MISSING'} {path}")
        for compiler in config["cc"]:
            print(f"  compiler {compiler}: {shutil.which(compiler) or 'MISSING'}")
        for ext in ("gz", "xz"):
            archive = REPO / "rootfs" / "base" / f"base-rootfs-{arch}.tar.{ext}"
            if archive.is_file():
                print(f"  available archive {archive} (not a filesystem image)")
    print("\nSafe path: provide compatible unpartitioned ext4 root/data images explicitly "
          "with guest --primary ... --secondary ...; both are copied before any write. "
          "No automatic sdcard substitution. The C payload needs cross-compilers; "
          "build-raw uses the installed nightly bare-metal Rust targets without libc.")
    for arch in ARCHES:
        print(f"\nExact archive fallback for {arch} (not executed):\n{safe_image_commands(arch)}")
    return 0


def bounded(value: str) -> int:
    n = int(value)
    if n < 1 or n > 1024:
        raise argparse.ArgumentTypeError("must be between 1 and 1024")
    return n


def seconds(value: str) -> int:
    n = int(value)
    if not 1 <= n <= 600:
        raise argparse.ArgumentTypeError("must be between 1 and 600 seconds")
    return n


def options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--iterations", type=bounded, default=32)
    parser.add_argument("--case-timeout", type=seconds, default=60,
                        help="payload watchdog seconds per case")
    parser.add_argument("--timeout", type=seconds, default=180,
                        help="overall payload deadline in seconds")
    parser.add_argument("--require-fault-injection", action="store_true",
                        help="fail on the unsupported sync failure/reset refusal seam")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("discover", help="list compilers, prescribed images and alternatives")
    b = sub.add_parser("build", help="compile libc/pthreads payload; guest builds are static")
    b.add_argument("--arch", choices=("host", *ARCHES), required=True)
    b.add_argument("--cc", help="compiler path/command, e.g. /opt/cross/bin/riscv64-linux-musl-gcc")
    raw = sub.add_parser("build-raw", help="compile six-case no_std Linux-syscall guest ELF using nightly")
    raw.add_argument("--arch", choices=ARCHES, required=True)
    raw.add_argument("--bootstrap", action="store_true", help="build minimal MLC_RUN console as bootstrap.elf")
    h = sub.add_parser("host", help="compile/run Linux smoke (not guest proof)")
    h.add_argument("--cc")
    options(h)
    g = sub.add_parser("guest", help="copy images, inject via debugfs, run QEMU via shell stdio")
    g.add_argument("--arch", choices=ARCHES, required=True)
    g.add_argument("--payload", "--binary", dest="payload", type=Path,
                   help="existing static ELF64 binary; guest never invokes a compiler")
    g.add_argument("--suite", choices=("c8", "raw6"), default="c8",
                   help="expected marker contract: C/pthreads eight or no_std raw-syscall six")
    g.add_argument("--bootstrap", type=Path,
                   help="install raw MLC_RUN console as /bin/sh only in the run copy (raw6)")
    g.add_argument("--kernel", type=Path, help="existing kernel (default repository kernel-rv/la)")
    g.add_argument("--primary", type=Path, help="root image; default prescribed sdcard-ARCH-pub.img")
    g.add_argument("--secondary", type=Path, help="data image; default prescribed disk.img/disk-la.img")
    g.add_argument("--qemu", help="QEMU executable override")
    g.add_argument("--ready-regex", default=r"(?:^|[\r\n])[^\r\n]*[#$] ?$",
                   help="byte regex for shell prompt; override for the supplied rootfs")
    g.add_argument("--boot-timeout", type=seconds, default=60)
    options(g)
    args = parser.parse_args()
    try:
        if args.action == "discover":
            return discover()
        if args.action == "build-raw":
            build_raw(args.arch, args.bootstrap)
            return 0
        if args.action == "build":
            build(args.arch, args.cc)
            return 0
        return host(args) if args.action == "host" else guest(args)
    except PermissionError as error:
        print(f"STOP: {error}\nFix permissions before continuing; no bypass attempted.", file=sys.stderr)
        return 2
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"Driver ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
