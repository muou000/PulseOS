#!/usr/bin/env python3
"""Verify PID 1 and BusyBox shutdown through an interactive snapshot guest."""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
PROMPT = re.compile(r"(?:^|[\r\n])[^\r\n]*[#$] ?$")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
FAULT = re.compile(r"Illegal instruction!|panicked at|Failed to (?:load shell ELF|resolve shell path)")


def prepare_probe(arch, image, log_dir):
    """Compile a libc-free guest and inject only into a private image copy."""
    base = Path(__file__).resolve().parent
    sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip()
    version = subprocess.check_output(["rustc", "-vV"], text=True)
    host = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
    linker = Path(sysroot) / "lib" / "rustlib" / host / "bin" / "rust-lld"
    obj = log_dir / "guest.o"
    elf = log_dir / "guest.elf"
    compile_cmd = ["clang", "--target=" + arch + "-unknown-linux-gnu", "-O2", "-Wall", "-Wextra", "-Werror",
                   "-ffreestanding", "-fno-stack-protector", "-fno-pic", "-c", str(base / "guest.c"), "-o", str(obj)]
    if arch == "riscv64":
        compile_cmd += ["-mno-relax"]
    subprocess.run(compile_cmd, check=True)
    subprocess.run([str(linker), "-flavor", "gnu", "-static", "--no-relax", "-T", str(base / "guest.ld"),
                    str(obj), "-o", str(elf)], check=True)
    copy = log_dir / "rootfs.img"
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", str(image), str(copy)], check=True)
    for request in (f'write "{elf}" /init-shutdown-probe', "set_inode_field /init-shutdown-probe mode 0100755"):
        result = subprocess.run(["debugfs", "-w", "-R", request, str(copy)],
                                check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if any(word in result.stdout.lower() for word in ("not found", "error", "permission denied")):
            raise RuntimeError(result.stdout)
    return copy


def qemu_command(arch, kernel, image):
    command = ["qemu-system-" + arch, "-machine", "virt", "-kernel", str(kernel),
               "-m", "8G", "-nographic", "-smp", "8"]
    if arch == "riscv64":
        command += ["-bios", "default"]
    command += ["-drive", f"file={image},if=none,format=raw,id=x0,snapshot=on"]
    if arch == "riscv64":
        command += ["-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0", "-no-reboot",
                    "-device", "virtio-net-device,netdev=net", "-netdev", "user,id=net"]
    else:
        command += ["-device", "virtio-blk-pci,drive=x0", "-no-reboot",
                    "-device", "virtio-net-pci,netdev=net0", "-netdev", "user,id=net0"]
    return command + ["-rtc", "base=utc", "-monitor", "none", "-serial", "stdio"]


def run_case(args, kernel, image, log_dir):
    if args.action == "identity":
        image = prepare_probe(args.arch, image, log_dir)
    command = qemu_command(args.arch, kernel, image)
    action = "exec /init-shutdown-probe" if args.action == "identity" else args.action
    payload = ("printf '\\nINIT_PID=%s\\n' \"$$\"; kill -0 1; "
               "printf 'INIT_EXISTS=%s\\n' \"$?\"; "
               f"{action}; printf '\\nSHUTDOWN_RETURNED=%s\\n' \"$?\"\n")
    with kernel.open("rb") as stream:
        kernel_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    (log_dir / "command.json").write_text(json.dumps({"qemu": command, "shell": payload,
                                                    "kernel_sha256": kernel_sha256}, indent=2) + "\n")
    text = ""
    sent = False
    errors = []
    deadline = time.monotonic() + args.timeout
    proc = subprocess.Popen(command, cwd=REPO, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, bufsize=0)
    try:
        with selectors.DefaultSelector() as selector, (log_dir / "guest.log").open("wb") as log:
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
                normalized = ANSI.sub("", text).replace("\x08", "")
                if FAULT.search(normalized):
                    errors.append("kernel fault")
                    break
                if not sent and PROMPT.search(normalized):
                    proc.stdin.write(payload.encode())
                    proc.stdin.flush()
                    sent = True
            if proc.poll() is None:
                errors.append("QEMU did not shut down before timeout")
            elif proc.returncode != 0:
                errors.append(f"QEMU exit status {proc.returncode}")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        proc.stdin.close()
        proc.stdout.close()
    lines = ANSI.sub("", text).replace("\r", "").splitlines()
    if "INIT_PID=1" not in lines:
        errors.append("initial shell is not PID 1")
    if "INIT_EXISTS=0" not in lines:
        errors.append("kill(1, 0) failed")
    if any("No such process" in line for line in lines):
        errors.append("shutdown reported ESRCH")
    if args.action == "identity" and "IDENTITY_PASS" not in lines:
        errors.append("PID/TID, child lifecycle or normal SIGUSR2 semantics failed")
    expected = ("Restart" if args.action in ("reboot", "reboot -f", "kill -TERM 1", "kill -INT 1")
                else "Halt" if args.action in ("halt", "kill -USR1 1", "kill -PWR 1") else "PowerOff")
    if not any("filesystem writeback complete; system power transition: " + expected in line for line in lines):
        errors.append(f"missing completed writeback and {expected} transition")
    # A successful signal sender can return before the receiver performs shutdown.
    for line in lines:
        if line.startswith("SHUTDOWN_RETURNED=") and line != "SHUTDOWN_RETURNED=0":
            errors.append(line)
    print(f"{'FAIL' if errors else 'PASS'} {args.arch} {action}: " + ("; ".join(errors) or "PID 1, signal delivery, QEMU exit 0"))
    print(f"Guest log: {log_dir / 'guest.log'}")
    for line in lines[-12:]:
        print(line)
    return 1 if errors else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("riscv64", "loongarch64"), default="riscv64")
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--action", choices=("identity", "poweroff", "reboot", "halt", "poweroff -f", "reboot -f",
                                            "kill -USR1 1", "kill -USR2 1", "kill -TERM 1",
                                            "kill -PWR 1", "kill -INT 1"), default="poweroff")
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--log-dir", type=Path)
    args = parser.parse_args()
    kernel = (args.kernel or REPO / ("kernel-rv" if args.arch == "riscv64" else "kernel-la")).resolve()
    image = (args.image or REPO / ("disk.img" if args.arch == "riscv64" else "disk-la.img")).resolve()
    if not shutil.which("qemu-system-" + args.arch):
        parser.error("QEMU executable is missing")
    for path in (kernel, image):
        if not path.is_file():
            parser.error(f"input is missing: {path}")
    log_dir = (args.log_dir or REPO / "records" / ("init-shutdown-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))).resolve()
    log_dir.mkdir(parents=True, exist_ok=False)
    return run_case(args, kernel, image, log_dir)


if __name__ == "__main__":
    sys.exit(main())
