#!/usr/bin/env python3
"""Boot a snapshot of a rootfs and verify interactive shell and child execution."""

import argparse
from datetime import datetime
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import time


REPO = Path(__file__).resolve().parents[2]
FAULT = re.compile(r"Illegal instruction!|panicked at|Failed to (?:load shell ELF|resolve shell path)")
PROMPT = re.compile(r"(?:^|[\r\n])[^\r\n]*[#$] ?$")
CHILD_MARKER = re.compile(r"PULSE_SHELL_CHILD_(\d+)")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("riscv64", "loongarch64"), default="riscv64")
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--data-image", type=Path)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--log-dir", type=Path)
    args = parser.parse_args()
    kernel = (args.kernel or REPO / ("kernel-rv" if args.arch == "riscv64" else "kernel-la")).resolve()
    image = (args.image or REPO / ("disk.img" if args.arch == "riscv64" else "disk-la.img")).resolve()
    data_image = args.data_image.resolve() if args.data_image else None
    qemu = shutil.which("qemu-system-" + args.arch)
    if not qemu:
        parser.error("QEMU executable is missing")
    for path in (kernel, image, data_image):
        if path is not None and not path.is_file():
            parser.error(f"input is missing: {path}")
    log_dir = args.log_dir or REPO / "records" / ("shell-boot-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    log_dir.mkdir(parents=True, exist_ok=False)
    log_path = log_dir / "guest.log"

    command = [qemu, "-machine", "virt", "-kernel", str(kernel), "-m", "8G", "-nographic", "-smp", "8"]
    if args.arch == "riscv64":
        command += ["-bios", "default"]
    command += ["-drive", f"file={image},if=none,format=raw,id=x0,snapshot=on"]
    if args.arch == "riscv64":
        command += ["-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0", "-no-reboot",
                    "-device", "virtio-net-device,netdev=net", "-netdev", "user,id=net"]
    else:
        command += ["-device", "virtio-blk-pci,drive=x0", "-no-reboot",
                    "-device", "virtio-net-pci,netdev=net0", "-netdev", "user,id=net0"]
    command += ["-rtc", "base=utc"]
    if data_image:
        command += ["-drive", f"file={data_image},if=none,format=raw,id=x1,snapshot=on", "-device",
                    "virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1" if args.arch == "riscv64"
                    else "virtio-blk-pci,drive=x1"]
    command += ["-monitor", "none", "-serial", "stdio"]

    payload = ("printf '\\nPULSE_SHELL_READY_%s\\n' OK; "
               "/bin/sh -c 'exit 0'; printf 'PULSE_SHELL_CHILD_%s\\n' \"$?\"\n")
    deadline = time.monotonic() + args.timeout
    text = ""
    sent = False
    reason = "shell startup or command timeout"
    passed = False
    proc = subprocess.Popen(command, cwd=REPO, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, bufsize=0)
    try:
        with selectors.DefaultSelector() as selector, log_path.open("wb") as log:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                events = selector.select(timeout=min(0.2, max(0, deadline - time.monotonic())))
                if not events:
                    if proc.poll() is not None:
                        reason = f"QEMU exited with status {proc.returncode}"
                        break
                    continue
                chunk = proc.stdout.read(65536)
                if not chunk:
                    reason = f"QEMU console closed (status {proc.poll()})"
                    break
                log.write(chunk)
                log.flush()
                text += chunk.decode("utf-8", errors="replace")
                normalized = ANSI.sub("", text).replace("\x08", "")
                fault = FAULT.search(normalized)
                if fault:
                    reason = normalized[fault.start():].splitlines()[0]
                    break
                if not sent and PROMPT.search(normalized):
                    if args.arch == "loongarch64":
                        passed = True
                        reason = "interactive shell prompt reached"
                        break
                    proc.stdin.write(payload.encode())
                    proc.stdin.flush()
                    sent = True
                if sent and "PULSE_SHELL_READY_OK" in normalized:
                    child = CHILD_MARKER.search(normalized)
                    if child:
                        passed = child.group(1) == "0"
                        reason = "interactive shell and child shell succeeded" if passed else "child shell failed"
                        break
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

    print(f"{'PASS' if passed else 'FAIL'}: {reason}")
    print(f"Guest log: {log_path}")
    for line in text.splitlines()[-12:]:
        print(line)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
