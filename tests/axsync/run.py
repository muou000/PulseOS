#!/usr/bin/env python3
"""Run the boot-time axsync checks with the repository's prescribed QEMU setup."""

import argparse
import hashlib
import json
from pathlib import Path
import selectors
import shutil
import subprocess
import time


REPO = Path(__file__).resolve().parents[2]
PASS = b"[AXSYNC_GUEST] All axsync lock stress & concurrency checks PASSED!"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("riscv64", "loongarch64"), required=True)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--log-dir", type=Path, required=True)
    args = parser.parse_args()
    qemu = shutil.which("qemu-system-" + args.arch)
    if not qemu:
        parser.error("QEMU executable is missing")
    kernel = REPO / ("kernel-rv" if args.arch == "riscv64" else "kernel-la")
    args.log_dir.mkdir(parents=True, exist_ok=False)
    command = [qemu, "-machine", "virt", "-kernel", str(kernel), "-m", "8G",
               "-nographic", "-smp", "8"]
    if args.arch == "riscv64":
        command += ["-cpu", "max", "-bios", "default"]
    command += ["-drive", "file=disk.img,if=none,format=raw,id=x0,snapshot=on"]
    if args.arch == "riscv64":
        command += ["-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0",
                    "-no-reboot", "-device", "virtio-net-device,netdev=net",
                    "-netdev", "user,id=net"]
    else:
        command += ["-device", "virtio-blk-pci,drive=x0", "-no-reboot",
                    "-device", "virtio-net-pci,netdev=net0", "-netdev", "user,id=net0"]
    command += ["-rtc", "base=utc"]
    kernel_hash = hashlib.sha256(kernel.read_bytes()).hexdigest()
    started = time.monotonic()
    output = bytearray()
    passed = False
    with subprocess.Popen(command, cwd=REPO, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        try:
            with selectors.DefaultSelector() as selector, (args.log_dir / "guest.log").open("wb") as log:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while time.monotonic() - started < args.timeout:
                    if not selector.select(timeout=0.2):
                        continue
                    chunk = proc.stdout.read1(65536)
                    if not chunk:
                        break
                    log.write(chunk)
                    log.flush()
                    output.extend(chunk)
                    if PASS in output:
                        passed = True
                        break
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
    summary = {"arch": args.arch, "passed": passed, "command": command,
               "kernel_sha256": kernel_hash, "seconds": time.monotonic() - started,
               "checks": [line for line in output.decode(errors="replace").splitlines()
                          if "[AXSYNC_GUEST]" in line]}
    (args.log_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
