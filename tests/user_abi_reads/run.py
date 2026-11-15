#!/usr/bin/env python3
"""Run user ABI read/write regressions on a private snapshot image (RV64 or LA64)."""
import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parent
REPO = BASE.parents[1]
spec = importlib.util.spec_from_file_location("init_shutdown_runner", REPO / "tests/init_shutdown/run.py")
shutdown = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shutdown)


def check_permissions(output):
    if re.search(r"permission denied|read-only file system|operation not permitted", output, re.I):
        raise PermissionError(output[-2000:])


def command(argv):
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check_permissions(result.stdout)
    if result.returncode:
        raise RuntimeError(f"command failed: {argv}\n{result.stdout[-4000:]}")
    return result.stdout


def prepare(arch, image, output, suite="reads"):
    source = BASE.parent / f"user_abi_{suite}"
    probe = f"/user-abi-{suite}-probe"
    sysroot = Path(command(["rustc", "--print", "sysroot"]).strip())
    host = next(line[6:] for line in command(["rustc", "-vV"]).splitlines() if line.startswith("host: "))
    linker = sysroot / "lib/rustlib" / host / "bin/rust-lld"
    obj, elf = output / "guest.o", output / "guest.elf"
    compile_cmd = ["clang", f"--target={arch}-unknown-linux-gnu", "-O2", "-Wall", "-Wextra", "-Werror",
                   "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic",
                   "-c", str(source / "guest.c"), "-o", str(obj)]
    if arch == "riscv64":
        compile_cmd.append("-mno-relax")
    command(compile_cmd)
    command([str(linker), "-flavor", "gnu", "-static", "--no-relax", "-T", str(BASE / "guest.ld"),
             str(obj), "-o", str(elf)])
    private_image = output / "rootfs.img"
    command(["cp", "--reflink=auto", "--sparse=always", "--", str(image), str(private_image)])
    for request in (f'write "{elf}" {probe}', f"set_inode_field {probe} mode 0100755"):
        result = command(["debugfs", "-w", "-R", request, str(private_image)])
        if re.search(r"not found|error|already exists", result, re.I):
            raise RuntimeError(result)
    return private_image


def run(args, output, kernel, image):
    private_image = prepare(args.arch, image, output, args.suite)
    marker = f"ABI_{args.suite.upper()}"
    qemu = shutdown.qemu_command(args.arch, kernel, private_image)
    payload = f"exec /user-abi-{args.suite}-probe\n".encode()
    with kernel.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    (output / "command.json").write_text(json.dumps({"qemu": qemu, "kernel_sha256": digest,
                                                    "shell": payload.decode()}, indent=2) + "\n")
    proc = subprocess.Popen(qemu, cwd=REPO, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, bufsize=0)
    text, sent = "", False
    errors = []
    deadline = time.monotonic() + args.timeout
    try:
        with selectors.DefaultSelector() as selector, (output / "guest.log").open("wb") as log:
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
                log.write(chunk); log.flush()
                text += chunk.decode("utf-8", errors="replace")
                check_permissions(text)
                normalized = shutdown.ANSI.sub("", text).replace("\x08", "")
                if shutdown.FAULT.search(normalized) or marker + "_FAIL" in normalized:
                    errors.append("kernel fault or guest assertion failed")
                    break
                if not sent and shutdown.PROMPT.search(normalized):
                    proc.stdin.write(payload); proc.stdin.flush()
                    sent = True
            if proc.poll() is None:
                errors.append("QEMU did not exit normally before deadline")
            elif proc.returncode != 0:
                errors.append(f"QEMU exited {proc.returncode}")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=5)
        proc.stdin.close(); proc.stdout.close()
        private_image.unlink()
    lines = shutdown.ANSI.sub("", text).replace("\r", "").splitlines()
    if marker + "_PASS" not in lines:
        errors.append("missing final assertion marker")
    if not any("filesystem writeback complete; system power transition: PowerOff" in line for line in lines):
        errors.append("missing completed shutdown")
    passed = sum(line.startswith(marker + "_OK ") for line in lines)
    result = {"arch": args.arch, "suite": args.suite, "passed_assertions": passed, "errors": errors, "kernel_sha256": digest}
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"{'FAIL' if errors else 'PASS'} {args.arch}: {passed} assertions; {output / 'guest.log'}")
    for line in lines:
        if marker + "_FAIL" in line:
            print(line)
    for error in errors:
        print(error)
    return bool(errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("reads", "writes"), default="reads")
    parser.add_argument("--arch", choices=("riscv64", "loongarch64"), default="riscv64")
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--log-dir", type=Path)
    args = parser.parse_args()
    kernel = (args.kernel or REPO / ("kernel-rv" if args.arch == "riscv64" else "kernel-la")).resolve()
    image = (args.image or REPO / ("disk.img" if args.arch == "riscv64" else "disk-la.img")).resolve()
    output = (args.log_dir or REPO / "records" / ("user-abi-" + ("157" if args.suite == "reads" else "158") + "-" + args.arch + "-" +
              datetime.now().strftime("%Y%m%d-%H%M%S-%f"))).resolve()
    output.mkdir(parents=True, exist_ok=False)
    return run(args, output, kernel, image)


if __name__ == "__main__":
    sys.exit(main())
