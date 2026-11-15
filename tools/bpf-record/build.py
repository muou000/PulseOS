#!/usr/bin/env python3
"""Build the standalone PulseOS recorder with the installed bare-metal toolchain."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

BASE = Path(__file__).resolve().parent
REPO = BASE.parent.parent
TARGETS = {"riscv64": "riscv64gc-unknown-none-elf", "loongarch64": "loongarch64-unknown-none-softfloat"}


def build(arch: str, acceptance: bool = False) -> Path:
    target = TARGETS[arch]
    variant = "acceptance" if acceptance else "guest"
    output = BASE / "build" / arch / variant / "bpf-record"
    output.parent.mkdir(parents=True, exist_ok=True)
    sysroot = Path(subprocess.check_output(["rustc", "+nightly", "--print", "sysroot"], text=True).strip())
    version = subprocess.check_output(["rustc", "+nightly", "-vV"], text=True)
    host = next(line[6:] for line in version.splitlines() if line.startswith("host: "))
    linker = sysroot / "lib/rustlib" / host / "bin/rust-lld"
    command = ["cargo", "+nightly", "rustc", "-p", "bpf-record", "--bin", "bpf-record",
               "--release", "--target", target, "--no-default-features", "--features", variant,
               "--", "-C", "panic=abort", "-C", "relocation-model=static", "-C", f"linker={linker}",
               "-C", f"link-arg=-T{BASE / 'guest.ld'}", "-C", "link-arg=--no-relax"]
    subprocess.run(command, cwd=REPO, check=True)
    shutil.copyfile(REPO / "target" / target / "release/bpf-record", output)
    output.chmod(0o755)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    (output.parent / "build.json").write_text(json.dumps({"arch": arch, "variant": variant,
        "command": command, "rustc": version, "sha256": digest}, indent=2) + "\n")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=TARGETS)
    parser.add_argument("--acceptance", action="store_true", help="include test-only lifecycle fault injection")
    args = parser.parse_args()
    print(build(args.arch, args.acceptance))
