#!/usr/bin/env python3
"""Build real kernels and verify that BPF/pipe boot checks are opt-in."""

import argparse
from pathlib import Path
import subprocess
import tempfile


REPO = Path(__file__).resolve().parents[2]
ARCHITECTURES = {"riscv64": "rv", "loongarch64": "la"}
CONFIGURATIONS = (
    (None, False),
    ("qemu bpf-trace", False),
    ("qemu guest-checks", True),
    ("qemu bpf-trace guest-checks", True),
)
PREFIXES = (b"[BPF_GUEST]", b"[PIPE_GUEST]")
RESULT_MARKERS = (
    b"[BPF_GUEST] BPF_MAP01 assertions: PASS",
    b"[BPF_GUEST] BPF_PROG_LOAD verifier assertions: PASS",
    b"[BPF_GUEST] BPF Program execution assertions: PASS",
    b"[BPF_GUEST] Perf Event assertions: PASS",
    b"[BPF_GUEST] BPF Link and attach assertions: PASS",
    b"[BPF_GUEST] PERF_EVENT sampling assertions: PASS",
    b"[PIPE_GUEST] Multi-page zero-copy read: PASS",
    b"[PIPE_GUEST] Partial-page fallback: PASS",
    b"[PIPE_GUEST] Remap failure total rollback: PASS",
    b"[PIPE_GUEST] Remap partial failure short read & restoration: PASS",
    b"[PIPE_GUEST] Lock-outside batch dealloc in read: PASS",
    b"[PIPE_GUEST] Closed-pipe cleanup: PASS",
    b"[PIPE_GUEST] All pipe checks PASSED!",
)


def check_build(arch, features, enabled):
    command = ["make", ARCHITECTURES[arch]]
    if features is not None:
        command.append(f"APP_FEATURES={features}")
    label = features or "default"
    print(f"Building {arch}: {label}", flush=True)
    # Keep compiler diagnostics without hiding a failing make behind tail's status.
    with tempfile.TemporaryFile(mode="w+") as log:
        result = subprocess.run(command, cwd=REPO, stdout=log, stderr=subprocess.STDOUT)
        log.seek(0)
        print("".join(log.readlines()[-30:]), end="", flush=True)
    result.check_returncode()

    # The stripped raw image contains only linked kernel data, not debug strings
    # from unreachable functions. Inspect it immediately after its own build.
    binary = REPO / f"{REPO.name}_{arch}-qemu-virt.bin"
    data = binary.read_bytes()
    if enabled:
        missing = [marker.decode() for marker in RESULT_MARKERS if marker not in data]
        if missing:
            raise RuntimeError(f"{arch} ({label}): missing result markers: {missing}")
    else:
        unexpected = [marker.decode() for marker in PREFIXES if marker in data]
        if unexpected:
            raise RuntimeError(f"{arch} ({label}): boot checks present: {unexpected}")
    print(f"PASS {arch} ({label}): guest checks {'present' if enabled else 'absent'}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=ARCHITECTURES, help="default: both architectures")
    args = parser.parse_args()
    # The standard build entrypoints share .axconfig.toml; never build in parallel.
    for arch in ([args.arch] if args.arch else ARCHITECTURES):
        for features, enabled in CONFIGURATIONS:
            check_build(arch, features, enabled)


if __name__ == "__main__":
    main()
