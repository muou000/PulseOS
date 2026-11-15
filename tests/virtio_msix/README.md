# LoongArch QEMU VirtIO MSI-X smoke test

Build with interrupt tracing, then boot the existing LoongArch rootfs:

```bash
set -o pipefail
make la LOG=trace 2>&1 | tail -30
python3 tests/virtio_msix/run.py --log-dir records/virtio-msix-smoke
```

`--kernel` defaults to `kernel-la`, `--image` to `disk-la.img`, and `--timeout`
to 60 seconds. Use a fresh log directory: the runner refuses to replace existing
`guest.log` or `summary.json` evidence. QEMU uses the repository's standard
LoongArch device, memory, CPU and networking parameters with `snapshot=on`.

The runner reads `/etc/passwd` using Bash builtins, then sends a request to a
temporary host TCP responder through QEMU's user network. Success requires the
expected file content and TCP response, MSI-X configuration for block IRQ 64
and network IRQ 65, and EIOINTC claims followed by registered driver handlers
for both IRQs. The JSON records commands, artifact hashes, counters and matching
log excerpts. The source image is never modified.

Run the host-side platform and mapping tests separately:

```bash
cargo test -p axplat --features irq --test loongarch_msix
cargo test -p axplat --all-features
RUSTFLAGS='--force-warn missing_docs' cargo test -p virtio-drivers
```

The VirtIO crate's existing test fakes lack public API documentation; the flag
downgrades only that documentation lint while compiling and running its tests.

This runtime test requires the repository's Bash-based `disk-la.img`, including
`/dev/tcp` support and its existing root account line. It covers one block and
one network device on QEMU, not physical boards, malformed PCI hardware or
vector exhaustion; the host tests exercise allocation and invalid-input
handling. Trace logging changes timing, so this is a correctness check, not a
performance benchmark. It does not validate INTx fallback or device teardown.
