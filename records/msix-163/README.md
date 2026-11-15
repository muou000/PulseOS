# Issue #163 validation

Validated on 2026-11-15. Base: `37d7414ca870fed824f15368f51ffeead578a867`.
Implementation: `5185f42f` (platform migration plus malformed PCI input handling).

## Host regression evidence

| Public behavior | Before | After |
| --- | --- | --- |
| Platform MSI-X allocation/routing | `Unsupported` | First IRQ/message data 64; PCH-MSI target `0x2ff0_0000` |
| Concurrent allocation and exhaustion | Tracer implementation allocated IRQ 256 | Exactly 192 unique IRQs, then stable `NoVectorAvailable` |
| Invalid/unallocated IRQ enablement | Tracer implementation accepted it | `Unsupported`, no controller write |
| Capability self-loop/multi-node loop | Repeated headers | Each header visited once, traversal terminates |
| Initial capability pointer inside PCI header | Header interpreted as capability | Traversal terminates |
| Truncated vendor capability at `0xfc` | Arithmetic panic | `MissingCommonConfig` |
| BAR index 255 | Arithmetic panic | `InvalidBarType` |
| BAR offset + length overflow | Arithmetic panic | `BarOffsetOutOfRange` |
| MSI-X table physical span overflow | Invalid mapping accepted | `InvalidBar` |

The exhaustion/routing rows describe the intermediate TDD implementations, not
regressions in the base branch. Each new case was observed red before its fix.
The physical MSI target is `0x2ff0_0000`; it is read from the platform configuration.

```bash
cargo test -p axplat --all-features
RUSTFLAGS='--force-warn missing_docs' cargo test -p virtio-drivers
```

Results: axplat 8 unit + 1 integration + 7 documentation tests; virtio-drivers
29 unit + 8 documentation tests. All 53 pass. The VirtIO flag downgrades only
the existing test-fake documentation lint; no code or tests are skipped.

A direct `cargo test -p axdriver --lib` attempt is unavailable in this host
configuration: existing axalloc feature selection and x86_64 `Step` trait
compilation errors occur before tests. The host seam tests compile the actual
platform source, and kernel integration is validated with cross-builds and QEMU.

## Builds and runtime

```bash
set -o pipefail
make test 2>&1 | tail -30
python3 tests/shell_boot/run.py --arch riscv64 --timeout 60 \
  --log-dir records/msix-163/rv-shell-final
make la LOG=trace 2>&1 | tail -30
python3 tests/virtio_msix/run.py --timeout 60 \
  --log-dir records/msix-163/final-runtime
```

The final dual-architecture gate passes. RISC-V reaches an interactive shell and
executes a child shell with exit status 0. The LoongArch test uses the standard
8-vCPU/8-GiB QEMU device topology with the existing `disk-la.img`, `snapshot=on`,
and user networking. It requires real EIOINTC claims, registered VirtIO handler
dispatch, a file read and a TCP request/response with a host loopback responder.

[Final runtime summary](final-runtime/summary.json) records the exact commands,
artifact hashes, IRQ counters, host response and matching guest log excerpts.
Final run: 211 block IRQ 64 claims/dispatches and 5 network IRQ 65 claims/dispatches;
file read and TCP round trip passed in 29.072 seconds, with no guest fault.
ELF SHA-256: `636298e095d8c11dab73fba01e4294832d67a276a5eccc01bd4549db7e9bcb62`. The build manifest confirms clean
source commit `5185f42f` and the exact booted ELF hash.

Full build logs and guest serial logs remain local under this directory; the
checked-in summary and [test runner](../../tests/virtio_msix/README.md) provide
the evidence and reproduction steps.

## Review and limits

Standards: 0 unresolved findings. Spec: the inherited malformed-capability
finding was fixed and independently re-reviewed; 0 unresolved findings.

Runtime coverage is QEMU block and network MSI-X. Physical boards, hot unplug,
and INTx runtime fallback were not exercised. Trace logging affects timing;
these are correctness checks, not performance measurements. Compatibility
entry-point and shared INTx cleanup remain scoped to #164.

The first final-runtime attempt timed out because SMP tracing inserted the Bash
prompt inside an ANSI sequence. Log replay reproduced the runner false negative;
matching prompt, evidence and fault markers in the raw stream fixed it. The
successful final run above used the same kernel.
