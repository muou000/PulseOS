# Issue #164 validation

Validated on 2026-11-15 against base `6b1290fb31540b31ff7af92cfefa6c76d2b3e32e`.
Implementation: `b366c5a99641f54e7e049240c62f28a9af28506a`.

## Before and after

| Boundary | Before | After |
| --- | --- | --- |
| Shared VirtIO PCI probe | Local MSI-X implementation plus compatibility retry | Calls `axhal::msix::configure_virtio_pci_msix` |
| MSI-X table/config/queue programming | `modules/axdriver/src/virtio_msix` | `platforms/axplat/src/msix.rs`; selected platform supplies allocation, message and routing |
| Invalid INTx line after MSI-X failure | LoongArch guesses `16 + device % 4` | Warns with BDF, MSI-X error and line, then skips device |
| Transport construction failure | Error discarded by `.ok()?` | Warning includes BDF and transport error |
| Invalid BAR/missing allocator/overflow | Unchecked unwrap, expect or addition | Controlled `DevError`, reported by PCI enumeration |

The following search has no matches in the final shared drivers (exit status 1):

```bash
rg -n 'LoongArch|loongarch|PCH[_-]?MSI|EIOINTC|MSI_VECTOR|configure_entry|MsixTableMapping|16 \+.*device|virtio_msix' \
  modules/axdriver/src modules/axdriver_virtio/src
```

## Tests and builds

Existing public-interface regression tests were reused for this migration.
Before changes, the platform allocation/routing test and all 9 PCI transport
tests passed. After changes:

| Command | Result |
| --- | --- |
| `cargo test -p axplat --features irq --test loongarch_msix` | 1 integration test passed |
| `cargo check -p axdriver_virtio --all-features` | Passed |
| `cargo test -p axplat --all-features` | 8 unit, 1 integration, 7 documentation tests passed |
| `RUSTFLAGS='--force-warn missing_docs' cargo test -p virtio-drivers` | 29 unit, 8 documentation tests passed |
| `make vf2 2>&1 \| tail -30` | Passed; U-Boot image generated |
| `make ls2k1000 2>&1 \| tail -30` | Passed |
| `make test 2>&1 \| tail -30` | RISC-V and LoongArch passed |

All piped build commands ran with `set -o pipefail`. The VirtIO test flag only
downgrades the existing test-fake documentation lint. Tests cover malformed
capability chains, truncated vendor capabilities, invalid BAR indices/offsets,
MSI-X table bounds, and platform vector allocation/routing/exhaustion.

All four build manifests identify the clean implementation commit above and
source tree hash `58e7491ccabea01a7c824c16c99d5958fce88352d8247e16772d45bc4ab36445`.
The first VF2 attempt overlapped a source edit and was rejected by build provenance;
the completed matrix was rerun with stable sources.

## Runtime

```bash
python3 tests/shell_boot/run.py --arch riscv64 --timeout 60 \
  --log-dir records/msix-164/rv-shell
set -o pipefail
make la LOG=trace 2>&1 | tail -30
python3 tests/virtio_msix/run.py --timeout 60 \
  --log-dir records/msix-164/la-runtime
```

RISC-V reached an interactive shell and a child shell exited with status 0.
LoongArch read `/etc/passwd` and completed a guest-to-host TCP round trip:
219 block IRQ 64 claims/registered-handler dispatches and 5 network IRQ 65
claims/registered-handler dispatches, with no guest faults. The
[runtime summary](la-runtime/summary.json) records commands, hashes and excerpts.
The booted ELF SHA-256 matches the clean build manifest:
`36b6541c8a9a98a6189cea12056cba26813ac96ae4989acc68f921636f9a3e7a`.

Full build and serial logs remain local. Physical boards were build-tested only;
INTx runtime fallback and hot unplug were not exercised. Trace timings are not
performance measurements.

## Standards

Independent review: 0 findings, no unresolved documented-standard violations
or code smells requiring changes.

## Spec

Independent review: 0 findings. Compatibility removal, platform-only MSI-X
configuration, controlled probe failures and the four-platform build matrix
satisfy #164.
