# Issue 196 real fault classification evidence — 2026-11-15

| Bundle | Actual completed fault records | Minor | Major | Unknown | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| `rv-baseline.tar.gz` | 263 | 0 | 0 | 263 | Expected classification failure |
| `rv-fault.tar.gz` | 264 | 262 | 2 | 0 | PASS |
| `la-fault.tar.gz` | 264 | 262 | 2 | 0 | PASS |

Each positive run includes 128 isolated anonymous read-first and write-first
fault targets, plus six distinct classification cases. QEMU's VirtIO read and
completion trace is independent of the kernel classification field. The host
maps the two injected data pages to device sectors using `debugfs bmap`; guest
stdin handshakes delimit device-trace spans around each exact fault address.

On both architectures, first anonymous reads, cached file mappings, private
file COW writes, and a cached target with a still-cold neighbor are Minor with
zero data-sector reads. The initial cold file target and the later explicit
neighbor fault are Major, each with eight completed 512-byte device sectors.
The private COW store leaves the second mapping's contents unchanged. The
resident-target path returns a shorter optional batch, so the cold neighbor's
read remains attributable to its own later fault. The initialized-kernel
`fault_io_block_cache_neighbor` check independently exercises a lower-cache hit
for the target while another range in the same read performs device I/O.

Both final logs also contain all 20 kernel mapping/filesystem lifecycle PASS
markers, including owner/waiter fill classification, hot-target/cold-neighbor,
cancellation/error/retry, unsupported backend/generation retry, stale mapping
rejection, COW, and block-cache neighbor exclusion. These checks exercise real
kernel protocols with controlled backing sources; they are separate from the
VirtIO-backed file workload evidence.

The baseline uses an archived kernel with BPF enabled. Its guest and capture
passed the existing transport checks; the new classifier oracle rejected
Unknown. Device traces show eight sectors for the cold target and eight for
the old batched neighbor read. `baseline-oracle.py` preserves the exact
five-case oracle used for that failure. The final six-case workload reflects
the implementation's shorter optional batch. Baseline RAW and capture remain
unchanged; no sample was synthesized or relabelled.

All captures retain `IncompleteError` / partial status and disable complete
attribution claims. The two acceptance runs have zero transport/export loss;
classification coverage of the six targets does not eliminate unrelated
capture-quality limits. Concurrent host runs were used for correctness only;
the recorded workload wall times are not performance acceptance evidence.

`index.json` binds every compressed archive and member to SHA-256. Each archive
contains exact guest output, device trace, serial boundary cursors, original
RAW, capture, full fault report, proc counters, kernel ELF/build provenance,
guest ELF/source/build snapshots, fixture bytes, and sector mapping. Rootfs and
raw boot copies are omitted; their hashes remain in `inputs.json`. Hashes are
identifiers, not signatures, and replay cannot verify the omitted rootfs.

Replay all indexed hashes and RAW/capture equality, then the positive runs'
independent device oracle, host classification/group totals and kernel
lifecycle markers. Baseline replay checks the unchanged Unknown records and
original rejection; it does not execute the archived baseline oracle or rerun
its historical device classification check:

```bash
python3 tests/bpf_sampling/fault_class_evidence.py tests/bpf_sampling/evidence/196
```

Recreate the deterministic bundles from the preserved source runs:

```bash
python3 tests/bpf_sampling/bundle_fault_class_evidence.py \
  --run rv-baseline=tests/bpf_sampling/runs/riscv64-fault-20261115-205350-unuhvqom \
  --run rv-fault=tests/bpf_sampling/runs/riscv64-fault-20261115-210722-tnd4s2aj \
  --run la-fault=tests/bpf_sampling/runs/loongarch64-fault-20261115-210807-a4a4jpc4 \
  --output /tmp/pulse196-evidence
```

`replay-report.json` is the actual archived replay result. A live reproduction
uses the `--fault-classes` commands in the parent README; include
`mapping-lifecycle-test` in the kernel features to rerun all 20 kernel checks.

The positive bundles use post-review kernel commit `09a11168`. An earlier LA
attempt at `runs/loongarch64-fault-20261115-210722-xuvdtft4` was rejected because
the serial callback accepted a timestamp prefix before the newline arrived.
The stored host value `364` disagreed with the original guest value
`3644279560`. The callback now waits for a complete line; its split-serial
regression failed before the fix and passed afterward. The original failed
run remains separate from the accepted rerun.

`validation.tar.gz`, indexed separately by `validation-index.json`, contains
the build and host-test logs, both raw6 mapping/filesystem runs with boot
kernels and payloads, default build provenance, the reader protocol harness,
and the rejected LA serial-boundary run. Its members were read back and verified
against the separate SHA-256 manifest. These files are auxiliary evidence and
are not part of the three-run device-oracle replay above.
