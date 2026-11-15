# Issue 136 validation evidence

Validated on 2026-11-16. Baseline: 061efff6f7144002d12625fb93663e7295aaf4eb. Implementation: 5d298bf30ed2f3bb534050d2bf8d4a3519f2d9a9.
The baseline kernels contain only the opt-in, read-only layout observation patch; the final kernels enable file-io-test.
All 20 final SG suite/architecture runs and four existing ABI guest runs passed. The two host logs contain 372 passing tests/doc examples.

| Suite | RV64 | LA64 |
| --- | --- | --- |
| backend | PASS | PASS |
| append | PASS | PASS |
| semantics | PASS | PASS |
| mappings | PASS | PASS |
| counts | PASS | PASS |
| unmap-race | PASS | PASS |
| shared-position | PASS | PASS |
| device-eof | PASS | PASS |
| small-bench | PASS | PASS |
| bench | PASS | PASS |
| abi-reads | PASS | PASS |
| abi-writes | PASS | PASS |

Each architecture checked 88 file operations: one FilePosition acquisition for shared-position I/O, zero for positioned I/O, and one operation entry. Peak pins were at most 16 in this matrix; staging bytes equaled the transferred payload. SNAPSHOT also checked balanced pin ownership, including fault, CoW, overlap and concurrent-unmap suites.
Both device-eof probes executed against a confirmed /dev/vda size; neither was skipped. ABI reads/writes passed 36/81 assertions per architecture. SG_OK counts denote completed groups, not the total number of C checks.

**Performance:** the final comparisons use a refreshed baseline in the same no-build/no-other-QEMU window, identical saved guest ELFs, QEMU settings and images. Earlier, slower baselines remain in records but do not determine these tables. Warm QEMU timing is not a native-machine performance claim.

| Architecture | Fragmented 64/256 KiB speedup range | 4 KiB scalar read | 4 KiB scalar write |
| --- | --- | --- | --- |
| RV64 | 1.201x–4.349x | 0.678x | 0.830x |
| LA64 | 0.960x–2.749x | 0.940x | 0.877x |

Values below 1 are regressions and are retained. In particular, the refreshed baseline exposes the remaining scalar small-I/O cost; the earlier baseline would have hidden it. Natural partially contiguous allocations are marked unmatched and do not support a controlled speedup claim.

- [RV64 large matrix](compare-bench-rv.md), [RV64 contiguous-page control](compare-small-bench-rv.md)
- [LA64 large matrix](compare-bench-la.md), [LA64 contiguous-page control](compare-small-bench-la.md)
- [Machine-readable final results](final-result.json)

**Negative control:** restoring the old cached-write error propagation using [this patch](negative-partial-write.patch) makes the exact final RV64 backend probe fail after cached_read_prefix PASS: cached_write_prefix FAIL AxErrorKind::Io, followed by PSGI -EIO. This expected failure is archived separately from the passing candidate. Historical pristine append/shared-position RED logs and the first matching append GREEN are retained as TDD evidence.

**Rejected fixture:** one refreshed LA64 baseline attempt observed 62 rather than the required 63 PFN discontinuities at 256 KiB and stopped with only 60/80 rows. No rows from that attempt enter the final table. An unchanged ELF/kernel retry established 63/63 and completed the matrix; both attempts are archived.

**Artifacts:** [validation.tar.gz](validation.tar.gz) contains per-run commands, results, console logs, small guest ELFs, build metadata, host logs, the feature build gate, the ABI configuration wrapper, and a SHA-256 manifest. It excludes all disk images, kernel binaries and object files. [The layout patch](layout-observation.patch) and the negative patch are also available directly.

| Kernel | SHA-256 |
| --- | --- |
| Baseline rv + layout hook | 23611b73eb1527e5cfc2d2903a5f732d86f2ae764713cb9c21786c82644f03e3 |
| Final rv | a16b31cded3ea04e69493685e73516e17cbca11a87944b18c32797e9906dca26 |
| Baseline la + layout hook | 4120fa39abca342891d1c1ef4c6080e3d25b1468217936485e3e84a4743ea7de |
| Final la | 645ba13ecc350945fb5f5f0817058453ba2f7dca737bc84444bfc5b037c08638 |
| Negative RV64 | 7cb23b9410b27d766b0b9c001edfc6a3c51549904b0249ad5cd749276218bd14 |

Extract the bundle and inspect manifest.json to verify raw files. Archived command paths describe the original workspace; use the saved guest ELF with run.py --guest-elf and an explicitly selected rebuilt kernel when reproducing. The runner checks guest shutdown and source-image integrity. SHA256SUMS covers the files in this evidence directory.


**Feature-disabled gates supplement** (source commit 81429b48bf0e32a0c2c4121c18c96a36c2e22843):

The ordinary dual-architecture make test and the separate RV64 qemu+bpf-trace
compilation passed. Runtime tests used the ordinary qemu kernels on both architectures,
without bpf-trace or file-io-test. Each archived kernel provenance file's selected
artifact SHA-256 matches both the tested kernel hash and a fresh checksum of the
current kernel. Configuration is identified from that artifact-bound provenance,
not inferred from the presence or order of other build logs.

The same semantics/append guest ELFs as the feature-enabled runs passed on these
normal kernels (four additional runs). Both semantics logs show PSGI RESET rejected
as unsupported, confirming the test gate was off.

| Runtime | semantics | append | Kernel SHA-256 |
| --- | --- | --- | --- |
| RV64 qemu | PASS | PASS | b97f7a91a673c5a8838108ef9738ed6c9993edb129653eaa742685f4d0e0ec62 |
| LA64 qemu | PASS | PASS | 3f7e932151100dde79245221c06929cb7d71b46a1312d062d7e0ca61c401a092 |

[gate-summary.json](gate-summary.json) records the separate build/runtime results
and the exact provenance feature strings. [gates.tar.gz](gates.tar.gz) contains
the four runs' commands, results, logs, small guest ELFs, the two build logs,
both kernel provenance JSON files and an independent SHA-256 manifest.
No kernel or disk images are included. The original validation.tar.gz,
final-result.json and all performance tables remain byte-for-byte unchanged;
this supplement does not rerun or reinterpret timing.
