# Issue 193 mapping and artifact evidence — 2026-11-15

> **Retention update — 2026-11-16:** The raw `.tar.gz` bundles described below
> have been removed from the current tree. Retained indexes, hashes, counts and
> replay reports record historical verification; they do not provide a complete
> replay from this checkout. Bundle names and links below are historical references.
> The old replay commands require complete bundles held separately; metadata
> cannot reconstruct their bytes. For new evidence, follow the
> [fresh-run instructions](../../README.md) and keep raw output out of Git.
> See the [sampling evidence retention policy](../../../../docs/sampling-evidence-retention.md).

These archives contain real RV64/LA64 QEMU output, original consumed RAW
records, capture v4, journal v2, and the exact kernel/parent/child ELF bytes.
They contain no synthesized sampling records or terminal-map substitutions.

| Run | RAW samples | Mapped / renamed / fork / exec / remapped / partial-remapped | Completed TLB tokens | Gate |
|---|---:|---|---:|---|
| [rv-cpu](rv-cpu.tar.gz) | 1442 | 15 / 16 / 14 / 15 / 12 / 14 | 39 | PASS |
| [la-cpu](la-cpu.tar.gz) | 1133 | 15 / 17 / 13 / 14 / 15 / 15 | 85 | PASS |

Every listed phase has real user IP samples whose stable task ID, address-space
ID, exec generation, file-object identity, byte offset and ELF symbol agree
between an independent RAW/journal oracle and the standalone Rust analyzer.
The partial-remapped phase moves only the second page of a two-page file
mapping and preserves byte pgoff 4096. Fork preserves the object while changing
address-space identity; exec replaces the address space and increases its
generation. The original sample IP is never rewritten.

Before/after proc snapshots are saved with their original bytes and serial
CRC32. The first journal is an ordered prefix of the final one, precedes every
source enable, and the final cut follows disable/quiescence. Journal v2 includes
explicit begin/end mutation records, so a snapshot cut during a write lease
cannot treat an old VMA revision as current. Open task/address-space mutations,
mapping transitions, unresolved TLB publication and timestamp ties remain
unknown. A dropped journal is partial and cannot satisfy this positive gate.

`artifacts.json` binds each content-addressed ELF to its SHA-256 and actual GNU
build-id, with explicit null when absent. Parent payloads intentionally have no
GNU build-id; child payloads have real linker-generated notes. Both preserve
embedded debug sections bound to the same exact ELF. Kernel debug sections and
GNU build-id are absent in these builds; symbols and runtime `_stext`/text range
are verified against the boot ELF. Both measured kernel relocation deltas are
zero. The host never substitutes a same-named ELF. The missing-ELF and swapped
same-name-ELF negative reports retain mapping facts and reject ELF resolution
for all six real examples.

The captures remain `IncompleteError` / partial, with complete attribution
disabled. This preserves source skips and other scoped unknown/error facts;
the mapping gate does not assert complete sampling or exact CPU utilization.
`busy_time_ns` and `idle_time_ns` remain null. Both runs have zero transport and
export loss, and no mapping-journal drops. General mutable mmap objects without
a protected executable identity can still have unknown SHA and unavailable
symbols.

`index.json` records each archive SHA and every member SHA. Tar entries and gzip
headers use fixed timestamps, so the same input files reproduce the archive
bytes. Each archive includes the guest source/build snapshots, kernel build
provenance, original inputs/result, raw journals, RAW frames, capture, positive
and negative reports, and all ELF/debug artifacts. Rootfs and raw boot copies
are omitted: RV boot bytes are independently reconstructed from the included
ELF and checked against their recorded SHA; LA boots its included ELF directly.
The source image identity remains recorded, but replay does not reconstruct or
claim to verify the omitted rootfs. Hashes are identifiers, not signatures.

Run independent archive verification from the repository root:

```bash
python3 tests/bpf_sampling/verify_mapping_evidence.py tests/bpf_sampling/evidence/193
```

This safely extracts only indexed regular files into temporary directories,
checks all SHA values and original serial framing, compares every normalized
record against independently decoded RAW bytes, verifies artifact/debug/boot
identity, reruns the temporal oracle and wrong/missing ELF negatives, and
reimports the original RAW/journal data. The full mapping report must remain
identical after reimport. `replay-report.json` contains the actual replay result.

Recreate the deterministic bundles from preserved run directories:

```bash
python3 tests/bpf_sampling/bundle_mapping_evidence.py \
  --run rv-cpu=tests/bpf_sampling/runs/riscv64-cpu-20261115-175151-t2fyqvro \
  --run la-cpu=tests/bpf_sampling/runs/loongarch64-cpu-20261115-175151-pp6glhlh \
  --output /tmp/pulse193-evidence
```

For a new live run:

```bash
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode cpu --archive --mappings --timeout 180
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode cpu --archive --mappings --timeout 180
```

Earlier local runs used intermediate journal v1 or the pre-final v4 metadata
framing. They are not acceptance bundles and their original captures/results
were preserved. The first intermediate pair also exposed an ANSI reset before
the exec marker; parser normalization was fixed with a regression test. The
final pair above uses journal v2, final v4 framing, and the corrected guest
raw-pointer-to-function conversion.

`validation.tar.gz` preserves the final dual-architecture enabled/default build
logs, Rust tests, no_std check, Python tests, final QEMU runner output and
archive replay output. Its member SHA values are recorded in `index.json`.
