# Production stack and mapping capture (#211)

The production guest `bpf-record` now prepares source-bound frame-pointer
capture, an initial mapping journal cut and actual build identities before
enabling sources. It disables and drains every source before taking the final
journal cut and saving the authoritative capture. Targets remain independently
running programs selected by their actual TID; the recorder launches no workload.

Software sources default to `--callchain fp`. The current kernel supports a
depth of 32 and a read budget of 512 bytes. Unsupported depths, budgets and
trace-only stack requests fail before resource preparation. An explicit
`--callchain none` requests single-IP records; missing stack capability only
downgrades with `--allow-fallback`, preserving the requested/effective decision.
Repeated CPU/task sources and tracepoints keep independent source identities.

An optional `--kernel-elf FILE` is accepted only when its actual GNU build-id
matches the note retained in the running kernel. Its complete SHA-256 is then
recorded. Protected mapped ELF files obtain SHA and GNU identity from the
producer journal; unknown and known absence of GNU build-id remain distinct.
Names are labels. The collector reads capture identities and verifies supplied
artifact bytes without rewriting the capture or resolving missing identities
from filenames or terminal maps.

## Failure and evidence boundaries

Initial observation failure rolls back before enable. Final journal failure
retains the original initial cut with an unknown final boundary. Source stop
failure, transport loss, bounded export overflow and output failure keep their
actual counters and partial status; a file without a complete trailer is not
accepted as finalized. A synced guest SHA witness is checked after transfer,
artifact collection and analysis.

The mapping lifecycle fixture exercises actual fork/exec, rename, file pgoff,
mremap, unmap/address reuse and exit. Nonleader exec uses the existing stable
task binding gate. Numeric PID/TID allocation currently follows a monotonic
task identity allocator; no forced allocator wrap or numeric reuse is claimed.
Adversarial mapping tests cover reused numeric labels independently.

## Review

### Standards

The first independent review found no hard documented-standard or unsafe
contract violation. It identified two maintenance concerns: repeated context
format switches and duplicated GNU-note decoding. The source layout lookup
was consolidated; artifact decoding is shared across the producer and host.

### Spec

The first independent review found one gate gap: user-only samples could pass
the new stack suite. The mixed workload now must contain an actual kernel-mode
chain of at least three frames, and a regression test rejects its absence.

## Finalization diagnosis

The first real RV mapping and LA stack attempts reached the workload/stop path
but did not save a capture within the observed interval. LA reported 96 real
samples followed by quiescence and no growth. The attempts were interrupted and
are failed evidence, not successful captures.

The public mapping validation seam reproduced 22,017 allocations for the same
803,707-byte journal plus one artifact. Validation now uses the common decoder
without materializing rows. The host debug microbenchmark measured:

| Same input | Allocations | Elapsed observations |
|---|---:|---|
| Materializing validation | 22,017 | 52.33 ms, 43.52 ms |
| Validation-only shared scan | 0 | 30.19 ms, 27.40 ms |

These are two development measurements, not a statistical speedup claim. The
original guest rerun restored actual STOP/SAVED and byte-identical collection,
but revealed that ordinary recorder allocations still saturated the journal:

| Guest rerun before reusable heap | Samples | Journal records | Journal dropped | Capture SHA-256 |
|---|---:|---:|---:|---|
| LA task | 96 | 10,501 | 3,436 | `ab4f1bf77ee012e675ff0ee18d39a201341a4c92b325bcdd7b56f6874b8374cd` |
| RV mapping lifecycle | 1,020 | 12,681 | 45,456 | `a6d4535ba8775d34b4a5914019f9d724d5602be45f3855267c4bf2d87b4e784c` |

The RV mapping gate failed because required lifecycle rows were absent. These
files prove the failure; they are not positive mapping-coverage evidence.

The recorder now reserves a single reusable 512 MiB process heap, with no
per-object mmap/munmap. Reservation is not resident memory: preparation and
post-serialization logs report live and peak buddy allocation separately from
session FD/ring ownership. Exhaustion does not create another arena. Two public
allocator tests cover 8,000 reuse cycles, alignment, disjointness, coalescing,
exhaustion and unsupported layouts, and an independent unsafe review found no
blocking ownership or arithmetic issue.
