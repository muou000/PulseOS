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
803,707-byte journal plus one artifact (two host baseline timings: 52.33 ms and
43.52 ms). The guest allocator maps each allocation separately, making these
discarded parsing objects observable VMA work. Validation must use the common
decoder without materializing rows; the original guest scenarios are rerun to
check that this also resolves finalization rather than inferring it from the
host allocation test alone.
