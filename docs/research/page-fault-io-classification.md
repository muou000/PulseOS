# Target-page storage read classification (#196)

This extends the [completion contract](page-fault-observation-contract.md).
The unit remains one returned resolver invocation, identified at entry, rather
than a hardware trap count, a final mapped inode, or a Linux process counter.

## Meaning and Linux comparison

| Completion | Wire classification | Meaning |
|---|---|---|
| Resolved | Minor (1) | Every target preparation used a verified path, and this invocation issued no storage data read for its fault target. |
| Resolved | Major (2) | At least one target preparation in this invocation completed an actual storage data read overlapping the target bytes. |
| Resolved | Unknown (0) | No target read was established, and at least one backend could not establish its I/O provenance. |
| NotHandled / NoMemory / ResolverError | Unknown (0), applicability `not_applicable` | No successful classification; reported separately from successful faults. |
| Resolver never returned | No completion | Entry/completion diagnostics retain the gap; no invented successful or canceled event. |

This is a PulseOS storage-read definition, **not exact Linux counter parity**.
Linux v6.12 `filemap_fault` sets `VM_FAULT_MAJOR` on a page-cache miss before
read-ahead. Its `mm_account_fault` also counts a successful retried fault as
major via `FAULT_FLAG_TRIED`, and excludes errors from major/minor accounting.
PulseOS does not infer I/O from a miss, elapsed time, file-backed status, or a
retry flag. Metadata reads, writes/writeback and optional neighbor reads are
outside the target data-read definition. A storage read means a completed
guest block-device operation, not a claim about physical host media access.
Sources: [Linux v6.12 filemap.c](https://github.com/torvalds/linux/blob/v6.12/mm/filemap.c#L3117-L3219),
[Linux v6.12 memory.c](https://github.com/torvalds/linux/blob/v6.12/mm/memory.c#L5548-L5609).

Independent expected cases:

- Anonymous first touch and resident-page COW: minor; allocation, zeroing and
  copying issue no storage data reads.
- Already cached file target: minor, even if optional neighboring pages are cold.
- Page-cache miss served by ext4's block cache or a hole zero-fill: minor.
- Cold ext4 target requiring an actual data read: major.
- A waiter whose competing fill wins: minor if it issues no target read itself.
  Waiting wall time does not make it major. If it must retry and issue its own
  target read, that actual read determines the class.
- An uninstrumented `FileMappingSource` or backend read: unknown until its
  provenance is implemented and independently verified. A later cache hit can
  still be classified from the actual pinning operation.

## Fact propagation and ownership

```text
Ext4Disk successful device read + overlap with requested target window
  -> ext4plus data extents (holes and metadata excluded)
  -> VFS read_at_with_io (default unknown)
  -> CachedFile pin/fill under existing page access and cache locks
  -> FileMappingSource / FilePagePrepared::io
  -> drive_page_fault_with_io / process resolver
  -> trap completion / ID8 v1 bytes / capture / FaultReport
```

The target window is relative to each actual read buffer. Extent and partial
block splits translate and intersect it. A read of another batch page cannot
set the target's storage-read result. The observed pin path may return a
shorter, one-page batch when its target is already resident; the existing
bounded-batch contract permits that result. It does not need to fill optional
neighbors to establish a target hit. Unobserved read and prefetch APIs retain
their normal behavior.

Evidence follows the prepared record, not a racing preflight cache probe.
Across cache-generation and mapping retries, an actual target read dominates
unknown, which dominates no-read. Reads from a discarded preparation remain
work done by this resolver invocation; the class does **not** attribute them to
the inode eventually mapped at the same VA. A terminal error or rejection is
never counted as a successful major even if an earlier attempt read data.

The change adds scalar facts to the existing prepare/commit/retry protocol.
File-cache pins, anonymous and COW preparation owners, mapping generations,
permission checks, deferred TLB completion and drop paths remain responsible
for ownership as in ADR-0001/0004. No observation token holds a page pin or lock.
Entry activation generation still rejects a completion belonging to an older
subscription. Process exit/cancellation does not manufacture completion.

## Transport and report

ID 8, schema version 1, size 80 and tags Unknown=0/Minor=1/Major=2 are unchanged.
Old `from_completion` and archived Unknown records remain supported. The new
classified constructor and capture validator reject major/minor paired with
unsuccessful outcomes. Report totals `resolved_minor`, `resolved_major`,
`resolved_unknown`, and `unsuccessful` are disjoint. Raw unknown tags remain
available for compatibility, while unsuccessful records display classification
applicability `not_applicable`.

System resolver started/completed/clock errors, per-source delivery, VM and
transport counters remain separate scopes. Report counts come from captured
completion records only; those layers are never added to inflate fault totals.
Unknown identity/access, partial captures and censored time windows retain their
existing diagnostics even when the class is known.

## Coverage boundary for map #180

Instrumented production storage backend: ext4 through `Ext4Disk`/VirtIO on the
RV64 and LA64 QEMU guests. FAT and third-party VFS readers retain unknown for
fills unless they implement actual read provenance. This does not establish
physical-platform, swap, DAX, network-filesystem or Linux tool parity. OOM,
nonreturning panic and every process-exit interleaving are not claimed covered
by the successful workload matrix. Deterministic backend and lifecycle checks
are protocol evidence; only the guest device-trace oracle establishes actual
storage reads. Runtime results and commands are recorded in
[the acceptance record](../../records/page-fault-io-196.md).
