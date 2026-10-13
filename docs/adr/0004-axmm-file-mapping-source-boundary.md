---
status: accepted
---

# Keep file mapping backends below the filesystem boundary

`axmm` owns the object-safe `FileMappingSource` contract and its page-batch,
mapping-flag, and opaque write-guard types. `axfs` depends on `axmm` to provide
the concrete page-cache implementation, while `axmm` has no dependency on
filesystem types; mappings hold the source through `Arc<dyn FileMappingSource>`.
The contract contains only the operations needed for file faults, prefetch,
generation validation, dirty publication, and sync, preserving the mapped-page
lifecycle protocol in ADR-0001.

The BuildStorm statistics interface is removed from `axfs`, including memory,
filesystem, page-cache, and syscall counters and their output. The qperf trace
ABI and phase markers remain owned by the tracing/task layers, so qperf sampling
continues without a statistics API.

## Consequences

- File mapping permissions exposed by `axmm` are limited to `READ` and `WRITE`;
  executable permission remains part of `MappingFlags`, while `APPEND` and
  `PATH` stay in the filesystem layer.
- Existing shared-page, private-COW, TLB completion, dirty publication, and
  storage-sync ownership rules remain unchanged.
- qperf reports no longer include BuildStorm counter summaries.
