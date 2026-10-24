---
status: accepted
---

# Keep Order-0 page caches visible to memory pressure

Unconstrained single-page Order-0 allocations may use bounded per-CPU caches, while DMA-constrained, higher-order, and otherwise aligned requests continue to use Buddy directly. Cached pages count as available memory; refill and drain use bounded watermarks, and global reclaim drains the caches before retrying an allocation. This reduces Buddy lock contention without changing frame-reference, mapped-page ownership, zeroing, or page-return semantics.
