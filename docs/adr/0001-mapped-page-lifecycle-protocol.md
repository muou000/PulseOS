---
status: accepted
---

# Preserve the mapped-page lifecycle protocol

Mapped-page changes use one ownership protocol: prepare resources before entering a non-sleepable mutation, revalidate the current mapping and permissions, commit the mapping, complete TLB visibility before retiring published ownership, and publish dirty state before releasing the backing ownership. Published mappings and unpublished prepared resources remain distinct ownership states; ordinary destruction must not replace published-mapping retirement. Shared physical pages and private COW remain part of the mapping contract, while dirty publication remains distinct from storage durability. This keeps file-backed fault, `mmap`/`munmap`/`msync`, and future anonymous-page work compatible without forcing a broad `AddrSpace` rewrite.

| Phase | Ownership before/after | Required invariant |
| --- | --- | --- |
| Prepare | Unpublished prepared resource owns file-cache frames or anonymous frames. | Preparation may sleep and must happen before the address-space mutation lock; a failed or stale preparation drops only unpublished resources. |
| Revalidate | Prepared resource still owns its frames; the mapping remains published by the address space. | Commit checks the current VMA/backend identity, mapping permissions, file window, cache identity, and PTE. A same-VA replacement or permission change rejects the old preparation. |
| Commit | PTE publication transfers selected prepared frames into published mapping ownership. | Mark a prepared frame consumed only after the PTE operation succeeds; shared pages remain shared and private file mappings remain read-only until COW. |
| TLB completion | Published old frames, backend references, and deferred writebacks remain retained. | Complete invalidation after releasing the address-space lock. Incomplete shootdown intentionally retains ownership and prevents unsafe reuse. |
| Dirty publication | The retired mapping retains backing identity until publication completes. | Mark dirty only for the expected cached physical page; this publishes dirty state and does not prove storage durability. |
| Retire | Published mapping ownership is released after visibility completion. | Use deferred retirement/`AddrSpace::Drop` paths; ordinary `Drop` of a prepared object only cleans unpublished resources. |

The first implementation slice applies the shared coordinator to file-backed faults and the `mmap`/`munmap`/`msync` lifecycle. Anonymous prepared faults use the existing compatible ownership path, while their mapping identity remains outside the file-backed token until a guest race test justifies extending it. `MS_INVALIDATE` remains parameter-compatible but does not yet discard file-cache pages; its storage and cache invalidation semantics stay in the guest/integration follow-up. The checked-in LTP sources document the required scenarios, but they are not executed by the current rootfs harness.
## Considered Options

- **Fold the protocol into each caller:** rejected because the same ordering and ownership knowledge would remain distributed across fault drivers and memory syscalls.
- **Replace retirement with ordinary `Drop`:** rejected because TLB completion, dirty publication, and incomplete shootdown retention are observable ownership constraints.
- **Introduce a new external adapter for target TLB/IPI behavior:** deferred because no second adapter or host substitute currently justifies that seam.
