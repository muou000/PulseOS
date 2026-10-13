---
status: accepted
---

# Flatten ArceOS into PulseOS and unify workspace architecture

## Context

PulseOS originally embedded the upstream ArceOS codebase under the `arceos/` subdirectory, relying on recursive Makefile invocations (`$(MAKE) -C arceos`) and dual cargo workspaces. Additional components were split across `crates/` and `platforms/`, leading to:
1. Two layers of build systems and divergent manifests (e.g., LS2K1000 invoking parent-directory manifests).
2. Unused legacy modules and tools (`axstd`, `axlibc`, `arceos_api`, `examples`, x86/aarch64 scripts) adding dead weight.
3. Scattered component categorization where ArceOS core modules (`axcpu`, `axsched`, `axio`, `axpoll`, `axplat`, `axdriver_*`) resided in `crates/` while others resided in `arceos/modules/`.
4. Ambiguities regarding license attribution and multi-license compatibility.

## Decision

1. **Prune obsolete components**: Removed unused ArceOS applications, POSIX/C library shims (`axstd`, `axlibc`, `arceos_api`), non-target architecture makefile targets, and dead feature flags.
2. **Flatten ArceOS tree**: Migrated `arceos/modules/*` directly to `modules/*`, `arceos/api/axfeat` to `api/axfeat`, `arceos/configs/` to `configs/`, and `arceos/scripts/make/` to `scripts/make/`. The `arceos/` subdirectory was completely eliminated.
3. **Consolidate into single Cargo workspace**: Unified all kernel modules into a single root `Cargo.toml` with `resolver = "2"`. The root `Makefile` was refactored to be fully self-contained.
4. **Categorize and migrate crates**:
   - Kernel-core modules moved from `crates/` to `modules/`: `axcpu`, `axsched`, `axdriver_base`, `axdriver_block`, `axdriver_net`, `axdriver_pci`, `axdriver_virtio`, `axio`, `axpoll`, `axfs-ng-vfs`.
   - Unified hardware platform interface moved to `platforms/axplat`.
   - Truly standalone, algorithmic, or vendored crates retained in `crates/`: `allocator`, `buddy-slab-allocator`, `eevdf-scheduler`, `ext4plus`, `smoltcp`, `virtio-drivers`, `memory_*`, `page_table_multiarch`, `handler_table`, `dwmmc-host`, `sdmmc-protocol`, `starry-vdso`.
5. **Unify platform build commands**: Standardized `scripts/make/cargo.mk` so all platforms (including LS2K1000) use the unified `cargo -C $(1) build` invocation while preserving platform-specific flags (`-Z build-std=core,alloc`, `-C target-feature=-ual`).
6. **Formalize license compliance**: Audited all 45 packages in the repository, assigned missing metadata (`starry-vdso`), and added a top-level `NOTICE` documenting ArceOS, Starry-OS, and third-party attributions under Apache License 2.0.

## Consequences & Considered Options

- **Keep ArceOS as an external submodule/subdirectory:** Rejected because synchronization friction, divergent lockfiles, and dual Makefiles imposed severe development and debugging overhead.
- **Global rename from `ax*` to `pulse_*`:** Deferred. While the tree is now flattened, retaining existing crate identifiers minimizes ripple effects and preserves git history readability.
- **Move all crates in `crates/` into `modules/`:** Rejected. Components like `eevdf-scheduler`, `ext4plus`, and `virtio-drivers` are general-purpose standalone packages intended to be maintained or extracted to independent GitHub repositories.
