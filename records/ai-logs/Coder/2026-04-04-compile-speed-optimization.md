# Coder Record

## 1. Basic Info
- Date: 2026-04-04
- Author: Codex (GPT-5.4)
- Branch/Commit: local workspace state (commit not captured in this run)
- Scope: compile-speed-oriented dependency and feature cleanup

## 2. Task Summary
- Goal: optimize project compile speed from code structure/dependency layout.
- Requested Focus:
  - remove `pulse_core`'s unconditional `arceos_posix_api` dependency
  - shrink `pulse_core` default features
  - slim the root crate's direct dependency set

## 3. Changes Made
1. Shrunk `pulse_core` default features.
- Changed [`pulse_core/Cargo.toml`](/home/muou/PulseOS/pulse_core/Cargo.toml) from default `["alloc", "fs"]` to empty default features.
- Kept filesystem-related loader stack behind explicit `fs` feature.
- Made `kernel-elf-parser` and `xmas-elf` optional and only enabled by `fs`.

2. Removed unconditional heavy dependencies from `pulse_core`.
- Removed direct dependency on `arceos_posix_api`.
- Removed unused direct dependencies `axalloc`, `axns`, and pinned `log`.
- Kept `linkme` because trap-handler/task-ext macros require it.
- Made `axtask` explicitly enable `multitask`, since the crate relies on that capability.

3. Gated filesystem loader code by feature.
- Added `#[cfg(feature = "fs")]` around loader module export in [`pulse_core/src/mm/mod.rs`](/home/muou/PulseOS/pulse_core/src/mm/mod.rs).
- Added `#[cfg(feature = "fs")]` to `Process::load_elf` and `Process::exec` in [`pulse_core/src/task/mod.rs`](/home/muou/PulseOS/pulse_core/src/task/mod.rs).

4. Slimmed the root crate dependency surface.
- Removed unused direct dependencies from [`Cargo.toml`](/home/muou/PulseOS/Cargo.toml):
  - `axhal`
  - `axconfig`
  - `syscalls`
- Kept `pulse_core` but now enable only `features = ["fs"]`.

5. Cleaned `pulse_syscalls` dependency declarations.
- Removed unused direct dependencies such as `axfs`, `axns`, and `spin`.
- Kept `linkme` because `register_trap_handler` macro requires it.
- Made `pulse_core` dependency explicit with `features = ["fs"]`.
- Made `axtask` explicitly enable `multitask`.

## 4. Why This Helps
- `pulse_core` can now compile without always dragging in `axfs`, ELF parsing crates, and `arceos_posix_api`.
- The root crate no longer directly participates in feature unification for several unused low-level dependencies.
- Explicit feature boundaries reduce the amount of code recompiled for changes outside the user-loader/filesystem path.
- `pulse_core` becomes a thinner, more reusable crate for non-filesystem-related development and checking.

## 5. Validation
- `cargo check -p pulse_core`: passed
- `cargo check -p pulse_syscalls`: failed on pre-existing error
- `cargo check -p Pulse`: failed on the same pre-existing error

## 6. Known Remaining Issue
- Existing compile error not introduced by this work:
  - [`pulse_syscalls/src/handler.rs`](/home/muou/PulseOS/pulse_syscalls/src/handler.rs#L54)
  - `Sysno::fstatat` is not present in the current `syscalls` crate revision.

## 7. Files Touched
- [`Cargo.toml`](/home/muou/PulseOS/Cargo.toml)
- [`pulse_core/Cargo.toml`](/home/muou/PulseOS/pulse_core/Cargo.toml)
- [`pulse_core/src/mm/mod.rs`](/home/muou/PulseOS/pulse_core/src/mm/mod.rs)
- [`pulse_core/src/task/mod.rs`](/home/muou/PulseOS/pulse_core/src/task/mod.rs)
- [`pulse_syscalls/Cargo.toml`](/home/muou/PulseOS/pulse_syscalls/Cargo.toml)

## 8. Follow-ups
- Fix `Sysno::fstatat` mismatch so full workspace checks can pass again.
- Optionally clean current warnings in `pulse_core` (`TaskExtRef` unused, `pt_root` unused).
- If further compile-speed work is needed, next likely win is moving `arceos_posix_api/build.rs` outputs to `OUT_DIR` and avoiding unnecessary rewrites.
