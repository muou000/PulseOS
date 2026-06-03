## 2025-05-20 - String Formatting Optimization in #![no_std] environment

**Learning:** `alloc::format!` inside hot loops (like processing memory maps in `/proc/<pid>/maps`) causes massive overhead due to repeated string allocations. Additionally, `cargo check --workspace` might fail on unrelated offline vendored dependencies if `RUSTC_BOOTSTRAP=1` and correct path are not used.

**Action:** Replace `alloc::format!` inside loops with `core::fmt::Write` trait `write!` macro on a pre-allocated or persistent `String` buffer to eliminate intermediate allocations and reduce memory fragmentation.
