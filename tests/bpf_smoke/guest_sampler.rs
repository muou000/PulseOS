//! The old #104 guest payload has been retired by #191.
//!
//! It emitted fixed records and build identities unrelated to consumed samples.
//! Use `python3 tests/bpf_smoke/run.py build --arch <arch>` to build the actual
//! consumer in `tests/bpf_sampling/guest.rs` with capture export enabled.
//! The retained static format artifact is `fixtures/format-v1.bin`; it is only
//! consumed by the offline `fixture-check` command and parser regression tests.
compile_error!("retired synthetic guest payload; use tests/bpf_smoke/run.py build --arch <arch>");
