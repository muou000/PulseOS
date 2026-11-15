# File I/O position transaction checks

Run `cargo test --manifest-path tests/axfs_io_host/Cargo.toml --target x86_64-unknown-linux-gnu`.

The harness compiles the production position-transaction module directly. It
checks shared-position exclusion across completed windows, positioned append,
zero-progress append, checked progress, and cancellation of a queued operation.
Synchronous entry also retains the position across a later wait, yields to
already queued operations, and leaves positioned requests independent.
It does not model the page cache, user pinning, or filesystem backend; the SG
guest suite covers their integration and the actual syscall operation counts.
