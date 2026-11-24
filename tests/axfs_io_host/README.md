# Filesystem I/O host checks

Run `cargo test --manifest-path tests/axfs_io_host/Cargo.toml --target x86_64-unknown-linux-gnu`.

The harness compiles the production position-transaction module directly. It
checks shared-position exclusion across completed windows, positioned append,
zero-progress append, checked progress, and cancellation of a queued operation.
Synchronous entry also retains the position across a later wait, yields to
already queued operations, and leaves positioned requests independent.
It does not model the page cache, user pinning, or filesystem backend; the SG
guest suite covers their integration and the actual syscall operation counts.

Run just the FAT block-device tests with
`cargo test --manifest-path tests/axfs_io_host/Cargo.toml --target x86_64-unknown-linux-gnu --test fat_disk`.
The harness uses the production FAT adapter with an injected asynchronous block driver.
It checks that read, write, and flush errors reach Hadris, and that a flush following a cancelled write waits for its original data.
