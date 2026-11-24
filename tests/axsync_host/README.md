# Mutex task-ID regression

Run the diagnostic executable from the repository root:

```sh
cargo run --locked --manifest-path tests/axsync_host/Cargo.toml
```

This compiles the actual `modules/sync/src/mutex.rs` against the resolved
`lock_api` version. A narrow host adapter supplies task IDs, including zero,
without creating 2^64 kernel tasks. It checks both zero-ID acquisition paths,
unchanged state on rejection, ordinary exclusivity, blocking recursive
acquisition, and guard transfer/drop through public APIs. The zero-ID checks
use only `RawMutex`, so the failing baseline never creates aliased data references.

The executable deliberately compiles the source with `cfg(test)` disabled;
the module's existing unit tests require the real kernel scheduler. This is
why the command is `cargo run`, not `cargo test`.

The adapter does not model the kernel scheduler: unexpected waits panic and
notifications are inert. The recursion check verifies its specific diagnostic
so an unexpected scheduler call cannot satisfy it. Actual blocking and wakeups
are exercised by `sync::run_lock_stress_checks()` on both QEMU architectures.
