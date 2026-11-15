# Mount coordination host tests

Run from the repository root:

```sh
cargo test --locked --manifest-path tests/axfs_mount_host/Cargo.toml
cargo test -p axfs-ng-vfs --lib
```

The harness compiles the production `modules/axfs/src/mounts.rs` directly and
links the repository's real `axfs-ng-vfs`. An in-memory directory filesystem
supplies nodes; mount topology, mount identity, registry updates and rollback
all execute production code. Tests observe public mount operations, path lookup,
and the same `list_mounts()` snapshot used by `/proc/mounts`.

Coverage includes successful mount/unmount, duplicate targets, failed probes,
late registry conflicts, rejected mount and unmount updates, busy child mounts,
competing probes, ancestors moved during probing, stale mount handles, and
bind mount stacks, read-only inheritance, peer/slave shadow attributes and
records, rejected move-shadow publication with retry, and lazy subtree rollback
and record cleanup. Move rejection preserves parent/child identities and rows;
retry moves each row once. Normal unmount removes peer/slave records through
the coordinator; rejected primary updates preserve them, and repeated normal
or lazy attempts cannot remove replacement mounts. Ordinary, bind, move,
shadow publication, and propagated unmount all exercise the same production
coordinator; tests do not replace its registry or VFS logic.

Registry rejection is injected through the coordinator's `cfg(test)` hook.
Tests serialize access to the production globals and remove their mounts after
each successful workflow. Host `kspin` enables SMP locking to exercise real
mutual exclusion between threads; kernel preemption and device I/O are outside
this harness. The standalone Cargo workspace avoids axfs's unrelated kernel
allocator and architecture dependencies. Its lockfile starts from the root
workspace's dependency versions.

The kernel build gate remains:

```sh
make test 2>&1 | tail -30
```
