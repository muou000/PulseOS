# #161 bind and propagation mount coordination

The coordinator now publishes ordinary, bind, peer, slave, and nested shadow
mounts through the same VFS attachment callback and axfs registry update.
Rejected updates restore topology before unlock. Lazy detach supplies its
actual subtree identities to the record-removal callback, including shadows.
Each shadow retains bind identity while copying its template's readonly state,
mount flags, source, and filesystem type.

Propagation retains the existing best-effort, per-destination behavior: a
failed shadow is absent from both topology and records, while the primary and
other successful shadows remain. The entire fan-out is not one transaction.
Move's primary rename and remount remain their existing workflows; move's
propagated shadows use the coordinator.

## Before and after

| Check | Before | After |
| --- | --- | --- |
| Ordinary mount below shared parent | Host lookup at `/peer/child` returned the parent filesystem, with no shadow | Peer and slave shadow paths, records, flags, and relationships agree |
| Bind of readonly source | RV syscall guest failed `readonly-bind-listed-ro got=0 want=1` after 56 successful assertions | Both architectures list `ro,bind` and reject writes |
| Shadow bind identity (review finding) | New host assertion `mountpoint_is_bind(shadow.mountpoint())` failed | Nested shadows retain bind identity and their own readonly/flags |
| Final syscall regression | Baseline failed before propagation checks | RV64: 251 assertions; LA64: 251 assertions; both normal poweroff |

Baseline RV kernel: clean source commit
`4eaa843425e260abc15cdf356386ceda96aead56` (merged #160 implementation), boot
SHA256 `9e20933a0b1ad194d90ff741d406f842f79a71a073b272cc7316ab9a8aa2d431`.
The initial guest contained the readonly-bind regression; subsequent slices
extended the same guest to peer/slave propagation and cleanup.

Final kernels: clean source commit
`c4ae5d906069f50b8965df32044bf7ae8862a21d`, identical source tree SHA256
`92fcb82d93bee8fe539d4db1e6585f715536ea470e4765d7a995fe71251991e3`.
Both saved provenance manifests were verified against their ELF and boot image
with `scripts/build_provenance.py::verify_manifest`.

## Validation

```sh
cargo test --locked --manifest-path tests/axfs_mount_host/Cargo.toml
# 15 passed
cargo test -p axfs-ng-vfs --lib
# 20 passed, including the existing shared/slave propagation regression
set -o pipefail
make test 2>&1 | tail -30
# exit 0, RV64 and LA64; existing warnings remain
python3 tests/user_abi_reads/run.py --suite mounts --arch riscv64 --log-dir records/issue161-final-rv
# PASS riscv64: 251 assertions
python3 tests/user_abi_reads/run.py --suite mounts --arch loongarch64 --log-dir records/issue161-final-la
# PASS loongarch64: 251 assertions
git diff --check
# exit 0
```

QEMU used the repository's 8-CPU, 8-GiB configuration with private image copies
and snapshot disks. The runner removed those copies after execution. The
broader 95-case LTP `fs_bind` matrix was not run; the existing VFS propagation
regression and focused syscall suite above were run in full.

Evidence:

Archived logs normalize terminal color escapes, carriage returns, and trailing
whitespace; assertion text and execution results are unchanged.

- [Original missing-shadow failure](host-red.log)
- [Review finding regression](shadow-identity-red.log)
- [Host tests](host-tests.log), [VFS tests](vfs-tests.log), [build gate](build-test.log)
- [RV baseline](../issue161-baseline-rv/result.json), [guest log](../issue161-baseline-rv/guest.log)
- [RV result](../issue161-final-rv/result.json), [guest log](../issue161-final-rv/guest.log), [command](../issue161-final-rv/command.json), [provenance](../issue161-final-rv/provenance.json)
- [LA result](../issue161-final-la/result.json), [guest log](../issue161-final-la/guest.log), [command](../issue161-final-la/command.json), [provenance](../issue161-final-la/provenance.json)

## Standards

Independent review against `0a581e56d87a33eac25172f6a81eeace6f55d14a`:
0 findings. Registry/topology lock ordering, deferred drops, rollback, and
scope conform to the documented contracts.

## Spec

Independent review initially found one P2: nested shadows copied from ordinary
mounts lost bind identity. Commit `c4ae5d90` fixed it, added a failing-then-passing
host assertion and guest coverage, and passed re-review. Final result:
0 unresolved findings. All validation above ran after that fix.
