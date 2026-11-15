# #162 move and unmount coordination

`MS_MOVE` now commits the VFS attachment and both axfs registries through the
mount coordinator. Registry updates select the actual moved identities, so
moving an upper stacked bind leaves the lower mount and its children at their
original paths. Rejected updates restore the original topology before unlock.

Normal and lazy unmount select propagated peers inside the coordinator. A
failed primary leaves peers intact; after primary success, each peer uses the
same detach transaction. Propagation remains best effort: busy peers retain
both their topology and records. Filesystem writeback remains outside the
coordinator's locks. Boot and remount retain their required registration
helpers; obsolete manual removal and pathname-renaming helpers are removed.

## Before and after

| Check | Before | After |
| --- | --- | --- |
| Move upper bind with nested mount | RV guest failed `move-retains-lower-root-row got=0 want=1` after 89 assertions | Lower root/child records remain; moved root/child each have one destination record |
| Coordinator unmount of shared child | Host regression left peer/slave `/child` rows | One coordinator call removes primary, peer and slave records |
| Failed move or primary unmount update | No transactional move boundary; peer cleanup owned by syscall | Injected rejection preserves identities and records; retry succeeds |
| Repeated normal/lazy unmount | Coverage did not include all propagated paths | Removed identities return `InvalidInput`/`EINVAL` and replacement mounts remain intact |

Baseline RV kernel source: clean commit
`c4ae5d906069f50b8965df32044bf7ae8862a21d` (#161 implementation, also present
at this branch's base `204b0a86d8ae6de38429d18f1012b465c2a57b40`). Its boot
SHA256 was `a1a46c12e44e174837ed88d482f19c77d94b1d80720c59f5f00346da58661568`.
The saved provenance manifest was checked against the ELF and boot image
before rebuilding. The baseline guest intentionally stops on its first failed
assertion, so its result also reports missing completion/poweroff markers.

## Validation

Final kernels were built from clean source commit
`e3d46767075e04b37ba546fb8ee33641d30cf46f`, with identical source-tree SHA256
`d93c1145d5a222de1a79b81a1b65580c4569d0acc5a0d0163e2d3da36e776a0a`.
Both saved manifests were verified against their ELF and boot image with
`scripts/build_provenance.py::verify_manifest`; guest results record the same
boot-image hashes.

Final results, after the review fix:

| Gate | Result |
| --- | --- |
| axfs host suite | 16 passed |
| axfs-ng-vfs suite | 23 passed |
| `make test` | Exit 0; RV64 and LA64, existing warnings remain |
| RV64 mount syscall guest | 397 assertions; normal poweroff |
| LA64 mount syscall guest | 397 assertions; normal poweroff |
| `git diff --check` | Exit 0 |

Commands:

```sh
cargo test --locked --manifest-path tests/axfs_mount_host/Cargo.toml
cargo test -p axfs-ng-vfs --lib
set -o pipefail
make test 2>&1 | tail -30
python3 tests/user_abi_reads/run.py --suite mounts --arch riscv64 --log-dir records/issue162-final-rv
python3 tests/user_abi_reads/run.py --suite mounts --arch loongarch64 --log-dir records/issue162-final-la
git diff --check
```

The guest runner uses the repository's 8-CPU, 8-GiB QEMU configuration with
private image copies and snapshot disks. These focused regressions do not
replace the broader LTP `fs_bind` matrix, which was not run.

Evidence (logs normalize terminal escapes, carriage returns and trailing
whitespace; assertion text and outcomes are unchanged):

- [Host failure before migration](unmount-host-red.log)
- [Host suite](host-tests.log), [VFS suite](vfs-tests.log), [build gate](build-test.log)
- [RV baseline result](../issue162-baseline-rv/result.json), [guest log](../issue162-baseline-rv/guest.log), [provenance](../issue162-baseline-rv/provenance.json)
- [RV final result](../issue162-final-rv/result.json), [guest log](../issue162-final-rv/guest.log), [command](../issue162-final-rv/command.json), [provenance](../issue162-final-rv/provenance.json)
- [LA final result](../issue162-final-la/result.json), [guest log](../issue162-final-la/guest.log), [command](../issue162-final-la/command.json), [provenance](../issue162-final-la/provenance.json)

## Standards

Independent review against `204b0a86d8ae6de38429d18f1012b465c2a57b40`
found no documented-standard violations. One non-blocking Duplicated Code
finding identified the guarded subtree traversal shared by move and lazy
unmount. It was extracted into a private helper using the existing writer and
caller-owned deferred-drop buffers.
Re-review of `e3d46767` confirmed the finding resolved, with no new findings.

The bounded concurrency review checked rollback on rejection/unwind, deferred
ownership drops, and successful-only `has_children` publication. Existing
topology guards and kernel preemption primitives remain trusted dependencies;
this is a source review, not a full Rust soundness proof.

## Spec

Independent review found no missing requirements, scope creep, or incorrect
implementation of #162. Move, ordinary unmount, and lazy detach use the
coordinator; identity-based updates preserve covered mounts; stale handles
cannot remove replacements; and obsolete coordination helpers are gone.
Re-review of the shared traversal confirmed zero findings.

Final review totals: Standards 0 unresolved (1 maintenance finding fixed);
Spec 0 findings.
