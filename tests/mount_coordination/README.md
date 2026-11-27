# Mount coordination regressions (#160, #161, #162)

Run against freshly built kernels:

```sh
python3 tests/user_abi_reads/run.py --suite mounts --arch riscv64
python3 tests/user_abi_reads/run.py --suite mounts --arch loongarch64
```

The shared runner compiles `guest.c`, installs it in a private sparse/reflink
image copy, and runs the repository's QEMU configuration (8 CPUs, 8 GiB,
snapshot disk). It leaves the source image unchanged and records the kernel
hash, QEMU command, guest output, and assertion results under `records/`.

The guest checks `/proc/mounts` against path visibility after tmpfs mount,
duplicate-target rejection, failed device probing, busy unmount, and successful
child/parent unmount. It also checks:

- Read-only inheritance from a bind source, including the listed `ro,bind`
  options and rejected writes.
- Bind and ordinary mount propagation from one shared parent to a peer and a
  slave, with a separate record for each visible mount.
- Nested shadow contents and independent child flags: a writable nested mount
  remains writable under a read-only bind root.
- Slave-local mounts do not propagate back to the master or its peer.
- Normal and lazy unmount remove primary and nested shadow records while
  preserving the original bind source.
- Moving an upper stacked bind and its nested mount updates exactly their
  records, leaving the lower root and child at the original path. Normal
  unmount and lazy detach then remove the correct identities, and repeated
  unmount attempts fail without changing the remaining records.
- Moving a subtree under a shared parent publishes peer and slave shadows;
  lazy detach removes all moved and propagated root/child rows. Repeated normal
  and lazy unmount attempts on the old peer paths return `EINVAL`.

Host tests exercise injected registry failures and topology rollback
separately; this guest validates the actual syscall wiring. The existing LTP
matrix is listed in `tests/ltp/runtest/fs_bind` (bind, rbind, move and mount
namespace scenarios); these focused syscall checks do not replace that matrix.

## Process mount tables (#295)

Build each probe with its target Linux C compiler and install it in a private
copy of the scheduler test image. Run from the repository root with both cross
compilers on `PATH`.

```sh
scratch=$(mktemp -d)
for arch in riscv64 loongarch64; do
    image=disk.img
    if [ "$arch" = loongarch64 ]; then image=disk-la.img; fi
    "${arch}-linux-gnu-gcc" -O2 -Wall -Wextra -Werror -static \
        tests/mount_coordination/proc_mounts.c -o "$scratch/proc-mounts-$arch"
    cp --reflink=auto --sparse=always "$image" "$scratch/$arch.img"
    scripts/install_to_rootfs.sh "$scratch/$arch.img" "$scratch/proc-mounts-$arch" /opt/proc-mounts
done
```

Boot each kernel with its QEMU command in [AGENTS.md](../../AGENTS.md), using
the matching image from `$scratch`. At the guest shell run `/opt/proc-mounts`.
It mounts a temporary tmpfs with special characters in both the source and
target, compares one full read with 7-byte reads through EOF for the root,
self, numeric current PID, PID 1 and live child paths, and checks directory
entries and `ENOENT` after reaping the child. Success ends with
`PASS complete six-field rows and mount field escapes` and exit status 0.
