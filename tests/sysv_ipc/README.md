# SysV IPC lifecycle checks

`lifecycle.c` follows a segment marked with `IPC_RMID` across fork. The
parent detaches first. The child checks that it can still use the mapping,
then releases the final attachment by `shmdt` or exit. Both paths must
invalidate the ID. A failed fork must leave only the parent's attachment,
and a vfork child's exit must preserve that attachment in the shared VM.
The semaphore case checks that two `SEM_UNDO` operations on the same
semaphore are rolled back when the child exits.

Build the probe with the matching Linux cross compiler and install it on a
private copy of the test image. For RV64, run from the repository root:

```sh
scratch=$(mktemp -d)
riscv64-linux-gnu-gcc -std=gnu11 -Wall -Wextra -Werror -O2 -static \
    tests/sysv_ipc/lifecycle.c -o "$scratch/lifecycle"
cp --reflink=auto --sparse=always disk.img "$scratch/disk.img"
scripts/install_to_rootfs.sh "$scratch/disk.img" "$scratch/lifecycle" /ipc-lifecycle
```

For LA64 use `loongarch64-linux-gnu-gcc` and `disk-la.img`. Build the kernels
with `make test` and boot the matching QEMU command from `AGENTS.md` with
the private image. Run `/ipc-lifecycle` at the guest prompt. Each case prints
a `PASS` line, and the program exits with status 0.

To exercise unmap rollback deterministically, use a separate kernel checkout:

```sh
git worktree add --detach "$scratch/reserved" HEAD
git -C "$scratch/reserved" apply "$PWD/tests/sysv_ipc/shmdt-reservation.patch"
make -C "$scratch/reserved" test
```

Boot the resulting RV64 `.bin` or LA64 `.elf` with the same private image
and run `/ipc-lifecycle --reservation`. The fixture holds an overlapping
address-space reservation for the first unmap at the probe address. The
guest must observe `EAGAIN`, retain access and a valid segment ID, then
successfully repeat `shmdt` at the same address and observe the ID's removal.
