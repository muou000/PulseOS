# Ordinary mount/unmount regression (#160)

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
child/parent unmount. Host tests exercise injected registry failures and
topology rollback separately; this guest validates the actual syscall wiring.
