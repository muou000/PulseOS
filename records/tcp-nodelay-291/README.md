# IPv4 TCP_NODELAY inheritance

The probe uses one IPv4 loopback listener with four successive connections for each initial value of `TCP_NODELAY`. It reads the first two accepted sockets, toggles the first child and checks the sibling and listener. A third connection is already queued (listener readable by `poll`) when the listener setting changes. That child must keep the old setting. The fourth connection must get the new one. [Regression probe](../../tests/net/accept_nodelay.c)

| System | Initial 0 | Initial 1 |
|---|---|---|
| Linux x86_64 6.6.87.2-microsoft-standard-WSL2 | PASS | PASS |
| RV64 and LA64, base `3f8b3396` | 1 failed check | 5 failed checks |
| RV64 and LA64, fix `e7032cae` | PASS | PASS |

On both baseline guests, the first and second children read back 0 when the listener was set to 1. Changing the listener from 0 to 1 also left the next child at 0. The probe exited 1 on both baseline guests and 0 on Linux and both fixed guests.

## Reproduction

Run from the repository root. Use `riscv64-linux-gnu-gcc` or `loongarch64-linux-gnu-gcc` for the corresponding guest. The example installs the RV64 executable into a private copy of the test image.

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror tests/net/accept_nodelay.c -o /tmp/accept_nodelay
/tmp/accept_nodelay
scratch=$(mktemp -d)
riscv64-linux-gnu-gcc -std=c11 -O2 -static tests/net/accept_nodelay.c -o "$scratch/probe"
cp --reflink=auto --sparse=always disk.img "$scratch/rv.img"
debugfs -w -R "write $scratch/probe /291-probe" "$scratch/rv.img"
```

Boot the matching kernel with the repository's QEMU command, select the copied disk with `snapshot=on`, and run `/291-probe` in the guest. For LA64 use `disk-la.img` and its cross compiler. Both kernel revisions used the default release configuration, eight vCPUs and 8 GiB RAM. Each boot image was verified against its build provenance. [QEMU commands](../../AGENTS.md) · [HTTP results and per-round measurements](http.md)
