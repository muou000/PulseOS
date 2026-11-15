# User ABI read regression (#157)

Build through `make test`, then run:

```sh
python3 tests/user_abi_reads/run.py --arch riscv64
python3 tests/user_abi_reads/run.py --arch loongarch64
```

The freestanding C probe exercises the actual guest syscall boundary. It checks
invalid addresses, short copies crossing from a writable page into `PROT_NONE`,
malformed fields, and error precedence for `fcntl`, socket options and addresses,
`nanosleep`, `ppoll`, `rt_sigaction`, semaphore operations, and `epoll_ctl`.
Signal handler values 0 and 1 must round-trip as ABI data. Failed signal-action
copies must preserve the installed action; failed epoll copies must leave the
descriptor unregistered. A valid zero semaphore operation provides a control.

The runner requires Clang, Rust's `rust-lld`, `debugfs`, and the selected QEMU.
It injects the probe into a private copy of `disk.img` (RV64) or `disk-la.img`
(LA64), boots using the repository's SMP=8, 8 GiB snapshot command, and removes
that private image afterward. Source images are unchanged. `--kernel`, `--image`,
`--timeout`, and `--log-dir` override defaults.

Logs, guest ELF, the QEMU command, kernel SHA-256, and assertion counts remain
under `records/`. Success requires the final guest marker, completed filesystem
writeback and poweroff, and QEMU exit status 0; timeout is a failure. This is
focused syscall evidence, not a full LTP run or a universal soundness proof.
