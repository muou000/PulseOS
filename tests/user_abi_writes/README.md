# User ABI write regression (#158)

Build through `make test`, then run the shared runner:

```sh
python3 tests/user_abi_reads/run.py --suite writes --arch riscv64
python3 tests/user_abi_reads/run.py --suite writes --arch loongarch64
```

The freestanding C probe exercises real syscall output in file, network, time,
task, IPC, and readiness families. It checks native field values and output-size
canaries, invalid addresses, and partial writes crossing into inaccessible pages.
A readable but unwritable page makes `F_GETLK` finish its input copy before its
output faults; the writable prefix must still contain the result and zero padding.

Padding checks cover `flock`, `sysinfo`, `msghdr`, `sigaltstack`, the existing
`semid_ds` ABI, and `epoll_event`. `GETALL` also faults midway through its second
array element and must retain all three bytes already written. These tests lock
in PulseOS's current ABI sizes and errno behavior, without extending syscall
support or changing the IPC layouts.

`recvmsg` uses a loopback UDP datagram. A socketpair fixture exposed an existing
kernel fault: creating `socketpair(AF_UNIX, SOCK_STREAM)` alone triggers a kernel
page fault at address zero on pristine commit `976121e0` as well as the migrated
kernel. The UDP fixture retains the same message-header output assertions while
leaving that separate LocalSocket problem outside this ABI migration. On the
pristine RV64 kernel, the complete probe fails at `sysinfo-inner-padding` (a
nonzero byte is returned); both migrated architectures pass all 81 assertions.

The runner reuses `tests/user_abi_reads/guest.ld` and the existing private-image
QEMU infrastructure. Its default suite remains `reads`. Clang, Rust's `rust-lld`,
`debugfs`, and the selected QEMU are required. Source images are unchanged; logs,
guest ELF, QEMU command, kernel SHA-256, and assertion counts remain in `records/`.
Success requires the final guest marker, completed shutdown writeback, poweroff,
and QEMU status 0. Timeout is a failure.
