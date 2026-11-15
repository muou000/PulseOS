# PID 1 and shutdown regression

Build through the repository entry points (`make rv`, `make la`, or `make test`).
The runner uses the prescribed SMP=8, 8 GiB QEMU invocation and a snapshot disk;
it never writes the source rootfs. Each invocation boots a fresh guest and saves
the QEMU command, kernel SHA-256 and console log under `records/`.

```bash
python3 tests/init_shutdown/run.py --action poweroff
python3 tests/init_shutdown/run.py --action reboot
python3 tests/init_shutdown/run.py --action halt
python3 tests/init_shutdown/run.py --action 'poweroff -f'
python3 tests/init_shutdown/run.py --action 'reboot -f'
python3 tests/init_shutdown/run.py --action identity
python3 tests/init_shutdown/run.py --arch loongarch64 --action identity
python3 tests/init_shutdown/run.py --arch loongarch64 --action 'kill -USR2 1'
python3 tests/init_shutdown/run.py --arch loongarch64 --action 'kill -TERM 1'
```

Pass `--kernel`, `--image`, `--timeout` or `--log-dir` to select inputs and output.
The default RISC-V image contains BusyBox. The local LoongArch image contains
systemd's `poweroff`/`reboot` clients, which require a running systemd manager;
use direct signals there to exercise the same kernel notification interface.
`kill -USR1 1`, `kill -PWR 1`, and `kill -INT 1` cover the additional halt/restart
notifications. BusyBox applet behavior is verified on RISC-V.

Every run requires the initial shell to report PID 1, `kill(1, 0)` to succeed,
the expected power transition after filesystem writeback, and QEMU to exit 0
without host termination. A timeout is a failure, never a shutdown success.

The `identity` action uses Clang (with RISC-V/LoongArch targets), Rust's bundled
`rust-lld`, and `debugfs` from e2fsprogs. It builds the freestanding `guest.c`
Linux-syscall program, injects it into a private image copy, and has the initial
shell `exec` it. It verifies:

- `getpid`, `gettid`, and `set_tid_address` return 1; `kill`, `tkill`, and `tgkill`
  find that identity; initial session and process group IDs are 1.
- Invalid signals return `EINVAL`, and nonexistent processes return `ESRCH`.
- A blocked `SIGINT` sent to the initial process group returns normally without
  triggering a machine restart.
- A forked child has PID=TID>1 and parent PID 1; its `SIGUSR2` retains ordinary
  termination semantics and can be reaped with the correct status.
- An unprivileged child receives `EPERM` for `kill(1, SIGUSR2)`.

Only after these assertions does the probe call the existing forced poweroff
syscall. Snapshot runs and the completed-writeback log confirm the shutdown
path is reached; they do not inject storage failures or prove persisted data
survives a power failure.
