# BPF and pipe boot checks

Normal builds (`make rv`, `make la`, `make test`) exclude the BPF and pipe guest
checks. Enable both explicitly with the root Cargo feature `guest-checks`:

```bash
set -o pipefail
make test APP_FEATURES="qemu guest-checks" 2>&1 | tail -30
```

Boot `kernel-rv` or `kernel-la` with the QEMU commands in the root `AGENTS.md`
and an image for that architecture. Before userspace starts, the test kernel
runs the original assertions and prints the existing `[BPF_GUEST]` and
`[PIPE_GUEST]` diagnostics. Their final success markers are:

```text
[BPF_GUEST] PERF_EVENT sampling assertions: PASS
[PIPE_GUEST] All pipe checks PASSED!
```

An assertion failure or returned error still panics with the original diagnostic.
`guest-checks` is independent of `bpf-trace`; for both boot checks and runtime
sampling, use `APP_FEATURES="qemu bpf-trace guest-checks"`. Other subsystem boot
checks and `mapping-lifecycle-test` retain their existing configuration.

Run the build regression with:

```bash
python3 tests/guest_checks/build.py
# Optional: restrict the same feature matrix to one architecture.
python3 tests/guest_checks/build.py --arch riscv64
```

It builds both QEMU architectures through `make rv` / `make la`, with all four
combinations of `guest-checks` and `bpf-trace`. It checks the freshly linked,
stripped kernel image for the absence of both diagnostic prefixes when checks
are disabled, and the presence of all 13 original result markers when enabled.
Build failures fail the regression. This verifies compilation and linkage;
executing the assertions requires a QEMU boot. Builds run sequentially because
they share `.axconfig.toml`, and leave the last tested configuration installed.
Run `make test` again to restore normal kernels.
