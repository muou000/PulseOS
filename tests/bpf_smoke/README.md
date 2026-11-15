# Real BPF capture gate

`run.py` delegates runtime work to `../bpf_sampling/run.py --archive`. Each run
rebuilds the real consumer, exports the records actually read from Perf Buffer,
and retains its diagnostics and input identities under `../bpf_sampling/runs/`.

```sh
python3 tests/bpf_smoke/run.py guest --arch riscv64 --mode task
python3 tests/bpf_smoke/run.py guest --arch loongarch64 --mode trace
python3 tests/bpf_smoke/run.py gate
```

`gate` runs task-clock, sched-switch, mixed scheduler, and fault
completion captures on both architectures by default. `--arch` and `--mode` narrow the requested runs. Kernel,
ELF and image overrides require `--arch`; use `--kernel`, `--kernel-elf`, and
`--image`. `--kernel-provenance` forwards an
explicit build manifest. Fault-injection runs accept `--fault` with `none`,
`zero-producer`, `zero-consumer`, `export-overflow`, `ring-overflow`, or `aborted`; the real sampler
defines their validation and failure behavior. `--ring-pages` accepts 1 or 16
(default 16); the one-page setting exercises ring wrap during real guest runs. The sampler uses the QEMU shape
specified in the repository's `AGENTS.md` with snapshot images and eight CPUs.
Build enabled kernels with `make test APP_FEATURES="qemu bpf-trace"` first.

`build` builds the current sampler with archive export. Missing
tools, guest failures, zero actual records, or rejected archives fail the gate.
The supported commands are `probe`, `build`, `guest`, and `gate`.

## Rejected-input regression tests

The removed `build-raw`, `smoke`, `parity`, and `fixture-check` commands and
`--primary` alias are rejected by argument parsing. The v1 artifact at
`fixtures/format-v1.bin` is retained only to test explicit format rejection by
the current analyzer and rejection of fabricated guest success markers. It is
not accepted capture input. The retired synthetic guest source also remains a
negative compilation fixture.

```sh
python3 tests/bpf_smoke/test_runner.py
```

The old run list and schema blob are historical artifacts of the retired guest
payload and are not executed by this driver. See `../bpf_sampling/README.md` for
the real sampler's semantic checks and limitations.
