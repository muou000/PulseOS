# Real BPF capture compatibility entrypoint

`run.py` delegates runtime work to `../bpf_sampling/run.py --archive`. Each run
rebuilds the real consumer, exports the records actually read from Perf Buffer,
and retains its diagnostics and input identities under `../bpf_sampling/runs/`.

```sh
python3 tests/bpf_smoke/run.py guest --arch riscv64 --mode task
python3 tests/bpf_smoke/run.py guest --arch loongarch64 --mode trace
python3 tests/bpf_smoke/run.py gate
```

`gate` and `smoke` run task-clock, sched-switch, mixed scheduler, and fault
completion captures on both architectures by default. `--arch` and `--mode` narrow the requested runs. Kernel,
ELF and image overrides require `--arch`; use `--kernel`, `--kernel-elf`, and
`--image` (`--primary` is retained as an alias). `--kernel-provenance` forwards an
explicit build manifest. Fault-injection runs accept `--fault` with `none`,
`zero-producer`, `zero-consumer`, `export-overflow`, `ring-overflow`, or `aborted`; the real sampler
defines their validation and failure behavior. `--ring-pages` accepts 1 or 16
(default 16); the one-page setting exercises ring wrap during real guest runs. The sampler uses the QEMU shape
specified in the repository's `AGENTS.md` with snapshot images and eight CPUs.
Build enabled kernels with `make test APP_FEATURES="qemu bpf-trace"` first.

`build` and the compatibility name `build-raw` build the current sampler with
archive export. Custom `--payload`, a second image, custom QEMU commands and the
old `BPF RESULT PASS`/LTP-style markers are no longer accepted by this entrypoint.
The old guest source now fails compilation with migration guidance. Missing
tools, guest failures, zero actual records, or rejected archives fail the gate.

The old `parity` command exits unsuccessfully. Its fabricated records and
unmeasured/defaulted counters do not prove complete off-CPU attribution or
cross-architecture parity. A successful real capture gate also does not make
that broader claim.

`fixtures/format-v1.bin` is retained only as a **static format fixture**. It
contains deterministic event data and metadata, not measured performance or
current build identities. The fixture cannot enter the runtime command path:

```sh
python3 tests/bpf_smoke/run.py fixture-check
python3 tests/bpf_smoke/test_runner.py
```

The old run list and schema blob are historical artifacts of the retired guest
payload and are not executed by this driver. See `../bpf_sampling/README.md` for
the real sampler's semantic checks and limitations.
