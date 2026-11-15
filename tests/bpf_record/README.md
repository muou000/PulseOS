# Generic guest recorder acceptance (#195)

Build the enabled kernels with the repository gate, then run the recorder
against separate guest processes:

```bash
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
python3 -m unittest discover -s tests/bpf_record -p 'test_*.py'
python3 tests/bpf_record/run.py guest --arch riscv64 --suite full
python3 tests/bpf_record/run.py guest --arch loongarch64 --suite full
python3 tests/bpf_record/run.py guest --arch riscv64 --suite existing
python3 tests/bpf_record/run.py guest --arch loongarch64 --suite existing
python3 tests/bpf_record/run.py guest --arch riscv64 --suite recovery
python3 tests/bpf_record/run.py guest --arch loongarch64 --suite recovery
python3 tests/bpf_record/run.py guest --arch riscv64 --suite benchmark
python3 tests/bpf_record/run.py guest --arch loongarch64 --suite benchmark
```

`--suite smoke` records CPU, the complete scheduler group, and faults.
`lifecycle` covers an existing numeric TID, duplicate same-type sources mixed
with task/scheduler/fault sources, source FD dup/close, SIGINT, SIGTERM, target
exit, and a pre-existing BusyBox shell process. `negative` checks invalid CLI
requests, second program load/attach failures, and an actual write failure
after 1024 file bytes. `benchmark` runs baseline, loaded-detached, and attached
phases. `full` combines smoke, lifecycle, negative and benchmark in one boot.
The existing-program and recovery suites run separately. `--duration-ms` changes the actual
recording duration, and `--kernel`, `--image`, and `--recorder` select explicit
artifacts.

`existing` separately captures all three CPU/scheduler/fault modes while the
installed `sh` repeatedly runs installed `dd` and `sleep`. Missing commands,
failed `dd`, or an exited workload fail this gate; the runner never substitutes
the test fixture for an unavailable real program.

`recovery` records a task, then a real nonleader thread that execs the fixture
after the recorder has enabled. The source must retain its stable task identity
while the numeric TID changes to the process leader; the timeline oracle requires
samples both before and after exec and shutdown only after the replacement
workload exits. A separate recovery case drives an actual rejected disable ioctl,
then checks successful quiescence, cleanup, a saved partial capture, a typed
control error, and a nonzero CLI exit.

The recorder contains no workload. `fixture.rs` is a separate test executable
with busy-loop, nanosleep/yield, and demand-fault workloads derived from the
existing sampling regression. The shell target is the rootfs's installed
`sh`. Both run before the recorder is started; task mode receives their actual
numeric TID. The fixture's file-dump command reads the recorder's file and
transports its exact bytes over serial with ordered offsets, byte count, and
CRC32. It never constructs capture records or fills missing fields.

Each run copies the rootfs, kernel, recorder and fixture into `runs/`, verifies
injected bytes, and uses the AGENTS.md QEMU command with `snapshot=on`. The
original rootfs hash must remain unchanged. `inputs.json`, `cases.sh`,
`guest.log`, exact `.pbcapture` files, analyzer reports, and `result.json`
retain reproducible inputs and observations. The host analyzer must accept
every normal file and reject the truncated write-failure file. Missing serial
chunks, trailers, source bindings, real samples, or required lifecycle markers
fail acceptance. Partial data remains partial; zero loss is never inferred
from missing diagnostics.

The acceptance build alone exposes failure and ownership hooks. The second
load contains an invalid BPF instruction; the second attach uses an invalid
attach type. The dup gate duplicates the actual perf-event descriptors and
closes the originals before sampling. The write gate writes a real file
prefix, then attempts a real write through a read-only descriptor, leaving no
trailer. The normal production executable rejects these test options.

Performance results are whole-workload measurements. All three phases use the
same external workload duration and iteration definition. The report records
wall time, iterations/second, ratios to baseline, recorder-owned FD/mapping
resources, actual before/after proc diagnostics for every phase, and overlap between every enabled source window and
the workload. Preparation and teardown margins are included, so these are not
steady-state overhead estimates. One run is observational evidence; no
statistical significance, performance threshold, or lossless completeness is
claimed.

System queue/fault counters retain their system scope; overlapping loss layers
are never added. Loaded-detached snapshots are taken by the recorder while its
objects exist, so their event/program rows and registered-event/subscription
counts measure the actual prepared resources. Baseline and attached system
snapshots are separate stable proc opens. Each run freezes its matching analyzer
binary before boot. Replay original files with
`python3 tests/bpf_record/verify.py RUN --analyzer target/debug/bpf-analyzer`.
Use `--functional-only` for older full runs whose initial benchmark evidence
predates the additional baseline snapshots; separate benchmark runs supply the
complete performance evidence.

Pending fault entry-generation rejection and accepted VM invocation shutdown
also have deterministic kernel tests. A QEMU workload generating faults during
stop complements those tests; its timing alone does not prove a specific
resolver was pending at the disable instruction.
