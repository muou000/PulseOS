# Generic guest recorder acceptance (#195, #211)

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
python3 tests/bpf_record/run.py guest --arch riscv64 --suite stacks
python3 tests/bpf_record/run.py guest --arch loongarch64 --suite stacks
python3 tests/bpf_record/run.py guest --arch riscv64 --suite mapping
python3 tests/bpf_record/run.py guest --arch loongarch64 --suite mapping
```

`--suite smoke` records CPU, the complete scheduler group, and faults.
`mixed` isolates the repeated CPU/task/scheduler/fault session in one boot.
`lifecycle` covers an existing numeric TID, duplicate same-type sources mixed
with task/scheduler/fault sources, source FD dup/close, SIGINT, SIGTERM, target
exit, and a pre-existing BusyBox shell process. `negative` checks invalid CLI
requests, second program load/attach failures, and an actual write failure
after 1024 file bytes. `benchmark` runs baseline, loaded-detached, and attached
phases. `full` combines smoke, lifecycle, negative and benchmark in one boot.
The existing-program and recovery suites run separately. `--duration-ms` changes the actual
recording duration, and `--kernel`, `--image`, and `--recorder` select explicit
artifacts.

The default software sources now request frame-pointer callchains. `--callchain
none` selects explicit single-IP recording; `--callchain fp --stack-depth 32`
requests the current bounded kernel stack contract. Unsupported depths and
unavailable combinations fail before enable. Tracepoint contexts stay unchanged
when mixed with repeated software sources.

`stacks` records real nested functions in the separate fixture, mixed repeated
CPU/task/scheduler/fault sources, and an existing installed shell. It also checks
SIGINT, target exit, retained-record overflow, a rejected initial snapshot, and a
failed final journal. The fixture is built with frame pointers and contains
three non-inlined nested functions; the gate requires an observed user chain of
at least three frames, records actual kernel depth and every termination reason,
and never synthesizes a chain. `mapping` waits for the production recorder to
enable before performing actual file mappings at byte offset 4096, mapped-file
and task rename, fork, exec, remap, unmap, address reuse and exit. Its oracle
checks those transitions against the unchanged raw journal. `recovery` remains
the real nonleader-exec gate. Numeric PID/TID reuse is not forced by these QEMU
workloads; adversarial analyzer tests exercise reused numbers with distinct
stable task and address-space identities.

All new runs deploy `/boot/kernel.elf` and pass `--kernel-elf` to the guest CLI.
For a raw RV boot binary the host first verifies both binary and matching ELF
hashes from the build provenance. The guest independently matches the supplied
ELF's actual GNU build-id to the running kernel note before recording its full
SHA256. The collector never treats that deployment path as identity.

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

After syncing its output, the recorder emits `RECORD SAVED ... sha256=...`.
The runner compares that witness to the bytes read back from the actual guest
file, then checks the same SHA after collection and analysis. Each capture's
`*-collection.json` records the immutable original identity manifest, verified
content-addressed ELF files, missing files, and unknown mapped-object identities.
No missing fact is added to the original capture. Collect a production file
with explicitly supplied candidate artifacts using:

```bash
python3 tools/bpf-record/collect.py sample.pbcapture --bundle bundle \
  --candidate boot-kernel.elf --candidate target.elf \
  --analyzer target/debug/bpf-analyzer
target/debug/bpf-analyzer sample.pbcapture --mapping-report --bundle bundle
```

`--artifact-manifest` on the analyzer exposes only identities from a fully
validated original capture. The collector verifies complete SHA256 and actual
GNU notes, preserves known no-build-id as `null`, and reports missing files.
Paths in the journal are labels and never trigger implicit host file lookup.
Optional debug objects must match their recorded SHA and GNU ID; separate debug
objects also require the executable's recorded GNU ID. Additional symbol files
do not upgrade partial capture status or change mapping coverage.

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
