# Generic guest recorder acceptance (#195, #211, #213)

Keep new raw captures, serial logs, ELF/image copies and generated archives in
local run directories or separate artifact storage; do not commit them to Git.
Commit compact results, input/tool identities, hashes and reproduction commands
under the [sampling evidence retention policy](../../docs/sampling-evidence-retention.md).
Historical `evidence/` summaries and indexes remain, but their raw bundles have
been retired from the current tree and full replay requires separate copies.

Build the enabled kernels with the repository gate, then run the recorder
against separate guest processes:

```bash
set -o pipefail
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
cargo build -p bpf-analyzer
python3 -m unittest discover -s tests/bpf_record -p 'test_*.py'
python3 tests/bpf_record/acceptance.py --plan
python3 tests/bpf_record/acceptance.py \
  --output tests/bpf_record/runs/213-fresh --analyzer target/debug/bpf-analyzer
```

The #213 matrix runs 18 independent boots per architecture, serially, with
benchmarks last. The output directory must be new and under `tests/bpf_record/`.
Repeated `--arch` and `--suite` select a smaller matrix. Each run retains its
original files under `ARCH/SUITE`; `index.json` records hashes and fails closed
if any guest case or recorder build identity fails. This is the guest stage;
the independent [`qualify.py` stage](QUALIFICATION.md) must also check the fixed
production Queries through perf and FlameGraph before claiming the full
workflow passed. It invokes `e2e.py` for each Query and rejects missing cases.

Individual suites remain available:

```bash
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
python3 tests/bpf_record/run.py guest --arch riscv64 --suite nonleader-exec
python3 tests/bpf_record/run.py guest --arch loongarch64 --suite nonleader-exec
python3 tests/bpf_record/run.py guest --arch riscv64 --suite installed-io
python3 tests/bpf_record/run.py guest --arch loongarch64 --suite installed-io
```

Positive suites build the normal `guest` recorder. Only `lifecycle`, `negative`,
`stacks-observation`, `recovery`, `benchmark`, and `full` build the `acceptance`
variant, whose extra flags drive control/ownership failure probes. `stacks`
selects the appropriate variant for each child boot. An explicit `--recorder`
must have an adjacent `build.json` matching its SHA, architecture and required
variant; an acceptance executable cannot satisfy a production suite.
`inputs.json` retains this build witness, the deployed ELF hashes and QEMU
version/binary SHA. Earlier #211 archives used acceptance builds, including
positive cases; those remain historical evidence for that variant and are not
relabeled as #213 production runs.

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
artifacts. `--analyzer` freezes an already-built host analyzer, and `--run-dir`
selects a new individual run directory under `tests/bpf_record/`.

The default software sources now request frame-pointer callchains. `--callchain
none` selects explicit single-IP recording; `--callchain fp --stack-depth 32`
requests the current bounded kernel stack contract. Unsupported depths and
unavailable combinations fail before enable. Tracepoint contexts stay unchanged
when mixed with repeated software sources.

The recorder reserves one reusable 512 MiB process heap. This is a virtual
address-space bound, not an RSS claim; allocation/free cycles reuse it instead
of generating per-object mmap/munmap journal traffic. `RECORD HEAP` reports the
reservation, live requested/rounded allocations and observed peak. The arena
is reclaimed on process exit; session FD/ring cleanup remains separately
reported. Retained records remain capped by `--record-bytes` (at most 64 MiB),
the journal read by 9 MiB, and the explicit kernel ELF input by 128 MiB.

`stacks` records real nested functions in the separate fixture, mixed repeated
CPU/task/scheduler/fault sources, and an existing installed shell. It also checks
SIGINT/SIGTERM, target exit, retained-record overflow, a rejected initial snapshot, and a
failed final journal. The fixture is built with frame pointers and contains
three non-inlined nested functions. The suite executes `stacks-cpu`, `stacks-task`,
`stacks-mixed`, `stacks-existing`, `stacks-sigint`, `stacks-sigterm`, `stacks-exit`,
`stacks-overflow`, and `stacks-observation` in separate boots, each with its own
inputs, original files and replayable results. These names can also be selected
directly. Fresh boots keep unrelated earlier workloads from exhausting the
bounded boot journal; they do not enlarge that journal or hide drops.
The gate requires an observed user chain of
at least three frames and an observed kernel chain of at least three frames in
the mixed workload, records user/kernel counts and every termination reason,
and never synthesizes a chain. Positive mapping-coverage gates reject any journal
loss; overflow captures remain diagnostic partial files. `mapping` waits for the production recorder to
enable before performing actual file mappings at byte offset 4096, mapped-file
and task rename, fork, exec, remap, unmap, address reuse and exit. Its oracle
checks those transitions against the unchanged raw journal. `nonleader-exec`
runs the stable task-binding case with the production executable. `recovery`
retains the same case alongside an injected stop failure in the acceptance build.
Numeric PID/TID reuse is not forced by these QEMU
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

`installed-io` starts one installed `dd` process before the production recorder,
binds its existing TID to a task source, and checks real kernel samples with the
same stable identity. The target must still be alive after recording; it is
then stopped and reaped. Its fixed kernel Query supplies the native function
proof without discarding mapping-mutation samples from the churning suite.

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
GNU notes through the analyzer's `--elf-identity ARCH` stdin interface and shared
guest/host decoder, preserves known no-build-id as `null`, and reports missing files.
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
