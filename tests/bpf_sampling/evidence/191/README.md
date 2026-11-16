# Issue 191 real guest evidence — 2026-11-15

> **Retention update — 2026-11-16:** The raw `.tar.gz` bundles described below
> have been removed from the current tree. Retained indexes, hashes, counts and
> replay reports record historical verification; they do not provide a complete
> replay from this checkout. Bundle names and links below are historical references.
> The old replay commands require complete bundles held separately; metadata
> cannot reconstruct their bytes. For new evidence, follow the
> [fresh-run instructions](../../README.md) and keep raw output out of Git.
> See the [sampling evidence retention policy](../../../../docs/sampling-evidence-retention.md).

These compressed bundles preserve actual QEMU output, consumed RAW frames,
standalone captures and analyzer results. They are not synthetic format fixtures.
The three negative probes deliberately fail and do not produce a capture.

| Run | Actual records | Wraps | Export dropped | Gate |
|---|---:|---:|---:|---|
| [rv-task](rv-task.tar.gz) | 82 | 0 | 0 | PASS |
| [la-task](la-task.tar.gz) | 40 | 0 | 0 | PASS |
| [rv-trace-wrap](rv-trace-wrap.tar.gz) | 555 | 10 | 0 | PASS |
| [la-trace-wrap](la-trace-wrap.tar.gz) | 571 | 8 | 0 | PASS |
| [export-overflow](export-overflow.tar.gz) | 39 | 0 | 38 | PASS |
| [ring-overflow](ring-overflow.tar.gz) | 235 | 0 | 0 | PASS |
| [zero-producer](zero-producer.tar.gz) | no capture | - | - | expected FAIL |
| [zero-consumer](zero-consumer.tar.gz) | no capture | - | - | expected FAIL |
| [aborted](aborted.tar.gz) | no capture | - | - | expected FAIL |

All six saved captures are incomplete and disallow complete attribution. Their
scoped diagnostics retain observed drops and unknown measurements. In particular,
`ring-overflow` has zero raw LOST notices but 317 authoritative sink drops; zero
notices do not imply zero loss. `export-overflow` retains only the records fitting
its bounded buffer and records all omitted samples separately.

`index.json` records bundle and member SHA-256 values, precise build identities,
measurements and actual errors. Each bundle includes the guest's actual ELF,
recovered read-only from that run's saved injected rootfs and checked against its
recorded payload hash. Kernel ELF and 8 GiB VM images are retained in the local
run directories, not duplicated here. Matching kernel hashes, build-time source
commit, dirty source-tree hash and effective config are saved in the manifest and
inside standalone capture diagnostics. These are evidence hashes, not signatures.

To inspect a capture independently, extract its bundle in a scratch directory
and run `cargo run -p bpf-analyzer -- <capture.pbcapture> --json` or `--loss`.
To redo normalization, use `cargo run -p bpf-capture --example runtime_import --
<extracted-run-directory> <new-file.pbcapture>`. The new file contains the chosen
output path, so its checksum can differ; record values and counts must agree.
The original QEMU command and workload/feature/fault settings are in inputs.json;
see ../../README.md for live rerun commands and counter semantics.
