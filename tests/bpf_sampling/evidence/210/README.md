# Current capture v6 native evidence (#210)

> **Retention update — 2026-11-16:** The raw `.tar.gz` bundles described below
> have been removed from the current tree. Retained indexes, hashes, counts and
> replay reports record historical verification; they do not provide a complete
> replay from this checkout. Bundle names and links below are historical references.
> The old replay commands require complete bundles held separately; metadata
> cannot reconstruct their bytes. For new evidence, follow the
> [fresh-run instructions](../../README.md) and keep raw output out of Git.
> See the [sampling evidence retention policy](../../../../docs/sampling-evidence-retention.md).

These are fresh RISC-V guest collections from the #210 implementation, using
`-cpu max`, 8 GiB RAM, eight CPUs and the AGENTS.md snapshot-disk QEMU command.
`index.json` records SHA-256 for each compressed bundle and every member.
Disk images are excluded; their original/injected hashes remain in the inputs.
No historical v2–v5 capture was rewritten to create these results.

| Bundle | Actual records | Result |
| --- | ---: | --- |
| `rv-task-stacks.tar.gz` | 2,706 | Guest lifecycle, independent analyzer and ELF stack oracle pass |
| `rv-cpu-stacks-mappings.tar.gz` | 3,267 | Original guest lifecycle passes; current extraction and analyzer revalidation pass |
| `rv-budget-negative.tar.gz` | 11,915 retained of 25,599 | 13,684 export drops; late mapping attribution correctly rejected |

Both positive captures use container v6 and `PBSRC003`, retain every explicit
logical-source binding, and remain `IncompleteError` with complete attribution
disallowed. The independent Python struct/CRC checks compare every normalized
record with the original RAW bytes and verify every logical ID against the
analyzer's transport-order bindings. They also check the distinct stack kernel
event IDs and declared periods. Results and artifact hashes are in
`v6-independent-comparison.json` inside each positive bundle.

The task capture binds logical source 1 to kernel event 9 and stable task 49.
Its saved input has unknown kernel source commit/provenance; this remains
unknown even though its boot/ELF hashes match the combined run. The combined
capture includes the matching kernel build provenance and binds logical IDs
1–16 to kernel events 9–24. Its 50/100 ms requested and effective periods fit the
existing 8 MiB archive bound. The original 10/20 ms combined run exhausted that
bound; its negative bundle preserves the actual raw data and failed outcome.

The combined guest exercises mappings, rename, fork, exec, remap and partial
remap. The independent mapping oracle observed 4/3/6/5/4/5 samples in those
respective phases and resolved all six against the copied ELF identities.
The analyzer agrees and also rejects missing ELF files and same-name wrong ELF
contents. The stack oracle verifies real user chains, kernel chains, target
mmap chains and all negative stack probes. Its source count is sixteen.

The combined run's initial host extractor still required literal 10/20 ms
periods. It therefore reported failure after a successful guest collection.
The extractor was corrected to require two distinct declared source instances
per CPU, independently of their periods; a same-period regression covers this.
Original `guest.log`, `original-inputs.json` and `original-result.json` are
preserved byte for byte. `inputs.json` is the separately completed import
manifest, recording its original input/log hashes plus the measured mapping
journal hash. `revalidation.json` reports the subsequent analyzer validation.
This is reanalysis of the newly collected source-bound RAW data, not a rewrite
of an older capture format or of the original failed result.

The bundles include source/build inputs, RAW/capture files, original diagnostics,
analyzer reports, stack/mapping evidence, required ELF artifacts, and the Python
checking tools. Collection workspace was `8768a3a44f3fd760a2a28a5432ecd118b77c1bbb`
plus the saved harness diff; exact executed payload hashes and source snapshots
are authoritative. This is functional evidence, not a performance benchmark.
