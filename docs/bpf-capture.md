# Current BPF capture contract

The only supported container is **v6**. Native software context v2 (single IP),
software stack context v3, and tracepoint schema versions describe payload
capabilities independently of the container version. Old containers and source
tables are rejected; historical archives are immutable evidence of their own
producer/analyzer baseline.

## Identity and validation

Declare all sources with `CaptureWriter::configure_recorder` before writing
records. Each normalized record carries an explicit logical source binding,
passed to `write_record_from` or stamped in its native RAW envelope. Duplicate
CPU/period configurations are allowed. Logical IDs, kernel event IDs and link
IDs are unique within the declaration table; program IDs may be shared.

The `PBSRC003` table retains kind, event/schema ID, monotonic timestamp clock,
requested/effective configuration, requested period or frequency, effective
period and frequency mode, requested/effective buffer pages, effective units,
typed fallback reason, scope, stable task identity, kernel event/program/link
IDs and per-source enable/disable windows. Numeric TIDs are target selectors;
task records must match the stable task identity, including across exec.
Effective CPU-clock sources require per-CPU scope; effective task-clock sources
require task scope, matching the current kernel's supported combinations.

Stack context `source_id` means **kernel event ID**. It must equal the declared
`kernel_event_id`, while the separate record binding selects the logical ID.
The declaration also validates the context's event/schema, period, CPU or stable
task identity. Sources are never recovered from diagnostic prose, payload
length, CPU, or period. Custom normalized schemas require explicit custom source
declarations and cannot impersonate a native software/tracepoint kind.

Only control-window fields may be updated after declaration. For every source:

```text
session.start <= enable.before <= enable.after
              <= disable.before <= disable.after <= session.stop
record.timestamp lies within [enable.before, disable.after]
```

These syscall observation windows do not assert atomic enable across sources.
Unknown final boundaries produce an unfinished prefix without a trailer;
readers reject it. Invalid declarations, duplicate/unknown bindings, wrong
kind/schema/length, stack identity conflicts and invalid windows fail closed.

## Container and bounded storage

All integers are little-endian. The existing 80-byte header locates the
metadata, normalized record section and 40-byte integrity trailer. Metadata is:

```text
schema registry | session metadata
u32 diagnostics length | diagnostics
u32 mappings length    | mappings (zero bytes when absent)
u32 sources length     | PBSRC003 source declarations + record bindings
u64 required extensions
```

Required bits are stack `1`, mappings `2`, and sources `4`. Sources are mandatory;
stack and mappings compose independently. Unknown bits, undeclared/nonexistent
sections, extra section bytes, invalid extents, missing trailers and IEEE CRC-32
mismatches are rejected. The CRC covers the header, metadata and record bytes.
The source table contains at most 512 declarations (160 bytes each), and one
four-byte logical ID per retained record.

The writer's caller-selected budget bounds normalized bytes plus bindings and
cannot exceed 64 MiB. A valid record exceeding the budget is counted as a
consumer discard and is not retained; bindings remain aligned. Mapping and
diagnostic metadata keep their independent existing limits. All paths remain
available with `no_std` plus `alloc`.

## Evidence and completeness

Mapping journals and artifact identities are retained as facts, including
unknown identities and counted journal gaps. Missing mapping metadata is
explicitly absent. Recorded stack termination status is preserved. Source
binding proves attribution to a declared event, not exhaustive producer,
mapping, artifact or unwind coverage. The current contract has no exhaustive
coverage certificate, so even a cleanly terminated capture stays partial.
Zero samples, missing diagnostics, observed loss, incomplete unwinds and
journal gaps cannot become complete attribution.

Consumer-observed delivered/lost/discarded/corrupt/out-of-bounds counters remain
separate from scoped runtime diagnostics. Overlapping producer/program/sink
counters are never summed into a fabricated total. The analyzer keeps scheduler
and fault reports, stack symbolization and existing export prerequisites; v6
does not claim that the generic recorder already collects stacks or mappings.

## Native input

Current native imports require producer-stamped logical source envelopes and
explicit typed source declarations. The importer does not add provenance to old
RAW archives by guessing. Use the matching current native collection harness
and importer; keep archived input, producer identity and matching historical
consumer together when reproducing old results.
