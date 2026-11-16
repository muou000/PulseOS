# Minimal historical regression inputs

`oracle-inputs.tar.gz` contains five byte-for-byte inputs needed by the current
tests, extracted from the former #191 and #211 full run archives. `index.json`
records the original archive and member SHA-256, source member names, and the
new fixture archive's SHA-256 and size. These are historical regression inputs,
not a fresh guest run or a complete replayable acceptance archive.

| Inputs | Regression |
| --- | --- |
| #211 mixed capture | Independent record decoding, repeated source identity, exact Query and corruption checks in `test_e2e.py` |
| #211 task capture and its original fixture ELF | Native perf/FlameGraph user-function symbol regression in `test_perf_pipeline.py`; the same ELF supplies the mixed capture's function ranges |
| #191 v2 capture and original `archive.json` | Original SHA and 82-record phase checks followed by rejection of the retired capture format in `query_cli_tests.rs` |

Only the ELF used by the user Query is retained. Kernel and unrelated ELF
artifacts, logs, and derived output are unnecessary for these tests. Captures
and the retained ELF are unmodified: no filtering, stripping, re-importing,
or replacement of partial status was performed.

Run the existing regressions with:

```sh
python3 -m unittest discover -s tests/bpf_record -p 'test_e2e.py'
PULSE_PERF=/usr/local/bin/perf FLAMEGRAPH_DIR=/path/to/pinned/FlameGraph \
  python3 -m unittest discover -s tests/bpf_sampling -p 'test_perf_pipeline.py'
cargo test -p bpf-analyzer --test query_cli_tests \
  historical_archive_retains_its_identity_and_is_not_accepted_as_current_capture
```

The optional native consumer test still requires an explicitly installed perf
and the content-checked FlameGraph revision; fixture cleanup does not skip it
or change its assertions. See [`QUALIFICATION.md`](../QUALIFICATION.md) for the
full production acceptance workflow, which must use newly generated run data.
