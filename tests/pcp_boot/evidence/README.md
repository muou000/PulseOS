# Actual PCP boot evidence

All original fixed-batch logs are retained, including failed and rejected candidates. No kernel binaries or disk images are duplicated here. See [the diagnosis](../../../records/pcp-boot-diagnosis.md) for the interpretation.

| Bundle | Pass / total |
|---|---:|
| [baseline-quiet](baseline-quiet.tar.gz) | 20 / 20 |
| [baseline-red](baseline-red.tar.gz) | 19 / 20 |
| [window-probe](window-probe.tar.gz) | 7 / 10 |
| [guard-window-probe](guard-window-probe.tar.gz) | 7 / 10 |
| [main-first-window-rv](main-first-window-rv.tar.gz) | 20 / 20 |
| [rejected-main-first-rv](rejected-main-first-rv.tar.gz) | 20 / 20 |
| [rejected-main-first-la](rejected-main-first-la.tar.gz) | 7 / 20 |
| [isolated-rv](isolated-rv.tar.gz) | 20 / 20 |
| [isolated-la](isolated-la.tar.gz) | 20 / 20 |
| [old-kernel-contract-red](old-kernel-contract-red.tar.gz) | 0 / 1 |
| [main-first-contract-red](main-first-contract-red.tar.gz) | 0 / 1 |

`baseline-red` initially classified its fragmented panic prefix as other_panic; its complete log proves the PCP used-pages assertion failure. The final runner waits for full panic output before classification.

`index.json` retains bundle/member hashes and original verdicts. `provenance-and-diffs.tar.gz` contains exact temporary probe diffs, kernel provenance, the final fix diff and the successful eight-run BPF gate output. The main-first candidates are explicitly rejected; only the barrier-isolated two batches are the accepted result.
