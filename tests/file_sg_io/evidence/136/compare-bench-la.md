# loongarch64 bench comparison

Guest SHA-256: f01618f14b6016c3582ca32320e7dd60f3cd0144b1c2106691f70f3fcd5a252d
Before kernel: 4120fa39abca342891d1c1ef4c6080e3d25b1468217936485e3e84a4743ea7de
After kernel: 645ba13ecc350945fb5f5f0817058453ba2f7dca737bc84444bfc5b037c08638

Latency is the median per-operation sample; throughput is cached guest I/O.
Natural allocations can have different physical layouts. Such rows remain
visible but are marked unmatched and must not support a controlled speedup claim.

| Layout | Operation | KiB | Before µs | After µs | Speedup | Before MiB/s | After MiB/s | PFN breaks |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| fragmented | read | 64 | 48.08 | 35.02 | 1.373× | 1299.80 | 1784.57 | [15] → [15] |
| fragmented | read | 256 | 200.94 | 138.79 | 1.448× | 1244.17 | 1801.34 | [63] → [63] |
| fragmented | readv | 64 | 140.55 | 51.13 | 2.749× | 444.68 | 1222.39 | [15] → [15] |
| fragmented | readv | 256 | 307.11 | 241.21 | 1.273× | 814.05 | 1036.45 | [63] → [63] |
| fragmented | write | 64 | 96.08 | 100.10 | 0.960× | 650.49 | 624.38 | [15] → [15] |
| fragmented | write | 256 | 391.19 | 365.42 | 1.071× | 639.08 | 684.15 | [63] → [63] |
| fragmented | writev | 64 | 323.29 | 130.85 | 2.471× | 193.33 | 477.65 | [15] → [15] |
| fragmented | writev | 256 | 493.70 | 235.68 | 2.095× | 506.38 | 1060.75 | [63] → [63] |
| natural | read | 64 | 48.89 | 38.43 | 1.272× | 1278.49 | 1626.28 | [15] → [15] |
| natural | read | 256 | 214.14 | 136.77 | 1.566× (unmatched) | 1167.44 | 1827.92 | [55] → [53] |
| natural | readv | 64 | 172.34 | 59.89 | 2.878× | 362.66 | 1043.65 | [15] → [15] |
| natural | readv | 256 | 198.33 | 141.77 | 1.399× (unmatched) | 1260.55 | 1763.44 | [55] → [53] |
| natural | write | 64 | 95.71 | 64.30 | 1.488× | 653.04 | 972.00 | [15] → [15] |
| natural | write | 256 | 429.87 | 265.88 | 1.617× (unmatched) | 581.58 | 940.28 | [55] → [53] |
| natural | writev | 64 | 322.19 | 87.24 | 3.693× | 193.98 | 716.44 | [15] → [15] |
| natural | writev | 256 | 449.01 | 252.11 | 1.781× (unmatched) | 556.78 | 991.65 | [55] → [53] |
