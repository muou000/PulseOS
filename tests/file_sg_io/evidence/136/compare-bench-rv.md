# riscv64 bench comparison

Guest SHA-256: 59a0e237dfa52041b544c7e65ef59cdb836bba62f05a5bc4ed0480cf737da748
Before kernel: 23611b73eb1527e5cfc2d2903a5f732d86f2ae764713cb9c21786c82644f03e3
After kernel: a16b31cded3ea04e69493685e73516e17cbca11a87944b18c32797e9906dca26

Latency is the median per-operation sample; throughput is cached guest I/O.
Natural allocations can have different physical layouts. Such rows remain
visible but are marked unmatched and must not support a controlled speedup claim.

| Layout | Operation | KiB | Before µs | After µs | Speedup | Before MiB/s | After MiB/s | PFN breaks |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| fragmented | read | 64 | 113.39 | 88.49 | 1.281× | 551.21 | 706.26 | [15] → [15] |
| fragmented | read | 256 | 439.97 | 338.41 | 1.300× | 568.22 | 738.76 | [63] → [63] |
| fragmented | readv | 64 | 325.12 | 128.66 | 2.527× | 192.23 | 485.79 | [15] → [15] |
| fragmented | readv | 256 | 434.73 | 362.06 | 1.201× | 575.07 | 690.49 | [63] → [63] |
| fragmented | write | 64 | 234.54 | 144.34 | 1.625× | 266.47 | 433.01 | [15] → [15] |
| fragmented | write | 256 | 898.31 | 542.90 | 1.655× | 278.30 | 460.49 | [63] → [63] |
| fragmented | writev | 64 | 799.67 | 183.88 | 4.349× | 78.16 | 339.90 | [15] → [15] |
| fragmented | writev | 256 | 933.62 | 575.66 | 1.622× | 267.78 | 434.28 | [63] → [63] |
| natural | read | 64 | 131.20 | 87.31 | 1.503× (unmatched) | 476.37 | 715.87 | [14] → [11] |
| natural | read | 256 | 263.38 | 356.12 | 0.740× (unmatched) | 949.22 | 702.01 | [19] → [16] |
| natural | readv | 64 | 339.88 | 149.13 | 2.279× (unmatched) | 183.89 | 419.09 | [14] → [11] |
| natural | readv | 256 | 432.26 | 350.76 | 1.232× (unmatched) | 578.35 | 712.73 | [19] → [16] |
| natural | write | 64 | 213.36 | 157.17 | 1.358× (unmatched) | 292.93 | 397.66 | [14] → [11] |
| natural | write | 256 | 557.12 | 563.44 | 0.989× (unmatched) | 448.73 | 443.70 | [19] → [16] |
| natural | writev | 64 | 766.16 | 189.28 | 4.048× (unmatched) | 81.58 | 330.21 | [14] → [11] |
| natural | writev | 256 | 895.02 | 560.97 | 1.595× (unmatched) | 279.32 | 445.66 | [19] → [16] |
