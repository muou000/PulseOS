# riscv64 small-bench comparison

Guest SHA-256: 65a6ae0a6a7552319310c3159262951a12da3dc2535153c4c3dd499cf0d4323f
Before kernel: 23611b73eb1527e5cfc2d2903a5f732d86f2ae764713cb9c21786c82644f03e3
After kernel: a16b31cded3ea04e69493685e73516e17cbca11a87944b18c32797e9906dca26

Latency is the median per-operation sample; throughput is cached guest I/O.
Natural allocations can have different physical layouts. Such rows remain
visible but are marked unmatched and must not support a controlled speedup claim.

| Layout | Operation | KiB | Before µs | After µs | Speedup | Before MiB/s | After MiB/s | PFN breaks |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| natural | read | 4 | 16.11 | 23.76 | 0.678× | 242.53 | 164.39 | [0] → [0] |
| natural | readv | 4 | 317.70 | 98.78 | 3.216× | 12.30 | 39.54 | [0] → [0] |
| natural | write | 4 | 27.17 | 32.73 | 0.830× | 143.78 | 119.34 | [0] → [0] |
| natural | writev | 4 | 769.67 | 97.04 | 7.932× | 5.08 | 40.26 | [0] → [0] |
