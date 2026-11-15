# loongarch64 small-bench comparison

Guest SHA-256: f392940354af1f3dc452671c65c2abc0026d779fa1298f0b860ba740e3ff9c63
Before kernel: 4120fa39abca342891d1c1ef4c6080e3d25b1468217936485e3e84a4743ea7de
After kernel: 645ba13ecc350945fb5f5f0817058453ba2f7dca737bc84444bfc5b037c08638

Latency is the median per-operation sample; throughput is cached guest I/O.
Natural allocations can have different physical layouts. Such rows remain
visible but are marked unmatched and must not support a controlled speedup claim.

| Layout | Operation | KiB | Before µs | After µs | Speedup | Before MiB/s | After MiB/s | PFN breaks |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| natural | read | 4 | 6.76 | 7.19 | 0.940× | 577.95 | 543.34 | [0] → [0] |
| natural | readv | 4 | 129.51 | 26.16 | 4.950× | 30.16 | 149.30 | [0] → [0] |
| natural | write | 4 | 11.35 | 12.94 | 0.877× | 344.14 | 301.95 | [0] → [0] |
| natural | writev | 4 | 322.87 | 36.99 | 8.728× | 12.10 | 105.60 | [0] → [0] |
