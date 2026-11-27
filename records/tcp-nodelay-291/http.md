# TCP_NODELAY HTTP results for #291

All 204 rounds passed the client and server checks (9,792 completed responses). Each performance cell gives requests/s, p50 ms and p95 ms. Each percentile measures total request time, and each reported value is the median of the three round-level values.

| Arch | Body | Connections | Keep-alive | Base stock | Fix stock | Stock RPS change | Base reapply | Fix reapply |
|---|---:|---:|---|---:|---:|---:|---:|---:|
| RV64 | 61 B | 1 | off | 25 / 27.81 / 78.69 | 80 / 9.77 / 18.60 | +220.0% | 37 / 19.92 / 39.90 | 89 / 8.27 / 18.55 |
| RV64 | 61 B | 1 | on | 34 / 25.56 / 43.39 | 130 / 5.13 / 16.16 | +282.4% | 64 / 12.99 / 24.08 | 141 / 5.42 / 12.85 |
| RV64 | 61 B | 8 | off | 37 / 186.93 / 261.61 | 101 / 73.56 / 95.02 | +173.0% | 46 / 158.22 / 199.45 | 86 / 83.14 / 114.37 |
| RV64 | 61 B | 8 | on | 62 / 108.40 / 249.65 | 89 / 52.87 / 176.21 | +43.5% | 57 / 112.79 / 244.17 | 88 / 66.56 / 150.07 |
| RV64 | 65,536 B | 1 | off | 29 / 28.06 / 48.74 | 71 / 10.82 / 22.84 | +144.8% | 30 / 26.43 / 55.04 | 58 / 15.60 / 25.22 |
| RV64 | 65,536 B | 1 | on | 31 / 26.15 / 58.98 | 68 / 11.12 / 28.35 | +119.4% | 39 / 20.13 / 47.77 | 98 / 8.53 / 16.23 |
| RV64 | 65,536 B | 8 | off | 30 / 251.68 / 329.16 | 73 / 95.00 / 134.09 | +143.3% | 36 / 182.58 / 286.60 | 89 / 82.44 / 114.77 |
| RV64 | 65,536 B | 8 | on | 36 / 173.98 / 351.05 | 72 / 86.38 / 159.48 | +100.0% | 55 / 123.88 / 209.75 | 76 / 90.20 / 142.92 |
| LA64 | 61 B | 1 | off | 114 / 6.56 / 18.35 | 260 / 3.14 / 4.45 | +128.1% | 131 / 6.09 / 12.45 | 255 / 3.06 / 4.73 |
| LA64 | 61 B | 1 | on | 60 / 15.18 / 23.89 | 362 / 2.26 / 4.30 | +503.3% | 221 / 2.76 / 10.93 | 369 / 2.15 / 4.09 |
| LA64 | 61 B | 8 | off | 63 / 111.98 / 159.42 | 201 / 36.59 / 40.65 | +219.0% | 96 / 69.33 / 109.03 | 198 / 35.39 / 41.55 |
| LA64 | 61 B | 8 | on | 184 / 38.77 / 61.20 | 280 / 23.63 / 43.93 | +52.2% | 200 / 30.66 / 69.58 | 297 / 20.41 / 40.82 |
| LA64 | 65,536 B | 1 | off | 56 / 12.01 / 30.01 | 201 / 4.07 / 6.07 | +258.9% | 103 / 8.59 / 17.28 | 191 / 4.29 / 6.33 |
| LA64 | 65,536 B | 1 | on | 89 / 9.43 / 20.57 | 239 / 3.49 / 6.13 | +168.5% | 118 / 6.97 / 14.77 | 257 / 3.31 / 5.80 |
| LA64 | 65,536 B | 8 | off | 95 / 77.69 / 113.20 | 199 / 35.75 / 46.55 | +109.5% | 112 / 65.89 / 82.44 | 204 / 34.68 / 46.13 |
| LA64 | 65,536 B | 8 | on | 128 / 49.91 / 112.94 | 261 / 26.81 / 40.48 | +103.9% | 144 / 40.98 / 80.97 | 291 / 24.03 / 35.20 |

## Same-daemon control, 61 B, c1, keep-alive

The diagnostic daemon reads back the listener and first accepted socket during fixture warmup. With PULSE_DIAG_REAPPLY set it also enables TCP_NODELAY on each accepted socket. Both modes use the identical executable, client, port and snapshot within each kernel boot.

| Arch | Kernel | Listener / child before reapply | Diagnostic env off | Diagnostic env on | RPS change | p50 change | p95 change |
|---|---|---|---:|---:|---:|---:|---:|
| RV64 | base | 1 / 0 | 31 / 25.84 / 55.69 | 64 / 12.99 / 24.08 | +106.5% | -49.7% | -56.8% |
| RV64 | fix | 1 / 1 | 102 / 8.08 / 20.53 | 141 / 5.42 / 12.85 | +38.2% | -32.9% | -37.4% |
| LA64 | base | 1 / 0 | 52 / 18.34 / 26.34 | 221 / 2.76 / 10.93 | +325.0% | -84.9% | -58.5% |
| LA64 | fix | 1 / 1 | 371 / 2.21 / 4.64 | 369 / 2.15 / 4.09 | -0.5% | -2.8% | -11.9% |

With a 61-byte page, c1 and keep-alive, reapplying NODELAY on the baseline reduced median p50 by 49.7% on RV64 and 84.9% on LA64. The stock daemon also improved in this case on the fixed kernel. The already-enabled reapply control rose from 64 to 141 requests/s across RV64 kernels and 221 to 369 on LA64. On the fixed RV64 kernel even setting the same value again coincided with a 32.9% lower p50. These shifts show substantial run-to-run variation on the shared host and limit attribution of the stock speedups to inheritance alone.

All sixteen stock workload cells had higher median RPS and lower median p50 and p95 after the fix, including the 64 KiB and short-connection cases. Individual rounds and the reapply controls also capture slowdowns. For example, reapplying the option on the fixed RV64 kernel for 64 KiB, c1, short connections yielded 58 requests/s versus 71 stock, and p95 rose from 22.84 to 25.22 ms.

## Workload and integrity

Darkhttpd 1.17 and weighttp 0.5-pulse1 ran on guest IPv4 loopback. The 61-byte page is the image’s index.html. The 65,536-byte page was created in the snapshot with `dd if=/dev/zero of=/opt/netbench/www/large.bin bs=65536 count=1`. Before timing each daemon instance, the harness downloaded both files and compared every byte with the expected content. [Test rootfs and binaries](https://github.com/muou000/PulseOS/releases/tag/rootfs-tests-20261125)

Each round used one client thread and 48 requests. The ordered product of body size (61, 65536), concurrency (1, 8) and keep-alive (off, on) was shuffled with Python random seeds 292, 293 and 294, one per repetition. Both daemon modes used the same case order in each repetition. The daemon was restarted on port 18080 between modes. Mode order was stock/off/reapply, reapply/off/stock, then off/stock/reapply. The off control ran the small c1 keep-alive case only.

For each timed round the checker required exit 0, exactly 48 requests started and retired, 48 passes, 48 HTTP 2xx responses, 48 latency samples, zero errors or failures, and 2,928 or 3,145,728 received body bytes. For a response with Content-Length, weighttp requires the complete body to count a pass. Reuse had to be zero for close and 48 minus concurrency for keep-alive. The server access log had to include exactly 48 HTTP 200 entries for the requested path with the round’s unique User-Agent. [Per-round observations](http-rounds.csv)

The following guest commands run stock darkhttpd and one keep-alive round. Use large.bin for 64 KiB, `-c 8` for eight concurrent connections and omit `-k` for short connections. For the reapply control compile darkhttpd 1.17 with the diagnostic patch and launch it with `PULSE_DIAG_REAPPLY=1`. [Diagnostic patch](https://github.com/muou000/PulseOS/blob/c2a22d73ed9b4de2eb79e4b292204c70d016165b/records/qemu-network-20261125/darkhttpd-nodelay.patch)

```sh
darkhttpd /opt/netbench/www --addr 0.0.0.0 --port 18080 --no-listing --log /tmp/access.log &
weighttp -q -t 1 -n 48 -c 1 -a 12 -s 5 -H 'User-Agent: run-1' -k http://127.0.0.1:18080/index.html
```

## Environment

Each architecture used the same snapshot-backed disk for both kernels. QEMU ran one measurement guest at a time with eight vCPUs, 8 GiB RAM, virtio-net and virtio-blk. RV64 used the virt machine, CPU max, OpenSBI and MMIO devices. LA64 used the virt machine and PCI devices. Timed requests remained on guest loopback. A localhost-bound hostfwd collected client JSON and performed fixture warmups between timed rounds. The host was shared with other work, including another QEMU benchmarking task. The measurements include host scheduling variation.

| Arch | Stage | Boot image SHA-256 | Build input tree SHA-256 |
|---|---|---|---|
| RV64 | base | `58a3a18d2af7b25c7f77068dddd351b07ebafa4bedd83c996e5ce51cb73151ef` | `9cb46dd5e21ea929356d397b047545f0ad270b0047e70c17ce15351ec179b5af` |
| RV64 | fix | `6714b65cc77a52d0d3685d0ba4277566f6b9ec83ebaff22070d7033fdf02f561` | `c1130b13683f359e0917f548da26cd2aae82f5cf17ab0d8a13dfe2b8a858c4aa` |
| LA64 | base | `845eb9a9198d3fb77ad5d48d072351f878d8b7aeb19f8ccc46ee558509d79465` | `9cb46dd5e21ea929356d397b047545f0ad270b0047e70c17ce15351ec179b5af` |
| LA64 | fix | `8ffc270043a9c7077bfd29efa379de989c1a2799697602319471484f82d73874` | `c1130b13683f359e0917f548da26cd2aae82f5cf17ab0d8a13dfe2b8a858c4aa` |

| Arch | Guest executable | SHA-256 (both kernels) |
|---|---|---|
| RV64 | `/usr/bin/darkhttpd` | `167fd54518fe7b5ee52fee2679c598ff2a5888aa4bbb6dc256871b8bb238cdba` |
| RV64 | `/usr/bin/http-audit-daemon` | `2fe9ec913a64a22b51e99960af622937cee445f61c8ee5a7947230135e752fad` |
| RV64 | `/usr/bin/weighttp` | `a828d1278cbbb34eabe7e953acf7fab7e83315ee922e9e48823d29f8eaab7a1d` |
| LA64 | `/usr/bin/darkhttpd` | `934c7c0838ed4fd49c2c6c59188aebe0a70b70b3773ea8f45a4c6ac494b1f692` |
| LA64 | `/usr/bin/http-audit-daemon` | `49dfa4d47c142f8725c223a9012c25dc5c5ed8a495c85bc54c41bacf4ce2ed8e` |
| LA64 | `/usr/bin/weighttp` | `54ededc51be561550eccce54f33703b02679e3137995c1aa01446b7fedc0f14e` |

QEMU reported `QEMU emulator version 11.1.50 (v11.1.0-2112-g2a0ac9c8ac)`. The baseline was clean commit `3f8b3396d8167156011409f6c950ee0ff8956955`. The boot images were checked against their build provenance.
