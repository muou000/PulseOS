# PulseOS QEMU HTTP baseline, 2026-11-25

Each architecture ran 48 workload rounds. A round requests one file 48 times with weighttp 0.5-pulse1, one client thread and a 12 s nominal benchmark limit. The host watchdog stops requests after 20 s. Three repetitions used different case order in a single boot per architecture. Loop runs put both peers in PulseOS. Forwarded runs put weighttp on the host, darkhttpd 1.17 in the guest, and traverse localhost-bound QEMU user-mode hostfwd and the guest VirtIO NIC. The guest logs every request. The 61-byte page is the shipped index. The 65,536-byte page contains zeroes and was generated only in the snapshot. Each file was independently compared byte-for-byte with the expected content before benchmarking.

## Workload results

Cells give median completed requests/second and valid rounds out of three. A valid client round needs exactly 48 successful requests, 48 HTTP 2xx responses, the expected body-byte sum, no errors, and matching connection-reuse behavior. Failed rounds are excluded from medians. In the RV64 matrix, all three rounds per cell also match the individually tagged requests in the server access log. In the LA64 matrix, downloading that log itself ended early at EOF, so these cells have client-side counts. The follow-up obtained server counts from the serial console.

| Arch | Route | Page | c1 close | c1 keep-alive | c8 close | c8 keep-alive |
|---|---|---|---:|---:|---:|---:|
| RV64 | guest loopback | 61 B | 136 (3/3) | 64 (3/3) | 129 (3/3) | 156 (3/3) |
| RV64 | guest loopback | 64 KiB | 98 (3/3) | 154 (3/3) | 113 (3/3) | 147 (3/3) |
| RV64 | hostfwd | 61 B | 142 (3/3) | 174 (3/3) | 113 (3/3) | 201 (3/3) |
| RV64 | hostfwd | 64 KiB | 65 (3/3) | 74 (3/3) | 63 (3/3) | 72 (3/3) |
| LA64 | guest loopback | 61 B | 96 (3/3) | 54 (3/3) | 126 (3/3) | 140 (3/3) |
| LA64 | guest loopback | 64 KiB | 98 (3/3) | 78 (3/3) | 74 (3/3) | 83 (3/3) |
| LA64 | hostfwd | 61 B | 103 (2/3) | 64 (3/3) | 81 (3/3) | 53 (3/3) |
| LA64 | hostfwd | 64 KiB | — (0/3) | 55 (3/3) | — (0/3) | 45 (3/3) |

The LA64 c1/close hostfwd 64 KiB rounds had 43, 27 and 30 complete bodies out of 48; all 48 status codes in each round were 2xx. The c8/close hostfwd 64 KiB client exceeded the 20 s watchdog in all three rounds. The small-page c1/close hostfwd client also exceeded it once. A Python HTTP read of the final access log got 142,915 bytes, 99,780 below the advertised length. This caused the LA harness to exit after saving all 48 client results.

## Accepted socket option and latency

Darkhttpd explicitly sets TCP_NODELAY on its listening fd before listen(). A diagnostic copy of the same upstream daemon logs getsockopt(TCP_NODELAY) on listener and child at first accept. It optionally calls setsockopt(TCP_NODELAY=1) on each accepted fd. The original disk images were copied before adding the diagnostic binary; stock tools were preserved. Runs alternate original settings and reapplication in one boot, using the same client, generator, endpoint, and fixed logging configuration. The Linux host control read 1 on the listener and 1 on the accepted fd. PulseOS returned 1 and 0 on both architectures.

| Arch | Payload | Original req/s (two rounds) | Reapply req/s | Original p50 total (ms) | Reapply p50 total (ms) |
|---|---:|---:|---:|---:|---:|
| RV | 61 B | 26, 33 | 52, 47 | 27.59, 24.20 | 13.61, 16.34 |
| RV | 64 KiB | 47, 40 | 47, 50 | 17.98, 19.82 | 17.09, 17.30 |
| LA | 61 B | 32, 32 | 55, 76 | 24.09, 25.53 | 15.02, 9.04 |
| LA | 64 KiB | 32, 34 | 41, 55 | 24.16, 23.47 | 21.53, 13.29 |

Source locations in kernel commit 3f8b3396d8167156011409f6c950ee0ff8956955: pulse_syscalls/src/impls/net/opt.rs implements TCP_NODELAY get/set at lines 239 and 575. TcpSocket::set_nagle_enabled affects the listener handle only (modules/net/src/smoltcp_impl/tcp.rs:701). The incoming SYN code creates a new default TCP socket (modules/net/src/smoltcp_impl/listen_table.rs:175); accept returns that handle at modules/net/src/smoltcp_impl/tcp.rs:438. smoltcp defaults to a 10 ms delayed ACK and enables Nagle (crates/smoltcp/src/socket/tcp.rs:268,542,545). Darkhttpd 1.17 sets TCP_NODELAY at darkhttpd.c:853 and writes headers separately from the body at lines 2569 and 2640. A/B rates are shared-host observations. Accepted-socket values give a direct ABI check.

## Independent EOF/body check with stock darkhttpd

Python http.client issued Connection: close requests over hostfwd and read each body until 65,536 bytes, EOF, or a 1.5 s socket timeout. The diagnostic binary was stopped and stock darkhttpd was restarted before this phase. Rows save each response’s status, advertised length, bytes read and any socket exception. The serial-console server log preserves the status and reported transfer size for the same unique per-request tag.

| Arch | Parallel requests | Exact / 32 | Short EOF | Socket exceptions | Server 200 / 32 |
|---|---:|---:|---:|---:|---:|
| RV | 1 | 25 | 7 | 0 | 32 |
| RV | 8 | 25 | 7 | 0 | 32 |
| LA | 1 | 25 | 7 | 0 | 32 |
| LA | 8 | 18 | 13 | 1 | 32 |

The server’s complete write and access-log entry can precede peer receipt. Inspect TcpSocket::drop and shutdown (modules/net/src/smoltcp_impl/tcp.rs:967,464), SocketSet removal (modules/net/src/smoltcp_impl/mod.rs), and sys_sendfile progress accounting (pulse_syscalls/src/impls/fs/io/transfer.rs:58). These are investigation points. The end-to-end checks do not identify where the missing bytes were discarded.

## Replay and retained evidence

The snapshots booted QEMU 11.1.50 with eight vCPUs and 8 GiB RAM. RV64 used -cpu max and VirtIO MMIO. LA64 used VirtIO PCI. The two runs were serial within this benchmark. Other emulators and a compiler were observed on the shared host. Kernel, rootfs and tool identities are recorded separately. [Environment](../environment.json)

To recreate the two file sizes and launch the server in a fresh snapshot, run the following commands in the guest. The example client uses loopback, eight concurrent connections and keep-alive. Other cases use concurrency one, omit -k, request index.html, or use the host client against the forwarded port. The original matrix tagged each round with a unique User-Agent to match access logs.

```sh
dd if=/dev/zero of=/opt/netbench/www/large.bin bs=65536 count=1
darkhttpd /opt/netbench/www --addr 0.0.0.0 --port 18080 --no-listing --log /opt/netbench/www/http-access.log &
weighttp -q -t 1 -n 48 -c 8 -a 12 -s 5 -k http://127.0.0.1:18080/large.bin
```

For the host-side EOF check, map a TCP port bound to 127.0.0.1 on the host to guest port 18080 and run the included script with `--port PORT -c 1` and `--port PORT -c 8`. [Standalone HTTP check](../http_close.py)

The operator kept the original per-round client JSON, HTTP response observations, access logs and serial output locally. Those files have no public archive or retention guarantee. The repository retains each round’s request count, p95 and integrity result, the repeated NODELAY experiment, and distributions of independently received response sizes. [HTTP measurements](http-details.json)
