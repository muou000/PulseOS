# Issue 304 readiness evidence

`socket_probe.c ready` measures zero-timeout `poll` and `epoll_wait` with one
readable descriptor plus 1, 16, or 64 idle connected descriptors. It performs
64 calls per sample, alternates the APIs for three rounds, and checks that only
the active descriptor is reported.

The 2026-11-25 baseline from the shared network audit was as follows.

| API | RV64 TCP, 1 / 16 / 64 | LA64 TCP, 1 / 16 / 64 |
|---|---:|---:|
| `epoll_wait` | 278 / 8,533 / 100,454 us | 70 / 1,683 / 23,397 us |
| `poll` | 203 / 6,960 / 100,743 us | 52 / 1,884 / 23,397 us |

The implementation records `interface_polls`, `socket_visits`, and `wakeups`
with `readiness_stats` debug output. Readiness syscalls drive network
interfaces once per operation and use side-effect-free socket state queries for
each monitored descriptor. The background network task continues to advance
protocol state when no synchronous readiness caller exists.

Build the probe with the static cross-compilers shown at the top of
`socket_probe.c`, place it in the guest test image, and run `./probe ready`.
Retain raw QEMU logs so the correctness counts and `readiness_stats` deltas can
be checked independently.
