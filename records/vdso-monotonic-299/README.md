# Monotonic Clock vDSO Snapshot Fix (#299)

## Root Cause and Hypothesis Discrimination

Before the fix (`main@e022adff`), [`VdsoTimeData::update`](../../crates/starry-vdso/src/vdso_time_data.rs) read the hardware counter three separate times (`monotonic_time_nanos()` for `wall_ns`, `monotonic_time_nanos()` for `mono_ns`, and `current_ticks()` for `cycle_now`), compiling to three `rdtime` instructions on RISC-V 64 and three `rdtime.d` instructions on LoongArch64.

When execution stalled between the second and third reads (e.g., QEMU TCG translation-block exits or host vCPU preemption), `cycle_last` captured a newer tick count $t_2 > t_1$ while `time_data[1]` (`CLOCK_MONOTONIC`) and `time_data[4]` (`CLOCK_MONOTONIC_RAW`) recorded the older base $\text{ticks\_to\_nanos}(t_1)$. Until the next timer-tick update, every user-space vDSO read lagged direct `SYS_clock_gettime` by $(t_2 - t_1) \times \text{NANOS\_PER\_TICK}$.

| Candidate Cause | Prediction | Observed Evidence | Conclusion |
| --- | --- | --- | --- |
| **H1**: Multi-read `VdsoTimeData::update()` snapshot skew | Strictly one-sided negative bracket errors (`fast < raw_before`, `above = 0`) in exact multiples of `NANOS_PER_TICK` (100 ns RV64, 10 ns LA64) | Baseline `above = 0` everywhere; RV64 errors are multiples of 100 ns (up to `-135,800 ns`), LA64 `-140 ns`; fixing to 1x `rdtime`/`rdtime.d` drives all violations and regressions to `0` | **Confirmed** |
| **H2**: `mult`/`shift` rate mismatch against `ticks_to_nanos` | Continuous linear drift over each 10 ms tick interval | Unit tests across 10 MHz (RV64 virt), 4 MHz (VF2), 100 MHz (LA64 virt / LS2K1000), and 33.33 MHz show 0 ns drift; baseline errors were step jumps | **Ruled out** (still hardened `clocks_calc_mult_shift` to use `ticks_to_nanos(ticks_per_sec)`) |
| **H3**: Cross-CPU counter skew or missing seqcount barriers | Bracket errors persist on 8-core concurrent runs even with single-snapshot VVAR | 0/36,000 bracket violations and 0 regressions on 8-core concurrent runs across both architectures after single-snapshot fix | **Ruled out** |
| **H4**: Real early timer wakeup in `clock_nanosleep` | Direct `SYS_clock_gettime` observes `raw_before < target` on `rc == 0` | `early_raw = 0` across all 40,500 baseline and 40,500 post-fix sleep cycles per architecture | **Ruled out** |

With the fix, `VdsoTimeData::update()` initializes `CACHED_MULT_SHIFT` first and takes a single `current_ticks()` snapshot (`1x rdtime` on RV64, `1x rdtime.d` on LA64) to derive `mono_ns = ticks_to_nanos(cycle_now)` and `wall_ns = mono_ns.wrapping_add(offset)`, restoring `raw_before <= fast_read <= raw_after` and same-thread monotonicity.

## Environment and Artifact Identity

- **Host / QEMU**: Linux (`x86_64`), QEMU `virt` (`-machine virt -m 8G -smp 8 -nographic -no-reboot -rtc base=utc`, `snapshot=on`, `-bios default -cpu max` on RV64), running one VM at a time.
- **Base commit**: `e022adffe68608288177406006d7406515373960`
- **Unified probe**: [tests/time/vdso_monotonic.c](../../tests/time/vdso_monotonic.c) (`-std=gnu11 -O2 -pthread -static`)
- **cyclictest**: `rt-tests 2.11` from `schedbench-{riscv64,loongarch64}.tar.xz` (`rootfs-sched-tests-20261125`)

| Artifact | Architecture | SHA-256 |
| --- | --- | --- |
| Baseline kernel (`baseline-rv.bin`) | RV64 | `31c8cebb942d1917e2a7fe223c0ba684c7a35e77474dffd4fa84414035266e18` |
| Fixed kernel (`PulseOS_riscv64-qemu-virt.bin`) | RV64 | `899d7fc6d338dc6ba5e1a41c16695627e08efb3468784dda45de675f36f9bb79` |
| Baseline kernel (`baseline-la.elf`) | LA64 | `9655c3a33acfc7e481047972f7e760d03828d26c0c2f4355c2b6ab3d3550384a` |
| Fixed kernel (`PulseOS_loongarch64-qemu-virt.elf`) | LA64 | `69d067af7cdd4879425c6aa3e19cffb5dac4257b266522c9ead220e4f96bc48f` |
| Base rootfs (`disk.img`) | RV64 | `1c85641c81d923211ca2229275ab9870203a098341d9e1363c237831cc79a1ab` |
| Base rootfs (`disk-la.img`) | LA64 | `1a0f51586aaf24f9d8c652e55d44b648c9fd949e068ab31b41a38c49573e6df3` |
| Test disk copy (`rv.img`) | RV64 | `5a0263ea4c8297ac19aa465e53a689e3f54b2f69063ad9b83aa81bea4f371973` |
| Test disk copy (`la.img`) | LA64 | `6cbde8540525287156b7367cc4792540a5740e6d850387a4f53e2523de0cc2d4` |
| Probe ELF (`/299-probe`) | RV64 | `3b71fa8186f5e7201e24c6fd8b1bac7956b5cf48035bbef5a023a4abc49e2c13` |
| Probe ELF (`/299-probe`) | LA64 | `cbd4658d4dff51bae14b8f03c5e24b549af32fe5eddf2788b3b85775a9aa6a95` |
| `cyclictest` (`/usr/bin/cyclictest`) | RV64 | `03e5bbc55dbc4776056a06a73981498e6a03e4801841999bd826ef8d6bb1667c` |
| `cyclictest` (`/usr/bin/cyclictest`) | LA64 | `d9986bad0ae6ce4d6825b863dda7f2c6d2c67e962dedf9b997047387a7227189` |

### Channel Call Identities

- **RV64**: `raw = syscall(113)` (`SYS_clock_gettime`); `libc = clock_gettime@0x209ac (glibc 2.39)`; `vdso = __vdso_clock_gettime@LINUX_4.15` (`offset=0x5fe` from `AT_SYSINFO_EHDR`, e.g. `ehdr=0x7f095000`, `addr=0x7f0955fe`).
- **LA64**: `raw = syscall(113)` (`SYS_clock_gettime`); `libc = clock_gettime@0x1200161f4 (glibc 2.39)`; `vdso = __vdso_clock_gettime@LINUX_5.10` (`offset=0x3d4` from `AT_SYSINFO_EHDR`, e.g. `ehdr=0x7f01a000`, `addr=0x7f01a3d4`).

## Clock Read Consistency (Before vs. After)

Each sleep cycle (`1 ms` period, `TIMER_ABSTIME`) checks `rc`, then executes `raw_b1 -> libc -> raw_a1` and `raw_b2 -> vdso -> raw_a2`. All `early_*` counts require `rc == 0`; `nonzero_rc = 0` in every run.

### Aggregate Round Results (3x Single-Core CPU 0, 3x 8-Core Concurrent)

| Arch | State | Round | C | Early (`raw`/`libc`/`vdso`) | Regressions (`raw`/`libc`/`vdso`) | `libc` Outside (`below`/`above`) | `vdso` Outside (`below`/`above`) | Min `libc - before` / `after - libc` (ns) | Min `vdso - before` / `after - vdso` (ns) |
| --- | --- | --- | ---: | :---: | :---: | :---: | :---: | ---: | ---: |
| RV64 | Before | `single-r1` | 1500 | 0 / 0 / 0 | 0 / 0 / 0 | **1** / 0 | 0 / 0 | **-7200** / 1700 | 800 / 1200 |
| RV64 | Before | `single-r2` | 1500 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 | **1** / 0 | 100 / 1700 | **-7700** / 1200 |
| RV64 | Before | `single-r3` | 1500 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 | 0 / 0 | 5300 / 1700 | 700 / 1200 |
| RV64 | Before | `smp8-r1` | 12000 | 0 / 0 / 0 | 0 / 0 / 0 | **111** / 0 | **151** / 0 | **-106700** / 1600 | **-135800** / 1200 |
| RV64 | Before | `smp8-r2` | 12000 | 0 / 0 / 0 | 0 / 0 / 0 | **125** / 0 | **167** / 0 | **-87000** / 1700 | **-64600** / 1300 |
| RV64 | Before | `smp8-r3` | 12000 | 0 / 0 / 0 | 0 / 0 / 0 | **138** / 0 | **178** / 0 | **-117600** / 1700 | **-125500** / 1200 |
| RV64 | **After** | `single-r1..r3` | 1500 each | 0 / 0 / 0 | 0 / 0 / 0 | **0 / 0** | **0 / 0** | 2600–6300 / 1200–1500 | 2000–2400 / 1000 |
| RV64 | **After** | `smp8-r1..r3` | 12000 each | 0 / 0 / 0 | 0 / 0 / 0 | **0 / 0** | **0 / 0** | 2800–5500 / 1300–1500 | 2100–2300 / 1100 |
| LA64 | Before | `single-r1..r3` | 1500 each | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 | 0 / 0 | 2480–2520 / 740–800 | 680–860 / 570–620 |
| LA64 | Before | `smp8-r1` | 12000 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 | **1** / 0 | 2480 / 760 | **-140** / 590 |
| LA64 | Before | `smp8-r2..r3` | 12000 each | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 | 0 / 0 | 1320–2390 / 690–810 | 710–780 / 540–620 |
| LA64 | **After** | `single-r1..r3` | 1500 each | 0 / 0 / 0 | 0 / 0 / 0 | **0 / 0** | **0 / 0** | 2370–2630 / 740–780 | 970–1040 / 600–660 |
| LA64 | **After** | `smp8-r1..r3` | 12000 each | 0 / 0 / 0 | 0 / 0 / 0 | **0 / 0** | **0 / 0** | 1980–2580 / 680–690 | 850–960 / 560–570 |

### Worst Individual Samples (Before vs. After)

- **RV64 Before (`smp8-r1`, `vdso_before`, iter 370, rc=0)**: `target=7499624000`, `raw_before=7500051900`, `fast=7499916100`, `raw_after=7500058400`, `fast-before=-135800 ns`, `after-fast=142300 ns`, `fast-target=292100 ns`.
- **RV64 Before (`smp8-r3`, `libc_before`, iter 365, rc=0)**: `target=10616737100`, `raw_before=10617220900`, `fast=10617103300`, `raw_after=10617234300`, `fast-before=-117600 ns`, `after-fast=131000 ns`, `fast-target=366200 ns`.
- **LA64 Before (`smp8-r1`, `vdso_before`, CPU 1 iter 397, rc=0)**: `target=6463941750`, `raw_before=6464077840`, `fast=6464077700`, `raw_after=6464079980`, `fast-before=-140 ns`, `after-fast=2280 ns`, `fast-target=135950 ns`.
- **RV64 After (`smp8-r1`, tightest `vdso_before`, iter 1, rc=0)**: `target=7009234100`, `raw_before=7009469700`, `fast=7009471800`, `raw_after=7009472900`, `fast-before=+2100 ns`, `after-fast=+1100 ns`, `fast-target=+237700 ns`.
- **LA64 After (`smp8-r1`, tightest `vdso_before`, iter 1246, rc=0)**: `target=7146510490`, `raw_before=7146558010`, `fast=7146558860`, `raw_after=7146559470`, `fast-before=+850 ns`, `after-fast=+610 ns`, `fast-target=+48370 ns`.

### Per-CPU Breakdown (`smp8-r1`, 1,500 Samples per CPU)

| CPU | RV64 Before `libc_below` / `vdso_below` (min `vdso-before` ns) | RV64 After `below`/`above`/`reg`/`early` | LA64 Before `libc_below` / `vdso_below` (min `vdso-before` ns) | LA64 After `below`/`above`/`reg`/`early` |
| :---: | :---: | :---: | :---: | :---: |
| 0 | 12 / 17 (-92300) | 0 / 0 / 0 / 0 | 0 / 0 (920) | 0 / 0 / 0 / 0 |
| 1 | 16 / 18 (-34500) | 0 / 0 / 0 / 0 | 0 / **1 (-140)** | 0 / 0 / 0 / 0 |
| 2 | 13 / 19 (-105200) | 0 / 0 / 0 / 0 | 0 / 0 (940) | 0 / 0 / 0 / 0 |
| 3 | 25 / 29 (-135800) | 0 / 0 / 0 / 0 | 0 / 0 (970) | 0 / 0 / 0 / 0 |
| 4 | 13 / 16 (-41300) | 0 / 0 / 0 / 0 | 0 / 0 (980) | 0 / 0 / 0 / 0 |
| 5 | 14 / 22 (-34200) | 0 / 0 / 0 / 0 | 0 / 0 (930) | 0 / 0 / 0 / 0 |
| 6 | 12 / 25 (-109900) | 0 / 0 / 0 / 0 | 0 / 0 (920) | 0 / 0 / 0 / 0 |
| 7 | 6 / 5 (-10200) | 0 / 0 / 0 / 0 | 0 / 0 (960) | 0 / 0 / 0 / 0 |

## Read Overhead and Tight-Loop Monotonicity (`50,000` Calls on CPU 0)

| Arch | State | Channel | `ns/call` (r1 / r2 / r3) | Median `ns/call` | Regressions (r1 / r2 / r3) | Min `step_ns` |
| --- | --- | --- | --- | ---: | :---: | ---: |
| RV64 | Before | `raw` | 3711.18 / 3460.53 / 3503.94 | 3503.94 | 0 / 0 / 0 | 2600 |
| RV64 | Before | `libc` | 255.95 / 198.65 / 196.57 | 198.65 | **1 / 1 / 1** | **-400** |
| RV64 | Before | `vdso` | 135.37 / 132.28 / 132.67 | 132.67 | 0 / **1** / 0 | **-300** |
| RV64 | **After** | `raw` | 3734.93 / 3605.07 / 3635.47 | 3635.47 | 0 / 0 / 0 | 2700 |
| RV64 | **After** | `libc` | 223.77 / 199.82 / 211.12 | 211.12 | **0 / 0 / 0** | 100 |
| RV64 | **After** | `vdso` | 130.52 / 130.39 / 136.63 | 130.52 | **0 / 0 / 0** | 100 |
| LA64 | Before | `raw` | 1598.92 / 1701.52 / 1635.40 | 1635.40 | 0 / 0 / 0 | 1090 |
| LA64 | Before | `libc` | 142.21 / 85.20 / 108.65 | 108.65 | 0 / 0 / 0 | 70 |
| LA64 | Before | `vdso` | 81.05 / 54.78 / 80.51 | 80.51 | 0 / 0 / 0 | 50 |
| LA64 | **After** | `raw` | 1673.91 / 1299.02 / 1461.44 | 1461.44 | 0 / 0 / 0 | 1060 |
| LA64 | **After** | `libc` | 120.77 / 83.99 / 82.43 | 83.99 | **0 / 0 / 0** | 60 |
| LA64 | **After** | `vdso` | 53.89 / 52.80 / 52.56 | 52.80 | **0 / 0 / 0** | 40 |

## `cyclictest` Verification (After Fix)

All runs used `-S --default-system` (or `taskset -c 0 /usr/bin/cyclictest -S --default-system ...` for pinned single-core) with `-d 0 -i 1000 -l 200 -q` (issue #297 tracks default NUMA topology probing). Every thread line satisfied `0 <= Min <= Avg <= Max`.

| Arch | Configuration | Threads | Completed Samples `C` | Min..Max Range (µs) | Avg Range (µs) | Invariant `Min <= Avg <= Max` |
| --- | --- | ---: | --- | --- | --- | :---: |
| RV64 | Pinned CPU 0 `OTHER` | 1 | `200` | `115..2294` | `203` | Pass |
| RV64 | Pinned CPU 0 `FIFO 10` | 1 | `200` | `52..486` | `166` | Pass |
| RV64 | All-core `-S OTHER` | 8 | `200, 200, 200, 200, 193, 191, 191, 187` | `83..1028` | `176..244` | Pass |
| RV64 | All-core `-S FIFO 10` r1 | 8 | `200` x 7, `196` | `89..2312` | `182..290` | Pass |
| RV64 | All-core `-S FIFO 10` r2 | 8 | `200` x 8 | `76..3026` | `185..262` | Pass |
| RV64 | All-core `-S FIFO 10` r3 | 8 | `200` x 8 | `30..1906` | `176..348` | Pass |
| LA64 | Pinned CPU 0 `OTHER` | 1 | `200` | `70..513` | `145` | Pass |
| LA64 | Pinned CPU 0 `FIFO 10` | 1 | `200` | `58..902` | `129` | Pass |
| LA64 | All-core `-S OTHER` | 8 | `200` x 8 | `44..2140` | `125..174` | Pass |
| LA64 | All-core `-S FIFO 10` r1 | 8 | `200` x 8 | `42..727` | `97..141` | Pass |
| LA64 | All-core `-S FIFO 10` r2 | 8 | `200` x 8 | `45..757` | `120..137` | Pass |
| LA64 | All-core `-S FIFO 10` r3 | 8 | `200` x 8 | `44..1243` | `101..171` | Pass |

## Reproduction

```sh
# 1. Host unit tests and kernel builds
cargo test -p starry-vdso --lib
make test

# 2. Host sanity run
gcc -std=gnu11 -O2 -Wall -Wextra -Werror -pthread tests/time/vdso_monotonic.c -o /tmp/probe-x86
/tmp/probe-x86 --threads 1 --iters 50 --bench-iters 10000 --fail-on-violation

# 3. Cross-compile guest probes and inject into private disk copies
riscv64-linux-gnu-gcc -std=gnu11 -O2 -Wall -Wextra -Werror -pthread -static \
    tests/time/vdso_monotonic.c -o /tmp/probe-rv
.tools/loongarch64/bin/loongarch64-linux-gnu-gcc -std=gnu11 -O2 -Wall -Wextra -Werror -pthread -static \
    tests/time/vdso_monotonic.c -o /tmp/probe-la
cp --reflink=auto --sparse=always disk.img /tmp/rv.img
cp --reflink=auto --sparse=always disk-la.img /tmp/la.img
debugfs -w -R "write /tmp/probe-rv /299-probe" /tmp/rv.img
debugfs -w -R "write /tmp/probe-la /299-probe" /tmp/la.img
```

Boot with the QEMU commands in [AGENTS.md](../../AGENTS.md) (`snapshot=on` on the private disk copy) and run:

```sh
/299-probe --threads 1 --cpu 0 --iters 0 --bench-iters 50000 --fail-on-violation
/299-probe --threads 1 --cpu 0 --iters 1500 --period-ns 1000000 --fail-on-violation
/299-probe --threads 8 --cpu 0 --iters 1500 --period-ns 1000000 --fail-on-violation
/usr/bin/cyclictest -S --default-system --policy=fifo -p 10 -d 0 -i 1000 -l 200 -q
```
