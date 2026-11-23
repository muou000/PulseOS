# Reserved CPU guest checks

Use an eight-CPU kernel and a test rootfs containing LTP. Build the guest probe
with the matching static libc and pthreads. For RISC-V:

```sh
run_dir=$(mktemp -d)
riscv64-linux-gnu-gcc -O2 -Wall -Wextra -Werror -static -pthread \
    tests/kernel_cpus/affinity.c -o "$run_dir/check-affinity"
cp --reflink=auto --sparse=always disk.img "$run_dir/default.img"
scripts/install_to_rootfs.sh "$run_dir/default.img" "$run_dir/check-affinity" /opt/check-affinity
cp --reflink=auto --sparse=always "$run_dir/default.img" "$run_dir/reserved.img"
echo 7 > "$run_dir/cpus"
scripts/install_to_rootfs.sh "$run_dir/reserved.img" "$run_dir/cpus" /etc/pulse-kernel-cpus
```

For LoongArch, use `loongarch64-linux-gnu-gcc` and `disk-la.img`. Boot each
private image with its architecture's QEMU command in the root `AGENTS.md`.
Run the preinstalled LTP cases, then the focused probe:

```sh
for t in sched_getaffinity01 sched_setaffinity01 getcpu01; do
    "/opt/ltp/testcases/bin/$t"
    echo "$t exited $?"
done
/opt/check-affinity 8 7
kill -USR2 1
```

On the default image use `/opt/check-affinity 8 -1`. The second argument is the
reserved logical CPU or `-1` for the empty reservation. The probe checks the
initial affinity, mixed and reserved-only requests, and the actual CPU after
a successful bind using the Linux `getcpu` syscall. Four children inherit the
parent's singleton mask across fork and exec. Each starts a pthread. All eight
threads move among the allowed CPUs and check where they resume after sleep
and yield. A successful run prints `AFFINITY PASS`.

To exercise the boot CPU case, repeat with `0` in the configuration file and
`/opt/check-affinity 8 0`. A single-vCPU default boot uses
`/opt/check-affinity 1 -1`. Writing `0-7` on an eight-vCPU guest must produce
the all-online-CPUs configuration error before PID 1 starts.

## Scheduler switch counts

In a disposable checkout of this revision, apply the test instrumentation and
build both kernels:

```sh
git apply tests/kernel_cpus/switch-counts.patch
make test
```

Boot those kernels with the same reserved image and repeat the workload and
shutdown above. At poweroff the kernel snapshots its counters. Check that
`first_tid=1` started on an allowed `first_cpu`. For the reserved CPU expect
`user_switches=0` and `gc_iterations>0` for the identified per-CPU garbage
collector (`gc_task`). The other CPUs should have user switches in the same
window. The counters cover boot through the snapshot and bypass the trace ring.
