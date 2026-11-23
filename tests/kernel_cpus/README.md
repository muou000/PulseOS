# Reserved CPU guest checks

Use an eight-CPU kernel and a test rootfs containing LTP. Build the guest probe
with the matching static libc and pthreads. The RISC-V image uses the following commands.

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
In the guest shell, run the preinstalled LTP cases, then the focused probe.

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
threads first compete for CPU time on the inherited CPU. They then move among
the allowed CPUs, checking the CPU immediately after waking and again after
yielding. A successful run prints `AFFINITY PASS`.

To exercise the boot CPU case, repeat with `0` in the configuration file and
`/opt/check-affinity 8 0`. A single-vCPU default boot uses
`/opt/check-affinity 1 -1`. Writing `0-7` on an eight-vCPU guest must produce
the all-online-CPUs configuration error before PID 1 starts.

## Scheduler switch counts

In a disposable checkout of this revision, apply the test instrumentation and
build both kernels.

```sh
git apply tests/kernel_cpus/switch-counts.patch
make test
```

Boot those kernels with the same reserved image and repeat the workload and
shutdown above. The incoming user thread's switch hook records the first
dispatch (`first_tid=1` on an allowed `first_cpu`) and starts counting.
At poweroff a single lock snapshots every CPU's counters. Within this interval
(`start_ns` through `end_ns`), the reserved CPU must have `user_switches=0`
and `gc_iterations>0` from its identified per-CPU garbage collector (`gc_task`).
Look for positive user switch-ins and user preemptions on allowed CPUs.
`user_preemptions` counts a preemptive reschedule that switches an outgoing
user task to a different task. All counts bypass the trace ring.
