# PCP boot accounting regression

This runner boots the real kernel with the repository's eight-CPU QEMU command
and stops after the precise PCP result marker. It does not inject a userspace
payload or mutate the backing image (`snapshot=on`). Every requested run is
retained, and **any failed run fails the batch**; it never retries until green.

```sh
python3 tests/pcp_boot/run.py --arch riscv64 --kernel kernel-rv \
  --image rootfs-riscv64.img --runs 20 --require-early
python3 tests/pcp_boot/run.py --arch loongarch64 --kernel kernel-la \
  --image rootfs-loongarch64.img --runs 20 --require-early
```

`--require-early` means the complete PCP check must finish **before** the primary
CPU's `init OK` / runtime release marker. Seven distinct secondary CPUs must have
published `init OK` before the PCP check starts, and the check must report eight
initialized CPU caches. Running first in application `main()` is insufficient:
that is already after secondary CPUs can enter their scheduler/GC loops.

Pulse opts into axruntime's `pcp-boot-checks` feature. After constructors return,
the primary disables local IRQs/preemption, waits for the other initialized CPUs,
and runs the unchanged allocator assertions before publishing its own INITED
count. Secondary CPUs assert their IRQ-off state before publishing readiness and
remain in the existing initialization spin. The primary guard is dropped only
after release. Other axruntime users do not enable this feature by default.

The runner waits briefly after a panic to retain complete assertion operands;
classifying an initial partial `panicked at` chunk is not sufficient. Kernel
hash, command, all console outputs and per-run verdicts are saved under `runs/`.
A successful marker only proves this boot-phase check; the full BPF gate must be
run separately to ensure initialization continues into real userspace capture.

The diagnosis, rejected candidates and actual results are recorded in
[`records/pcp-boot-diagnosis.md`](../../records/pcp-boot-diagnosis.md). Compact log
bundles are in `evidence/`; full debug kernel/ELF/provenance copies remain in the
local `runs/` directories. Temporary delay/log probes are absent from live source.
