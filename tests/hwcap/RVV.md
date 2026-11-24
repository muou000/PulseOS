# RISC-V user vector state

Build the QEMU kernel and the two rootfs variants using the repository's normal image targets.
Run the test with the Ubuntu 26.10 QEMU image and again with the Ubuntu 24.04.5 VisionFive 2 image.
The runner needs a static RV64GC GNU cross toolchain with Linux hwprobe headers, QEMU, and debugfs.

```sh
python3 tests/hwcap/run_rvv.py on --image disk.img
python3 tests/hwcap/run_rvv.py on --vlen 256 --image disk.img
python3 tests/hwcap/run_rvv.py off --image disk-vf2.img
```

Each invocation copies the supplied image, installs a guest probe in the copy, boots the
distribution shell, checks its release, and reads both `AT_HWCAP` and `riscv_hwprobe` for all harts and hart 1 alone.
The off case boots a QEMU CPU without V or Zve extensions. It runs RV64GC code throughout.

In the on case, two processes pin themselves to hart 0. Each fills all bytes of the 32
vector registers with a process- and round-specific pattern, and sets distinct values of
`vl`, `vtype`, `vcsr`, and `vstart`. Both busy-wait on a shared ready/acknowledged
handshake before reading back the entire bank. The peer can acknowledge a round only after the
worker has installed its vector state. As both tasks share one hart, every completed round
requires each task to resume after the peer ran. The handshake contains no syscalls.
The driver checks both worker results and the shell's exit status. Serial logs are kept
under `tests/hwcap/runs/`.
