# axplat-loongarch64-ls2k1000

PulseOS platform implementation for the Loongson 2K1000 development board.

The board uses a raw PulseOS image loaded by U-Boot into the cached DMW1
address `0x9000000098000000`. U-Boot must start it with `go <entry> <dtb>`.
The platform validates that handoff ABI, parses the live DTB before allocator
initialization, and derives the enabled CPUs, discontiguous RAM regions,
reserved memory, and LIOINTC cascade line from it.

The initial board support covers NS16550 console output, LoongArch timer/IPI,
two-core bring-up, LIOINTC dispatch, and the fixed board AHCI controller used
for the SATA-backed root filesystem. AHCI is serialized polling I/O; it does
not yet use its LIOINTC interrupt. GMAC and RTC support are deliberately out
of scope for this initial platform crate.

Build from the repository root with:

```bash
make ls2k1000
```

See `docs/ls2k1000-porting-record.md` for the exact U-Boot handoff and the
validation boundary between a successful cross-build and a physical-board
boot.

The range container has host tests that compile the production leaf module
without board or assembly dependencies. From the repository root:

```bash
rustc --edition=2024 --test -D warnings platforms/axplat-loongarch64-ls2k1000/tests/mem_ranges.rs -o /tmp/ls2k1000-ranges
/tmp/ls2k1000-ranges
```

To check these same tests with Miri (with the nightly Miri component installed):

```bash
range_miri_sysroot="$(cargo miri setup --print-sysroot)"
rustup run nightly miri --sysroot "$range_miri_sysroot" --edition=2024 --test platforms/axplat-loongarch64-ls2k1000/tests/mem_ranges.rs
```

The tests cover first-publication ownership (including empty lists), zero and
maximum capacities, ordering, normalization, and concurrent publication/readers.
The local `Sync`, copy and slice safety arguments live in `src/mem/ranges.rs`;
test executions supplement those arguments and do not prove all interleavings.
