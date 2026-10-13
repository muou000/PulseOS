# Pinned libbpf Fixture and Toolchain Contract

This directory defines the repository-owned toolchain probe, fixed-layout BPF ELF fixture, and host-side ELF validator for the PulseOS BPF performance observation subsystem (#77, #83, #90).

## 1. Pinned Toolchain Versions

- **Host Compiler**: Clang 18.1.3 (`clang -target bpfel`)
- **Host LLVM Tools**: LLVM 18.1.3 (`llvm-objdump`)
- **libbpf**: 1.3.0 (`pkg-config --modversion libbpf`)
- **BPF Architecture**: `EM_BPF` (machine ID 247), 64-bit Little-Endian (`bpfel`)
- **Fixture Schema Version**: 1

## 2. Host Fixture vs. Guest Sampler Compilation

It is critical to distinguish between two compilation phases:

1. **Host Fixture Compilation**:
   - Compiles BPF C source (`fixture.bpf.c`) into standard eBPF bytecode object file (`fixture.bpf.o`) using `clang -target bpfel`.
   - Runs strictly on the host without requiring a running PulseOS guest or cross-compiler.
   - Produces machine-independent BPF bytecode that can be loaded on any supported guest architecture (RISC-V64 and LoongArch64).
   - Must be verified host-side before any guest execution.

2. **Guest Sampler Compilation**:
   - Compiles user-space C payloads for the guest OS (RISC-V64 or LoongArch64) that link against `libbpf` to open, load, attach, and consume BPF programs inside PulseOS.
   - Requires target-specific cross-compilers (`gcc-riscv64-linux-gnu` / `gcc-loongarch64-linux-gnu` or musl variants) and guest rootfs staging.
   - When guest compilers are unavailable, the probe reports actionable diagnostic messages indicating missing dependencies.

## 3. Compatibility Boundary (ADR #83)

The PulseOS first-tier BPF compatibility contract specifies:

- **Fixed-layout ELF**:
  - `tracepoint/sched/sched_switch`: tracepoint event program with fixed context struct.
  - `perf_event`: software performance sampling program with fixed context struct.
  - Classic `SEC("maps")` with `struct bpf_map_def` (types: `BPF_MAP_TYPE_ARRAY`, `BPF_MAP_TYPE_PERF_EVENT_ARRAY`).
- **Supported Relocations**:
  - Only `R_BPF_64_64` Map-FD relocations against declared maps.
- **Strictly Unsupported (Forbidden)**:
  - `.BTF`, `.BTF.ext`, `.rel.BTF`, and CO-RE relocations are rejected by `check.py` and must fail explicitly if present.

## 4. Reproducible Commands

From a clean checkout:

### Toolchain Probe
```bash
# Probe host BPF compilation tools (clang, llvm-objdump, libbpf)
python3 tools/bpf-fixture/probe.py --host-only

# Probe with machine-readable JSON output
python3 tools/bpf-fixture/probe.py --host-only --json

# Probe full toolchain including guest cross-compilers (exits non-zero if missing)
python3 tools/bpf-fixture/probe.py
```

### Build Fixture ELF
```bash
# Build fixture.bpf.o using host clang and verify against expected metadata
make -C tools/bpf-fixture build
# Or directly:
python3 tools/bpf-fixture/build.py
```

### Host-side Fixture Validation
```bash
# Validates ELF header, machine type, instruction counts, map definitions,
# verifies no BTF sections exist, and checks SHA-256 integrity against expected metadata
make -C tools/bpf-fixture check
# Or directly:
python3 tools/bpf-fixture/check.py
```

### Run Test Suite
```bash
make -C tools/bpf-fixture test
# Or directly:
python3 -m unittest discover -s tools/bpf-fixture -p "test_*.py"
```

