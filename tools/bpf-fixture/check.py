#!/usr/bin/env python3
"""Host-side validator for fixed-layout BPF ELF fixture.

Validates:
  - ELF format: Little-Endian ELF64, EM_BPF (machine=247).
  - Absence of unsupported BTF/CO-RE sections (.BTF, .BTF.ext, etc.).
  - SHA-256 integrity and fixture drift against expected_metadata.json.
  - Schema version against VERSION file contract.
  - Program sections, instruction count limits, and program types.
  - Map definitions (type, key_size, value_size, max_entries).
  - Relocations: only supported Map-FD relocations (R_BPF_64_64).

Exits 0 on success, non-zero on validation failure.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Tuple

HERE = Path(__file__).resolve().parent
DEFAULT_ELF = HERE / "fixture.bpf.o"
DEFAULT_METADATA = HERE / "expected_metadata.json"
DEFAULT_VERSION = HERE / "VERSION"

from elf_util import EM_BPF, FORBIDDEN_SECTIONS, R_BPF_64_64, compute_sha256, parse_elf, parse_version_file


def validate_fixture(
    elf_path: Path,
    metadata_path: Path,
    version_path: Path = DEFAULT_VERSION,
) -> Tuple[bool, List[str]]:
    errors: List[str] = []

    if not elf_path.is_file():
        return False, [f"BPF ELF file not found: {elf_path}"]

    if not metadata_path.is_file():
        return False, [f"Expected metadata file not found: {metadata_path}"]

    try:
        with metadata_path.open("r", encoding="utf-8") as f:
            expected = json.load(f)
    except Exception as exc:
        return False, [f"Failed to parse expected metadata: {exc}"]

    # 1. Validate Schema Version against VERSION file
    if version_path.is_file():
        try:
            v_info = parse_version_file(version_path)
            pinned_schema = int(v_info.get("FIXTURE_SCHEMA_VERSION", 1))
            meta_schema = int(expected.get("schema_version", 0))
            if meta_schema != pinned_schema:
                errors.append(
                    f"Schema version mismatch: metadata specifies schema_version {meta_schema}, "
                    f"but {version_path.name} specifies {pinned_schema}"
                )
        except Exception as exc:
            errors.append(f"Failed to validate schema version against {version_path}: {exc}")
    else:
        errors.append(f"VERSION file not found: {version_path}")

    # 2. Parse ELF
    try:
        header, sections, relocations, maps = parse_elf(elf_path)
    except Exception as exc:
        return False, [f"ELF parsing error for {elf_path}: {exc}"]

    # 3. Machine check
    if header["machine"] != EM_BPF:
        errors.append(f"Invalid ELF machine architecture: {header['machine']} (expected EM_BPF = {EM_BPF})")

    # 4. Check for forbidden sections (BTF / CO-RE)
    sec_names = [s["name"] for s in sections if s["name"]]
    for s_name in sec_names:
        for forbidden in FORBIDDEN_SECTIONS:
            if s_name == forbidden or s_name.startswith(forbidden):
                errors.append(
                    f"Unsupported BTF/CO-RE section '{s_name}' rejected. "
                    f"Fixed-layout PulseOS libbpf fixture forbids BTF metadata per ADR #83."
                )

    # 5. SHA-256 integrity check (drift check)
    actual_sha = compute_sha256(elf_path)
    expected_sha = expected.get("sha256")
    if actual_sha != expected_sha:
        errors.append(
            f"Fixture drift detected! SHA256 mismatch for {elf_path}:\n"
            f"  Actual:   {actual_sha}\n"
            f"  Expected: {expected_sha}"
        )

    # 6. Program sections, types, and instruction counts
    expected_progs = expected.get("programs", {})
    for prog_sec, p_info in expected_progs.items():
        matched_sec = next((s for s in sections if s["name"] == prog_sec), None)
        if not matched_sec:
            errors.append(f"Missing required program section: {prog_sec}")
            continue

        insn_count = matched_sec["size"] // 8
        expected_count = p_info.get("instruction_count")
        if expected_count is not None and insn_count != expected_count:
            errors.append(
                f"Instruction count mismatch for {prog_sec}: "
                f"actual {insn_count}, expected {expected_count}"
            )

        # Validate program type matches section name convention
        expected_type = p_info.get("type")
        if expected_type == "tracepoint" and not prog_sec.startswith("tracepoint/"):
            errors.append(f"Program type mismatch: section {prog_sec} is marked as tracepoint but name does not match")
        elif expected_type == "perf_event" and prog_sec != "perf_event":
            errors.append(f"Program type mismatch: section {prog_sec} is marked as perf_event but name is not 'perf_event'")

    # 7. Map definitions
    expected_maps = expected.get("maps", {})
    for map_name, m_info in expected_maps.items():
        if map_name not in maps:
            errors.append(f"Missing required map '{map_name}' in ELF maps section")
            continue
        actual_map = maps[map_name]
        for key, exp_val in m_info.items():
            if actual_map.get(key) != exp_val:
                errors.append(
                    f"Map '{map_name}' attribute '{key}' mismatch: "
                    f"actual {actual_map.get(key)}, expected {exp_val}"
                )

    # 8. Relocations: only supported Map-FD relocations
    for rel in relocations:
        if rel["type"] != R_BPF_64_64:
            errors.append(
                f"Unsupported relocation type {rel['type']} in section {rel['section']} at offset {rel['offset']}. "
                f"Only R_BPF_64_64 (type {R_BPF_64_64}) Map-FD relocations are supported."
            )
        if rel["sym_name"] not in expected_maps:
            errors.append(
                f"Unsupported relocation target in section {rel['section']} referencing non-map symbol '{rel['sym_name']}'. "
                f"Only relocations targeting defined maps are supported."
            )

    return (len(errors) == 0), errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate fixed-layout BPF ELF fixture against expected contract.")
    parser.add_argument("--elf", type=Path, default=DEFAULT_ELF, help="Path to fixture ELF")
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA, help="Path to expected metadata JSON")
    parser.add_argument("--version-file", type=Path, default=DEFAULT_VERSION, help="Path to VERSION file")
    args = parser.parse_args()

    ok, errors = validate_fixture(args.elf, args.metadata, args.version_file)
    if not ok:
        print(f"FAILED: Fixture validation errors for {args.elf}:", file=sys.stderr)
        for err in errors:
            print(f"  * {err}", file=sys.stderr)
        return 1

    print(f"Fixture validation PASSED: {args.elf}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
