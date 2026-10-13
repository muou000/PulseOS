#!/usr/bin/env python3
"""Build script for pinned BPF fixture.

Compiles fixture.bpf.c using host clang into fixture.bpf.o, extracts
deterministic ELF section/program/map metadata, and verifies or generates
expected_metadata.json.
"""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

HERE = Path(__file__).resolve().parent
FIXTURE_SRC = HERE / "fixture.bpf.c"
FIXTURE_OBJ = HERE / "fixture.bpf.o"
METADATA_FILE = HERE / "expected_metadata.json"
VERSION_FILE = HERE / "VERSION"

from elf_util import EM_BPF, FORBIDDEN_SECTIONS, compute_sha256, parse_elf, parse_version_file


def generate_metadata(path: Path) -> Dict[str, Any]:
    header, sections, relocations, maps = parse_elf(path)
    file_sha256 = compute_sha256(path)
    file_size = path.stat().st_size
    version_info = parse_version_file(VERSION_FILE)
    schema_version = int(version_info.get("FIXTURE_SCHEMA_VERSION", 1))

    programs: Dict[str, Dict[str, Any]] = {}
    for sec in sections:
        name = sec["name"]
        if name.startswith("tracepoint/") or name == "perf_event":
            insn_count = sec["size"] // 8
            prog_type = "tracepoint" if name.startswith("tracepoint/") else "perf_event"
            programs[name] = {
                "type": prog_type,
                "size_bytes": sec["size"],
                "instruction_count": insn_count,
            }

    sec_summary = [s["name"] for s in sections if s["name"]]

    return {
        "schema_version": schema_version,
        "filename": path.name,
        "machine": header["machine"],
        "machine_name": "EM_BPF",
        "endianness": header["endianness"],
        "file_size": file_size,
        "sha256": file_sha256,
        "sections": sec_summary,
        "programs": programs,
        "maps": maps,
        "relocations": relocations,
        "forbidden_sections": FORBIDDEN_SECTIONS,
    }


def compile_fixture(clang_path: str = "clang") -> None:
    clang = shutil.which(clang_path)
    if not clang:
        raise RuntimeError(f"clang not found in PATH or at '{clang_path}'.")

    cmd = [
        clang,
        "-target", "bpfel",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables",
        "-c",
        str(FIXTURE_SRC),
        "-o",
        str(FIXTURE_OBJ),
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to compile {FIXTURE_SRC}:\n{res.stderr}\n{res.stdout}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and verify BPF fixture.")
    parser.add_argument("--clang", default="clang", help="Path to clang binary")
    parser.add_argument("--update-metadata", action="store_true", help="Update expected_metadata.json")
    args = parser.parse_args()

    print(f"Compiling {FIXTURE_SRC} -> {FIXTURE_OBJ} ...")
    compile_fixture(args.clang)
    print(f"Compiled successfully: {FIXTURE_OBJ}")

    metadata = generate_metadata(FIXTURE_OBJ)

    if args.update_metadata or not METADATA_FILE.exists():
        with METADATA_FILE.open("w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
            f.write("\n")
        print(f"Generated metadata at {METADATA_FILE}")
    else:
        with METADATA_FILE.open("r", encoding="utf-8") as f:
            expected = json.load(f)

        if metadata["sha256"] != expected.get("sha256"):
            print(f"WARNING: SHA256 mismatch!\n  Compiled: {metadata['sha256']}\n  Expected: {expected.get('sha256')}")
            print("Run with --update-metadata to update pinned expected metadata if intended.")
            return 1
        print("Compiled fixture matches expected metadata.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
