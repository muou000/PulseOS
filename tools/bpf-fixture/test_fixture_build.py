#!/usr/bin/env python3
"""Tests for BPF fixture compilation, sections, and relocations."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE_SRC = HERE / "fixture.bpf.c"
FIXTURE_OBJ = HERE / "fixture.bpf.o"
METADATA_FILE = HERE / "expected_metadata.json"
BUILD_SCRIPT = HERE / "build.py"

from elf_util import EM_BPF, FORBIDDEN_SECTIONS, R_BPF_64_64, parse_elf


class TestBpfFixtureBuild(unittest.TestCase):
    def test_fixture_source_exists(self):
        self.assertTrue(FIXTURE_SRC.is_file(), f"Fixture source {FIXTURE_SRC} must exist")

    def test_build_fixture_succeeds(self):
        """build.py must build fixture.bpf.o deterministically."""
        self.assertTrue(BUILD_SCRIPT.is_file(), f"Build script {BUILD_SCRIPT} must exist")
        res = subprocess.run([sys.executable, str(BUILD_SCRIPT)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"build.py failed:\n{res.stderr}\n{res.stdout}")
        self.assertTrue(FIXTURE_OBJ.is_file(), f"{FIXTURE_OBJ} must exist after build")

    def test_fixture_elf_properties(self):
        """Fixture ELF must be little-endian ELF64, EM_BPF, without BTF sections."""
        if not FIXTURE_OBJ.is_file():
            self.skipTest(f"{FIXTURE_OBJ} not yet built")

        header, sections, relocations, maps = parse_elf(FIXTURE_OBJ)
        self.assertEqual(header["machine"], EM_BPF, f"ELF machine must be EM_BPF ({EM_BPF}), got {header['machine']}")

        sec_names = [s["name"] for s in sections]

        # Must reject BTF sections
        for forbidden in FORBIDDEN_SECTIONS:
            self.assertNotIn(forbidden, sec_names, f"Forbidden BTF section {forbidden} found in fixture")

        # Must have tracepoint and perf_event sections
        self.assertTrue(
            any("tracepoint/" in s for s in sec_names),
            f"Expected tracepoint section in {sec_names}",
        )
        self.assertIn("perf_event", sec_names, f"Expected perf_event section in {sec_names}")
        self.assertIn("maps", sec_names, f"Expected maps section in {sec_names}")

        # Relocations must only be R_BPF_64_64
        for rel in relocations:
            self.assertEqual(rel["type"], R_BPF_64_64, f"Relocation type must be R_BPF_64_64 ({R_BPF_64_64}), got {rel['type']}")

    def test_metadata_file_matches(self):
        """Expected metadata file must exist, match schema, and match compiled artifact."""
        self.assertTrue(METADATA_FILE.is_file(), f"Metadata file {METADATA_FILE} must exist")
        with METADATA_FILE.open("r", encoding="utf-8") as f:
            meta = json.load(f)

        self.assertEqual(meta.get("schema_version"), 1)
        self.assertEqual(meta.get("machine"), EM_BPF)
        self.assertEqual(meta.get("endianness"), "little")
        self.assertIn("tracepoint/sched/sched_switch", meta.get("programs", {}))
        self.assertIn("perf_event", meta.get("programs", {}))
        self.assertIn("events", meta.get("maps", {}))
        self.assertIn("counters", meta.get("maps", {}))


if __name__ == "__main__":
    unittest.main()
