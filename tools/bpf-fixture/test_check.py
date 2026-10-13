#!/usr/bin/env python3
"""Tests for the host-side fixture checker (check.py)."""

import json
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECK_SCRIPT = HERE / "check.py"
FIXTURE_OBJ = HERE / "fixture.bpf.o"
METADATA_FILE = HERE / "expected_metadata.json"
VERSION_FILE = HERE / "VERSION"


BUILD_SCRIPT = HERE / "build.py"


class TestBpfChecker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not FIXTURE_OBJ.is_file():
            subprocess.run([sys.executable, str(BUILD_SCRIPT)], check=True)

    def test_check_script_exists(self):
        self.assertTrue(CHECK_SCRIPT.is_file(), f"check.py must exist at {CHECK_SCRIPT}")

    def test_valid_fixture_passes_check(self):
        """Standard fixture.bpf.o must pass check.py with returncode 0."""
        self.assertTrue(FIXTURE_OBJ.is_file())
        res = subprocess.run([sys.executable, str(CHECK_SCRIPT)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"check.py failed on valid fixture:\n{res.stderr}\n{res.stdout}")
        self.assertIn("Fixture validation PASSED", res.stdout)

    def test_missing_file_rejected(self):
        """Checker must exit non-zero when ELF file is missing."""
        res = subprocess.run(
            [sys.executable, str(CHECK_SCRIPT), "--elf", "/nonexistent/fixture.bpf.o"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("not found", (res.stderr + res.stdout).lower())

    def test_fixture_drift_rejected(self):
        """Checker must reject modified/drifted fixture with SHA256 mismatch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tampered_elf = Path(tmpdir) / "tampered.o"
            shutil.copy(FIXTURE_OBJ, tampered_elf)

            # Mutate one byte
            data = bytearray(tampered_elf.read_bytes())
            data[100] ^= 0xFF
            tampered_elf.write_bytes(data)

            res = subprocess.run(
                [sys.executable, str(CHECK_SCRIPT), "--elf", str(tampered_elf)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0, "Drifted fixture must fail check")
            output = res.stderr + res.stdout
            self.assertTrue(
                "sha256 mismatch" in output.lower() or "drift" in output.lower(),
                f"Expected sha256/drift error in output: {output}",
            )

    def test_btf_section_rejected(self):
        """Checker must reject ELF containing unsupported BTF section."""
        with tempfile.TemporaryDirectory() as tmpdir:
            btf_elf = Path(tmpdir) / "with_btf.o"
            shutil.copy(FIXTURE_OBJ, btf_elf)

            data = bytearray(btf_elf.read_bytes())
            idx = data.find(b".llvm_addrsig\x00")
            if idx != -1:
                data[idx:idx + 5] = b".BTF\x00"
            else:
                idx = data.find(b".text\x00")
                data[idx:idx + 5] = b".BTF\x00"
            btf_elf.write_bytes(data)

            res = subprocess.run(
                [sys.executable, str(CHECK_SCRIPT), "--elf", str(btf_elf)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0, "ELF with .BTF section must be rejected")
            output = res.stderr + res.stdout
            self.assertIn(".btf", output.lower())
            self.assertTrue(
                "unsupported" in output.lower() or "forbidden" in output.lower() or "rejected" in output.lower(),
                f"Expected unsupported BTF message in: {output}",
            )

    def test_schema_version_mismatch_rejected(self):
        """Checker must reject when metadata schema_version disagrees with VERSION file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tampered_meta = Path(tmpdir) / "tampered_meta.json"
            meta_data = json.loads(METADATA_FILE.read_text(encoding="utf-8"))
            meta_data["schema_version"] = 999
            tampered_meta.write_text(json.dumps(meta_data), encoding="utf-8")

            res = subprocess.run(
                [sys.executable, str(CHECK_SCRIPT), "--metadata", str(tampered_meta)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            output = res.stderr + res.stdout
            self.assertIn("schema version mismatch", output.lower())

    def test_unsupported_relocation_rejected(self):
        """Checker must reject ELF containing unsupported relocation type."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tampered_elf = Path(tmpdir) / "tampered_rel.o"
            tampered_meta = Path(tmpdir) / "meta.json"
            shutil.copy(FIXTURE_OBJ, tampered_elf)

            # Mutate relocation type: R_BPF_64_64 (1) -> 2 (unsupported)
            # Find .reltracepoint section in ELF
            with FIXTURE_OBJ.open("rb") as f:
                data = bytearray(f.read())

            # Read section header to find relocation section offset
            e_shoff = struct.unpack_from("<Q", data, 40)[0]
            e_shentsize = struct.unpack_from("<H", data, 58)[0]
            e_shnum = struct.unpack_from("<H", data, 60)[0]

            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                sh_type = struct.unpack_from("<I", data, off + 4)[0]
                sh_offset = struct.unpack_from("<Q", data, off + 24)[0]
                sh_size = struct.unpack_from("<Q", data, off + 32)[0]
                if sh_type in (4, 9) and sh_size >= 16:  # relocation section
                    # Modify r_info to have r_type = 2
                    r_info_off = sh_offset + 8
                    info = struct.unpack_from("<Q", data, r_info_off)[0]
                    r_sym = info >> 32
                    new_info = (r_sym << 32) | 2  # change type to 2
                    struct.pack_into("<Q", data, r_info_off, new_info)
                    break

            tampered_elf.write_bytes(data)

            # Update meta sha to test specifically the relocation check
            meta_data = json.loads(METADATA_FILE.read_text(encoding="utf-8"))
            import hashlib
            meta_data["sha256"] = hashlib.sha256(data).hexdigest()
            tampered_meta.write_text(json.dumps(meta_data), encoding="utf-8")

            res = subprocess.run(
                [sys.executable, str(CHECK_SCRIPT), "--elf", str(tampered_elf), "--metadata", str(tampered_meta)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0, "Unsupported relocation must be rejected")
            output = res.stderr + res.stdout
            self.assertIn("unsupported relocation", output.lower())


if __name__ == "__main__":
    unittest.main()
