"""Public archive CLI preserves originals and verifies every stored byte."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("evidence.py")


class EvidenceArchiveTests(unittest.TestCase):
    def command(self, *arguments):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, arguments)],
                              capture_output=True, text=True)

    def test_original_bytes_are_portable_deduplicated_and_hash_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runs = []
            for name in ("positive", "rejected"):
                run = root / name
                (run / "artifacts").mkdir(parents=True)
                (run / "guest.log").write_bytes(b"actual guest output\n")
                (run / "capture.pbcapture").write_bytes(b"immutable capture fixture")
                (run / "kernel.elf").write_bytes(b"\x7fELF matching symbols")
                (run / "artifacts/kernel.elf").write_bytes((run / "kernel.elf").read_bytes())
                (run / "kernel.provenance.json").write_text("{}\n")
                (run / "kernel").write_bytes(b"raw boot bytes")
                (run / "disk.img").write_bytes(b"disk bytes")
                (run / "bpf-analyzer").write_bytes(b"rebuildable analyzer")
                (run / "result.json").write_text(json.dumps({"passed": name == "positive"}))
                runs.append(run)
            output = root / "evidence"
            packed = self.command("pack", "--run", f"riscv64/positive={runs[0]}",
                                  "--run", f"riscv64/rejected={runs[1]}", "--output", output)
            self.assertEqual(packed.returncode, 0, packed.stderr)
            index = json.loads((output / "index.json").read_text())
            archive = output / "riscv64.tar.gz"
            self.assertEqual(index["archives"][archive.name]["sha256"],
                             hashlib.sha256(archive.read_bytes()).hexdigest())
            with tarfile.open(archive) as stream:
                members = stream.getmembers()
                self.assertTrue(any(member.islnk() for member in members))
                self.assertFalse(any(member.name.endswith("/disk.img") for member in members))
                self.assertFalse(any(member.name.endswith("/kernel") for member in members))
                self.assertFalse(any(member.name.endswith("/bpf-analyzer") for member in members))
            omitted = index["runs"]["riscv64/positive"]["omitted"]
            self.assertEqual(omitted["disk.img"]["sha256"], hashlib.sha256(b"disk bytes").hexdigest())
            self.assertEqual(index["runs"]["riscv64/rejected"]["result"], {"passed": False})
            verified = self.command("verify", output, "--extract", root / "extracted")
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual((root / "extracted/riscv64/positive/capture.pbcapture").read_bytes(),
                             (runs[0] / "capture.pbcapture").read_bytes())


if __name__ == "__main__":
    unittest.main()
