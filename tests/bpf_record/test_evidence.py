"""Public archive CLI preserves originals and verifies every stored byte."""
from __future__ import annotations

import hashlib
import io
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
            repeated = root / "repeated"
            again = self.command("pack", "--run", f"riscv64/rejected={runs[1]}",
                                 "--run", f"riscv64/positive={runs[0]}", "--output", repeated)
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertEqual(archive.read_bytes(), (repeated / archive.name).read_bytes())
            self.assertEqual((output / "index.json").read_bytes(), (repeated / "index.json").read_bytes())

    def test_container_checksum_cannot_hide_modified_original_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / "run"
            run.mkdir()
            (run / "guest.log").write_bytes(b"saved")
            output = root / "evidence"
            packed = self.command("pack", "--run", f"case={run}", "--output", output)
            self.assertEqual(packed.returncode, 0, packed.stderr)
            archive = output / "case.tar.gz"
            with tarfile.open(archive, "w:gz") as stream:
                member = tarfile.TarInfo("case/guest.log")
                member.mode, member.size = 0o644, 5
                stream.addfile(member, io.BytesIO(b"wrong"))
            index = json.loads((output / "index.json").read_text())
            index["archives"][archive.name].update(
                sha256=hashlib.sha256(archive.read_bytes()).hexdigest(), bytes=archive.stat().st_size)
            (output / "index.json").write_text(json.dumps(index))
            verified = self.command("verify", output, "--extract", root / "extracted")
            self.assertNotEqual(verified.returncode, 0)
            self.assertIn("member SHA", verified.stderr)
            self.assertFalse((root / "extracted").exists())

    def test_untrusted_links_and_paths_never_extract(self):
        for kind, name, target in ((tarfile.REGTYPE, "../escaped", ""),
                                   (tarfile.SYMTYPE, "case/link", "case/original"),
                                   (tarfile.LNKTYPE, "case/link", "../escaped"),
                                   (tarfile.LNKTYPE, "case/link", "case/missing")):
            with self.subTest(kind=kind, name=name, target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "case.tar.gz"
                with tarfile.open(archive, "w:gz") as stream:
                    member = tarfile.TarInfo(name)
                    member.mode, member.type, member.linkname = 0o644, kind, target
                    stream.addfile(member, io.BytesIO(b""))
                metadata = {"sha256": hashlib.sha256(b"").hexdigest(), "bytes": 0, "mode": 0o644}
                if kind == tarfile.LNKTYPE:
                    metadata["hardlink"] = target
                index = {"format": "pulse-recorder-evidence", "version": 1, "archives": {
                    archive.name: {"sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                                   "bytes": archive.stat().st_size, "members": {name: metadata}}}}
                (root / "index.json").write_text(json.dumps(index))
                verified = self.command("verify", root, "--extract", root / "extracted")
                self.assertNotEqual(verified.returncode, 0)
                self.assertFalse((root / "extracted").exists())

    def test_pack_rejects_input_symlinks_and_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / "run"
            run.mkdir()
            (run / "original").write_bytes(b"original")
            (run / "link").symlink_to("original")
            output = root / "evidence"
            packed = self.command("pack", "--run", f"case={run}", "--output", output)
            self.assertNotEqual(packed.returncode, 0)
            self.assertFalse(output.exists())
            (run / "link").unlink()
            output.mkdir()
            (output / "keep").write_bytes(b"preexisting")
            packed = self.command("pack", "--run", f"case={run}", "--output", output)
            self.assertNotEqual(packed.returncode, 0)
            self.assertEqual((output / "keep").read_bytes(), b"preexisting")


if __name__ == "__main__":
    unittest.main()
