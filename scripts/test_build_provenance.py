"""Build-origin regressions; all files/artifacts live in a temporary repository."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import build_provenance as provenance


class BuildProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "src").mkdir()
        (self.repo / "src/main.rs").write_text("fn main() {}\n")
        process = self.repo / "modules/process/src"
        process.mkdir(parents=True)
        (process / "lib.rs").write_text("pub mod task;\n")
        (self.repo / "Cargo.toml").write_text("[package]\nname='fixture'\n")
        (self.repo / ".gitignore").write_text(".axconfig.toml\n*.elf\n*.bin\n*.json\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Test",
                        "-c", "user.email=test@example.invalid", "commit", "-qm", "initial"], check=True)
        self.config = self.repo / ".axconfig.toml"
        self.config.write_text('arch = "riscv64"\n')
        self.elf = self.repo / "kernel.elf"
        self.binary = self.repo / "kernel.bin"
        self.sidecar = Path(str(self.elf) + ".provenance.json")
        self.pending = Path(str(self.sidecar) + ".pending")

    def start(self):
        provenance.start(self.repo, self.config, self.pending, self.sidecar,
                         {"arch": "riscv64", "features": "qemu bpf-trace"},
                         toolchain={"rustc": "test", "cargo": "test"})

    def finish(self):
        self.elf.write_bytes(b"real-elf-output")
        self.binary.write_bytes(b"real-binary-output")
        return provenance.finish(self.repo, self.config, self.pending, self.sidecar,
                                 self.elf, self.binary)

    def test_records_build_time_commit_and_verifies_actual_outputs(self):
        self.start()
        saved = self.finish()
        self.assertFalse(saved["source"]["git_worktree_dirty"])
        self.assertIn("modules", saved["source"]["roots"])
        self.assertNotIn("pulse_core", saved["source"]["roots"])
        self.assertEqual(saved["configuration"]["values"]["features"], "qemu bpf-trace")
        self.assertEqual(saved["configuration"]["axconfig_text"], self.config.read_text())
        self.assertEqual(provenance.verify_manifest(self.sidecar, self.elf, self.binary), saved)
        # A later workspace edit must not change an already bound artifact's origin.
        (self.repo / "src/main.rs").write_text("fn changed_later() {}\n")
        self.assertEqual(provenance.verify_manifest(self.sidecar, self.elf, self.binary), saved)
        self.binary.write_bytes(b"different-boot-image")
        with self.assertRaisesRegex(ValueError, "boot image"):
            provenance.verify_manifest(self.sidecar, self.elf, self.binary)

    def test_refuses_mid_build_source_or_configuration_change(self):
        for relative in ("src/main.rs", "modules/process/src/lib.rs", ".axconfig.toml"):
            with self.subTest(relative=relative):
                self.start()
                with (self.repo / relative).open("a") as output:
                    output.write("# changed during build\n")
                with self.assertRaisesRegex(ValueError, "changed during build"):
                    self.finish()
                self.assertFalse(self.sidecar.exists())

    def test_new_dirty_source_and_ignored_input_are_hashed(self):
        clean = provenance.source_snapshot(self.repo)
        (self.repo / "src/new.rs").write_text("pub const NEW: u32 = 7;\n")
        new = provenance.source_snapshot(self.repo)
        self.assertTrue(new["git_worktree_dirty"])
        self.assertNotEqual(clean["tree_sha256"], new["tree_sha256"])
        # Binary include_bytes/incbin inputs must not disappear because Git ignores *.bin.
        (self.repo / "src/embedded.bin").write_bytes(b"payload")
        ignored = provenance.source_snapshot(self.repo)
        self.assertNotEqual(new["tree_sha256"], ignored["tree_sha256"])

    def test_begin_removes_stale_manifest_and_finish_cannot_reuse_pending(self):
        self.start()
        self.finish()
        self.assertTrue(self.sidecar.exists())
        self.start()
        self.assertFalse(self.sidecar.exists())
        self.finish()
        with self.assertRaises(FileNotFoundError):
            self.finish()

    def test_invalid_schema_or_elf_hash_is_rejected(self):
        self.start()
        saved = self.finish()
        self.elf.write_bytes(b"wrong-elf")
        with self.assertRaisesRegex(ValueError, "ELF"):
            provenance.verify_manifest(self.sidecar, self.elf, self.binary)
        saved["format_version"] = 99
        self.sidecar.write_text(json.dumps(saved))
        with self.assertRaisesRegex(ValueError, "version"):
            provenance.verify_manifest(self.sidecar, self.elf, self.binary)


if __name__ == "__main__":
    unittest.main()
