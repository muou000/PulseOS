"""Public collection seam: files are selected only by recorded content identity."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[2] / "tools/bpf-record/collect.py"
spec = importlib.util.spec_from_file_location("collect_recorder", MODULE)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def elf(build_id=None):
    note = b"" if build_id is None else struct.pack("<III", 4, len(build_id), 3) + b"GNU\0" + build_id
    note += b"\0" * (-len(note) % 4)
    data = bytearray(120 + len(note))
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 243, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 4 if note else 1, 4, 120, 0, 0, len(note), len(note), 4)
    data[120:] = note
    return bytes(data)


def manifest(data, build_id):
    sha = hashlib.sha256(data).hexdigest()
    return {"arch": "riscv64", "mapping_metadata": True, "objects": [], "artifacts": [
        {"sha256": sha, "gnu_build_id": build_id, "path": f"artifacts/{sha}.elf",
         "debug_sha256": None, "debug_build_id": None}]}


class CollectionTests(unittest.TestCase):
    def test_over_budget_identity_cannot_be_collected_as_known_absent(self):
        data = bytearray(elf())
        struct.pack_into("<Q", data, 40, len(data))
        struct.pack_into("<H", data, 60, 4097)
        data.extend(bytes(4097 * 64))
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "large-section-table"
            source.write_bytes(data)
            bundle = root / "bundle"
            with self.assertRaisesRegex(ValueError, "table"):
                collector.collect_artifacts(manifest(data, None), bundle, [source])
            self.assertFalse(bundle.exists())

    def test_extended_section_numbering_does_not_become_a_missing_build_id(self):
        data = bytearray(elf())
        struct.pack_into("<Q", data, 40, 64)
        with self.assertRaisesRegex(ValueError, "table"):
            collector.elf_build_id(bytes(data), "riscv64")

    def test_matching_bytes_are_collected_without_fabricating_a_build_id(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            data = elf()
            source = root / "renamed-file"
            source.write_bytes(data)
            captured = manifest(data, None)
            result = collector.collect_artifacts(captured, root / "bundle", [source])
            self.assertEqual(result["artifacts"][0]["status"], "verified")
            self.assertIsNone(result["artifacts"][0]["gnu_build_id"])
            self.assertEqual((root / "bundle" / captured["artifacts"][0]["path"]).read_bytes(), data)

    def test_same_basename_and_unknown_object_cannot_supply_missing_facts(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "kernel.elf"
            source.write_bytes(elf(b"wrong-id"))
            captured = manifest(elf(b"true-id!"), b"true-id!".hex())
            captured["objects"] = [{"object": 9, "sha256": None, "path_label": "kernel.elf"}]
            result = collector.collect_artifacts(captured, root / "bundle", [source])
            self.assertEqual(result["artifacts"][0]["status"], "missing")
            self.assertEqual(result["unknown_objects"], captured["objects"])
            self.assertFalse((root / "bundle" / captured["artifacts"][0]["path"]).exists())

    def test_matching_sha_with_wrong_recorded_build_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "target"
            data = elf(b"real-id!")
            source.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "GNU build-id"):
                collector.collect_artifacts(manifest(data, b"fake-id!".hex()), root / "bundle", [source])


if __name__ == "__main__":
    unittest.main()
