"""Independent binary fixtures for real ELF identity and bundle rejection."""
import json
from pathlib import Path
import struct
import tempfile
import unittest

import artifacts


def elf(build_id=None, elf_type=3, offset=4096, vaddr=8192):
    data = bytearray(8192)
    data[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, elf_type, 243, 1, vaddr, 64, 0, 0, 64, 56, 1 + (build_id is not None), 64, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, offset, vaddr, vaddr, 4096, 4096, 4096)
    if build_id is not None:
        note = struct.pack('<III', 4, len(build_id), 3) + b'GNU\0' + build_id
        note += bytes(-len(note) % 4)
        data[512:512 + len(note)] = note
        struct.pack_into('<IIQQQQQQ', data, 120, 4, 4, 512, 0, 0, len(note), len(note), 4)
    return bytes(data)


class ArtifactTests(unittest.TestCase):
    def test_actual_build_id_and_explicit_absence(self):
        self.assertIsNone(artifacts.elf_identity(elf())['gnu_build_id'])
        actual = bytes.fromhex('0123456789abcdef0123456789abcdef01234567')
        identity = artifacts.elf_identity(elf(actual))
        self.assertEqual(identity['gnu_build_id'], actual.hex())
        self.assertNotEqual(identity['gnu_build_id'], identity['sha256'][:40])

    def test_pie_and_nonzero_pgoff_kept_as_bytes(self):
        info = artifacts.elf_identity(elf())
        self.assertEqual(info['elf_type'], 3)
        self.assertEqual(info['load_segments'][0]['offset'], 4096)
        self.assertEqual(info['load_segments'][0]['vaddr'], 8192)

    def test_wrong_same_name_and_missing_elf_do_not_fall_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'payload.elf'
            source.write_bytes(elf())
            manifest = artifacts.bundle(root, [source])
            self.assertEqual(artifacts.verify(root), manifest)
            saved = root / manifest['artifacts'][0]['path']
            saved.write_bytes(elf(b'wrong'))
            with self.assertRaisesRegex(ValueError, 'differ'):
                artifacts.verify(root)
            saved.unlink()
            with self.assertRaises(FileNotFoundError):
                artifacts.verify(root)

    def test_manifest_cannot_invent_build_id_or_traverse_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'payload.elf'
            source.write_bytes(elf())
            manifest = artifacts.bundle(root, [source])
            manifest['artifacts'][0]['gnu_build_id'] = manifest['artifacts'][0]['sha256'][:40]
            (root / 'artifacts.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'differ'):
                artifacts.verify(root)
            manifest['artifacts'][0]['path'] = '../payload.elf'
            (root / 'artifacts.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'content addressed'):
                artifacts.verify(root)

    def test_truncated_note_and_bad_load_segment_are_rejected(self):
        broken = bytearray(elf(b'abcd'))
        struct.pack_into('<I', broken, 516, 4096)
        with self.assertRaisesRegex(ValueError, 'truncated'):
            artifacts.elf_identity(broken)
        broken = bytearray(elf())
        struct.pack_into('<Q', broken, 96, 9000)
        with self.assertRaises(ValueError):
            artifacts.elf_identity(broken)

    def test_conflicting_real_gnu_notes_are_rejected(self):
        broken = bytearray(elf(b'aaaa'))
        struct.pack_into('<H', broken, 56, 3)
        note = struct.pack('<III', 4, 4, 3) + b'GNU\0bbbb'
        broken[560:560 + len(note)] = note
        struct.pack_into('<IIQQQQQQ', broken, 176, 4, 4, 560, 0, 0, len(note), len(note), 4)
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            artifacts.elf_identity(broken)

    def test_embedded_debug_is_bound_to_exact_elf_even_without_build_id(self):
        data = bytearray(elf())
        names = b'\0.shstrtab\0.debug_info\0'
        data[300:300 + len(names)] = names
        data[600:604] = b'abcd'
        struct.pack_into('<Q', data, 40, 1024)
        struct.pack_into('<HHH', data, 58, 64, 3, 1)
        struct.pack_into('<IIQQQQIIQQ', data, 1088, 1, 3, 0, 0, 300, len(names), 0, 0, 1, 0)
        struct.pack_into('<IIQQQQIIQQ', data, 1152, 11, 1, 0, 0, 600, 4, 0, 0, 1, 0)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'payload.elf'
            source.write_bytes(data)
            manifest = artifacts.bundle(root, [source])
            entry = manifest['artifacts'][0]
            self.assertEqual(entry['debug_status'], 'embedded')
            self.assertEqual(entry['debug_sha256'], entry['sha256'])
            self.assertIsNone(entry['debug_build_id'])
            artifacts.verify(root)


if __name__ == '__main__':
    unittest.main()
