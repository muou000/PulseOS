"""Consumer symbol views preserve loaded bytes and every real function symbol."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('perf_symbols', Path(__file__).parents[2] / 'scripts/perf_symbols.py')
symbols = importlib.util.module_from_spec(spec)
spec.loader.exec_module(symbols)


def elf_fixture(label='.L0 ', machine=258):
    data = bytearray(1024)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, 2, machine, 1, 0x1000, 64, 128, 0, 64, 56, 1, 64, 3, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 400, 0x1000, 0x1000, 16, 16, 1)
    data[400:416] = b'kernel-code-12345'
    strings = b'\0' + label.encode() + b'\0real_func\0.Lfunction\0global_label\0'
    data[800:800 + len(strings)] = strings
    struct.pack_into('<IIQQQQIIQQ', data, 192, 0, 2, 0, 0, 512, 120, 2, 1, 8, 24)
    struct.pack_into('<IIQQQQIIQQ', data, 256, 0, 3, 0, 0, 800, len(strings), 0, 0, 1, 0)
    # Only the first defined entry is an eligible local untyped debug label.
    for index, (name, info, other, address, size) in enumerate([
        (label, 0, 0x40, 0x1000, 0), ('real_func', 2, 0, 0x1000, 8),
        ('.Lfunction', 2, 0, 0x1008, 8), ('global_label', 16, 0, 0x1008, 0),
    ], start=1):
        struct.pack_into('<IBBHQQ', data, 512 + index * 24, strings.index(name.encode()), info, other, 1, address, size)
    return bytes(data)


class PerfSymbolsTests(unittest.TestCase):
    def test_only_local_untyped_label_visibility_changes(self):
        original = elf_fixture()
        derived, count = symbols.hide_local_labels(original)
        self.assertEqual(count, 1)
        changed = [i for i, pair in enumerate(zip(original, derived)) if pair[0] != pair[1]]
        self.assertEqual(changed, [541])
        self.assertEqual(derived[541], 0x42)
        self.assertEqual(original[400:416], derived[400:416])
        self.assertEqual(original[560:632], derived[560:632])

    def test_loaded_symbol_metadata_cannot_be_changed(self):
        data = bytearray(elf_fixture())
        struct.pack_into('<Q', data, 64 + 8, 536)
        with self.assertRaisesRegex(ValueError, 'PT_LOAD'):
            symbols.hide_local_labels(bytes(data))

    def test_riscv_mapping_labels_only_match_reserved_zero_size_family(self):
        for label in ('$d', '$d.7', '$x', '$x.1', '$xrv64i2p1_m2p0_zicsr2p0', '$xrv64i2p1_zca1p0.3'):
            with self.subTest(label=label):
                original = elf_fixture(label, 243)
                derived, count = symbols.hide_local_labels(original)
                self.assertEqual(count, 1)
                self.assertEqual([i for i in range(len(original)) if original[i] != derived[i]], [541])
                self.assertEqual(symbols.hide_local_labels(elf_fixture(label, 258))[1], 0)
                sized = bytearray(original)
                struct.pack_into('<Q', sized, 536 + 16, 8)
                self.assertEqual(symbols.hide_local_labels(bytes(sized))[1], 0)
        for label in ('$debug', '$xcustom', '$xrv64', '$xrv64invalid!', '$xrv32i2p1'):
            with self.subTest(label=label):
                original = elf_fixture(label, 243)
                self.assertEqual(symbols.hide_local_labels(original), (original, 0))

    def test_truncated_symbol_table_is_rejected(self):
        with self.assertRaises(ValueError):
            symbols.hide_local_labels(elf_fixture()[:600])

    def test_original_elf_and_existing_outputs_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original, derived = directory / 'original.elf', directory / 'view.elf'
            original.write_bytes(elf_fixture())
            report = symbols.prepare_symbol_view(original, derived)
            self.assertEqual(original.read_bytes(), elf_fixture())
            self.assertNotEqual(report['original_sha256'], report['derived_sha256'])
            self.assertTrue(report['load_bytes_unchanged'])
            with self.assertRaises(FileExistsError):
                symbols.prepare_symbol_view(original, original)
            self.assertEqual(original.read_bytes(), elf_fixture())


if __name__ == '__main__':
    unittest.main()
