"""The native perf dump is an independent oracle for raw CPU samples."""
import unittest
import perf_evidence


class PerfEvidenceTests(unittest.TestCase):
    def test_native_dump_requires_parsed_chain_and_source_identity(self):
        dump = """0x230@/tmp/perf.data [0x58]: event: 9
. ... raw event: size 88 bytes
.  0000:  09 00 00 00 02 00 58 00 15 00 00 00 00 00 00 00  ......X.........
.  0010:  00 00 40 00 00 00 00 00 07 00 00 00 08 00 00 00  ..@.............
.  0020:  0a 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00  ................
.  0030:  14 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00  ................
.  0040:  00 fe ff ff ff ff ff ff 00 00 40 00 00 00 00 00  ..........@.....
.  0050:  04 00 40 00 00 00 00 00                          ..@.....
2 10 0x230 [0x58]: PERF_RECORD_SAMPLE(IP, 0x2): 7/8: 0x400000 period: 20 addr: 0
... FP chain: nr:3
.....  0: fffffffffffffe00
.....  1: 0000000000400000
.....  2: 0000000000400004
"""
        self.assertEqual(perf_evidence.native_samples(dump), [(21, 0x400000, 7, 8, 10, 2, 20, 2,
                         ((1 << 64) - 512, 0x400000, 0x400004))])
        with self.assertRaises(ValueError):
            perf_evidence.native_samples(dump.replace('period: 20', 'period: 21'))
        with self.assertRaises(ValueError):
            perf_evidence.native_samples(dump.replace('.....  2: 0000000000400004', '.....  2: 0000000000400008'))

    def test_known_functions_must_form_one_ordered_chain(self):
        script = 'worker 7/8 [002] 1.0: 20 cpu-clock:\n  401020 leaf (elf)\n  401010 middle (elf)\n  401000 outer (elf)\n\n'
        tree = '    100.00% [.] leaf\n        |\n        ---outer\n           middle\n           leaf\n\n'
        perf_evidence.verify_named_chain(script, tree, ['leaf', 'middle', 'outer'])
        with self.assertRaises(ValueError):
            perf_evidence.verify_named_chain(script, tree.replace('           middle\n           leaf', '           leaf\n           middle'), ['leaf', 'middle', 'outer'])

    def test_known_leaf_weights_use_original_ip_ranges(self):
        rows = [{'samples': 2, 'period_ns': 30, 'symbol': 'leaf'},
                {'samples': 1, 'period_ns': 10, 'symbol': 'other'}]
        samples = [(1, 0x102, 7, 7, 1, 0, 10, 2, ()),
                   (2, 0x104, 7, 7, 2, 0, 20, 2, ()),
                   (1, 0x120, 7, 7, 3, 0, 10, 2, ())]
        perf_evidence.verify_function_weights(samples, rows, {'leaf': [0x100, 0x110]})
        rows[0]['period_ns'] = 20
        with self.assertRaises(ValueError):
            perf_evidence.verify_function_weights(samples, rows, {'leaf': [0x100, 0x110]})


if __name__ == '__main__':
    unittest.main()
