"""Oracle regressions use immutable historical bytes, never new-run evidence."""
from collections import Counter
from pathlib import Path
import struct
import tarfile
import unittest
import zlib

from e2e import capture_facts, selected_samples


class OriginalCaptureOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        archive = Path(__file__).parent / "evidence/211/riscv64.tar.gz"
        with tarfile.open(archive) as stream:
            cls.original = stream.extractfile("riscv64/stacks-mixed/mixed.pbcapture").read()

    def test_decode_original_record_bytes_without_analyzer_timeline(self):
        facts = capture_facts(self.original, "riscv64")
        samples = selected_samples(facts, {"mode": "user"})
        self.assertEqual(len(samples), 21)
        self.assertEqual(sum(sample["fields"][6] for sample in samples), 210_000_000)
        self.assertEqual(samples[0]["sequence_index"], 34)
        self.assertEqual(samples[0]["fields"], (
            5, 4195898, 51, 51, 5048855400, 4, 10_000_000, 2,
            ((1 << 64) - 512, 4195898, 4195974, 4195942, 4196830, 4200652, 4194562)))
        self.assertEqual(facts["sources"][1]["kernel_event_id"], 9)
        self.assertEqual(facts["status"], "IncompleteError")

    def test_equal_clock_cpu_and_period_do_not_merge_logical_instances(self):
        facts = capture_facts(self.original, "riscv64")
        selected = selected_samples(facts, {"mode": "user", "cpu": 4})
        counts = Counter(sample["fields"][0] for sample in selected)
        self.assertGreater(counts[5], 0)
        self.assertGreater(counts[13], 0)
        self.assertEqual(facts["sources"][5]["cpu"], facts["sources"][13]["cpu"])
        self.assertEqual(facts["sources"][5]["period"], facts["sources"][13]["period"])

    def test_crc_trailer_and_record_removal_are_rejected(self):
        for broken in (self.original[:-40], self.original[:-1], self.original[:100] + self.original[101:]):
            with self.subTest(length=len(broken)), self.assertRaises(ValueError):
                capture_facts(broken, "riscv64")
        altered = bytearray(self.original)
        records = struct.unpack_from("<Q", altered, 40)[0]
        altered[records + 48] ^= 1
        with self.assertRaisesRegex(ValueError, "CRC"):
            capture_facts(altered, "riscv64")

    def test_rechecks_binding_even_when_attacker_recomputes_crc(self):
        altered = bytearray(self.original)
        sources = altered.index(b"PBSRC003")
        count = struct.unpack_from("<I", altered, sources + 8)[0]
        struct.pack_into("<I", altered, sources + 24 + count * 160, 999)
        trailer = struct.unpack_from("<Q", altered, 64)[0]
        struct.pack_into("<I", altered, trailer + 24, zlib.crc32(altered[:trailer]))
        with self.assertRaisesRegex(ValueError, "source binding"):
            capture_facts(altered, "riscv64")


if __name__ == "__main__":
    unittest.main()
