"""Oracle regressions use immutable historical bytes, never new-run evidence."""
from collections import Counter
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zlib

from e2e import CPUFields, capture_facts, command, compare_query, fixture_chain, negative_exports, selected_samples


class OriginalCaptureOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        archive = Path(__file__).parent / "evidence/211/riscv64.tar.gz"
        with tarfile.open(archive) as stream:
            cls.original = stream.extractfile("riscv64/stacks-mixed/mixed.pbcapture").read()
            cls.fixture = stream.extractfile("riscv64/stacks-mixed/record-fixture.elf").read()

    def test_known_functions_come_from_original_elf_not_perf_demangler(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "fixture.elf"
            path.write_bytes(self.fixture)
            selected = selected_samples(capture_facts(self.original, "riscv64"), {"mode": "user"})
            chain = fixture_chain(path, "0dec7702fde7adf808862aaba5e9dfc4cce8a524250c850618a17e02f4126d62", selected)
            self.assertEqual([row["symbol"] for row in chain], [
                "_RNvCscYEoEou2e8x_7fixture11sample_leaf",
                "_RNvCscYEoEou2e8x_7fixture13sample_middle",
                "_RNvCscYEoEou2e8x_7fixture12sample_outer"])
            with self.assertRaisesRegex(ValueError, "SHA"):
                fixture_chain(path, "0" * 64, selected)

    def test_decode_original_record_bytes_without_analyzer_timeline(self):
        facts = capture_facts(self.original, "riscv64")
        samples = selected_samples(facts, {"mode": "user"})
        self.assertEqual(len(samples), 21)
        self.assertEqual(sum(sample["fields"].period_ns for sample in samples), 210_000_000)
        self.assertEqual(samples[0]["sequence_index"], 34)
        self.assertEqual(samples[0]["fields"], (
            5, 4195898, 51, 51, 5048855400, 4, 10_000_000, 2,
            ((1 << 64) - 512, 4195898, 4195974, 4195942, 4196830, 4200652, 4194562)))
        self.assertEqual(facts["sources"][1]["kernel_event_id"], 9)
        self.assertEqual(facts["status"], "IncompleteError")

    def test_equal_clock_cpu_and_period_do_not_merge_logical_instances(self):
        facts = capture_facts(self.original, "riscv64")
        selected = selected_samples(facts, {"mode": "user", "cpu": 4})
        counts = Counter(sample["fields"].logical_source for sample in selected)
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

    def test_mixed_query_keeps_fault_rows_without_counting_them_as_cpu_samples(self):
        selected = [{"sequence_index": 2, "task_id": 10, "semantic": None,
                     "fields": CPUFields(3, 4096, 7, 7, 100, 0, 20, 2, ((1 << 64) - 512, 4096))}]
        report = {"sample_weight": {"unit": "samples", "samples": 1, "total": 1},
                  "cpu_samples": [{"sequence_index": 2, "logical_source": 3, "weight": 1,
                      "timestamp_ns": 100, "cpu_id": 0, "pid": 7, "tid": 7, "task_id": 10,
                      "sample_period": 20, "ip": 4096, "mode": 2}], "stack_samples": []}
        table = """CPU samples: 1; weight: 1 samples
1 4 90 0 7 7 10 fixture page_fault address=0x1000 origin=user
2 3 100 0 7 7 10 fixture perf_event_v2 period=20 pc=0x1000 mode=2
"""
        compare_query(selected, report, table, "[INCOMPLETE_CAPTURE];pid:7:tid:7;[user];pc:0x1000 1\n", "samples", "IncompleteError")

    def test_simulated_child_permission_diagnostic_stops_command(self):
        # No OS permission failure is induced: subprocess is the mocked system
        # boundary and emits a deliberately simulated diagnostic.
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream), tempfile.TemporaryDirectory() as name:
                values = {"stdout": "", "stderr": ""}
                values[stream] = "simulated child: Permission denied"
                process = subprocess.CompletedProcess(["simulated"], 1, **values)
                with patch("e2e.subprocess.run", return_value=process), self.assertRaises(PermissionError):
                    command(Path(name), "simulated", ["simulated"])

    def test_each_negative_requires_its_intended_semantic_diagnostic(self):
        diagnostics = ["Error: ELF unavailable: No such file or directory (os error 2)",
                       "Error: ELF SHA256 mismatch",
                       "Error: failed to parse BPF capture: Capture error: TruncatedTrailer",
                       "Error: failed to parse BPF capture: Capture error: BadTrailerMagic",
                       "Error: failed to parse BPF capture: Capture error: ChecksumMismatch { expected: 1, actual: 2 }",
                       "Error: failed to parse BPF capture: Capture error: TruncatedTrailer"]
        for changed in range(len(diagnostics)):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as name:
                directory = Path(name)
                capture = directory / "original.pbcapture"
                capture.write_bytes(self.original)
                outputs = [subprocess.CompletedProcess(["simulated"], 1, "", text) for text in diagnostics]
                outputs[changed].stderr = "Error: unrelated output I/O failure"
                with patch("e2e.subprocess.run", side_effect=outputs), self.assertRaisesRegex(ValueError, "semantic rejection"):
                    negative_exports(directory, Path("simulated"), capture, [], [{"path": "artifacts/test.elf"}])

    def test_crash_cannot_count_as_an_expected_rejection(self):
        for returncode in (-11, 101):
            with self.subTest(returncode=returncode), tempfile.TemporaryDirectory() as name:
                directory = Path(name)
                capture = directory / "original.pbcapture"
                capture.write_bytes(self.original)
                output = subprocess.CompletedProcess(["simulated"], returncode, "", "Error: ELF unavailable: absent")
                with patch("e2e.subprocess.run", return_value=output), self.assertRaisesRegex(ValueError, "semantic rejection"):
                    negative_exports(directory, Path("simulated"), capture, [], [{"path": "artifacts/test.elf"}])

    def test_complete_and_partial_status_must_both_match_original_capture(self):
        from e2e import compare_capture_status
        compare_capture_status({"status": "Complete"}, {"status": "Complete", "is_complete": True})
        compare_capture_status({"status": "IncompleteError"}, {"status": "IncompleteError", "is_complete": False})
        with self.assertRaises(ValueError):
            compare_capture_status({"status": "Complete"}, {"status": "Complete", "is_complete": False})
        with self.assertRaises(ValueError):
            compare_capture_status({"status": "IncompleteError"}, {"status": "Complete", "is_complete": True})

    def test_folded_requires_original_identity_frame_order_termination_and_stack_weights(self):
        from e2e import CPUFields, compare_folded
        selected = [
            {"task_id": 10, "fields": CPUFields(3, 16, 7, 7, 100, 0, 20, 2, ((1 << 64) - 512, 16, 32, 48)),
             "semantic": {"stack_status": "complete", "termination": "complete_at_terminator", "ips": [16, 32, 48]}},
            {"task_id": 99, "fields": CPUFields(4, 64, 0, 0, 110, 1, 30, 1, ((1 << 64) - 128, 64, 80)),
             "semantic": {"stack_status": "partial", "termination": "depth_limit", "ips": [64, 80]}},
            {"task_id": 11, "fields": CPUFields(3, 4096, 8, 8, 120, 0, 40, 2, ()),
             "semantic": {"stack_status": "unavailable", "termination": "invalid_instruction_pointer", "ips": []}},
        ]
        stacks = ["[INCOMPLETE_CAPTURE];pid:7:tid:7;[user];pc:0x30;pc:0x20;pc:0x10",
                  "[INCOMPLETE_CAPTURE];task:99;[kernel];[partial:depth_limit];pc:0x50;pc:0x40",
                  "[INCOMPLETE_CAPTURE];pid:8:tid:8;[user];[unavailable:invalid_instruction_pointer]"]
        for weight, amounts in (("samples", (1, 1, 1)), ("period", (20, 30, 40))):
            text = "".join(f"{stack} {amount}\n" for stack, amount in zip(stacks, amounts))
            compare_folded(selected, text, weight, "IncompleteError")
            for bad in (text.replace("pid:7:tid:7", "fabricated_wrong_task"),
                        text.replace("pc:0x30;pc:0x20;pc:0x10", "fabricated_wrong_function"),
                        text.replace("pc:0x30;pc:0x20;pc:0x10", "pc:0x10;pc:0x20;pc:0x30"),
                        text.replace("[partial:depth_limit];", ""),
                        text.replace("[unavailable:invalid_instruction_pointer]", "[unavailable:invalid_instruction_pointer];pc:0x1000"),
                        text.replace("[INCOMPLETE_CAPTURE];", "")):
                with self.subTest(weight=weight, bad=bad), self.assertRaisesRegex(ValueError, "folded stacks"):
                    compare_folded(selected, bad, weight, "IncompleteError")
        moved = f"{stacks[0]} 10\n{stacks[1]} 40\n{stacks[2]} 40\n"
        with self.assertRaisesRegex(ValueError, "folded stacks"):
            compare_folded(selected, moved, "period", "IncompleteError")
        complete = "pid:7:tid:7;[user];pc:0x30;pc:0x20;pc:0x10 1\n"
        compare_folded(selected[:1], complete, "samples", "Complete")


if __name__ == "__main__":
    unittest.main()
