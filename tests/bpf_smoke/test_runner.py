#!/usr/bin/env python3
"""Host test runner and harness validation for BPF guest sampler smoke (#104).

Run: python3 tests/bpf_smoke/test_runner.py
Validates the harness protocol, log markers, capture extraction, safe image staging,
and ensures unbuilt payloads or corrupt captures are cleanly rejected.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

# Ensure tests/bpf_smoke is in sys.path
BASE = Path(__file__).resolve().parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

import run


def sample_capture_payload() -> bytes:
    """A minimal deterministic capture payload conforming to bpf-capture schema."""
    fixture_path = BASE / "fixture_capture.bin"
    if fixture_path.is_file():
        return fixture_path.read_bytes()
    # Fallback to minimal header if fixture not yet generated
    header = bytearray(80)
    header[0:8] = b"PBCAP001"
    struct.pack_into("<IIIIQQQQQQQ", header, 8,
                     1, 1, 80, 1,
                     80, 0,
                     80, 0, 0,
                     80, 40)
    trailer = bytearray(40)
    trailer[0:8] = b"PBCAPTRL"
    struct.pack_into("<QQIIII", trailer, 8,
                     0, 0, 0, 0, 40, 0)
    return bytes(header + trailer)


def sample_markers(token="testtoken", status=0, capture_bytes: bytes | None = None) -> str:
    cap = capture_bytes if capture_bytes is not None else sample_capture_payload()
    cap_hex = cap.hex()
    cap_hash = hashlib.sha256(cap).hexdigest()
    lines = [
        "BPF_SESSION_START version=1 scope=all_cpus clock=monotonic sample_period=100000",
        "BPF BEGIN fixture_open_load_attach",
        "BPF PASS fixture_open_load_attach",
        "BPF BEGIN workload_and_consume",
        "BPF PASS workload_and_consume",
        "BPF BEGIN fixture_detach_close",
        "BPF PASS fixture_detach_close",
        "BPF_SESSION_STOP status=CompleteOk records=0 delivered=0 lost=0",
        f"BPF_CAPTURE_BEGIN bytes={len(cap)} sha256={cap_hash}",
        f"BPF_CAPTURE_DATA {cap_hex}",
        "BPF_CAPTURE_END",
        "BPF SUMMARY pass=3 fail=0 skip=0",
        "BPF RESULT PASS functional_only=1",
        f"BPF_HOST_EXIT {token} {status}",
    ]
    return "\n".join(lines) + "\n"


class LogValidatorTests(unittest.TestCase):
    def test_complete_valid_log_passes(self):
        text = sample_markers()
        errors = run.validate_log(text, shell_token="testtoken")
        self.assertEqual(errors, [])

    def test_missing_session_start_rejected(self):
        text = sample_markers().replace("BPF_SESSION_START", "WRONG_START")
        errors = run.validate_log(text, shell_token="testtoken")
        self.assertTrue(any("START" in e for e in errors))

    def test_missing_session_stop_rejected(self):
        text = sample_markers().replace("BPF_SESSION_STOP", "WRONG_STOP")
        errors = run.validate_log(text, shell_token="testtoken")
        self.assertTrue(any("STOP" in e for e in errors))

    def test_missing_lifecycle_stage_rejected(self):
        text = sample_markers().replace("BPF PASS fixture_open_load_attach\n", "")
        errors = run.validate_log(text, shell_token="testtoken")
        self.assertTrue(any("fixture_open_load_attach" in e for e in errors))

    def test_nonzero_shell_exit_rejected(self):
        text = sample_markers(status=1)
        errors = run.validate_log(text, shell_token="testtoken")
        self.assertTrue(any("shell exit" in e.lower() for e in errors))

    def test_kernel_panic_detected(self):
        text = sample_markers() + "Kernel panic - not syncing: fatal exception\n"
        errors = run.validate_log(text, shell_token="testtoken")
        self.assertTrue(any("panic" in e.lower() for e in errors))


class CaptureExtractionTests(unittest.TestCase):
    def test_extract_valid_capture_artifact(self):
        expected_bytes = sample_capture_payload()
        text = sample_markers(capture_bytes=expected_bytes)
        artifact, sha = run.extract_capture_artifact(text)
        self.assertIsNotNone(artifact)
        self.assertEqual(artifact, expected_bytes)
        self.assertEqual(sha, hashlib.sha256(expected_bytes).hexdigest())

    def test_corrupted_hex_chunk_rejected(self):
        text = sample_markers().replace("BPF_CAPTURE_DATA ", "BPF_CAPTURE_DATA zz")
        with self.assertRaises(ValueError):
            run.extract_capture_artifact(text)

    def test_mismatched_sha256_rejected(self):
        text = sample_markers().replace("sha256=", "sha256=0000000000000000000000000000000000000000000000000000000000000000")
        with self.assertRaises(ValueError):
            run.extract_capture_artifact(text)

    def test_missing_capture_markers_returns_none(self):
        text = "some log line\nwithout capture\n"
        self.assertIsNone(run.extract_capture_artifact(text))


class ImageAndElfTests(unittest.TestCase):
    def test_elf_arch_and_static_linkage_validation(self):
        with tempfile.TemporaryDirectory(prefix="elf-check-", dir=BASE) as tmp:
            path = Path(tmp) / "payload"
            data = bytearray(120)
            data[:6] = b"\x7fELF\x02\x01"
            # riscv64 is machine 243, loongarch64 is 258
            struct.pack_into("<H", data, 18, 243)
            struct.pack_into("<Q", data, 32, 64)
            struct.pack_into("<HH", data, 54, 56, 1)
            struct.pack_into("<I", data, 64, 1)
            struct.pack_into("<Q", data, 96, len(data))
            path.write_bytes(data)

            run.check_elf(path, "riscv64")
            with self.assertRaises(ValueError):
                run.check_elf(path, "loongarch64")

            # PT_INTERP (ph[0] == 3) must be rejected
            struct.pack_into("<I", data, 64, 3)
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                run.check_elf(path, "riscv64")


class HarnessPlanMissingRunnerTests(unittest.TestCase):
    def test_plan_step1_missing_guest_runner_fails_early(self):
        """Verifies plan step 1: missing guest payload/runner causes explicit failure."""
        missing = BASE / "non_existent_payload.elf"
        with self.assertRaises(FileNotFoundError):
            run.check_payload_exists(missing)


class AnalyzerFeedIntegrationTests(unittest.TestCase):
    def test_analyzer_on_valid_capture_reports_zero_loss_and_table(self):
        fixture_path = BASE / "fixture_capture.bin"
        self.assertTrue(fixture_path.is_file(), "fixture_capture.bin must exist")
        ok, report = run.feed_analyzer(fixture_path)
        self.assertTrue(ok, f"feed_analyzer failed: {report}")
        self.assertIn("Status: Complete", report)
        self.assertIn("INTEGRITY CHECK PASSED", report)
        self.assertIn("Lost Records: 0", report)
        self.assertIn("sched_switch", report)

    def test_analyzer_on_corrupted_capture_fails(self):
        with tempfile.TemporaryDirectory(prefix="analyzer-corrupt-", dir=BASE) as tmp:
            bad_path = Path(tmp) / "bad_capture.bin"
            bad_path.write_bytes(b"NOT_A_VALID_CAPTURE_FILE_HEADER")
            ok, report = run.feed_analyzer(bad_path)
            self.assertFalse(ok)
            self.assertIn("Failed to parse BPF capture", report)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
