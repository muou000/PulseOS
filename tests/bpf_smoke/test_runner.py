#!/usr/bin/env python3
"""Tests for the legacy CLI's real-capture routing and static fixture isolation."""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))
import run


class RuntimeRoutingTests(unittest.TestCase):
    def test_guest_always_uses_current_sampler_and_archive(self):
        args = run.build_parser().parse_args([
            "guest", "--arch", "riscv64", "--mode", "trace", "--kernel", "kernel",
            "--kernel-elf", "symbols", "--kernel-provenance", "manifest.json",
            "--fault", "export-overflow", "--ring-pages", "1", "--primary", "image", "--timeout", "73",
        ])
        argv = run.sampling_command("guest", args.arch, args.mode, args)
        self.assertEqual(argv[:3], [sys.executable, str(run.SAMPLING_DRIVER), "guest"])
        for option, value in (("--arch", "riscv64"), ("--mode", "trace"),
                              ("--kernel", "kernel"), ("--kernel-elf", "symbols"),
                              ("--kernel-provenance", "manifest.json"), ("--fault", "export-overflow"), ("--ring-pages", "1"),
                              ("--image", "image"), ("--timeout", "73.0")):
            self.assertEqual(argv[argv.index(option) + 1], value)
        self.assertIn("--archive", argv)
        self.assertNotIn("guest_sampler", " ".join(argv))
        self.assertNotIn("fixture", " ".join(argv))

    def test_build_raw_compatibility_name_builds_real_archive_payload(self):
        with mock.patch.object(run, "run_sampling", return_value=0) as launch:
            self.assertEqual(run.main(["build-raw", "--arch", "loongarch64"]), 0)
        args = launch.call_args.args
        self.assertEqual(args[:3], ("build", "loongarch64", "task"))
        self.assertIn("--archive", run.sampling_command(*args))

    def test_gate_requires_software_scheduler_and_fault_on_both_architectures(self):
        with mock.patch.object(run, "run_sampling", return_value=0) as launch:
            self.assertEqual(run.main(["gate"]), 0)
        self.assertEqual([call.args[:3] for call in launch.call_args_list], [
            ("guest", "riscv64", "task"), ("guest", "riscv64", "trace"),
            ("guest", "riscv64", "sched"), ("guest", "riscv64", "fault"),
            ("guest", "loongarch64", "task"), ("guest", "loongarch64", "trace"),
            ("guest", "loongarch64", "sched"), ("guest", "loongarch64", "fault"),
        ])

    def test_missing_tools_or_runtime_failures_cannot_pass_gate(self):
        for exit_code in (1, 2, 77):
            with self.subTest(exit_code=exit_code), mock.patch.object(run, "run_sampling", return_value=exit_code):
                self.assertNotEqual(run.main(["gate", "--arch", "riscv64"]), 0)

    def test_single_guest_propagates_child_failure(self):
        with mock.patch.object(run.subprocess, "run", return_value=argparse.Namespace(returncode=42)):
            self.assertEqual(run.main(["guest", "--arch", "riscv64"]), 42)

    def test_dual_arch_gate_rejects_a_single_kernel_or_image_override(self):
        for option in ("--kernel", "--kernel-elf", "--kernel-provenance", "--image"):
            with self.subTest(option=option), mock.patch.object(run, "run_sampling") as launch:
                self.assertNotEqual(run.main(["gate", option, "one-arch-file"]), 0)
                launch.assert_not_called()

    def test_custom_legacy_payload_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            run.main(["guest", "--arch", "riscv64", "--payload", "static-five-records.elf"])
        self.assertNotEqual(raised.exception.code, 0)

    def test_legacy_parity_command_cannot_make_a_parity_claim(self):
        with mock.patch.object(run, "run_sampling") as launch:
            self.assertNotEqual(run.main(["parity"]), 0)
            launch.assert_not_called()

    def test_static_fixture_check_is_explicit_and_never_launches_a_guest(self):
        with mock.patch.object(run, "feed_analyzer", return_value=(True, "format valid")) as feed, \
                mock.patch.object(run, "run_sampling") as launch, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(run.main(["fixture-check"]), 0)
        launch.assert_not_called()
        self.assertEqual(feed.call_args.args, (run.FORMAT_FIXTURE,))
        self.assertIn("STATIC FORMAT FIXTURE", out.getvalue())
        self.assertIn("no runtime evidence", out.getvalue())


class RejectedLegacyEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sampling_dir = BASE.parent / "bpf_sampling"
        sys.path.insert(0, str(sampling_dir))
        spec = importlib.util.spec_from_file_location("bpf_real_sampler", sampling_dir / "run.py")
        cls.sampler = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.sampler)

    def test_fixed_five_record_legacy_success_is_rejected(self):
        # This was the old gate's entire positive runtime protocol. A valid
        # static capture and claimed counts do not establish producer/consumer work.
        text = "\n".join([
            "BPF_SESSION_START version=1 scope=all_cpus clock=monotonic sample_period=100000",
            "BPF PASS fixture_open_load_attach", "BPF PASS workload_and_consume",
            "BPF PASS fixture_detach_close",
            "BPF_STATE_REPORT state=attached_capture status=PASS wall_time_ns=1200000 workload_iters=400 memory_bytes=45056 samples=1 events=5 lost=0",
            "BPF_SESSION_STOP status=CompleteOk records=5 delivered=5 lost=0",
            "BPF_CAPTURE_DATA " + run.FORMAT_FIXTURE.read_bytes().hex(),
            "BPF RESULT PASS functional_only=1", "BPF_HOST_EXIT old 0",
        ])
        for mode in ("task", "trace"):
            self.assertTrue(self.sampler.validate_log(text, "old", mode))
            with self.assertRaises(ValueError):
                self.sampler.raw_archive.extract(text, mode)

    def test_old_guest_source_cannot_compile_into_a_runtime_payload(self):
        with tempfile.TemporaryDirectory(prefix="retired-payload-", dir=BASE) as tmp:
            result = subprocess.run([
                "rustc", "--crate-type=lib", "--emit=metadata", "--out-dir", tmp,
                str(BASE / "guest_sampler.rs"),
            ], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("retired synthetic guest payload", result.stdout)


class ImageAndElfTests(unittest.TestCase):
    def test_payload_elf_arch_and_static_linkage_are_checked(self):
        with tempfile.TemporaryDirectory(prefix="elf-check-", dir=BASE) as tmp:
            path = Path(tmp) / "payload"
            data = bytearray(120)
            data[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", data, 18, 243)
            struct.pack_into("<Q", data, 32, 64)
            struct.pack_into("<HH", data, 54, 56, 1)
            struct.pack_into("<I", data, 64, 1)
            struct.pack_into("<Q", data, 96, len(data))
            path.write_bytes(data)
            run.check_elf(path, "riscv64")
            with self.assertRaises(ValueError):
                run.check_elf(path, "loongarch64")
            struct.pack_into("<I", data, 64, 3)
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                run.check_elf(path, "riscv64")

    def test_image_staging_cannot_overwrite_external_paths(self):
        with self.assertRaises(ValueError):
            run.scoped(BASE.parent / "not-in-smoke")


class StaticFormatFixtureTests(unittest.TestCase):
    def test_fixture_is_only_a_format_artifact(self):
        self.assertTrue(run.FORMAT_FIXTURE.is_file())
        ok, report = run.feed_analyzer(run.FORMAT_FIXTURE)
        self.assertTrue(ok, report)
        self.assertIn("INTEGRITY CHECK PASSED", report)

    def test_corrupt_capture_fails_the_analyzer(self):
        with tempfile.TemporaryDirectory(prefix="analyzer-corrupt-", dir=BASE) as tmp:
            path = Path(tmp) / "bad.bin"
            path.write_bytes(b"NOT_A_CAPTURE")
            ok, report = run.feed_analyzer(path)
            self.assertFalse(ok)
            self.assertIn("failed to parse bpf capture", report.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
