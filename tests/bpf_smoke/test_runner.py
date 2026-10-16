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


def sample_ltp_markers() -> list[str]:
    runlist = run.load_runlist()
    lines = []
    pass_cnt = 0
    conf_cnt = 0
    for e in runlist:
        lines.append(f"LTP_TEST_START {e.name}")
        lines.append(f"LTP_TEST_RESULT {e.name} {e.expected_class} status=expected")
        if e.expected_class == "TPASS":
            pass_cnt += 1
        elif e.expected_class == "TCONF":
            conf_cnt += 1
    lines.append(f"LTP_SUMMARY total={len(runlist)} pass={pass_cnt} fail=0 conf={conf_cnt}")
    return lines


def sample_markers(token="testtoken", status=0, capture_bytes: bytes | None = None) -> str:
    cap = capture_bytes if capture_bytes is not None else sample_capture_payload()
    cap_hex = cap.hex()
    cap_hash = hashlib.sha256(cap).hexdigest()
    lines = [
        "BPF_SESSION_START version=1 scope=all_cpus clock=monotonic sample_period=100000",
        *sample_ltp_markers(),
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


class Seam1RunlistValidationTests(unittest.TestCase):
    def test_runlist_file_exists_and_parses_classes(self):
        entries = run.load_runlist()
        self.assertGreater(len(entries), 0)
        expected_supported = {
            "bpf_map01",
            "bpf_prog01",
            "bpf_verifier",
            "perf_event_open01",
            "perf_buffer_mmap_epoll",
            "fixture_sampling",
        }
        expected_unsupported = {
            "perf_event_open02",
            "perf_event_open03",
            "bpf_prog06",
            "bpf_prog07",
            "bpf_prog_unsupported_type",
            "bpf_btf_core",
        }
        names = {e.name for e in entries}
        for s in expected_supported:
            self.assertIn(s, names, f"missing expected supported test {s}")
        for u in expected_unsupported:
            self.assertIn(u, names, f"missing expected unsupported test {u}")

        supported_map = {e.name: e.expected_class for e in entries}
        for s in expected_supported:
            self.assertEqual(supported_map[s], "TPASS")
        for u in expected_unsupported:
            self.assertEqual(supported_map[u], "TCONF")

    def test_validate_ltp_log_honest_classification_passes(self):
        runlist = run.load_runlist()
        log_lines = []
        pass_count = 0
        conf_count = 0
        for e in runlist:
            log_lines.append(f"LTP_TEST_START {e.name}")
            log_lines.append(f"LTP_TEST_RESULT {e.name} {e.expected_class} status=ok")
            if e.expected_class == "TPASS":
                pass_count += 1
            elif e.expected_class == "TCONF":
                conf_count += 1
        log_lines.append(f"LTP_SUMMARY total={len(runlist)} pass={pass_count} fail=0 conf={conf_count}")
        results, errors = run.validate_ltp_log("\n".join(log_lines), runlist)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), len(runlist))

    def test_validate_ltp_log_rejects_unsupported_reported_as_pass(self):
        runlist = run.load_runlist()
        log_lines = []
        for e in runlist:
            log_lines.append(f"LTP_TEST_START {e.name}")
            # Falsely report TPASS for everything
            log_lines.append(f"LTP_TEST_RESULT {e.name} TPASS status=falsified")
        log_lines.append(f"LTP_SUMMARY total={len(runlist)} pass={len(runlist)} fail=0 conf=0")
        results, errors = run.validate_ltp_log("\n".join(log_lines), runlist)
        self.assertTrue(any("unsupported capability falsely reported TPASS" in err for err in errors))

    def test_validate_ltp_log_missing_case_fails(self):
        runlist = run.load_runlist()
        log_lines = ["LTP_SUMMARY total=0 pass=0 fail=0 conf=0"]
        results, errors = run.validate_ltp_log("\n".join(log_lines), runlist)
        self.assertTrue(any("missing result for" in err for err in errors))


class Seam2GuestProtocolTests(unittest.TestCase):
    def test_guest_sampler_source_defines_all_runlist_cases(self):
        source_text = run.RAW_SOURCE.read_text()
        runlist = run.load_runlist()
        for e in runlist:
            self.assertIn(
                f'LTP_TEST_START {e.name}',
                source_text,
                f"guest_sampler.rs must implement case: {e.name}"
            )
            self.assertIn(
                f'LTP_TEST_RESULT {e.name} {e.expected_class}',
                source_text,
                f"guest_sampler.rs must emit result marker for {e.name} with {e.expected_class}"
            )

    def test_validate_log_enforces_runlist(self):
        # A log with missing LTP cases must be rejected by validate_log
        corrupted = sample_markers().replace("LTP_TEST_RESULT bpf_map01 TPASS", "LTP_TEST_RESULT bpf_map01 TFAIL")
        errors = run.validate_log(corrupted, shell_token="testtoken")
        self.assertTrue(any("bpf_map01" in err for err in errors))


class Seam3GateEvidenceTests(unittest.TestCase):

    def test_evidence_record_format_contains_required_fields(self):
        metadata = {
            "kind": "PulseOS BPF guest smoke",
            "arch": "riscv64",
            "qemu_command": ["qemu-system-riscv64"],
            "guest_command": "payload",
            "inputs": {
                "kernel": "/path/to/kernel",
                "primary": "/path/to/primary.img",
                "secondary": "/path/to/disk.img",
            },
            "input_sha256": {
                "kernel": "aaaabbbb1111",
                "primary": "ccccdddd2222",
                "secondary": "eeeeffff3333",
            },
            "source_sha256": "12345678",
        }
        test_results = {"bpf_map01": "TPASS", "bpf_prog06": "TCONF"}
        runlist_summary = {"total": 2, "pass": 1, "fail": 0, "conf": 1}
        capture_meta = {
            "sha256": "abcdef123456",
            "bytes": 1024,
            "integrity_passed": True,
        }
        analyzer_output = "Lost Records: 0\nStatus: Complete\nINTEGRITY CHECK PASSED"
        errors = []


        record = run.build_evidence_record(
            metadata=metadata,
            test_results=test_results,
            runlist_summary=runlist_summary,
            capture_meta=capture_meta,
            analyzer_output=analyzer_output,
            errors=errors,
            qemu_exit=0,
            driver_reason="",
        )

        self.assertEqual(record["arch"], "riscv64")
        self.assertIn("fixture_sha256", record)
        self.assertEqual(record["kernel_sha256"], "aaaabbbb1111")
        self.assertEqual(record["image_sha256"], "ccccdddd2222")
        self.assertEqual(record["test_results"], test_results)
        self.assertEqual(record["runlist_summary"], runlist_summary)
        self.assertEqual(record["capture_sha256"], "abcdef123456")
        self.assertTrue(record["capture_integrity"])
        self.assertEqual(record["analyzer_loss_counters"]["lost_records"], 0)
        self.assertTrue(record["gate_pass"])

    def test_evidence_record_reports_gate_failure_on_errors(self):
        record = run.build_evidence_record(
            metadata={"arch": "riscv64", "input_sha256": {}},
            test_results={},
            runlist_summary={"total": 0, "pass": 0, "fail": 0, "conf": 0},
            capture_meta=None,
            analyzer_output="",
            errors=["something broke"],
            qemu_exit=1,
            driver_reason="timeout",
        )
        self.assertFalse(record["gate_pass"])
        self.assertFalse(record["capture_integrity"])
        self.assertEqual(record["errors"], ["something broke"])

    def test_gate_parser_registers_gate_subcommand(self):
        parser = run.build_parser()
        args = parser.parse_args(["gate", "--arch", "riscv64"])
        self.assertEqual(args.command, "gate")
        self.assertEqual(args.arch, "riscv64")


class Seam4ParityManifestValidationTests(unittest.TestCase):
    def _valid_manifest(self) -> dict:
        return run.sample_valid_parity_manifest()

    def test_valid_manifest_passes_and_classifies_as_parity_candidate(self):
        manifest = self._valid_manifest()
        errors = run.validate_parity_manifest(manifest)
        self.assertEqual(errors, [])
        status = run.classify_parity_status(manifest)
        self.assertEqual(status, "parity_candidate")
        self.assertNotEqual(status, "replacement")
        self.assertEqual(
            manifest["comparison_semantics"]["mode"],
            "mechanism_level_cross_check",
        )
        self.assertFalse(
            manifest["comparison_semantics"]["raw_sample_equality_required"]
        )

    def test_missing_architecture_fails_manifest_and_prevents_parity_status(self):
        manifest = self._valid_manifest()
        del manifest["architectures"]["loongarch64"]
        errors = run.validate_parity_manifest(manifest)
        self.assertTrue(any("loongarch64" in e for e in errors), f"expected arch error in {errors}")
        self.assertEqual(run.classify_parity_status(manifest), "failed_or_incomplete")

    def test_missing_run_state_fails_manifest(self):
        for state_name in ("baseline", "loaded_detached", "attached_capture"):
            manifest = self._valid_manifest()
            del manifest["architectures"]["riscv64"]["states"][state_name]
            errors = run.validate_parity_manifest(manifest)
            self.assertTrue(any(state_name in e for e in errors), f"expected {state_name} error in {errors}")
            self.assertEqual(run.classify_parity_status(manifest), "failed_or_incomplete")

    def test_incomplete_trailer_or_schema_mismatch_prevents_complete_claim(self):
        manifest = self._valid_manifest()
        manifest["architectures"]["riscv64"]["capture"]["trailer_complete"] = False
        errors = run.validate_parity_manifest(manifest)
        self.assertTrue(any("trailer" in e.lower() for e in errors))
        self.assertEqual(run.classify_parity_status(manifest), "failed_or_incomplete")

        manifest2 = self._valid_manifest()
        manifest2["architectures"]["loongarch64"]["capture"]["schema_valid"] = False
        errors2 = run.validate_parity_manifest(manifest2)
        self.assertTrue(any("schema" in e.lower() for e in errors2))
        self.assertEqual(run.classify_parity_status(manifest2), "failed_or_incomplete")

    def test_missing_or_mismatched_hashes_and_fixture_identity_fail(self):
        manifest = self._valid_manifest()
        manifest["architectures"]["riscv64"]["kernel_sha256"] = ""
        errors = run.validate_parity_manifest(manifest)
        self.assertTrue(any("kernel_sha256" in e for e in errors))
        self.assertEqual(run.classify_parity_status(manifest), "failed_or_incomplete")

        manifest2 = self._valid_manifest()
        manifest2["architectures"]["loongarch64"]["fixture_sha256"] = "0" * 64
        errors2 = run.validate_parity_manifest(manifest2)
        self.assertTrue(any("fixture" in e.lower() for e in errors2))
        self.assertEqual(run.classify_parity_status(manifest2), "failed_or_incomplete")

    def test_nonzero_loss_counter_prevents_parity_claim(self):
        for counter_key in ("lost_records", "ringbuf_lost", "re_entry_drops", "helper_failures", "consumer_corrupt_records"):
            manifest = self._valid_manifest()
            manifest["architectures"]["riscv64"]["loss_counters"][counter_key] = 1
            errors = run.validate_parity_manifest(manifest)
            self.assertTrue(any(counter_key in e for e in errors), f"expected {counter_key} error in {errors}")
            self.assertEqual(run.classify_parity_status(manifest), "failed_or_incomplete")

    def test_missing_analyzer_outputs_fail_manifest(self):
        for out_key in ("loss_report", "event_table", "json_summary", "oncpu_folded", "offcpu_folded"):
            manifest = self._valid_manifest()
            manifest["architectures"]["loongarch64"]["analyzer_outputs"][out_key] = ""
            errors = run.validate_parity_manifest(manifest)
            self.assertTrue(any(out_key in e for e in errors), f"expected {out_key} error in {errors}")
            self.assertEqual(run.classify_parity_status(manifest), "failed_or_incomplete")

    def test_static_only_evidence_classified_as_development_baseline(self):
        manifest = self._valid_manifest()
        manifest["execution_mode"] = "static_only"
        self.assertEqual(run.classify_parity_status(manifest), "development_baseline")


class Seam5ThreeStateAndAttributionTests(unittest.TestCase):
    def test_parse_state_metrics_and_compute_overhead(self):
        log_text = "\n".join([
            "BPF_STATE_REPORT state=baseline status=PASS wall_time_ns=1000000 workload_iters=400 memory_bytes=16384 samples=0 events=0 lost=0",
            "BPF_STATE_REPORT state=loaded_detached status=PASS wall_time_ns=1100000 workload_iters=400 memory_bytes=24576 samples=0 events=0 lost=0",
            "BPF_STATE_REPORT state=attached_capture status=PASS wall_time_ns=1500000 workload_iters=400 memory_bytes=45056 samples=1 events=5 lost=0",
        ])
        states = run.parse_state_metrics(log_text)
        self.assertEqual(set(states.keys()), {"baseline", "loaded_detached", "attached_capture"})
        self.assertEqual(states["baseline"]["wall_time_ns"], 1_000_000)
        self.assertEqual(states["attached_capture"]["events"], 5)
        self.assertGreater(states["attached_capture"]["event_throughput_per_sec"], 0.0)

        overhead = run.compute_state_overhead(states)
        self.assertEqual(overhead["loaded_detached_vs_baseline_ns"], 100_000)
        self.assertEqual(overhead["attached_capture_vs_baseline_ns"], 500_000)
        self.assertAlmostEqual(overhead["loaded_detached_ratio"], 1.10)
        self.assertAlmostEqual(overhead["attached_capture_ratio"], 1.50)
        self.assertEqual(overhead["memory_delta_loaded_detached_bytes"], 8192)
        self.assertEqual(overhead["memory_delta_attached_capture_bytes"], 28672)

    def test_guest_sampler_source_emits_all_three_states_and_semantic_events(self):
        source_text = run.RAW_SOURCE.read_text()
        for st in ("baseline", "loaded_detached", "attached_capture"):
            self.assertIn(f"BPF_STATE_REPORT state={st}", source_text)
        # Verify task_metadata (1), sched_switch (2), task_block (3), task_wake (4), perf_sample (0x1000)
        self.assertIn("guest_sampler", source_text)
        self.assertIn("0x1000u32", source_text)

    def test_compare_dual_arch_attribution_checks_mechanism_and_detects_mismatch(self):
        manifest = run.sample_valid_parity_manifest()
        rv = manifest["architectures"]["riscv64"]
        la = manifest["architectures"]["loongarch64"]
        comparison = run.compare_dual_arch_attribution(rv, la)
        self.assertTrue(comparison["both_complete"])
        self.assertTrue(comparison["zero_loss_both"])
        self.assertTrue(comparison["attribution_consistent"])
        self.assertEqual(comparison["comparison_mode"], "mechanism_level_cross_check")
        self.assertFalse(comparison["raw_sample_equality_required"])

        # Corrupt loongarch64 loss counter -> zero_loss_both must become False
        la_bad = dict(la)
        la_bad["loss_counters"] = {**la["loss_counters"], "lost_records": 2}
        comp_bad = run.compare_dual_arch_attribution(rv, la_bad)
        self.assertFalse(comp_bad["zero_loss_both"])
        self.assertFalse(comp_bad["attribution_consistent"])


class Seam6ParityOrchestrationTests(unittest.TestCase):
    def test_parity_parser_registers_parity_subcommand(self):
        parser = run.build_parser()
        args = parser.parse_args(["parity", "--arch", "riscv64"])
        self.assertEqual(args.command, "parity")
        self.assertEqual(args.arch, "riscv64")

    def test_qperf_target_preserved_in_makefile(self):
        makefile = run.REPO / "Makefile"
        self.assertTrue(makefile.is_file())
        text = makefile.read_text()
        self.assertIn("qperf:", text)
        self.assertIn("kernel-rv-qperf", text)
        self.assertIn("kernel-la-qperf", text)
        self.assertIn("__pulse_qperf_trace_v1", text)

    def test_generate_parity_package_creates_retained_artifacts_and_manifest(self):
        with tempfile.TemporaryDirectory(prefix="parity-pkg-", dir=run.BASE) as tmp_dir:
            pkg_dir = Path(tmp_dir) / "pkg"
            pkg_dir.mkdir()
            manifest = run.sample_valid_parity_manifest()
            manifest_path, report_path = run.write_parity_package(manifest, pkg_dir)
            self.assertTrue(manifest_path.is_file())
            self.assertTrue(report_path.is_file())

            report_text = report_path.read_text()
            self.assertIn("PARITY STATUS: parity_candidate", report_text)
            self.assertIn("mechanism_level_cross_check", report_text)
            self.assertIn("qperf baseline retained: True", report_text)
            self.assertNotIn("replacement", report_text)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)



