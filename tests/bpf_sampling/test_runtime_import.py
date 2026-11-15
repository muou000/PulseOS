#!/usr/bin/env python3
"""Exercise the actual Rust importer/analyzer with synthetic RAW test fixtures.

These are format/integrity regressions, never QEMU or performance evidence.
Run: python3 tests/bpf_sampling/test_runtime_import.py
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import zlib

import archive
from test_archive import fixture

REPO = Path(__file__).resolve().parents[2]
IMPORTER = REPO / "target/debug/examples/runtime_import"
ANALYZER = REPO / "target/debug/bpf-analyzer"


class RuntimeImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Build once and run the resulting executables for every case. No mock
        # parser or stale release binary is allowed to validate the conversion.
        result = subprocess.run([
            "cargo", "build", "-p", "bpf-capture", "-p", "bpf-analyzer",
            "--example", "runtime_import", "--bin", "bpf-analyzer",
        ], cwd=REPO, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        if result.returncode:
            raise RuntimeError("cannot build importer/analyzer:\n" + result.stdout[-6000:])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="bpf-import-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.output = self.directory / "capture.pbcapture"
        self.seed()

    def seed(self, sample_count=1):
        raw, metadata, snapshots = archive.extract(fixture(sample_count), "task")
        self.raw = raw
        self.metadata = metadata
        (self.directory / "records.pbraw").write_bytes(raw)
        for point, snapshot in snapshots.items():
            (self.directory / f"stats-{point}.txt").write_bytes(snapshot)
        # These identities hash actual synthetic fixture bytes. They are not
        # purported PulseOS builds; the input label and unknown source commit
        # survive into the standalone capture's diagnostics.
        artifacts = {}
        for name in ("kernel.elf", "image", "payload"):
            path = self.directory / name
            path.write_bytes(f"synthetic importer test artifact: {name}\n".encode())
            artifacts[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.inputs = {
            "kind": "synthetic format fixture; no guest execution or runtime evidence",
            "arch": "riscv64", "mode": "task", "kernel_source_commit": None,
            "kernel_elf_path": str(self.directory / "kernel.elf"),
            "image": str(self.directory / "image"),
            "kernel_sha256": artifacts["kernel.elf"],
            "kernel_elf_sha256": artifacts["kernel.elf"],
            "boot_image_sha256": artifacts["image"],
            "payload_sha256": artifacts["payload"],
            # The test's boot/symbol identity is the same fixture byte sequence;
            # neither file is claimed to be a bootable or parsed ELF artifact.
            "kernel_elf_matches_boot": True,
        }

    def test_mixed_scheduler_capture_preserves_records_and_programs(self):
        from test_sched_archive import fixture_sched
        raw, self.metadata, _ = archive.extract(fixture_sched(), 'sched')
        self.inputs['mode'] = 'sched'
        (self.directory / 'records.pbraw').write_bytes(raw)
        self.assert_imported()
        result = self.analyzer('--json')
        self.assertEqual(result.returncode, 0, result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report['records_count'], 5)
        self.assertEqual(report['event_counts']['sched_switch'], 2)
        self.assertEqual(report['event_counts']['task_wake'], 1)
        self.assertFalse(report['attribution_claim_allowed'])

    def seed_fault(self):
        from test_fault_archive import fixture_fault
        raw, self.metadata, _ = archive.extract(fixture_fault(), "fault")
        self.raw = raw
        self.inputs["mode"] = "fault"
        (self.directory / "records.pbraw").write_bytes(raw)

    def test_fault_capture_keeps_workload_witness_and_unknown_classification(self):
        self.seed_fault()
        self.assert_imported()
        summary=self.summary()
        self.assertEqual(summary["records_count"],2)
        self.assertEqual(summary["event_counts"]["page_fault"],2)
        self.assertFalse(summary["is_complete"])
        diagnostics=summary["runtime_diagnostics"]
        counters={(row["scope"],row["name"]):row["value"] for row in diagnostics["counters"]}
        self.assertEqual(counters[("system","fault_completed")],2)
        self.assertEqual(counters[("fault_workload","read_hits")],1)
        self.assertEqual(counters[("fault_workload","write_hits")],1)
        identities={row["name"]:row["value"] for row in diagnostics["identities"]}
        self.assertEqual(identities["fault_target/127/read_address"],"0x400000")
        self.assertEqual(identities["fault_target/127/write_address"],"0x402000")
        report=self.analyzer("--fault-report","--json")
        self.assertEqual(report.returncode,0,report.stdout)
        parsed=json.loads(report.stdout)["faults"]
        self.assertEqual(parsed["valid_events"],2)
        self.assertEqual(parsed["unknown_classification"],2)
        self.assertEqual(parsed["duration"]["sum_ns"],20)
        self.assertFalse(parsed["is_complete"])

    def test_fault_import_independently_requires_observer_counters_and_complete_target_list(self):
        self.seed_fault()
        del self.metadata["snapshots"]["after"]["global"]["fault_completed"]
        self.assert_rejected("mandatory fault diagnostics")
        self.seed_fault()
        self.metadata["fault_targets"].pop()
        self.assert_rejected("fault targets")

    def test_fault_unknown_access_round_trips_to_explicit_report_counter(self):
        from test_fault_archive import fixture_fault
        raw,self.metadata,_=archive.extract(fixture_fault(unknown_access=True),'fault')
        self.inputs['mode']='fault'
        (self.directory/'records.pbraw').write_bytes(raw)
        self.assert_imported()
        result=self.analyzer('--fault-report','--json')
        self.assertEqual(result.returncode,0,result.stdout)
        report=json.loads(result.stdout)['faults']
        self.assertEqual(report['valid_events'],3)
        self.assertEqual(report['unknown_access'],1)
        self.assertEqual(report['unknown_classification'],3)
        self.assertFalse(report['is_complete'])

    def test_fault_archive_driver_saves_loss_and_semantic_reports(self):
        import capture as driver
        self.seed_fault()
        (self.directory/'kernel').write_bytes((self.directory/'kernel.elf').read_bytes())
        (self.directory/'disk.img').write_bytes((self.directory/'image').read_bytes())
        (self.directory/'inputs.json').write_text(json.dumps(self.inputs))
        (self.directory/'archive.json').write_text(json.dumps(self.metadata))
        result=driver.convert(self.directory)
        self.assertEqual(result['semantic_report']['valid_instances'],2)
        self.assertIn('Status:',(self.directory/'analyzer-loss.txt').read_text())
        report=json.loads((self.directory/'faults-report.json').read_text())
        self.assertEqual(report['faults']['valid_events'],2)

    def test_fault_import_rechecks_hit_counts_and_eight_cpu_sources(self):
        self.seed_fault()
        self.metadata["fault_workload"]["read_hits"]=0
        self.assert_rejected("fault workload hits")
        self.seed_fault()
        for point in ("before","after"):
            self.metadata["snapshots"][point]["events"][20]["config"]=2
        self.assert_rejected("fault source")

    def test_fault_import_rejects_timing_corruption_even_with_resealed_envelopes(self):
        self.seed_fault()
        raw=bytearray(self.raw)
        frame_start=64+24
        struct.pack_into("<Q",raw,frame_start+12+56,11)
        struct.pack_into("<I",raw,64+16,zlib.crc32(raw[frame_start:frame_start+96]))
        self.reseal_raw(raw)
        (self.directory/"records.pbraw").write_bytes(raw)
        self.assert_rejected("fault completion")

    def test_fault_workload_does_not_guess_hits_after_export_overflow(self):
        self.seed_fault()
        raw=bytearray(self.raw);struct.pack_into("<I",raw,44,1)
        (self.directory/"records.pbraw").write_bytes(raw)
        self.metadata.update(export_dropped=1,export_dropped_samples=1)
        self.assert_rejected("untruncated fault export")

    def import_capture(self):
        (self.directory / "inputs.json").write_text(json.dumps(self.inputs))
        (self.directory / "archive.json").write_text(json.dumps(self.metadata))
        return subprocess.run([str(IMPORTER), str(self.directory), str(self.output)],
                              cwd=REPO, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=20)

    def analyzer(self, *options, path=None):
        return subprocess.run([str(ANALYZER), str(path or self.output), *options],
                              cwd=REPO, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=20)

    def assert_imported(self):
        result = self.import_capture()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(self.output.is_file())
        return result

    def assert_rejected(self, expected=None):
        result = self.import_capture()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("runtime import rejected:", result.stdout)
        self.assertNotIn("panicked", result.stdout.lower())
        if expected:
            self.assertIn(expected, result.stdout)
        self.assertFalse(self.output.exists(), "rejected data must not create a capture")

    def summary(self):
        result = self.analyzer("--json")
        self.assertEqual(result.returncode, 0, result.stdout)
        return json.loads(result.stdout)

    def reseal_raw(self, raw):
        """Recompute only outer framing to reach inner RAW validation paths."""
        struct.pack_into("<Q", raw, 32, len(raw) - 64)
        struct.pack_into("<I", raw, 40, zlib.crc32(raw[64:]))
        return raw

    def test_conversion_preserves_each_input_pc_time_identity_and_record_count(self):
        self.seed(sample_count=3)
        self.assert_imported()
        summary = self.summary()
        self.assertEqual(summary["records_count"], 3)
        self.assertEqual(summary["consumer_projection"]["delivered"], 3)
        data = self.output.read_bytes()
        self.assertEqual(data[:8], b"PBCAP001")
        self.assertEqual(struct.unpack_from("<I", data, 8)[0], 2)
        position, count = struct.unpack_from("<QQ", data, 40)
        self.assertEqual(count, 3)
        for index in range(3):
            event, version, timestamp, cpu, pid, tid, reserved, task, size, pad = struct.unpack_from("<IIQIIIIQII", data, position)
            self.assertEqual((event, version, timestamp, cpu, pid, tid, task, size),
                             (0x1001, 2, 200+index, 3, 40, 41, 99, 32))
            self.assertEqual((reserved, pad), (0, 0))
            period, address, pc, mode, reserved = struct.unpack_from("<QQQII", data, position+48)
            self.assertEqual((period, address, pc, mode, reserved), (10, 0, 0x400110+index*4, 2, 0))
            position += 48+size
        table = self.analyzer("--table")
        self.assertEqual(table.returncode, 0, table.stdout)
        self.assertEqual(table.stdout.count("perf_sample_v2"), 3)
        for pc in ("400110", "400114", "400118"):
            self.assertIn(pc, table.stdout)

    def test_unknown_runtime_evidence_stays_unknown_and_partial(self):
        self.assert_imported()
        summary = self.summary()
        self.assertFalse(summary["is_complete"])
        self.assertFalse(summary["attribution_claim_allowed"])
        self.assertNotEqual(summary["status"], "Complete")
        self.assertEqual(summary["pulse_commit"], "unknown")
        self.assertIsNone(summary["loss_counters"])
        diagnostics = summary["runtime_diagnostics"]
        identities = {row["name"]: row["value"] for row in diagnostics["identities"]}
        self.assertIsNone(identities["kernel_source_commit"])
        self.assertIsNone(identities["clock_resolution_ns"])
        counters = {(row["scope"], row["name"]): row["value"] for row in diagnostics["counters"]}
        self.assertIsNone(counters[("unavailable", "process_rss_bytes")])
        self.assertIsNone(counters[("unavailable", "verifier_failures")])
        report = self.analyzer("--loss")
        self.assertEqual(report.returncode, 0, report.stdout)
        self.assertIn("PARTIAL:", report.stdout)
        self.assertIn("Attribution Claim: Disallowed", report.stdout)
        self.assertNotIn("INTEGRITY CHECK PASSED", report.stdout)
        self.assertEqual(len(diagnostics["phases"]), 3)

    def test_zero_program_execution_cannot_support_a_delivered_record(self):
        self.metadata["snapshots"]["after"]["programs"][5]["runs"] = 0
        self.assert_rejected("program counters do not reconcile")

    def test_counter_sum_overflow_is_a_clean_rejection(self):
        for fd in (5, 6):
            self.metadata["snapshots"]["after"]["events"][fd]["delivered"] = (1 << 64)-1
        self.assert_rejected("counter sum overflow")

    def test_counter_regression_is_rejected(self):
        self.metadata["snapshots"]["before"]["events"][14]["delivered"] = 2
        self.assert_rejected("counter regressed")

    def test_missing_raw_archive_is_rejected(self):
        (self.directory / "records.pbraw").unlink()
        self.assert_rejected()

    def test_empty_truncated_corrupt_or_malformed_raw_archives_are_rejected(self):
        bad_crc = bytearray(self.raw)
        bad_crc[-1] ^= 1
        bad_frame_crc = self.reseal_raw(bytearray(bad_crc))
        zero_length = bytearray(self.raw)
        struct.pack_into("<I", zero_length, 64+12, 0)
        zero_length = self.reseal_raw(zero_length)
        wrong_cpu = bytearray(self.raw)
        struct.pack_into("<I", wrong_cpu, 64+8, 2)  # context retains CPU 3
        wrong_cpu = self.reseal_raw(wrong_cpu)
        variants = {"empty": b"", "header": self.raw[:63], "truncated": self.raw[:-1],
                    "stream_crc": bad_crc, "frame_crc": bad_frame_crc,
                    "zero_frame_length": zero_length, "wrong_cpu": wrong_cpu}
        for name, raw in variants.items():
            with self.subTest(name=name):
                (self.directory / "records.pbraw").write_bytes(raw)
                self.assert_rejected()

    def test_zero_consumed_records_are_rejected(self):
        raw = struct.pack("<8sQQQQII16x", b"PBRW0001", 100, 300, 0, 0, 0, 0)
        (self.directory / "records.pbraw").write_bytes(raw)
        self.metadata.update(frames=0, samples=0)
        self.assert_rejected("empty, truncated or corrupt RAW archive")

    def test_export_overflow_preserves_available_records_but_blocks_completeness(self):
        # Three delivered records, one exported and two explicitly dropped.
        for group, key in (("events", 14), ("events", 8)):
            self.metadata["snapshots"]["after"][group][key]["delivered"] = 3
        self.metadata["snapshots"]["after"]["programs"][5]["runs"] = 3
        self.metadata["snapshots"]["after"]["events"][14]["observed"] = 3
        for key in ("timer_enqueued", "timer_dequeued"):
            self.metadata["snapshots"]["after"]["global"][key] = 3
        self.metadata.update(export_dropped=2, export_dropped_samples=2, export_dropped_notices=0)
        raw = bytearray(self.raw)
        struct.pack_into("<I", raw, 44, 2)
        (self.directory / "records.pbraw").write_bytes(raw)
        self.assert_imported()
        summary = self.summary()
        self.assertEqual(summary["records_count"], 1)
        self.assertFalse(summary["is_complete"])
        counters = {(row["scope"], row["name"]): row["value"]
                    for row in summary["runtime_diagnostics"]["counters"]}
        self.assertEqual(counters[("export", "dropped_records")], 2)
        self.assertEqual(counters[("export", "dropped_samples")], 2)

    def test_consumer_error_is_retained_as_scoped_error(self):
        self.metadata["snapshots"]["after"]["events"][8]["consumer_corrupt"] = 1
        self.assert_imported()
        summary = self.summary()
        self.assertFalse(summary["is_complete"])
        errors = [row for row in summary["runtime_diagnostics"]["counters"]
                  if row["scope"] == "event/8" and row["name"] == "consumer_corrupt"]
        self.assertEqual(errors, [{"scope":"event/8", "name":"consumer_corrupt", "kind":"error", "value":1}])

    def test_truncated_capture_cannot_be_analyzed_as_complete(self):
        self.assert_imported()
        data = self.output.read_bytes()
        for removed in (1, 40, len(data)-79):
            with self.subTest(removed=removed):
                bad = self.directory / f"truncated-{removed}.pbcapture"
                bad.write_bytes(data[:-removed])
                result = self.analyzer("--json", path=bad)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("failed to parse bpf capture:", result.stdout.lower())
                self.assertNotIn('"is_complete": true', result.stdout)
                self.assertNotIn("panicked", result.stdout.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
