#!/usr/bin/env python3
"""Exercise the actual Rust importer/analyzer with synthetic RAW test fixtures.

These are format/integrity regressions, never QEMU or performance evidence.
Run: python3 tests/bpf_sampling/test_runtime_import.py
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import zlib

import archive
from test_archive import fixture, sample_frame

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

    def test_importer_requires_explicit_record_source_binding(self):
        # Missing typed logical provenance must never be recovered from the
        # single task, CPU, sample period or diagnostic identity strings.
        for source in self.metadata["sources"]:
            source.pop("logical_id", None)
        self.assert_rejected("logical_id")

    def test_unknown_stamped_id_is_not_recovered_from_matching_task_and_period(self):
        raw = bytearray(self.raw)
        frame = 64 + 24
        struct.pack_into("<I", raw, frame + 24, 99)
        size = struct.unpack_from("<H", raw, frame + 6)[0]
        struct.pack_into("<I", raw, 64 + 16, zlib.crc32(raw[frame:frame + size]))
        self.reseal_raw(raw)
        (self.directory / "records.pbraw").write_bytes(raw)
        self.assert_rejected("undeclared recorder source")

    def test_typed_source_control_window_cannot_exclude_retained_samples(self):
        self.metadata["sources"][0].update(disable_before=150, disable_after=160)
        self.assert_rejected("outside source control window")

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

    def seed_stack(self):
        from test_stack_archive import stack_fixture
        self.raw, self.metadata, _ = archive.extract(stack_fixture(), "task")
        self.inputs["context_format"] = "software-stack-v3"
        (self.directory / "records.pbraw").write_bytes(self.raw)

    def alter_stack(self, offset, format, value):
        # Reseal transport CRCs to exercise the Rust importer's independent
        # native/source validation, bypassing the Python extraction checks.
        raw = bytearray(self.raw)
        frame = 64 + 24
        struct.pack_into(format, raw, frame + 36 + offset, value)
        struct.pack_into("<I", raw, 64 + 16, zlib.crc32(raw[frame:frame + 680]))
        self.reseal_raw(raw)
        (self.directory / "records.pbraw").write_bytes(raw)

    def test_stack_v3_preserves_chain_source_and_explicit_partial_reason(self):
        self.seed_stack()
        self.assert_imported()
        data = self.output.read_bytes()
        self.assertEqual(struct.unpack_from("<I", data, 8)[0], 6)
        summary = self.summary()
        sample = summary["stack_samples"][0]["sample"]
        self.assertEqual(sample["source_id"], 13)
        self.assertEqual(sample["ips"], [0x400110, 0x400100, 0x400080])
        self.assertEqual(sample["termination"], "read_fault")
        self.assertEqual(sample["stack_status"], "partial")
        self.assertEqual(sample["sample_period"], 10)
        counters = {(c["scope"], c["name"]): c["value"]
                    for c in summary["runtime_diagnostics"]["counters"]}
        self.assertEqual(counters[("source/13", "recorded_stack_samples")], 1)
        folded = self.directory / "stack.folded"
        result = self.analyzer("--oncpu", str(folded))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("[partial:read_fault];pc:0x400080;pc:0x400100;pc:0x400110 1", folded.read_text())

    def test_stack_importer_independently_rejects_source_period_and_required_extension(self):
        for offset, format, value, error in [
            (64, "<Q", 999, "source instance not declared"),
            (0, "<Q", 99, "scope/period mismatch"),
            (104, "<H", 4, "invalid software stack native context"),
            (120, "<Q", 1, "invalid software stack native context"),
        ]:
            with self.subTest(offset=offset):
                self.seed_stack()
                self.alter_stack(offset, format, value)
                self.assert_rejected(error)

    def seed_stack_cpu_instances(self, duplicate=False):
        self.seed_stack()
        self.inputs["mode"] = "cpu"
        self.metadata["mode"] = "cpu"
        self.metadata["config"]["mode"] = "cpu"
        prototype = copy.deepcopy(self.metadata["sources"][0])
        self.metadata["sources"] = []
        for point in ("before", "after"):
            snapshot = self.metadata["snapshots"][point]
            source = snapshot["events"].pop(14)
            for index in range(16):
                event = copy.deepcopy(source)
                count = int(point == "after" and index < 2)
                event.update(fd=100+index, id=100+index, clock=0, config=0,
                             scope="cpu", target=index//2, task_id=0,
                             observed=count, delivered=count)
                snapshot["events"][100+index] = event
                if point == "before":
                    row = copy.deepcopy(prototype)
                    row.update(fd=100+index, event_id=100+index, logical_id=index+1, scope=1, target=index//2, bound_task_id=0, config=1, requested_config=1, link_id=200+index)
                    self.metadata["sources"].append(row)
            snapshot["programs"][5]["runs"] = 2 if point == "after" else 0
            for cpu in range(8):
                snapshot["events"][5+cpu]["delivered"] = 2 if point == "after" and cpu == 0 else 0
            snapshot["global"].update(timer_enqueued=2 if point == "after" else 0,
                                      timer_dequeued=2 if point == "after" else 0)
        stream = bytearray()
        for index in range(2):
            context = bytearray(self.raw[124:764])
            struct.pack_into("<I", context, 24, 0)
            struct.pack_into("<Q", context, 64, 100 if duplicate else 100+index)
            frame = sample_frame(1 if duplicate else index+1, 3, context)
            stream.extend(struct.pack("<QIIII", index, 0, len(frame), zlib.crc32(frame), 0) + frame)
        raw = bytearray(self.raw[:64]) + stream
        struct.pack_into("<Q", raw, 24, 2)
        self.reseal_raw(raw)
        self.metadata.update(frames=2, samples=2)
        (self.directory / "records.pbraw").write_bytes(raw)

    def test_same_cpu_same_period_instances_reconcile_independently(self):
        self.seed_stack_cpu_instances()
        self.assert_imported()
        report = self.summary()
        self.assertEqual([row["sample"]["source_id"] for row in report["stack_samples"]], [100, 101])
        counters = {(c["scope"], c["name"]): c["value"]
                    for c in report["runtime_diagnostics"]["counters"]}
        for source in (100, 101):
            self.assertEqual(counters[(f"source/{source}", "recorded_stack_samples")], 1)
        self.output.unlink()
        self.seed_stack_cpu_instances(duplicate=True)
        self.assert_rejected("per-source stack sample count does not reconcile")

    def test_stack_source_snapshot_identity_and_declaration_cannot_drift(self):
        self.seed_stack()
        self.metadata["sources"][0]["event_id"] = 999
        self.assert_rejected("declared source instance")
        self.seed_stack()
        self.metadata["snapshots"]["after"]["events"][14]["id"] = 999
        self.assert_rejected("event identity changed")

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

    def test_fault_import_preserves_known_classes_without_recounting_system_totals(self):
        from test_fault_archive import fixture_fault

        def classify(context):
            # Synthetic protocol evidence: one known minor and one known major.
            access = struct.unpack_from("<I", context, 64)[0]
            struct.pack_into("<I", context, 76, 1 if access == 1 else 2)

        raw, self.metadata, _ = archive.extract(fixture_fault(change_context=classify), "fault")
        self.inputs["mode"] = "fault"
        (self.directory / "records.pbraw").write_bytes(raw)
        self.assert_imported()
        result = self.analyzer("--fault-report", "--json")
        self.assertEqual(result.returncode, 0, result.stdout)
        report = json.loads(result.stdout)["faults"]
        self.assertEqual(report["valid_events"], 2)
        self.assertEqual(report["resolved_minor"], 1)
        self.assertEqual(report["resolved_major"], 1)
        self.assertEqual(report["resolved_unknown"], 0)
        self.assertEqual(report["unsuccessful"], 0)
        counters = {(row["scope"], row["name"]): row["value"]
                    for row in self.summary()["runtime_diagnostics"]["counters"]}
        self.assertEqual(counters[("system", "fault_completed")], 2)
        self.assertEqual(counters[("fault_workload", "read_hits")], 1)
        self.assertEqual(counters[("fault_workload", "write_hits")], 1)

    def test_fault_import_rejects_invalid_class_pairs_after_resealed_envelopes(self):
        for outcome, classification in [(1, 3), (1, 0xffffffff), (2, 1), (3, 2), (4, 1)]:
            with self.subTest(outcome=outcome, classification=classification):
                self.seed_fault()
                raw = bytearray(self.raw)
                frame_start = 64 + 24
                struct.pack_into("<II", raw, frame_start + 36 + 72, outcome, classification)
                struct.pack_into("<I", raw, 64 + 16,
                                 zlib.crc32(raw[frame_start:frame_start + 120]))
                self.reseal_raw(raw)
                (self.directory / "records.pbraw").write_bytes(raw)
                self.assert_rejected("fault completion")

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
        self.assert_rejected("typed source differs")

    def test_fault_import_rejects_timing_corruption_even_with_resealed_envelopes(self):
        self.seed_fault()
        raw=bytearray(self.raw)
        frame_start=64+24
        struct.pack_into("<Q",raw,frame_start+36+56,11)
        struct.pack_into("<I",raw,64+16,zlib.crc32(raw[frame_start:frame_start+120]))
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
        self.assertEqual(struct.unpack_from("<I", data, 8)[0], 6)
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
