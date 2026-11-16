"""Public host evidence gate: plausible totals cannot replace source binding."""
import hashlib
import unittest
from run import validate_report, verify_saved_hash, stack_proof


class RecorderEvidenceTests(unittest.TestCase):
    def test_same_type_instances_need_actual_records_for_both(self):
        report = {"records_count": 6, "recorder": {"sources": [
            {"logical_source": 1, "kind": "software-v2", "event_id": 65537, "cpu": 0, "tid": None, "records_count": 2},
            {"logical_source": 2, "kind": "software-v2", "event_id": 65537, "cpu": 0, "tid": None, "records_count": 2},
            {"logical_source": 3, "kind": "tracepoint", "event_id": 6, "cpu": 0, "tid": None, "records_count": 1},
            {"logical_source": 4, "kind": "tracepoint", "event_id": 8, "cpu": 0, "tid": None, "records_count": 1},
        ], "record_sources": [1, 1, 2, 2, 3, 4]}}
        self.assertEqual(validate_report("mixed", report), [])
        for source in report["recorder"]["sources"][:2]:
            source["kind"] = "software-stack-v3"
        self.assertEqual(validate_report("mixed", report), [])
        report["recorder"]["sources"][1]["records_count"] = 0
        self.assertTrue(validate_report("mixed", report))

    def test_missing_bindings_or_zero_records_are_not_runtime_evidence(self):
        self.assertTrue(validate_report("cpu", {"records_count": 10, "recorder": None}))
        self.assertTrue(validate_report("cpu", {"records_count": 0, "recorder": {"sources": [], "record_sources": []}}))

    def test_requested_rate_comes_from_typed_source_not_diagnostic_prose(self):
        report = {"records_count": 1, "recorder": {"record_sources": [1], "sources": [
            {"logical_source": 1, "kind": "software-v2", "event_id": 4097,
             "cpu": None, "tid": 42, "records_count": 1},
        ]}, "runtime_diagnostics": {"identities": [{"name": "recorder_config", "value":
            "requested_frequency=99 effective_period_ns=10101011 frequency_conversion=ceil_ns fallback=none"}]}}
        self.assertTrue(validate_report("existing-shell", report))
        report["recorder"]["sources"][0].update(
            requested_frequency_hz=99, requested_sample_period=0, period=10101011,
            config="task-clock", requested_config="task-clock", unit="nanoseconds", fallback="none")
        report["runtime_diagnostics"]["identities"] = []
        self.assertEqual(validate_report("existing-shell", report), [])

    def test_guest_sync_witness_must_match_the_collected_file_sha(self):
        original = b"actual synced guest file"
        digest = hashlib.sha256(original).hexdigest()
        case = {"log": f"RECORD SAVED output=sample bytes={len(original)} sha256={digest}\n"}
        self.assertEqual(verify_saved_hash(case, original), digest)
        with self.assertRaises(ValueError):
            verify_saved_hash(case, original + b"host replacement")
        with self.assertRaises(ValueError):
            verify_saved_hash({"log": case["log"] * 2}, original)

    def test_stack_gate_rejects_a_single_ip_claim_and_late_initial_snapshot(self):
        event = {"event_id": 0x1002, "semantic": {"mode": 2, "chain_len": 1, "ips": [4096], "termination": "complete"}}
        report = {"recorder": {"sources": [{"enable_before_ns": 100, "disable_after_ns": 200}]},
                  "runtime_diagnostics": {"counters": [{"name": "mapping_initial_snapshot_ns", "value": 50}]}}
        collection = {"artifacts": [{"sha256": "a" * 64, "status": "verified"}], "captured_manifest": {
            "mapping_metadata": True, "coverage": {"started_ns": 0, "snapshot_ns": 300, "dropped": 0},
            "kernel": {"sha256": "a" * 64}}}
        with self.assertRaisesRegex(ValueError, "three frames"):
            stack_proof({"events": [event]}, report, collection, require_depth=True)
        event["semantic"].update(chain_len=3, ips=[4096, 8192, 12288])
        self.assertEqual(stack_proof({"events": [event]}, report, collection, require_depth=True)["max_user_depth"], 3)
        report["runtime_diagnostics"]["counters"][0]["value"] = 101
        with self.assertRaisesRegex(ValueError, "before enable"):
            stack_proof({"events": [event]}, report, collection, require_depth=True)


if __name__ == "__main__":
    unittest.main()
