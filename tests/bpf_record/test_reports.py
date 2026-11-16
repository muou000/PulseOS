"""Public host evidence gate: plausible totals cannot replace source binding."""
import unittest
from run import validate_report


class RecorderEvidenceTests(unittest.TestCase):
    def test_same_type_instances_need_actual_records_for_both(self):
        report = {"records_count": 6, "recorder": {"sources": [
            {"logical_source": 1, "kind": "software-v2", "event_id": 65537, "cpu": 0, "tid": None, "records_count": 2},
            {"logical_source": 2, "kind": "software-v2", "event_id": 65537, "cpu": 0, "tid": None, "records_count": 2},
            {"logical_source": 3, "kind": "tracepoint", "event_id": 6, "cpu": 0, "tid": None, "records_count": 1},
            {"logical_source": 4, "kind": "tracepoint", "event_id": 8, "cpu": 0, "tid": None, "records_count": 1},
        ], "record_sources": [1, 1, 2, 2, 3, 4]}}
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


if __name__ == "__main__":
    unittest.main()
