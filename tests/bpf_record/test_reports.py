"""Public host evidence gate: plausible totals cannot replace source binding."""
import hashlib
import unittest
from run import validate_report, verify_saved_hash, stack_proof, mapping_lifecycle_proof


class RecorderEvidenceTests(unittest.TestCase):
    def test_mapping_oracle_uses_post_exec_address_space_at_each_marker(self):
        journal = """PULSE_BPF_MAPPINGS version=2 available=1 started_ns=0 snapshot_ns=100 dropped=0 records=10
TASK seq=1 ts=1 task=10 pid=5 tid=5 space=9 exec=0 kind=fork parent=1 class=user comm_hex=7368
TASK seq=2 ts=10 task=10 pid=5 tid=5 space=13 exec=1 kind=exec parent=1 class=user comm_hex=66697874757265
SPACE seq=3 ts=20 begin_ns=19 space=13 revision=1 count=1
MAP start=4096 len=8192 pgoff=4096 perms=5 object=7
ENDSPACE
TASK seq=4 ts=30 task=10 pid=5 tid=5 space=13 exec=1 kind=rename parent=1 class=user comm_hex=6e6577
TASK seq=5 ts=35 task=11 pid=6 tid=6 space=14 exec=0 kind=fork parent=10 class=user comm_hex=6e6577
TASK seq=6 ts=36 task=11 pid=6 tid=6 space=15 exec=1 kind=exec parent=10 class=user comm_hex=6368696c64
TASK seq=7 ts=37 task=11 pid=6 tid=6 space=15 exec=1 kind=exit parent=10 class=user comm_hex=6368696c64
SPACE seq=8 ts=40 begin_ns=39 space=13 revision=2 count=1
MAP start=32768 len=8192 pgoff=4096 perms=5 object=7
ENDSPACE
SPACE seq=9 ts=50 begin_ns=49 space=13 revision=3 count=1
MAP start=4096 len=8192 pgoff=0 perms=3 object=0
ENDSPACE
TASK seq=10 ts=60 task=10 pid=5 tid=5 space=13 exec=1 kind=exit parent=1 class=user comm_hex=6e6577
END records=10 dropped=0 snapshot_ns=100
"""
        text = """MAPPING STEP phase=mapped pid=5 base=4096 len=8192 pgoff=4096 at_ns=25
MAPPING STEP phase=renamed pid=5 base=4096 at_ns=32
MAPPING STEP phase=remapped pid=5 old=4096 base=32768 len=8192 pgoff=4096 at_ns=45
MAPPING STEP phase=reused_address pid=5 base=4096 len=8192 at_ns=55
MAPPING COMPLETE pid=5 child=6 old=4096 moved=32768 at_ns=61
"""
        result = mapping_lifecycle_proof(text, {"journal": journal, "coverage": {"dropped": 0}})
        self.assertEqual(result["mapped_object"], "7")
        self.assertEqual(result["byte_pgoff"], 4096)

    def test_same_type_instances_need_actual_records_for_both(self):
        report = {"records_count": 7, "recorder": {"sources": [
            {"logical_source": 1, "kind": "software-v2", "event_id": 65537, "cpu": 0, "tid": None, "period": 10000000, "records_count": 2},
            {"logical_source": 2, "kind": "software-v2", "event_id": 65537, "cpu": 0, "tid": None, "period": 10000000, "records_count": 2},
            {"logical_source": 3, "kind": "tracepoint", "event_id": 6, "cpu": 0, "tid": None, "records_count": 1},
            {"logical_source": 4, "kind": "tracepoint", "event_id": 8, "cpu": 0, "tid": None, "records_count": 1},
            {"logical_source": 5, "kind": "software-stack-v3", "event_id": 65537, "cpu": None, "tid": 42, "records_count": 1},
        ], "record_sources": [1, 1, 2, 2, 3, 4, 5]}}
        self.assertEqual(validate_report("mixed", report), [])
        for source in report["recorder"]["sources"][:2]:
            source["kind"] = "software-stack-v3"
        self.assertEqual(validate_report("mixed", report), [])
        report["recorder"]["sources"][1]["records_count"] = 0
        self.assertTrue(validate_report("mixed", report))

    def test_mixed_gate_requires_real_task_samples_and_same_period_cpu_sources(self):
        report = {"records_count": 4, "recorder": {"sources": [
            {"logical_source": 1, "kind": "software-stack-v3", "event_id": 4098, "cpu": 0, "tid": None, "period": 10000000, "records_count": 1},
            {"logical_source": 2, "kind": "software-stack-v3", "event_id": 4098, "cpu": 0, "tid": None, "period": 20000000, "records_count": 1},
            {"logical_source": 3, "kind": "tracepoint", "event_id": 6, "cpu": 0, "tid": None, "records_count": 1},
            {"logical_source": 4, "kind": "tracepoint", "event_id": 8, "cpu": 0, "tid": None, "records_count": 1},
        ], "record_sources": [1, 2, 3, 4]}}
        self.assertTrue(validate_report("mixed", report))
        report["recorder"]["sources"][1]["period"] = 10000000
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
        with self.assertRaisesRegex(ValueError, "kernel chain"):
            stack_proof({"events": [event]}, report, collection, require_depth=True, require_kernel=True)
        kernel = {"event_id": 0x1002, "semantic": {"mode": 1, "chain_len": 3,
                  "ips": [0xffff0000, 0xffff1000, 0xffff2000], "termination": "complete"}}
        self.assertEqual(stack_proof({"events": [event, kernel]}, report, collection,
                                    require_depth=True, require_kernel=True)["max_kernel_depth"], 3)
        collection["captured_manifest"]["coverage"]["dropped"] = 1
        with self.assertRaisesRegex(ValueError, "journal loss"):
            stack_proof({"events": [event, kernel]}, report, collection,
                        require_depth=True, require_kernel=True)
        collection["captured_manifest"]["coverage"]["dropped"] = 0
        report["runtime_diagnostics"]["counters"][0]["value"] = 101
        with self.assertRaisesRegex(ValueError, "before enable"):
            stack_proof({"events": [event]}, report, collection, require_depth=True)


if __name__ == "__main__":
    unittest.main()
