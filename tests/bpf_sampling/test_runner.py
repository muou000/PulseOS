"""Regression checks for the real sampling evidence gate; no guest mocks."""
import unittest
import run


TOKEN = "test-token"
VALID = """SAMPLING START version=2 mode=task cpus=8 pid=2 tid=2
SAMPLING SINK_REJECT mode=task source_errno=-22 cpu_errno=-22 preserved=1
SAMPLING TASK_SLEEP before_ns=1000000 after_ns=2000000 wall_ns=100000000
SAMPLING OBSERVED mode=task samples=8 foreign=0 a=3 b=4 lost=0 cpu_mask=0x3
SAMPLING PASS disabled mode=task records=8
SAMPLING PASS detached mode=task records=8
SAMPLING FD_LIFECYCLE kind=link_target_close alive=9 loop_a=8 settled=10 after_stop=10 lost=0
SAMPLING FD_LIFECYCLE kind=ioctl_dup_final_close alive=7 loop_a=6 settled=8 after_stop=8 lost=0
SAMPLING RESULT PASS mode=task samples=8 foreign=0 a=3 b=4 lost=0 source=kernel_ring
BPF_HOST_EXIT test-token 0
"""
CPU_VALID = (VALID.replace("mode=task", "mode=cpu").replace("foreign=0", "foreign=20")
            .replace("records=8", "records=28"))

TRACE_VALID = """SAMPLING START version=2 mode=trace cpus=8 pid=2 tid=2
SAMPLING SINK_REJECT mode=trace source_errno=-22 cpu_errno=-22 preserved=1
SAMPLING TRACE_OBSERVED sched=10 subjects=3 subjects_capped=0 target_contexts=0 lost=0 cpu_mask=0x7
SAMPLING PASS disabled mode=trace records=10
SAMPLING PASS detached mode=trace records=10
SAMPLING TRACE_RESULT PASS sched=10 subjects=3 subjects_capped=0 target_contexts=0 lost=0 source=kernel_ring
BPF_HOST_EXIT test-token 0
"""

BLOCK_VALID = (TRACE_VALID.replace("mode=trace", "mode=block").replace("TRACE_", "BLOCK_")
               .replace("sched=", "blocks=").replace("subjects=3", "subjects=1"))
WAKE_VALID = (TRACE_VALID.replace("mode=trace", "mode=wake").replace("TRACE_", "WAKE_")
              .replace("sched=", "wakes=").replace("subjects=3", "subjects=1"))


class EvidenceGateTests(unittest.TestCase):
    def test_real_lifecycle_evidence_accepted(self):
        self.assertEqual(run.validate_log(VALID, TOKEN), [])
        self.assertEqual(run.validate_log(CPU_VALID, TOKEN, "cpu"), [])

    def test_legacy_fake_capture_pass_is_not_sampling_evidence(self):
        legacy = "BPF RESULT PASS functional_only=1\nBPF_HOST_EXIT test-token 0\n"
        self.assertTrue(run.validate_log(legacy, TOKEN))

    def test_zero_samples_or_post_disable_growth_rejected(self):
        self.assertTrue(run.validate_log(VALID.replace("a=3", "a=0"), TOKEN))
        self.assertTrue(run.validate_log(VALID.replace("RESULT PASS mode=task samples=8", "RESULT PASS mode=task samples=9"), TOKEN))
        self.assertTrue(run.validate_log(CPU_VALID.replace("RESULT PASS mode=cpu samples=8 foreign=20", "RESULT PASS mode=cpu samples=8 foreign=21"), TOKEN, "cpu"))

    def test_missing_detach_and_echoed_marker_rejected(self):
        self.assertTrue(run.validate_log(VALID.replace("SAMPLING PASS detached mode=task records=8\n", ""), TOKEN))
        self.assertTrue(run.validate_log("echo '" + VALID.replace("\n", "' ; echo '") + "'", TOKEN))

    def test_modes_and_task_identity_not_interchangeable(self):
        self.assertTrue(run.validate_log(CPU_VALID, TOKEN, "task"))
        self.assertTrue(run.validate_log(VALID, TOKEN, "cpu"))
        self.assertTrue(run.validate_log(CPU_VALID.replace("mode=cpu", "mode=task"), TOKEN))

    def test_real_trace_evidence_is_distinct_from_cpu_samples(self):
        self.assertEqual(run.validate_log(TRACE_VALID, TOKEN, "trace"), [])
        self.assertTrue(run.validate_log(VALID, TOKEN, "trace"))
        self.assertTrue(run.validate_log(TRACE_VALID, TOKEN, "cpu"))

    def test_empty_or_inconsistent_trace_fails(self):
        self.assertTrue(run.validate_log(TRACE_VALID.replace("sched=10", "sched=0"), TOKEN, "trace"))
        self.assertTrue(run.validate_log(TRACE_VALID.replace("subjects=3", "subjects=1"), TOKEN, "trace"))
        self.assertTrue(run.validate_log(TRACE_VALID.replace("TRACE_RESULT PASS sched=10", "TRACE_RESULT PASS sched=11"), TOKEN, "trace"))
        self.assertTrue(run.validate_log(TRACE_VALID.replace("PASS detached mode=trace records=10", "PASS detached mode=trace records=9"), TOKEN, "trace"))

    def test_block_and_wake_need_their_own_nonzero_record_evidence(self):
        for mode, text, count in (("block", BLOCK_VALID, "blocks"), ("wake", WAKE_VALID, "wakes")):
            self.assertEqual(run.validate_log(text, TOKEN, mode), [])
            self.assertTrue(run.validate_log(TRACE_VALID, TOKEN, mode))
            self.assertTrue(run.validate_log(text.replace(f"{count}=10", f"{count}=0"), TOKEN, mode))
            self.assertTrue(run.validate_log(text.replace("subjects=1", "subjects=0"), TOKEN, mode))

    def test_missing_or_wrong_sink_rejection_cannot_pass(self):
        self.assertTrue(run.validate_log(VALID.replace("source_errno=-22", "source_errno=0"), TOKEN))
        self.assertTrue(run.validate_log(VALID.replace("preserved=1", "preserved=0"), TOKEN))

    def test_final_close_and_original_fd_retention_required(self):
        self.assertTrue(run.validate_log(VALID.replace("after_stop=10", "after_stop=11"), TOKEN))
        self.assertTrue(run.validate_log(VALID.replace("loop_a=8", "loop_a=0"), TOKEN))
        self.assertTrue(run.validate_log(VALID.replace("kind=ioctl_dup_final_close", "kind=unknown"), TOKEN))

    def test_wall_time_task_clock_cannot_pass(self):
        self.assertTrue(run.validate_log(VALID.replace("after_ns=2000000", "after_ns=101000000"), TOKEN))
        self.assertTrue(run.validate_log(VALID.replace("wall_ns=100000000", "wall_ns=1000"), TOKEN))
        self.assertTrue(run.validate_log(VALID.replace("SAMPLING TASK_SLEEP before_ns=1000000 after_ns=2000000 wall_ns=100000000\n", ""), TOKEN))


if __name__ == "__main__":
    unittest.main()
