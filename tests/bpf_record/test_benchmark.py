import unittest
from run import benchmark_stats


def snapshot(point, *, timer=0, lost=0, prefix="BENCH_STATS"):
    return f"""{prefix} BEGIN phase=baseline point={point}
PULSE_BPF_STATS version=1 pid=20 available=1 registered_events=0 trace_subscriptions=0
GLOBAL timer_enqueued={timer} timer_dequeued={timer} timer_full={lost} timer_busy=0 trace_enqueued=0 trace_full=0 trace_recursive=0 fault_started=5 fault_completed=5 fault_clock_errors=0
END events=0 programs=0
{prefix} END phase=baseline point={point}
"""


class BenchmarkSnapshotTests(unittest.TestCase):
    def test_actual_scoped_deltas_and_resource_snapshots_are_retained(self):
        report = benchmark_stats(snapshot("before", timer=7) + snapshot("after", timer=10, lost=2))
        self.assertEqual(report["baseline"]["global_counter_deltas"]["timer_enqueued"], 3)
        self.assertEqual(report["baseline"]["global_counter_deltas"]["timer_full"], 2)
        self.assertEqual(report["baseline"]["before"]["header"]["registered_events"], 0)

    def test_missing_counter_or_partial_snapshot_is_not_zero_loss(self):
        for text in (
            snapshot("before") + snapshot("after").replace(" timer_full=0", ""),
            snapshot("before"),
            snapshot("before") + snapshot("after").replace("END events=0 programs=0", ""),
        ):
            with self.assertRaises(ValueError):
                benchmark_stats(text)


if __name__ == "__main__":
    unittest.main()
