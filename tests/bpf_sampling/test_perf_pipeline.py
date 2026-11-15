"""Independent external-consumer checks for the explicit perf pipeline."""
from pathlib import Path
import importlib.util
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("perf_pipeline", Path(__file__).parents[2] / "scripts/perf_pipeline.py")
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)


class PerfPipelineTests(unittest.TestCase):
    def test_perf_script_preserves_counts_periods_and_chain_names(self):
        text = """worker 7/8 [002] 1.000000000: 10 cpu-clock:
        401020 leaf (/artifacts/a.elf)
        401010 parent (/artifacts/a.elf)

worker 7/8 [002] 1.010000000: 20 cpu-clock:
        401020 leaf (/artifacts/a.elf)
        401010 parent (/artifacts/a.elf)

"""
        result = pipeline.inspect_perf_script(text)
        self.assertEqual(result["sample_count"], 2)
        self.assertEqual(result["total_period_ns"], 30)
        self.assertEqual(result["symbols"], ["leaf", "parent"])
        self.assertEqual(result["event_names"], ["cpu-clock"])

    def test_zero_period_and_missing_frames_are_rejected(self):
        for body in ["worker 7/8 [002] 1.0: 0 cpu-clock:\n  401020 leaf (elf)\n",
                     "worker 7/8 [002] 1.0: 10 cpu-clock:\n\n"]:
            with self.assertRaises(ValueError):
                pipeline.inspect_perf_script(body)
        self.assertEqual(pipeline.inspect_perf_script("")["sample_count"], 0)

    def test_svg_total_and_unit_are_independent_checks(self):
        svg = '<svg xmlns="http://www.w3.org/2000/svg"><g><title>all (30 nanoseconds, 100%)</title></g><g><title>leaf (10 nanoseconds, 33.33%)</title></g></svg>'
        pipeline.inspect_svg(svg, 30, "period_ns", ["leaf"])
        for total, unit, expected in [(2, "period_ns", []), (30, "samples", []), (30, "period_ns", ["absent"])]:
            with self.assertRaises(ValueError):
                pipeline.inspect_svg(svg, total, unit, expected)

    def test_folded_empty_stays_empty_and_zero_weight_is_rejected(self):
        self.assertEqual(pipeline.inspect_folded(""), 0)
        self.assertEqual(pipeline.inspect_folded("root;leaf 10\nroot;other 20\n"), 30)
        with self.assertRaises(ValueError):
            pipeline.inspect_folded("root;leaf 0\n")

    def test_revision_label_does_not_authorize_modified_scripts(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "REVISION").write_text(pipeline.FLAMEGRAPH_REVISION)
            for name in pipeline.FLAMEGRAPH_SHA256:
                (directory / name).write_text("# modified tool\n")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                pipeline.verify_flamegraph(directory)

    def test_buildid_list_distinguishes_absent_notes_from_ids(self):
        manifest = {'kernel_artifact_path': 'artifacts/kernel.elf', 'artifacts': [
            {'path': 'artifacts/kernel.elf', 'gnu_build_id': None},
            {'path': 'artifacts/user.elf', 'gnu_build_id': 'ab' * 20}]}
        text = '                                         [kernel.kallsyms]\n' + 'ab' * 20 + ' /artifacts/user.elf\n'
        pipeline.inspect_buildids(text, manifest)
        with self.assertRaises(ValueError):
            pipeline.inspect_buildids(text.replace('ab' * 20, 'cd' * 20), manifest)
        with self.assertRaises(ValueError):
            pipeline.inspect_buildids(text.replace('[kernel.kallsyms]', '/artifacts/wrong.elf'), manifest)


if __name__ == "__main__":
    unittest.main()
