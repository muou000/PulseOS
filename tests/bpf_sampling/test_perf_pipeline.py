"""Independent external-consumer checks for the explicit perf pipeline."""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest

from stack_evidence import elf_symbols

spec = importlib.util.spec_from_file_location("perf_pipeline", Path(__file__).parents[2] / "scripts/perf_pipeline.py")
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)


class PerfPipelineTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("PULSE_PERF") and os.environ.get("FLAMEGRAPH_DIR"),
                         "requires explicitly installed native perf and pinned FlameGraph")
    def test_native_user_functions_survive_riscv_mapping_labels(self):
        # Historical bytes are a regression fixture, not fresh production proof.
        repo = Path(__file__).parents[2]
        analyzer = Path(os.environ.get("PULSE_ANALYZER", repo / "target/debug/bpf-analyzer"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix = "riscv64/stacks-task/"
            fixtures = repo / "tests/bpf_record/fixtures"
            index = json.loads((fixtures / "index.json").read_text())
            self.assertEqual(pipeline.digest(fixtures / index["archive"]), index["sha256"])
            with tarfile.open(fixtures / index["archive"]) as archive:
                for member in archive.getmembers():
                    if (member.name.startswith(prefix)
                            and ("/artifacts/" in member.name or member.name.endswith("stack-task.pbcapture"))
                            and (member.isfile() or member.islnk())):
                        target = root / member.name.removeprefix(prefix)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(archive.extractfile(member).read())
            before = {path.name: pipeline.digest(path) for path in (root / "artifacts").iterdir()}
            capture = root / "stack-task.pbcapture"
            original = pipeline.digest(capture)
            data = root / "perf.data"
            exported = subprocess.run([str(analyzer), str(capture), "--mode", "user",
                                       "--bundle", str(root), "--perf-data", str(data)],
                                      text=True, capture_output=True)
            self.assertEqual(exported.returncode, 0, exported.stderr)
            command = [sys.executable, str(repo / "scripts/perf_pipeline.py"), str(data),
                       "--bundle", str(root), "--perf", os.environ["PULSE_PERF"],
                       "--flamegraph", os.environ["FLAMEGRAPH_DIR"], "--output", str(root / "native")]
            manifest = json.loads(Path(str(data) + ".json").read_text())
            functions = [function for artifact in manifest["artifacts"]
                         for function in elf_symbols(root / artifact["path"])[1]]
            for suffix in ("11sample_leaf", "13sample_middle", "12sample_outer"):
                names = [name for _, _, name in functions if name.endswith(suffix)]
                self.assertEqual(len(names), 1, names)
                command += ["--expect-symbol", names[0]]
            consumed = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(consumed.returncode, 0, consumed.stderr)
            result = json.loads(consumed.stdout)
            self.assertTrue(any(view["hidden_local_labels"] > 0 for view in result["user_symbol_views"]))
            self.assertEqual(original, pipeline.digest(capture))
            self.assertEqual(before, {path.name: pipeline.digest(path) for path in (root / "artifacts").iterdir()})

            # This resolves into the original bundle but must never escape the
            # distinct consumer root when the artifact is staged.
            manifest["artifacts"][0]["path"] = "../" + root.name + "/" + manifest["artifacts"][0]["path"]
            hostile = root / "hostile.json"
            hostile.write_text(json.dumps(manifest))
            command[command.index(str(root / "native"))] = str(root / "hostile-native")
            rejected = subprocess.run(command + ["--manifest", str(hostile)], text=True, capture_output=True)
            self.assertEqual(rejected.returncode, 1)
            self.assertIn("consumer symbol path escapes", rejected.stderr)
            self.assertEqual(original, pipeline.digest(capture))
            self.assertEqual(before, {path.name: pipeline.digest(path) for path in (root / "artifacts").iterdir()})

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

    def test_distinct_software_clocks_keep_separate_weights(self):
        text = """worker 7/8 [002] 1.000000000: 10 cpu-clock:HG:
        401020 leaf (/artifacts/a.elf)

worker 7/8 [003] 1.000000000: 20 task-clock:HG:
        401020 leaf (/artifacts/a.elf)

worker 7/8 [002] 1.010000000: 10 cpu-clock:HG:
        401020 leaf (/artifacts/a.elf)

"""
        result = pipeline.inspect_perf_script(text)
        self.assertEqual(result["event_weights"], {
            "cpu-clock:HG": {"samples": 2, "period_ns": 20},
            "task-clock:HG": {"samples": 1, "period_ns": 20},
        })
        self.assertEqual(result["sample_count"], 3)
        self.assertEqual(result["total_period_ns"], 40)

    def test_header_only_sample_requires_explicit_empty_chain_verification(self):
        text = "worker 7/8 [002] 1.000000001: 10 task-clock:HG:\n\n"
        with self.assertRaises(ValueError):
            pipeline.inspect_perf_script(text)
        result = pipeline.inspect_perf_script(text, allow_empty_chains=True)
        self.assertEqual(result["empty_chain_samples"], [{
            "comm": "worker", "pid": 7, "tid": 8, "cpu": 2,
            "timestamp_ns": 1000000001, "period_ns": 10, "event": "task-clock:HG",
        }])
        manifest = {"sources": [{"id": 7, "effective_config": "task-clock"}],
                    "samples": [{"source_id": 7, "saved_chain_len": 0, "pid": 7,
                                 "tid": 8, "cpu": 2, "timestamp_ns": 1000000001,
                                 "period_ns": 10}]}
        pipeline.verify_empty_chains(result, manifest)
        for field, value in [("saved_chain_len", 1), ("timestamp_ns", 1000000002),
                             ("period_ns", 20), ("tid", 9)]:
            changed = {**manifest, "samples": [{**manifest["samples"][0], field: value}]}
            with self.assertRaisesRegex(ValueError, "zero-length callchains"):
                pipeline.verify_empty_chains(result, changed)

    def test_empty_kernel_identity_uses_pinned_collapser_zero_tid_label(self):
        # The unmodified pinned --tid collapser emits ?/0 for a 0/0 header,
        # and ?/40 for a 40/0 header. These labels do not supply a known PID.
        samples = [{"comm": "[unknown]", "pid": 0, "tid": 0, "period_ns": 10},
                   {"comm": "worker", "pid": 40, "tid": 0, "period_ns": 20}]
        self.assertEqual(pipeline.mark_empty_chains(
            "[unknown]-?/0 10\nworker-?/40 20\n", samples, "period_ns"),
            "[unknown]-?/0;[unavailable_callchain] 10\nworker-?/40;[unavailable_callchain] 20\n")

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
        # When HEADER_BUILD_ID exists, native perf lists that feature's real
        # IDs and can omit DSOs with no GNU note entirely.
        pipeline.inspect_buildids('ab' * 20 + ' /artifacts/user.elf\n', manifest)
        with self.assertRaises(ValueError):
            pipeline.inspect_buildids(text.replace('ab' * 20, 'cd' * 20), manifest)
        with self.assertRaises(ValueError):
            pipeline.inspect_buildids(text.replace('[kernel.kallsyms]', '/artifacts/wrong.elf'), manifest)
        with self.assertRaises(ValueError):
            pipeline.inspect_buildids('cd' * 20 + ' [kernel.kallsyms]\n' +
                                      'ab' * 20 + ' /artifacts/user.elf\n', manifest)


if __name__ == "__main__":
    unittest.main()
