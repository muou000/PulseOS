"""The public acceptance plan must exercise the production guest executable."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from run import cases_script


BASE = Path(__file__).resolve().parent


class AcceptancePlanTests(unittest.TestCase):
    def test_plan_reserves_injection_builds_for_declared_control_probes(self):
        result = subprocess.run(
            [sys.executable, str(BASE / "acceptance.py"), "--plan"],
            text=True, capture_output=True, check=True,
        )
        plan = json.loads(result.stdout)
        self.assertEqual({run["arch"] for run in plan["runs"]}, {"riscv64", "loongarch64"})
        for arch in ("riscv64", "loongarch64"):
            runs = {run["suite"]: run for run in plan["runs"] if run["arch"] == arch}
            for suite in ("smoke", "stacks-cpu", "stacks-task", "stacks-mixed", "stacks-existing", "mapping", "nonleader-exec", "installed-io"):
                self.assertEqual(runs[suite]["variant"], "guest")
                script, captures, _ = cases_script("/installed", suite, 1000)
                self.assertTrue(captures)
                self.assertNotIn("--test-", script)
            for suite in ("lifecycle", "negative", "stacks-observation", "benchmark", "recovery"):
                self.assertEqual(runs[suite]["variant"], "acceptance")

    def test_nonleader_exec_can_run_with_the_production_recorder(self):
        script, captures, failures = cases_script("/installed", "nonleader-exec", 1000)
        self.assertEqual(captures, ["nonleader-exec"])
        self.assertEqual(failures, [])
        self.assertIn('--tid "$initial_tid"', script)
        self.assertNotIn("--test-", script)

    def test_installed_io_samples_an_already_running_external_dd_task(self):
        script, captures, failures = cases_script("/installed", "installed-io", 1000)
        self.assertEqual(captures, ["installed-io"])
        self.assertEqual(failures, [])
        self.assertIn("command -v dd", script)
        self.assertIn("dd if=/dev/zero of=/dev/null bs=65536", script)
        self.assertIn('--events task --tid "$target"', script)
        self.assertIn("--period-ns 1000000", script)
        self.assertIn("INSTALLED_IO READY", script)
        self.assertIn("INSTALLED_IO STOPPED", script)
        self.assertLess(script.index("dd if=/dev/zero"), script.index("RECORD_CASE BEGIN"))
        self.assertNotIn("record-fixture cpu", script)
        self.assertNotIn("--test-", script)

    def test_production_suite_rejects_a_byte_matched_acceptance_executable(self):
        # Structurally valid input for preflight only; never sampling evidence.
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", header, 18, 243)
        struct.pack_into("<Q", header, 32, 64)
        struct.pack_into("<HH", header, 54, 56, 1)
        elf = bytes(header) + struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 120, 120, 4096)
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "bpf-record"
            binary.write_bytes(elf)
            (binary.parent / "build.json").write_text(json.dumps({
                "arch": "riscv64", "variant": "acceptance",
                "sha256": hashlib.sha256(elf).hexdigest(),
            }))
            result = subprocess.run([
                sys.executable, str(BASE / "run.py"), "guest", "--arch", "riscv64",
                "--suite", "stacks-task", "--recorder", str(binary),
            ], text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("must match riscv64 guest executable bytes", result.stderr)
        self.assertNotIn("Logs:", result.stdout)


if __name__ == "__main__":
    unittest.main()
