"""The public acceptance plan must exercise the production guest executable."""
import json
from pathlib import Path
import subprocess
import sys
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
            for suite in ("smoke", "stacks-cpu", "stacks-task", "stacks-mixed", "stacks-existing", "mapping", "nonleader-exec"):
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


if __name__ == "__main__":
    unittest.main()
