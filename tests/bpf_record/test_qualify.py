"""The public destination gate must reject a partial or selected guest matrix."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class DestinationGateTests(unittest.TestCase):
    def test_missing_and_incomplete_matrices_do_not_qualify(self):
        script = Path(__file__).with_name("qualify.py")
        for index in (None, {"guest_passed": False, "runs": []},
                      {"guest_passed": True, "runs": [{"arch": "riscv64", "suite": "stacks-task", "passed": True}]}):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as name:
                directory = Path(name)
                if index is not None:
                    (directory / "index.json").write_text(json.dumps(index))
                    (directory / "plan.json").write_text(json.dumps({"runs": index["runs"]}))
                completed = subprocess.run([sys.executable, str(script), str(directory),
                    "--analyzer", "/unused", "--perf", "/unused", "--flamegraph", "/unused",
                    "--output", str(directory / "qualified")], capture_output=True, text=True)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("requires the complete dual-architecture guest matrix", completed.stderr)
                self.assertFalse((directory / "qualified/qualification.json").exists())


if __name__ == "__main__":
    unittest.main()
