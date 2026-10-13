#!/usr/bin/env python3
"""Tests for the BPF toolchain probe."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROBE_SCRIPT = HERE / "probe.py"


class TestBpfProbe(unittest.TestCase):
    def test_script_exists(self):
        self.assertTrue(PROBE_SCRIPT.is_file(), f"probe.py must exist at {PROBE_SCRIPT}")

    def test_missing_guest_compiler_exits_nonzero(self):
        """When guest compiler is required but missing, probe must exit non-zero with actionable message."""
        result = subprocess.run(
            [
                sys.executable,
                str(PROBE_SCRIPT),
                "--require-guest-cc",
                "riscv64",
                "--riscv64-cc",
                "/nonexistent/path/to/riscv64-gcc",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0, "Probe must exit non-zero when guest compiler is missing")
        output = result.stdout + result.stderr
        self.assertIn("riscv64", output.lower())
        self.assertTrue(
            "missing" in output.lower() or "not found" in output.lower() or "unavailable" in output.lower(),
            f"Actionable missing message expected in output: {output}",
        )

    def test_missing_clang_exits_nonzero(self):
        """When clang binary is unavailable or overridden to nonexistent path, probe must exit non-zero."""
        result = subprocess.run(
            [sys.executable, str(PROBE_SCRIPT), "--clang", "/nonexistent/path/to/clang"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        output = result.stdout + result.stderr
        self.assertIn("clang", output.lower())
        self.assertTrue("not found" in output.lower() or "missing" in output.lower() or "unavailable" in output.lower())

    def test_missing_libbpf_exits_nonzero(self):
        """When libbpf is unavailable (empty PKG_CONFIG_PATH / nonexistent), probe must exit non-zero."""
        env = dict(os.environ)
        env["PKG_CONFIG_PATH"] = "/dev/null"
        env["PKG_CONFIG_LIBDIR"] = "/dev/null"
        result = subprocess.run(
            [sys.executable, str(PROBE_SCRIPT), "--host-only"],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        output = result.stdout + result.stderr
        self.assertIn("libbpf", output.lower())

    def test_missing_llvm_objdump_exits_nonzero(self):
        """When llvm-objdump is unavailable, probe must exit non-zero."""
        result = subprocess.run(
            [sys.executable, str(PROBE_SCRIPT), "--llvm-objdump", "/nonexistent/llvm-objdump"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        output = result.stdout + result.stderr
        self.assertIn("llvm-objdump", output.lower())

    def test_non_disassembling_llvm_objdump_exits_nonzero(self):
        """When llvm-objdump only reports a version but cannot disassemble BPF, probe must fail."""
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"mock-objdump version 1.0.0\"; exit 0; fi\nexit 1\n")
            script_path = f.name
        try:
            os.chmod(script_path, 0o755)
            result = subprocess.run(
                [sys.executable, str(PROBE_SCRIPT), "--host-only", "--llvm-objdump", script_path, "--json"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, "Probe must exit non-zero for mock non-disassembling executable")
            data = json.loads(result.stdout)
            self.assertFalse(data.get("host_ok"))
            self.assertFalse(data.get("ok"))
            self.assertFalse(data["llvm_objdump"].get("ok"))
            self.assertFalse(data["llvm_objdump"].get("bpf_inspection_supported"))
        finally:
            if os.path.exists(script_path):
                os.remove(script_path)

        true_bin = shutil.which("true")
        if true_bin:
            result = subprocess.run(
                [sys.executable, str(PROBE_SCRIPT), "--host-only", "--llvm-objdump", true_bin, "--json"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, "Probe must exit non-zero when llvm-objdump is /usr/bin/true")
            data = json.loads(result.stdout)
            self.assertFalse(data.get("host_ok"))
            self.assertFalse(data.get("ok"))
            self.assertFalse(data["llvm_objdump"].get("ok"))
            self.assertFalse(data["llvm_objdump"].get("bpf_inspection_supported"))

    def test_host_probe_succeeds_and_reports_versions(self):
        """On a machine with clang, llvm-objdump, and libbpf installed, --host-only exits 0 and reports versions."""
        result = subprocess.run(
            [sys.executable, str(PROBE_SCRIPT), "--host-only", "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Host probe failed: {result.stderr}\n{result.stdout}")
        data = json.loads(result.stdout)
        self.assertTrue(data.get("host_ok"))
        self.assertIn("clang", data)
        self.assertIn("llvm_objdump", data)
        self.assertIn("libbpf", data)
        self.assertTrue(data["clang"].get("bpf_target_supported"))
        self.assertTrue(data["llvm_objdump"].get("bpf_inspection_supported"))


    def _run_guest_cc_probe(self, cc_path: str, arch: str = "riscv64") -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(PROBE_SCRIPT),
                "--host-only",
                "--require-guest-cc",
                arch,
                f"--{arch}-cc",
                cc_path,
                "--json",
            ],
            capture_output=True,
            text=True,
        )

    def test_version_failing_guest_compiler_exits_nonzero(self):
        """When guest compiler candidate fails '--version' (e.g. /usr/bin/false), probe must exit non-zero."""
        false_bin = shutil.which("false")
        if false_bin:
            result = self._run_guest_cc_probe(false_bin)
            self.assertNotEqual(result.returncode, 0, "Probe must exit non-zero for version-failing /usr/bin/false")
            data = json.loads(result.stdout)
            self.assertFalse(data.get("ok"))
            self.assertFalse(data["guest_compilers"]["riscv64"].get("ok"))
            self.assertIn("failed", data["guest_compilers"]["riscv64"].get("error", "").lower())

        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write("#!/bin/sh\nexit 1\n")
            script_path = f.name
        try:
            os.chmod(script_path, 0o755)
            result = self._run_guest_cc_probe(script_path)
            self.assertNotEqual(result.returncode, 0, "Probe must exit non-zero when --version returns non-zero")
            data = json.loads(result.stdout)
            self.assertFalse(data.get("ok"))
            self.assertFalse(data["guest_compilers"]["riscv64"].get("ok"))
        finally:
            if os.path.exists(script_path):
                os.remove(script_path)

    def test_non_compiler_guest_executable_exits_nonzero(self):
        """When guest compiler candidate does not target the requested architecture (e.g. /usr/bin/true or host gcc), probe must fail."""
        true_bin = shutil.which("true")
        if true_bin:
            result = self._run_guest_cc_probe(true_bin)
            self.assertNotEqual(result.returncode, 0, "Probe must exit non-zero when guest compiler is /usr/bin/true")
            data = json.loads(result.stdout)
            self.assertFalse(data.get("ok"))
            self.assertFalse(data["guest_compilers"]["riscv64"].get("ok"))

        # Also test with host gcc targeting x86_64 when riscv64 is requested
        gcc_bin = shutil.which("gcc")
        if gcc_bin:
            proc = subprocess.run([gcc_bin, "-dumpmachine"], capture_output=True, text=True)
            if "riscv64" not in proc.stdout:
                result = self._run_guest_cc_probe(gcc_bin)
                self.assertNotEqual(result.returncode, 0, "Probe must exit non-zero when host gcc targets non-riscv64 arch")
                data = json.loads(result.stdout)
                self.assertFalse(data.get("ok"))
                self.assertFalse(data["guest_compilers"]["riscv64"].get("ok"))

    def test_valid_mock_guest_compiler_succeeds(self):
        """A valid cross-compiler mock that targets the requested arch passes guest compiler probe."""
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write("#!/bin/sh\n"
                    "if [ \"$1\" = \"--version\" ]; then echo \"riscv64-linux-gnu-gcc (Ubuntu 11.4.0) 11.4.0\"; exit 0; fi\n"
                    "if [ \"$1\" = \"-dumpmachine\" ]; then echo \"riscv64-linux-gnu\"; exit 0; fi\n"
                    "exit 0\n")
            script_path = f.name
        try:
            os.chmod(script_path, 0o755)
            result = self._run_guest_cc_probe(script_path)
            self.assertEqual(result.returncode, 0, f"Valid mock compiler must succeed: {result.stdout}")
            data = json.loads(result.stdout)
            self.assertTrue(data.get("ok"))
            self.assertTrue(data["guest_compilers"]["riscv64"].get("ok"))
            self.assertEqual(data["guest_compilers"]["riscv64"].get("version"), "11.4.0")
        finally:
            if os.path.exists(script_path):
                os.remove(script_path)


if __name__ == "__main__":
    unittest.main()
