#!/usr/bin/env python3
"""Host driver, log validation, and HWCAP model unit tests for AT_HWCAP regression harness."""
from pathlib import Path
import sys
import unittest

import run


def loongarch_hwcap_model(cpucfg1: int) -> int:
    hwcap_loongarch_cpucfg = 1 << 0
    hwcap_loongarch_lam = 1 << 1
    hwcap_loongarch_ual = 1 << 2
    hwcap_loongarch_fpu = 1 << 3
    cpucfg1_ual = 1 << 20

    hwcap = hwcap_loongarch_cpucfg | hwcap_loongarch_lam | hwcap_loongarch_fpu
    if cpucfg1 & cpucfg1_ual:
        hwcap |= hwcap_loongarch_ual
    return hwcap


def valid_markers(token="testtoken", status=0):
    lines = [
        "HWCAP START version=1",
        "HWCAP BEGIN check_auxv_hwcap",
        "HWCAP NOTE cpucfg1=0x3f2f2fe ual_supported=true hwcap=0xf",
        "HWCAP PASS check_auxv_hwcap",
        "HWCAP SUMMARY pass=1 fail=0",
        "HWCAP RESULT PASS",
        f"HWCAP_HOST_EXIT {token} {status}",
    ]
    return "\n".join(lines) + "\n"


class LogValidationTests(unittest.TestCase):
    def test_all_markers_and_zero_shell_exit_required(self):
        text = valid_markers()
        self.assertEqual(run.validate_log(text, shell_token="testtoken"), [])

    def test_missing_pass_fails(self):
        text = valid_markers().replace("HWCAP PASS check_auxv_hwcap\n", "")
        self.assertTrue(run.validate_log(text, shell_token="testtoken"))

    def test_nonzero_exit_fails(self):
        text = valid_markers(status=1)
        self.assertTrue(run.validate_log(text, shell_token="testtoken"))

    def test_explicit_fail_marker_fails(self):
        text = valid_markers() + "HWCAP FAIL some check failed\n"
        self.assertTrue(run.validate_log(text, shell_token="testtoken"))

    def test_kernel_panic_fails(self):
        text = valid_markers() + "kernel panicked at src/main.rs:10:10\n"
        self.assertTrue(run.validate_log(text, shell_token="testtoken"))


class QemuCommandTests(unittest.TestCase):
    def test_prescribed_qemu_command_args(self):
        cmd = run.qemu_command("qemu", Path("/kernel"), Path("/primary"))
        self.assertEqual(cmd[cmd.index("-m") + 1], "8G")
        self.assertEqual(cmd[cmd.index("-smp") + 1], "8")
        self.assertEqual(cmd[cmd.index("-machine") + 1], "virt")
        self.assertEqual(cmd[cmd.index("-rtc") + 1], "base=utc")
        self.assertIn("-no-reboot", cmd)
        self.assertIn("virtio-blk-pci,drive=x0", cmd)


class LoongarchHwcapModelTests(unittest.TestCase):
    def test_ual_set_gives_0xf(self):
        self.assertEqual(loongarch_hwcap_model(1 << 20), 0xF)
        self.assertEqual(loongarch_hwcap_model(0x3F2F2FE), 0xF)

    def test_ual_clear_gives_0xb(self):
        self.assertEqual(loongarch_hwcap_model(0), 0xB)
        self.assertEqual(loongarch_hwcap_model(~(1 << 20) & 0xFFFFFFFF), 0xB)

    def test_vector_bits_remain_cleared(self):
        all_bits = loongarch_hwcap_model(0xFFFFFFFFFFFFFFFF)
        self.assertEqual(all_bits, 0xF)
        self.assertEqual(all_bits & ~0xF, 0)
        self.assertEqual(all_bits & (1 << 4), 0)
        self.assertEqual(all_bits & (1 << 5), 0)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
