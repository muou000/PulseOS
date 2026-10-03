#!/usr/bin/env python3
"""Host driver checks. These are NOT PulseOS guest or fault-injection evidence.

Run: python3 /home/muou/PulseOS/tests/mapped_lifecycle/test_runner.py
Uses a temporary ext4 filesystem to verify debugfs injection on isolated copies,
plus a fake console process to verify log parsing, deadlines and shell stdio.
"""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

import run


def markers(token="testtoken", status=0):
    lines = ["MLC START version=1 page_size=4096 iterations=1 case_timeout=10"]
    for case in run.CASES:
        lines += [f"MLC BEGIN {case}", f"MLC PASS {case}"]
    lines += ["MLC SKIP sync_failure_reset_refusal no integration FileNode fault/power hook",
              "MLC SUMMARY pass=8 fail=0 skip=1", "MLC RESULT PASS functional_only=1",
              f"MLC_HOST_EXIT {token} {status}"]
    return "\n".join(lines) + "\n"


class LogTests(unittest.TestCase):
    def test_all_markers_and_zero_shell_exit_required(self):
        text = markers()
        self.assertEqual(run.validate_log(text, shell_token="testtoken"), [])
        for bad in (text.replace("MLC PASS partial_munmap\n", ""),
                    text + "MLC FAIL assertion\n",
                    text + "MLC PASS partial_munmap\n",
                    text.replace("MLC_HOST_EXIT testtoken 0", "MLC_HOST_EXIT testtoken 1"),
                    text.replace("testtoken", "wrongtoken"),
                    text + "kernel panicked at somewhere\n"):
            self.assertTrue(run.validate_log(bad, shell_token="testtoken"))

    def test_echo_cannot_satisfy_exit_or_pass_markers(self):
        echo = "/ # printf 'MLC_HOST_EXIT testtoken 0\\n'; echo 'MLC PASS partial_munmap'\n"
        self.assertTrue(run.validate_log(echo, shell_token="testtoken"))
        text = markers().replace("MLC_HOST_EXIT testtoken 0\n", echo)
        self.assertTrue(run.validate_log(text, shell_token="testtoken"))

    def test_fault_injection_is_never_claimed(self):
        self.assertTrue(run.validate_log(markers(), shell_token="testtoken", require_faults=True))

    def test_raw_six_case_contract_is_distinct(self):
        lines = ["MLC START version=2 suite=raw6 page_size=4096 iterations=32"]
        for case in run.RAW_CASES:
            lines += [f"MLC BEGIN {case}", f"MLC PASS {case}"]
        lines += ["MLC SKIP sync_failure_reset_refusal no integration FileNode fault/power hook",
                  "MLC SKIP raw_mlocked_ebusy optional mlock semantics not exercised",
                  "MLC SUMMARY pass=6 fail=0 skip=2",
                  "MLC RESULT PASS functional_only=1 suite=raw6", "MLC_HOST_EXIT testtoken 0"]
        text = "\n".join(lines) + "\n"
        self.assertEqual(run.validate_log(text, shell_token="testtoken", suite="raw6"), [])
        self.assertTrue(run.validate_log(text, shell_token="testtoken", suite="c8"))
        self.assertTrue(run.validate_log(markers(), shell_token="testtoken", suite="raw6"))
        self.assertTrue(run.validate_log(text.replace("MLC PASS raw_fork_pipe_shared_private\n", ""),
                                         shell_token="testtoken", suite="raw6"))

    def test_outputs_cannot_escape_directory(self):
        with self.assertRaises(ValueError):
            run.scoped(run.REPO / "kernel-rv")


class QemuTests(unittest.TestCase):
    def test_prescribed_resources_devices_and_snapshot(self):
        for arch in run.ARCHES:
            cmd = run.qemu_command(arch, "qemu", Path("/kernel"), Path("/primary"), Path("/data"))
            self.assertEqual(cmd[cmd.index("-m") + 1], "8G")
            self.assertEqual(cmd[cmd.index("-smp") + 1], "8")
            self.assertEqual(cmd[cmd.index("-machine") + 1], "virt")
            self.assertEqual(cmd[cmd.index("-rtc") + 1], "base=utc")
            self.assertIn("-no-reboot", cmd)
            drives = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "-drive"]
            self.assertEqual(drives, ["file=/primary,if=none,format=raw,id=x0,snapshot=on",
                                      "file=/data,if=none,format=raw,id=x1,snapshot=on"])
            if arch == "riscv64":
                self.assertIn("virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0", cmd)
                self.assertIn("virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1", cmd)
                self.assertIn("virtio-net-device,netdev=net", cmd)
                self.assertIn("-bios", cmd)
            else:
                self.assertIn("virtio-blk-pci,drive=x0", cmd)
                self.assertIn("virtio-blk-pci,drive=x1", cmd)
                self.assertIn("virtio-net-pci,netdev=net0", cmd)
            self.assertEqual(cmd[-4:], ["-monitor", "none", "-serial", "stdio"])

    def test_shell_console_handshake_and_exit(self):
        with tempfile.TemporaryDirectory(prefix="console-", dir=run.BASE) as tmp:
            # Fake console runs on the host; never presented as a QEMU guest result.
            script = ("import sys\n"
                      "sys.stdout.write('boot\\n/ # '); sys.stdout.flush()\n"
                      "line = sys.stdin.readline()\n"
                      "print(line, end='')\n"
                      "print(" + repr(markers()) + ", end='', flush=True)\n")
            text, _, reason = run.drive_guest(
                [sys.executable, "-c", script], "echo fake_console", "testtoken",
                Path(tmp) / "console.log", r"(?:^|[\r\n])[^\r\n]*[#$] ?$", 3, 3)
            self.assertEqual(reason, "")
            self.assertEqual(run.validate_log(text, shell_token="testtoken"), [])
            self.assertIn("echo fake_console", text)

    def test_shell_boot_and_payload_deadlines(self):
        with tempfile.TemporaryDirectory(prefix="deadlines-", dir=run.BASE) as tmp:
            scripts = [
                ("import time; print('no shell', flush=True); time.sleep(10)", "boot/shell prompt timeout"),
                ("import sys,time; print('/ # ', end='', flush=True); sys.stdin.readline(); time.sleep(10)",
                 "payload timeout"),
            ]
            for i, (script, expected) in enumerate(scripts):
                _, _, reason = run.drive_guest(
                    [sys.executable, "-c", script], "echo fake_console", "testtoken",
                    Path(tmp) / f"deadline-{i}.log", r"(?:^|[\r\n])[^\r\n]*[#$] ?$", 1, 1)
                self.assertEqual(reason, expected)


class ImageTests(unittest.TestCase):
    @unittest.skipUnless(run.shutil.which("mke2fs") and run.shutil.which("debugfs"),
                         "mke2fs/debugfs unavailable")
    def test_debugfs_copy_injection_preserves_original(self):
        with tempfile.TemporaryDirectory(prefix="debugfs-check-", dir=run.BASE) as tmp:
            root = Path(tmp)
            stage = root / "stage"
            (stage / "usr" / "bin").mkdir(parents=True)
            (stage / "bin").symlink_to("usr/bin")
            (stage / "usr" / "bin" / "dash").write_bytes(b"fake shell; image tooling check only\n")
            (stage / "usr" / "bin" / "sh").symlink_to("dash")
            image = root / "original.img"
            with image.open("wb") as stream:
                stream.truncate(32 * 1024 * 1024)
            run.command([run.shutil.which("mke2fs"), "-q", "-F", "-t", "ext4",
                         "-O", "^has_journal,^metadata_csum", "-d", str(stage), str(image)])
            self.assertEqual(run.check_image(image), image.resolve())
            before = run.digest(image)
            payload = root / "payload"
            payload.write_bytes(b"test injection bytes only; not a guest ELF\x00\xff")
            work = root / "copy-test"
            work.mkdir()
            copy = run.copy_image(image, work, "primary.img")
            binary, _ = run.inject(copy, payload, work)
            self.assertEqual(run.digest(image), before)
            self.assertNotEqual(run.digest(copy), before)
            self.assertRegex(run.debugfs(copy, "stat " + binary), r"Mode:\s+0755")
            run.install_bootstrap(copy, payload, work)
            self.assertEqual(run.digest(image), before)
            self.assertIn("mapped-lifecycle-bootstrap", run.debugfs(copy, "stat /usr/bin/sh"))
            with self.assertRaises(ValueError):
                run.copy_image(image, work, "primary.img")
            with self.assertRaises(ValueError):
                run.debugfs(copy, "stat /missing-payload")

    def test_elf_arch_and_static_linkage_validation(self):
        with tempfile.TemporaryDirectory(prefix="elf-check-", dir=run.BASE) as tmp:
            path = Path(tmp) / "payload"
            data = bytearray(120)
            data[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", data, 18, 243)
            struct.pack_into("<Q", data, 32, 64)
            struct.pack_into("<HH", data, 54, 56, 1)
            struct.pack_into("<I", data, 64, 1)
            struct.pack_into("<Q", data, 96, len(data))  # PT_LOAD covers headers
            path.write_bytes(data)
            run.check_elf(path, "riscv64")
            with self.assertRaises(ValueError):
                run.check_elf(path, "loongarch64")
            struct.pack_into("<I", data, 64, 3)
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                run.check_elf(path, "riscv64")
            struct.pack_into("<I", data, 64, 1)
            struct.pack_into("<Q", data, 72, 120)  # headers outside LOAD
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                run.check_elf(path, "riscv64")


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
