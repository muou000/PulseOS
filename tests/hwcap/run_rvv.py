#!/usr/bin/env python3
"""Boot a QEMU RVV or RV64GC rootfs and exercise the user-visible V contract."""
import argparse
from pathlib import Path
import re
import runpy
import shlex

import run as hwcap


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["on", "off"])
    parser.add_argument("--kernel", type=Path, default=hwcap.REPO / "kernel-rv")
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--vlen", type=int, help="override QEMU's VLEN in bits")
    args = parser.parse_args()
    if args.vlen is not None and args.mode == "off":
        parser.error("--vlen requires mode on")
    run = hwcap.new_run("riscv64-" + args.mode)
    probe = run / "rvv"
    hwcap.command(["riscv64-linux-gnu-gcc", "-O2", "-Wall", "-Wextra", "-Werror",
                   "-march=rv64gc", "-static", str(hwcap.BASE / "rvv.c"),
                   str(hwcap.BASE / "rvv_state.S"), "-o", str(probe)])
    disk = hwcap.copy_image(hwcap.check_image(args.image), run, "disk.img")
    try:
        guest, _ = hwcap.inject(disk, probe, run)
        model = "max" if args.mode == "on" else "rv64,v=false"
        if args.vlen is not None:
            model += f",vlen={args.vlen}"
        qemu_command = runpy.run_path(str(hwcap.REPO / "tests/init_shutdown/run.py"))["qemu_command"]
        cmd = qemu_command("riscv64", args.kernel.resolve(strict=True), disk)
        cmd[cmd.index("-cpu") + 1] = model
        token = run.name.rsplit("-", 1)[-1]
        shell = ('. /etc/os-release; printf "\\nRVV_OS=%s\\n" "$VERSION_ID"; '
                 f'{guest} {args.mode}; printf "\\nHWCAP_HOST_EXIT {token} %s\\n" "$?"')
        print(shlex.join(cmd), flush=True)
        text, _, reason = hwcap.drive_guest(cmd, shell, token, run / "guest.log",
                                            r"(?:^|[\r\n])[^\r\n]*[#$] ?$", 30, 30)
        lines = re.sub(r"\x1b\[[0-9;]*m", "", text).replace("\r", "").splitlines()
        for line in lines:
            if re.match(r"^(RVV|HWCAP_HOST_EXIT)", line):
                print(line)
        version = "26.10" if args.mode == "on" else "24.04"
        workers = [line for line in lines if line.startswith("RVV worker=")]
        if args.mode == "on":
            width = str(args.vlen // 8) if args.vlen is not None else r"[1-9][0-9]*"
            for worker in (0, 1):
                expected = rf"RVV worker={worker} hart=0 rounds=8 vlenb={width} state=PASS"
                if not any(re.fullmatch(expected, line) for line in workers):
                    raise SystemExit(f"FAIL missing worker {worker} result (see {run / 'guest.log'})")
        if (reason or f"HWCAP_HOST_EXIT {token} 0" not in lines or
                "RVV PASS" not in lines or f"RVV_OS={version}" not in lines):
            raise SystemExit(f"FAIL {reason} (see {run / 'guest.log'})")
    finally:
        disk.unlink()
    print(f"PASS (see {run / 'guest.log'})")


if __name__ == "__main__":
    main()
