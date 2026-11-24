#!/usr/bin/env python3
"""Exercise the vfat mount syscall on a dedicated FAT32 disk and an ext4 root."""

import argparse
import importlib.util
import shlex
import subprocess
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def runner(name):
    spec = importlib.util.spec_from_file_location(name, REPO / "tests" / name / "run.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--arch", required=True, choices=("riscv64", "loongarch64"))
    cli.add_argument("--kernel", type=Path)
    cli.add_argument("--image", type=Path)
    cli.add_argument("--output", required=True, type=Path, help="new directory for the guest log")
    args = cli.parse_args()
    rv = args.arch == "riscv64"
    kernel = (args.kernel or REPO / ("kernel-rv" if rv else "kernel-la")).resolve(strict=True)
    root = (args.image or REPO / ("disk.img" if rv else "disk-la.img")).resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    console = runner("bpf_smoke")
    qemu = runner("init_shutdown")
    with tempfile.TemporaryDirectory(prefix="vfat-test-") as temp:
        staging = Path(temp)
        image = staging / "root.img"
        scratch = staging / "fat32.img"
        subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", root, image], check=True)
        subprocess.run([REPO / "scripts/install_to_rootfs.sh", image, HERE / "guest.sh",
                        "/vfat-probe.sh"], check=True)
        with scratch.open("xb") as f:
            f.truncate(64 << 20)
        subprocess.run(["mkfs.fat", "-F", "32", str(scratch)], check=True)
        command = qemu.qemu_command(args.arch, kernel, image)
        device = ("virtio-blk-device,bus=virtio-mmio-bus.1" if rv else "virtio-blk-pci")
        command.extend(["-drive", f"file={scratch},if=none,format=raw,id=fat",
                        "-device", f"{device},drive=fat"])
        print(shlex.join(command), flush=True)
        (args.output / "command.txt").write_text(shlex.join(command) + "\n")
        # A second kernel starts with an empty page cache and the same FAT disk.
        for mode, marker, logfile in (("write", "VFAT_PASS", "guest.log"),
                                      ("cold-read", "VFAT_COLD_READ_OK", "cold-read.log")):
            shell = f"sh /vfat-probe.sh {mode}; " + r"""printf '\nBPF_HOST_EXIT vfat %s\n' "$?" """
            log = args.output / logfile
            text, _, reason = console.drive_guest(command, shell, "vfat", log,
                                                  r"(?:^|[\r\n])[^\r\n]*[#$] ?$", 180, 120)
            lines = qemu.ANSI.sub("", text).splitlines()
            if reason or marker not in lines or "BPF_HOST_EXIT vfat 0" not in lines:
                raise SystemExit(f"FAT32 {mode} failed ({reason or 'guest assertion'}), see {log}")
        subprocess.run(["fsck.fat", "-n", str(scratch)], check=True)
        print(f"PASS {args.arch} FAT32")


if __name__ == "__main__":
    main()
