"""Exercise exact syscall error returns on a FAT volume under QEMU blkdebug."""

from pathlib import Path
import shutil
import subprocess


def build_probe(repo, image, arch, temp):
    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    version = subprocess.check_output(["rustc", "-vV"], text=True)
    host = next(line[6:] for line in version.splitlines() if line.startswith("host: "))
    linker = sysroot / "lib/rustlib" / host / "bin/rust-lld"
    obj = temp / "probe.o"
    elf = temp / "probe"
    flags = ["-mno-relax"] if arch == "riscv64" else []
    subprocess.run(["clang", f"--target={arch}-unknown-linux-gnu", "-O2", "-Wall", "-Werror",
                    "-ffreestanding", "-fno-builtin", "-fno-pic", "-fno-stack-protector",
                    *flags, "-c", Path(__file__).with_name("probe.c"), "-o", obj], check=True)
    subprocess.run([linker, "-flavor", "gnu", "-static", "--no-relax", "-T",
                    repo / "tests/init_shutdown/guest.ld", obj, "-o", elf], check=True)
    subprocess.run([repo / "scripts/install_to_rootfs.sh", "-m", "0755", image, elf,
                    "/vfat-probe"], check=True)


def faults(scratch, boot):
    temp = scratch.parent

    def shell(mode):
        probe = (f"mkdir -p /tmp/vfat-probe && mount -t vfat /dev/vdb /tmp/vfat-probe && "
                 f"printf {mode} | /vfat-probe")
        # This disposable guest exits with its flush fault still active.
        return probe if mode == "f" else probe + " && umount /tmp/vfat-probe"

    boot(str(scratch), shell("s"), "VFAT_PROBE_PASS", "seed")
    # The first guest created a 4 KiB file full of Z on a fresh volume.
    # Restrict read/write errors to its actual data sector, avoiding FAT metadata.
    raw = scratch.read_bytes()
    signature = b"Z" * 4096
    start = raw.find(signature)
    if start < 0 or start % 512 or raw.find(signature, start + 1) >= 0:
        raise ValueError("expected one sector-aligned 4 KiB fixture payload")
    for tag, event, operation in (("read", "read_aio", "read"),
                                  ("writeback", "write_aio", "write"),
                                  ("flush", "flush_to_disk", "flush")):
        disk = temp / f"{tag}.img"
        shutil.copyfile(scratch, disk)
        config = temp / f"{tag}.conf"
        rule = f'[inject-error]\nevent = "{event}"\niotype = "{operation}"\nerrno = "5"\n'
        if operation == "flush":
            # A background volume checkpoint can reach the device before fsync.
            rule += 'once = "off"\n'
        else:
            rule += f'once = "on"\nsector = "{start // 512}"\n'
        config.write_text(rule)
        boot(f"blkdebug:{config}:{disk}", shell(tag[0]), f"VFAT_{tag.upper()}_EIO", tag)
    boot(str(scratch), shell("b"), "VFAT_BUSY_FD_AND_MMAP_OK", "busy")
