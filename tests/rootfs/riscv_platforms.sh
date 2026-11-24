#!/usr/bin/env bash
# Run the real archive selection, hashing, extraction and ISA validation using
# small local release fixtures. No network or physical board is required.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT
cd "${scratch}"
mkdir -p scripts rootfs/base qemu/etc vf2/etc fixture-bin
cp "${repo}"/scripts/{build_img,fetch-rootfs,rootfs-riscv64}.sh scripts/
export ROOTFS_VARIANT=tests IMG_SIZE=8M RISCV_PLATFORM=qemu-virt
echo 'Ubuntu 26.10' > qemu/etc/issue
echo 'Ubuntu 24.04.5' > vf2/etc/issue
riscv64-linux-gnu-as -march=rv64gcv -mabi=lp64d -o qemu/vector.o /dev/null
base=rootfs/base/ubuntu-base-26.10-base-riscv64.tar.gz
tar -czf "${base}" -C qemu .

mkdir -p vf2/opt/{lmbench,ltp,sysbench,unixbench,io_uring/liburing-tests}
mkdir -p vf2/usr/{bin,local/bin,local/share/sysbench}
touch vf2/usr/bin/{lat_syscall,bw_pipe,lat_pipe,sysbench,fio} vf2/usr/local/bin/sysbench
echo suite > vf2/opt/io_uring/liburing-tests/MANIFEST.txt
tar -cJf tests-20261120.tar.xz -C vf2 .

# Substitute only the two release digests for the fixture archives.
base_sha="$(sha256sum "${base}" | cut -d' ' -f1)"
suite_sha="$(sha256sum tests-20261120.tar.xz | cut -d' ' -f1)"
sed -i "s/^rv_ubuntu_sha=.*/rv_ubuntu_sha=${base_sha}/; s/^rv_tests_sha=.*/rv_tests_sha=${suite_sha}/" \
    scripts/rootfs-riscv64.sh
old=rootfs/base/rootfs-tests-riscv64.tar.xz
echo 'stale 20261116 cache' > "${old}"
echo 'truncated 20261120 download' > rootfs/base/rootfs-tests-20261120-riscv64.tar.xz
if scripts/build_img.sh riscv64 > build.log 2>&1; then
    echo 'QEMU accepted a cached test bundle with the wrong digest' >&2
    exit 1
fi
grep -F 'Missing tests rootfs input' build.log

# Serve only the newer release asset requested by the fetcher.
cat > fixture-bin/curl <<'CURL'
#!/usr/bin/env bash
set -eu
while [[ $# -gt 0 && "$1" != -o ]]; do shift; done
[[ "$3" == https://github.com/muou000/PulseOS/releases/download/rootfs-tests-20261120/rootfs-tests-riscv64.tar.xz ]]
cp tests-20261120.tar.xz "$2"
CURL
chmod +x fixture-bin/curl
export PATH="${PWD}/fixture-bin:${PATH}"
scripts/build_img.sh --fetch riscv64
grep -Fx 'stale 20261116 cache' "${old}"
cmp tests-20261120.tar.xz rootfs/base/rootfs-tests-20261120-riscv64.tar.xz

# Both images build with only the cached archives available.
printf '#!/bin/sh\nexit 1\n' > fixture-bin/curl
RISCV_PLATFORM=visionfive2 scripts/build_img.sh --fetch riscv64
for image in rootfs-riscv64.img rootfs-visionfive2.img; do
    debugfs -R 'cat /opt/io_uring/liburing-tests/MANIFEST.txt' "${image}" 2>/dev/null | grep -Fx suite
done
debugfs -R 'cat /etc/issue' rootfs-riscv64.img 2>/dev/null | grep -Fx 'Ubuntu 26.10'
debugfs -R 'cat /etc/issue' rootfs-visionfive2.img 2>/dev/null | grep -Fx 'Ubuntu 24.04.5'

# A legacy-named cache with the right digest can be reused without fetching.
mv rootfs/base/rootfs-tests-20261120-riscv64.tar.xz "${old}"
scripts/build_img.sh --fetch riscv64

# Verify ELF ISA rejection independently of the archive digest checks.
cp "${base}" rootfs/base/alpine-minirootfs-riscv64.tar.gz
if ROOTFS_VARIANT=base RISCV_PLATFORM=visionfive2 scripts/build_img.sh riscv64 > build.log 2>&1; then
    echo 'VisionFive 2 accepted an ELF requiring V' >&2
    exit 1
fi
grep -F 'VisionFive 2 rootfs ELF requires the unsupported RISC-V vector extension' build.log
