#!/usr/bin/env bash
# Run the real archive selection, hashing, extraction and ISA validation using
# small local release fixtures. No network or physical board is required.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT
cd "${scratch}"
mkdir -p scripts rootfs/base qemu/etc vf2/etc fixture-bin
cp "${repo}"/scripts/{build_img,fetch-rootfs,rootfs-archives,rootfs-rocksdb}.sh scripts/
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

# Supply a tiny RV64GC Debian package through the real downloader and installer.
tools=(db_bench cache_bench ldb sst_dump)
libdir=deb/usr/lib/riscv64-linux-gnu
loader=ld-linux-riscv64-lp64d.so.1
mkdir -p deb/{DEBIAN,usr/bin,usr/share/doc/fixture} "${libdir}"
cat > deb/DEBIAN/control <<'CONTROL'
Package: fixture
Version: 1
Architecture: riscv64
Maintainer: PulseOS
Description: RocksDB packaging fixture
CONTROL
echo 'fixture license' > deb/usr/share/doc/fixture/copyright
echo '.global _start; _start: ret' | riscv64-linux-gnu-as -march=rv64gc -mabi=lp64d -o tool.o
riscv64-linux-gnu-ld -o tool tool.o
net_tools=(iperf3 darkhttpd weighttp)
mkdir -p net/opt/netbench/{bin,licenses,www}
for name in "${net_tools[@]}"; do
    cp tool "net/opt/netbench/bin/${name}"
done
echo 'network test fixture' > net/opt/netbench/www/index.html
echo 'network tool license' > net/opt/netbench/licenses/fixture
tar -cJf netbench-riscv64.tar.xz -C net ./opt/netbench
for name in "${tools[@]}"; do
    cp tool "deb/usr/bin/${name}"
done
riscv64-linux-gnu-ld -shared -o "${libdir}/libfixture.so.1" tool.o
cp "${libdir}/libfixture.so.1" "${libdir}/${loader}"
dpkg-deb --build deb rocksdb.deb
printf 'riscv64\t%s\thttps://fixture.invalid/rocksdb.deb\n' \
    "$(sha256sum rocksdb.deb | cut -d' ' -f1)" > scripts/rocksdb-packages.tsv

# Substitute the digests of the local release fixtures.
base_sha="$(sha256sum "${base}" | cut -d' ' -f1)"
suite_sha="$(sha256sum tests-20261120.tar.xz | cut -d' ' -f1)"
net_sha="$(sha256sum netbench-riscv64.tar.xz | cut -d' ' -f1)"
sed -i "s/^    \\[riscv64\\]=.*/    [riscv64]=${net_sha}/" scripts/rootfs-archives.sh
sed -i "s/^rv_ubuntu_sha=.*/rv_ubuntu_sha=${base_sha}/; s/^rv_tests_sha=.*/rv_tests_sha=${suite_sha}/" \
    scripts/rootfs-archives.sh
old=rootfs/base/rootfs-tests-riscv64.tar.xz
echo 'stale 20261116 cache' > "${old}"
echo 'truncated 20261120 download' > rootfs/base/rootfs-tests-20261120-riscv64.tar.xz
if scripts/build_img.sh riscv64 > build.log 2>&1; then
    echo 'QEMU accepted a cached test bundle with the wrong digest' >&2
    exit 1
fi
grep -F 'Missing tests rootfs input' build.log

# Serve the pinned rootfs, network overlay and RocksDB fixtures.
cat > fixture-bin/curl <<'CURL'
#!/usr/bin/env bash
set -eu
while [[ $# -gt 0 && "$1" != -o ]]; do shift; done
case "$3" in
    https://github.com/muou000/PulseOS/releases/download/rootfs-tests-20261120/rootfs-tests-riscv64.tar.xz)
        cp tests-20261120.tar.xz "$2" ;;
    https://github.com/muou000/PulseOS/releases/download/rootfs-tests-20261125/netbench-riscv64.tar.xz)
        cp netbench-riscv64.tar.xz "$2" ;;
    https://fixture.invalid/rocksdb.deb) cp rocksdb.deb "$2" ;;
    *) exit 1 ;;
esac
CURL
chmod +x fixture-bin/curl
export PATH="${PWD}/fixture-bin:${PATH}"
scripts/build_img.sh --fetch riscv64
grep -Fx 'stale 20261116 cache' "${old}"
cmp tests-20261120.tar.xz rootfs/base/rootfs-tests-20261120-riscv64.tar.xz

# With the original test suites cached, --fetch still repairs an incomplete overlay.
net_cache=rootfs/base/netbench-riscv64.tar.xz
echo 'truncated overlay' > "${net_cache}"
scripts/build_img.sh --fetch riscv64
cmp netbench-riscv64.tar.xz "${net_cache}"

# Both images build with only the cached archives available.
printf '#!/bin/sh\nexit 1\n' > fixture-bin/curl
RISCV_PLATFORM=visionfive2 scripts/build_img.sh --fetch riscv64
for image in rootfs-riscv64.img rootfs-visionfive2.img; do
    debugfs -R 'cat /opt/io_uring/liburing-tests/MANIFEST.txt' "${image}" 2>/dev/null | grep -Fx suite
    for name in "${net_tools[@]}"; do
        debugfs -R "cat /opt/netbench/bin/${name}" "${image}" 2>/dev/null | cmp - tool
        debugfs -R "stat /usr/bin/${name}" "${image}" 2>/dev/null | grep -F "Fast link dest: \"/opt/netbench/bin/${name}\""
    done
    debugfs -R 'cat /opt/netbench/www/index.html' "${image}" 2>/dev/null | grep -Fx 'network test fixture'
    debugfs -R 'cat /opt/netbench/licenses/fixture' "${image}" 2>/dev/null | grep -Fx 'network tool license'
    for name in "${tools[@]}"; do
        debugfs -R "stat /usr/bin/${name}" "${image}" 2>/dev/null | grep -F 'Mode:  0755'
        debugfs -R "cat /usr/bin/${name}" "${image}" 2>/dev/null | \
            grep -Fx "exec /opt/rocksdb/lib/${loader} --library-path /opt/rocksdb/lib /opt/rocksdb/bin/${name} \"\$@\""
        debugfs -R "cat /opt/rocksdb/bin/${name}" "${image}" 2>/dev/null | cmp - tool
    done
    for name in "${loader}" libfixture.so.1; do
        debugfs -R "cat /opt/rocksdb/lib/${name}" "${image}" 2>/dev/null | cmp - "${libdir}/${name}"
    done
    debugfs -R 'cat /opt/rocksdb/licenses/fixture' "${image}" 2>/dev/null | grep -Fx 'fixture license'
done
debugfs -R 'cat /etc/issue' rootfs-riscv64.img 2>/dev/null | grep -Fx 'Ubuntu 26.10'
debugfs -R 'cat /etc/issue' rootfs-visionfive2.img 2>/dev/null | grep -Fx 'Ubuntu 24.04.5'

# A legacy-named cache with the right digest can be reused without fetching.
mv rootfs/base/rootfs-tests-20261120-riscv64.tar.xz "${old}"
scripts/build_img.sh --fetch riscv64

# A test image always needs a verified network overlay, even with auto selection.
echo 'truncated overlay' > "${net_cache}"
for fault in corrupt missing; do
    [[ "${fault}" != missing ]] || rm "${net_cache}"
    if ROOTFS_VARIANT=auto scripts/build_img.sh riscv64 > build.log 2>&1; then
        echo "Image builder accepted a ${fault} network overlay" >&2
        exit 1
    fi
    grep -F 'Missing or corrupt netbench-riscv64.tar.xz' build.log
done
cp netbench-riscv64.tar.xz "${net_cache}"
scripts/build_img.sh riscv64

# Builds without --fetch reject both corrupt and missing cached packages.
cache=rootfs/base/rocksdb/riscv64/rocksdb.deb
for fault in corrupt missing; do
    if [[ "${fault}" == corrupt ]]; then
        echo 'truncated' > "${cache}"
    else
        rm "${cache}"
    fi
    if scripts/build_img.sh riscv64 > build.log 2>&1; then
        echo "Image builder accepted a ${fault} RocksDB package" >&2
        exit 1
    fi
    grep -F 'Missing or corrupt rocksdb.deb' build.log
done

# Base skips even a cached test archive; auto falls back when that archive is absent.
ROOTFS_VARIANT=base scripts/build_img.sh --fetch riscv64
debugfs -R 'stat /opt/netbench' rootfs-riscv64.img 2>&1 | grep -F 'File not found'
mv "${old}" saved-tests.tar.xz
ROOTFS_VARIANT=auto scripts/build_img.sh --fetch riscv64
debugfs -R 'stat /opt/netbench' rootfs-riscv64.img 2>&1 | grep -F 'File not found'

# Verify ELF ISA rejection independently of the archive digest checks.
cp "${base}" rootfs/base/alpine-minirootfs-riscv64.tar.gz
if ROOTFS_VARIANT=base RISCV_PLATFORM=visionfive2 scripts/build_img.sh riscv64 > build.log 2>&1; then
    echo 'VisionFive 2 accepted an ELF requiring V' >&2
    exit 1
fi
grep -F 'VisionFive 2 rootfs ELF requires the unsupported RISC-V vector extension' build.log
