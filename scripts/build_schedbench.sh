#!/usr/bin/env bash
# Cross-build the rt-tests programs distributed with the QEMU test rootfs.
set -euo pipefail
export LC_ALL=C SOURCE_DATE_EPOCH=0
umask 022

script="$(realpath "${BASH_SOURCE[0]}")"
repo="$(cd "$(dirname "${script}")/.." && pwd)"
arch="${1:-}"
case "${arch}" in
    riscv64)     isa="-march=rv64gc -mabi=lp64d"; machine=RISC-V ;;
    loongarch64) isa="-march=loongarch64 -mabi=lp64d"; machine=LoongArch ;;
    *) echo "Usage: $0 {riscv64|loongarch64} [output-directory]" >&2; exit 1 ;;
esac
out="$(realpath -m "${2:-${repo}/target/schedbench}")"
mkdir -p "${out}"
work="$(mktemp -d "${out}/.schedbench-${arch}-XXXXXX")"
trap 'rm -rf "${work}"' EXIT
prefix="${work}/stage/opt/schedbench"

rt=rt-tests-2.11
numa=numactl-2.0.19
triplet="${arch}-linux-gnu"
if ! command -v "${triplet}-gcc" >/dev/null; then
    if [[ "${arch}" == loongarch64 ]]; then
        export PATH="${repo}/.tools/loongarch64/bin:${PATH}"
    else
        export PATH="${repo}/.tools/riscv64/usr/bin:${PATH}"
        export LD_LIBRARY_PATH="${repo}/.tools/riscv64/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
    fi
fi
export CC="${triplet}-gcc"
export CFLAGS="-O2 ${isa} -ffile-prefix-map=${work}=."
jobs="${JOBS:-$(nproc)}"

# The small upstream source archives travel with both ELF binaries.
mkdir -p "${prefix}"/{bin,src,licenses}
get_source() {
    local url="$1" sum="$2" name="${1##*/}"
    if [[ -n "${SCHEDBENCH_SOURCES:-}" ]]; then
        cp "${SCHEDBENCH_SOURCES}/${name}" "${prefix}/src/${name}"
    else
        curl -fLsS --retry 3 -o "${prefix}/src/${name}" "${url}"
    fi
    echo "${sum}  ${prefix}/src/${name}" | sha256sum -c -
    tar -xf "${prefix}/src/${name}" -C "${work}"
}
get_source "https://www.kernel.org/pub/linux/utils/rt-tests/${rt}.tar.xz" \
    c01ce99d4b86a99ef83fb75ddc97ddd7669eb85996a2c35bc9ad9e83ecad47bc
get_source "https://github.com/numactl/numactl/releases/download/v2.0.19/${numa}.tar.gz" \
    f2672a0381cb59196e9c246bf8bcc43d5568bc457700a697f1a1df762b9af884

cd "${work}/${numa}"
./configure --host="${triplet}" --disable-shared --enable-static
make -j"${jobs}" libnuma.la

cd "${work}/${rt}"
make -j"${jobs}" CROSS_COMPILE="${triplet}-" CFLAGS="${CFLAGS}" \
    CPPFLAGS="-D_GNU_SOURCE -Isrc/include -I../${numa}" \
    LDFLAGS="-static -L../${numa}/.libs" no_libcpupower=1 PYLIB= \
    hackbench cyclictest
for tool in hackbench cyclictest; do
    "${triplet}-strip" "${tool}"
    readelf -hW "${tool}" | grep -E "Machine: +${machine}$"
    if readelf -lW "${tool}" | grep INTERP || readelf -dW "${tool}" | grep NEEDED; then
        echo "Expected static ELF: ${tool}" >&2
        exit 1
    fi
    install -m755 "${tool}" "${prefix}/bin/"
done
install -m644 COPYING "${prefix}/licenses/rt-tests-GPL2"
install -m644 "${work}/${numa}/LICENSE.LGPL2.1" "${prefix}/licenses/libnuma-LGPL2.1"
install -m755 "${script}" "${prefix}/src/"

archive="schedbench-${arch}.tar.xz"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    -cJf "${work}/${archive}" -C "${work}/stage" ./opt/schedbench
mv -f "${work}/${archive}" "${out}/${archive}"
sha256sum "${out}/${archive}"
