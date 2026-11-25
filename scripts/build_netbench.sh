#!/usr/bin/env bash
# Build one of the small, static overlays distributed with the test images.
set -euo pipefail
export LC_ALL=C SOURCE_DATE_EPOCH=0
umask 022

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
arch="${1:-}"
case "${arch}" in
    riscv64)     isa_flags="-march=rv64gc -mabi=lp64d"; machine=RISC-V ;;
    loongarch64) isa_flags="-march=loongarch64 -mabi=lp64d"; machine=LoongArch ;;
    *) echo "Usage: $0 {riscv64|loongarch64} [output-directory]" >&2; exit 1 ;;
esac
out="$(realpath -m "${2:-${repo}/target/netbench}")"
cache="$(realpath -m "${NETBENCH_CACHE:-${repo}/.tools/netbench-src}")"
mkdir -p "${cache}" "${out}"
work="$(mktemp -d "${out}/.netbench-${arch}-XXXXXX")"
trap 'rm -rf "${work}"' EXIT
stage="${work}/stage"
jobs="${JOBS:-$(nproc)}"
triplet="${arch}-linux-gnu"
if ! command -v "${triplet}-gcc" >/dev/null; then
    if [[ "${arch}" == loongarch64 ]]; then
        export PATH="${repo}/.tools/loongarch64/bin:${PATH}"
    else
        export PATH="${repo}/.tools/riscv64/usr/bin:${PATH}"
        export LD_LIBRARY_PATH="${repo}/.tools/riscv64/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
    fi
fi
export CC="${triplet}-gcc" AR="${triplet}-ar" RANLIB="${triplet}-ranlib" STRIP="${triplet}-strip"
export CFLAGS="-O2 ${isa_flags}"
for tool in "${CC}" "${AR}" "${RANLIB}" "${STRIP}"; do
    command -v "${tool}" >/dev/null || { echo "Missing cross tool: ${tool}" >&2; exit 1; }
done

netbench_source() {
    local url="$1" digest="$2" file="${cache}/$2" tmp
    if [[ ! -f "${file}" ]] || ! echo "${digest}  ${file}" | sha256sum -c --status; then
        tmp="$(mktemp "${cache}/.download-XXXXXX")"
        if curl -fLsS --retry 3 -o "${tmp}" "${url}" && echo "${digest}  ${tmp}" | sha256sum -c >&2; then
            mv -f "${tmp}" "${file}"
        else
            rm -f "${tmp}"
            return 1
        fi
    fi
    printf '%s\n' "${file}"
}

build_iperf3() (
    local release=iperf-3.22.1
    local source_archive
    source_archive=$(netbench_source "https://downloads.es.net/pub/iperf/${release}.tar.gz" \
        de018b5252e2a7068c89fac8b35a295d83334f2b7814aa9532a2a8107b04a4a9)
    tar -xzf "$source_archive"
    cd "$release"

    ./configure --build="$(./config/config.guess)" --host="$triplet" \
        --enable-static-bin --disable-shared --without-openssl --without-sctp
    make -C src -j"$jobs" iperf3
    "$STRIP" src/iperf3
    install -Dm755 src/iperf3 "$stage/opt/netbench/bin/iperf3"
    install -Dm644 LICENSE "$stage/opt/netbench/licenses/iperf3-LICENSE"
)

build_http() {
    local darkhttpd=darkhttpd-1.17 weighttp=weighttp-weighttp-0.5
    local archive prefix="${stage}/opt/netbench"
    local -a flags
    read -r -a flags <<< "${CFLAGS}"

    archive="$(netbench_source "https://codeload.github.com/emikulic/darkhttpd/tar.gz/refs/tags/v1.17" \
        4fee9927e2d8bb0a302f0dd62f9ff1e075748fa9f5162c9481a7a58b41462b56)"
    tar -xzf "${archive}"
    archive="$(netbench_source "https://codeload.github.com/lighttpd/weighttp/tar.gz/refs/tags/weighttp-0.5" \
        5900600cc108041d0e38abd02354d7d3b14649c827c4266c0d550b87904f1141)"
    tar -xzf "${archive}"

    # An abortive close is optional. PulseOS returns ENOPROTOOPT for SO_LINGER.
    patch --fuzz=0 -d "${weighttp}" -p1 < "${repo}/scripts/weighttp-linger.patch"
    "${CC}" "${flags[@]}" -static "${darkhttpd}/darkhttpd.c" -o darkhttpd
    "${CC}" "${flags[@]}" -static -pthread '-DPACKAGE_VERSION="0.5-pulse1"' \
        "${weighttp}/src/weighttp.c" -lm -o weighttp
    "${STRIP}" darkhttpd weighttp

    install -d "${prefix}/bin" "${prefix}/licenses"
    install -m755 darkhttpd weighttp "${prefix}/bin/"
    install -m644 "${darkhttpd}/COPYING" "${prefix}/licenses/darkhttpd"
    install -m644 "${weighttp}/COPYING" "${prefix}/licenses/weighttp"
}

cd "${work}"
mkdir -p "${stage}/opt/netbench/"{bin,licenses,www}
build_iperf3
build_http
printf '%s\n' '<!doctype html><title>PulseOS</title><p>PulseOS netbench</p>' > "${stage}/opt/netbench/www/index.html"
for tool in iperf3 darkhttpd weighttp; do
    elf="${stage}/opt/netbench/bin/${tool}"
    header="$(readelf -hW "${elf}")"
    segments="$(readelf -lW "${elf}")"
    dynamic="$(readelf -dW "${elf}")"
    if ! grep -Eq "Machine: +${machine}$" <<< "${header}" || grep -q INTERP <<< "${segments}" || grep -q NEEDED <<< "${dynamic}"; then
        echo "Expected a static ${arch} ELF: ${elf}" >&2
        exit 1
    fi
    if [[ "${arch}" == riscv64 ]] && readelf -A "${elf}" | grep -E 'Tag_RISCV_arch:.*_(v[0-9]|zv)' >/dev/null; then
        echo "Unsupported vector extension for VisionFive 2: ${elf}" >&2
        exit 1
    fi
done
name="netbench-${arch}.tar.xz"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    -cJf "${work}/${name}" -C "${stage}" ./opt/netbench
mv -f "${work}/${name}" "${out}/${name}"
sha256sum "${out}/${name}"
