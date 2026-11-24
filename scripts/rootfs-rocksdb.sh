#!/usr/bin/env bash
# Cache checksummed Debian packages or stage their RocksDB tools in a test rootfs.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
action="${1:-}"
arch="${2:-}"
case "${arch}" in
    riscv64) loader=ld-linux-riscv64-lp64d.so.1 ;;
    loongarch64) loader=ld-linux-loongarch-lp64d.so.1 ;;
    *) echo "Unsupported RocksDB architecture: ${arch}" >&2; exit 1 ;;
esac
cache="${repo}/rootfs/base/rocksdb/${arch}"
case "${action}" in
    fetch)
        mkdir -p "${cache}"
        tmp="$(mktemp -d "${cache}/.fetch-XXXXXX")"
        ;;
    install)
        stage="${3:?missing rootfs staging directory}"
        command -v dpkg-deb >/dev/null || { echo 'RocksDB tools require dpkg-deb on the build host' >&2; exit 1; }
        tmp="$(mktemp -d)"
        ;;
    *) echo "Usage: $0 {fetch ARCH|install ARCH STAGE}" >&2; exit 1 ;;
esac
trap 'rm -rf "${tmp}"' EXIT

while IFS=$'\t' read -r target sha url; do
    [[ "${target}" == "${arch}" ]] || continue
    name="${url##*/}"
    file="${cache}/${name}"
    if [[ ! -f "${file}" ]] || ! echo "${sha}  ${file}" | sha256sum -c --status; then
        if [[ "${action}" == install ]]; then
            echo "Missing or corrupt ${name}. Run scripts/fetch-rootfs.sh --tests --arch ${arch}." >&2
            exit 1
        fi
        echo "[${arch}] Downloading ${name}"
        curl -fsSL --retry 3 -o "${tmp}/${name}" "${url}"
        echo "${sha}  ${tmp}/${name}" | sha256sum -c -
        mv -f "${tmp}/${name}" "${file}"
    fi
    if [[ "${action}" == install ]]; then
        dpkg-deb -x "${file}" "${tmp}"
    fi
done < "${repo}/scripts/rocksdb-packages.tsv"
[[ "${action}" == install ]] || exit 0

# Keep Debian's loader and libraries private. The guest may run an older
# glibc (Loongnix, Ubuntu LTS) or use a different dynamic loader entirely.
prefix=/opt/rocksdb
dest="${stage}${prefix}"
libs="${tmp}/usr/lib/${arch}-linux-gnu"
[[ -x "${libs}/${loader}" ]] || { echo "Missing RocksDB loader: ${loader}" >&2; exit 1; }
mkdir -p "${dest}"/{bin,lib,licenses} "${stage}/usr/bin"
cp -a "${libs}/"*.so.* "${dest}/lib/"
for copyright in "${tmp}"/usr/share/doc/*/copyright; do
    package="${copyright%/copyright}"
    install -m644 "${copyright}" "${dest}/licenses/${package##*/}"
done
for tool in db_bench cache_bench ldb sst_dump; do
    install -m755 "${tmp}/usr/bin/${tool}" "${dest}/bin/${tool}"
    cat > "${stage}/usr/bin/${tool}" <<EOF
#!/bin/sh
exec ${prefix}/lib/${loader} --library-path ${prefix}/lib ${prefix}/bin/${tool} "\$@"
EOF
    chmod 755 "${stage}/usr/bin/${tool}"
done
echo "[${arch}] Installed RocksDB tools in ${prefix}"
