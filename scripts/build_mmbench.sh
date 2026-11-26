#!/usr/bin/env bash
# Build the memory management workloads for the QEMU test rootfs.
set -euo pipefail
export LC_ALL=C SOURCE_DATE_EPOCH=0
umask 022

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
arch="${1:-}"
case "${arch}" in
    riscv64)     isa_flags=(-march=rv64gc -mabi=lp64d); machine=RISC-V ;;
    loongarch64) isa_flags=(-march=loongarch64 -mabi=lp64d); machine=LoongArch ;;
    *) echo "Usage: $0 {riscv64|loongarch64} [output-directory]" >&2; exit 1 ;;
esac
cc="${arch}-linux-gnu-gcc"
if ! command -v "${cc}" >/dev/null; then
    if [[ "${arch}" == loongarch64 ]]; then
        export PATH="${repo}/.tools/loongarch64/bin:${PATH}"
    else
        export PATH="${repo}/.tools/riscv64/usr/bin:${PATH}"
        export LD_LIBRARY_PATH="${repo}/.tools/riscv64/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
    fi
fi
command -v "${cc}" >/dev/null || { echo "Missing cross compiler: ${cc}" >&2; exit 1; }

out="$(realpath -m "${2:-${repo}/target/mmbench}")"
cache="${MMBENCH_CACHE:-${repo}/.tools/mmbench-src}"
mkdir -p "${cache}" "${out}"
cache="$(realpath "${cache}")"
work="$(mktemp -d "${out}/.mmbench-${arch}-XXXXXX")"
trap 'rm -rf "${work}"' EXIT
cd "${work}"

# SQLite publishes SHA3-256 for both source archives on its download page.
version=3540100
fetch() (
    local name="$1" expected="$2" digest tmp
    if [[ -f "${cache}/${name}" ]]; then
        digest="$(openssl dgst -sha3-256 -r "${cache}/${name}")"
        if [[ "${digest%% *}" == "${expected}" ]]; then return; fi
    fi
    tmp="$(mktemp "${cache}/.download-XXXXXX")"
    trap 'rm -f "${tmp}"' EXIT
    curl -fsSL --retry 3 "https://www.sqlite.org/2026/${name}" -o "${tmp}"
    digest="$(openssl dgst -sha3-256 -r "${tmp}")"
    [[ "${digest%% *}" == "${expected}" ]] || { echo "Invalid SHA3-256: ${name}" >&2; return 1; }
    mv -f "${tmp}" "${cache}/${name}"
)
fetch "sqlite-src-${version}.zip" 877c6f4996ce7adb368686bce21638de9e3d91534832ad3d9d119037d1bc22ad
fetch "sqlite-amalgamation-${version}.zip" 92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30

python3 - "${cache}" "${version}" <<'PY'
from pathlib import Path
import sys
from zipfile import ZipFile

cache, version = sys.argv[1:]
for kind, files in [
    ("src", ("test/speedtest1.c", "LICENSE.md")),
    ("amalgamation", ("sqlite3.c", "sqlite3.h")),
]:
    prefix = f"sqlite-{kind}-{version}"
    with ZipFile(Path(cache) / f"{prefix}.zip") as archive:
        for name in files:
            Path(Path(name).name).write_bytes(archive.read(f"{prefix}/{name}"))
PY

dest="stage/opt/mmbench"
mkdir -p "${dest}/bin"
"${cc}" -O2 "${isa_flags[@]}" -static -s -DSQLITE_OMIT_LOAD_EXTENSION \
    -I. speedtest1.c sqlite3.c -pthread -lm -o "${dest}/bin/speedtest1"
"${cc}" -O2 "${isa_flags[@]}" -static -s -Wall -Wextra \
    "${repo}/tests/mmbench/anon_residency.c" -o "${dest}/bin/anon_residency"
install -m644 LICENSE.md "${dest}/sqlite-LICENSE.md"
for elf in "${dest}"/bin/*; do
    header="$(readelf -hW "${elf}")"
    segments="$(readelf -lW "${elf}")"
    if ! grep -Eq "Machine: +${machine}$" <<< "${header}" || grep -q INTERP <<< "${segments}"; then
        echo "Expected a static ${arch} ELF: ${elf}" >&2
        exit 1
    fi
done

name="mmbench-${arch}.tar.xz"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    -cJf "${name}" -C stage ./opt/mmbench
mv -f "${name}" "${out}/${name}"
sha256sum "${out}/${name}"
