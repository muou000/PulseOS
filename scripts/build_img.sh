#!/usr/bin/env bash
# Build the PulseOS rootfs images (riscv64/loongarch64) from the base
# tarballs provided by scripts/fetch-rootfs.sh.
# Usage: scripts/build_img.sh [all|riscv64|loongarch64]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_DIR="${REPO_ROOT}/rootfs/base"
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}}"

MIN_IMG_MIB="${MIN_IMG_MIB:-128}"
EXTRA_MARGIN_MIB="${EXTRA_MARGIN_MIB:-128}"
SIZE_FACTOR_PERCENT="${SIZE_FACTOR_PERCENT:-180}"
IMG_SIZE="${IMG_SIZE:-}"
FS_LABEL_PREFIX="${FS_LABEL_PREFIX:-pulse}"

ARCHES=(riscv64 loongarch64)

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

usage() {
    cat <<USAGE
Usage:
  scripts/build_img.sh [all|riscv64|loongarch64]   (default: \${ARCH:-riscv64})

Base tarballs are expected under rootfs/base; run scripts/fetch-rootfs.sh
if they are missing.

Env:
  OUTPUT_DIR          image output directory (default: repo root)
  IMG_SIZE            fixed image size (e.g. 128M, 1G); overrides auto-size
  MIN_IMG_MIB         minimum auto-sized image size in MiB (default: 128)
  EXTRA_MARGIN_MIB    free-space margin in MiB when auto-sized (default: 128)
  SIZE_FACTOR_PERCENT auto-size multiplier in percent (default: 180)
USAGE
}

die() {
    echo "Error: $*" >&2
    exit 1
}

parse_size_to_mib() {
    local raw="$1" n unit bytes
    [[ "${raw}" =~ ^([0-9]+)([KkMmGg]?)$ ]] \
        || die "Cannot parse IMG_SIZE=${raw}. Examples: 128M, 1G"
    n="${BASH_REMATCH[1]}"
    unit="${BASH_REMATCH[2]}"
    case "${unit}" in
        "" ) bytes="${n}" ;;
        [Kk]) bytes=$((n * 1024)) ;;
        [Mm]) bytes=$((n * 1024 * 1024)) ;;
        [Gg]) bytes=$((n * 1024 * 1024 * 1024)) ;;
    esac
    echo $(((bytes + 1048575) / 1048576))
}

find_base_tar() {
    local arch="$1" f
    for f in \
        "${BASE_DIR}/base-rootfs-${arch}.tar.xz" \
        "${BASE_DIR}/base-rootfs-${arch}.tar.gz"
    do
        [[ -f "${f}" ]] && { echo "${f}"; return 0; }
    done
    return 1
}

patch_loongarch64_musl_sched_stubs() {
    local stage_dir="$1"
    local ld_musl="${stage_dir}/lib64/ld-musl-loongarch-lp64d.so.1"

    [[ -f "${ld_musl}" ]] || return 0

    # Alpine's current loongarch64 musl keeps a few scheduler entry points as
    # ENOSYS stubs.  rt-tests/cyclictest calls these libc symbols directly, so
    # the kernel never sees sched_getparam/sched_getscheduler unless the loader
    # forwards them to the Linux syscalls.
    perl -0pi -e '
        s/\x63\xc0\xff\x02\x04\x68\xbf\x02\x61\x20\xc0\x29\xff\x83\xbf\x54/\x0b\xe4\x81\x02\x00\x00\x2b\x00\x84\x80\x40\x00\x20\x00\x00\x4c/g;
        s/\x63\xc0\xff\x02\x04\x68\xbf\x02\x61\x20\xc0\x29\xff\x63\xbf\x54/\x0b\xe0\x81\x02\x00\x00\x2b\x00\x84\x80\x40\x00\x20\x00\x00\x4c/g;
        s/\x63\xc0\xff\x02\x04\x68\xbf\x02\x61\x20\xc0\x29\xff\x1f\xbf\x54/\x0b\xd8\x81\x02\x00\x00\x2b\x00\x84\x80\x40\x00\x20\x00\x00\x4c/g;
        s/\x63\xc0\xff\x02\x04\x68\xbf\x02\x61\x20\xc0\x29\xff\xff\xbe\x54/\x0b\xdc\x81\x02\x00\x00\x2b\x00\x84\x80\x40\x00\x20\x00\x00\x4c/g;
    ' "${ld_musl}"
}

ensure_loongarch64_gnu_libdir_compat() {
    local stage_dir="$1"
    local usr_lib64="${stage_dir}/usr/lib64"

    # Keep /usr/lib64 available when a base tarball only stages the GNU libc
    # payload in /lib64. Standard layouts (e.g. Ubuntu) already ship a real
    # /usr/lib64 and are left untouched.
    [[ ! -e "${usr_lib64}" ]] || return 0
    mkdir -p "${stage_dir}/usr"
    ln -sfn ../lib64 "${usr_lib64}"
}

build_one_arch() {
    local arch="$1" base_tar
    base_tar="$(find_base_tar "${arch}")" \
        || die "Missing base tar for ${arch}. Run scripts/fetch-rootfs.sh first."

    local tmpdir stage_dir tmp_img
    tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/pulseos-rootfs-${arch}-XXXXXX")"
    stage_dir="${tmpdir}/stage"
    tmp_img="${tmpdir}/rootfs-${arch}.img"
    mkdir -p "${stage_dir}"

    cleanup_one() {
        rm -rf "${tmpdir}"
    }
    trap cleanup_one RETURN

    echo "[${arch}] Extracting base: ${base_tar}"
    tar --no-same-owner -xaf "${base_tar}" -C "${stage_dir}"
    # Base tarballs carry restrictive modes (read-only dirs, 000 files like
    # /etc/gshadow); normalize owner rwx so patches, mkfs -d population and
    # cleanup can always access the stage. Exec bits are preserved.
    chmod -R u+rwX "${stage_dir}"

    if [[ "${arch}" == "loongarch64" ]]; then
        patch_loongarch64_musl_sched_stubs "${stage_dir}"
        ensure_loongarch64_gnu_libdir_compat "${stage_dir}"
    fi

    local img_mib
    if [[ -n "${IMG_SIZE}" ]]; then
        img_mib="$(parse_size_to_mib "${IMG_SIZE}")"
    else
        local used_mib
        used_mib=$((( $(du -sk "${stage_dir}" | awk '{print $1}') + 1023) / 1024))
        img_mib=$(((used_mib * SIZE_FACTOR_PERCENT + 99) / 100 + EXTRA_MARGIN_MIB))
        (( img_mib < MIN_IMG_MIB )) && img_mib="${MIN_IMG_MIB}"
    fi

    mkdir -p "${OUTPUT_DIR}"
    local out_img="${OUTPUT_DIR}/rootfs-${arch}.img"
    local fs_label="${FS_LABEL_PREFIX}-${arch}"
    fs_label="${fs_label:0:15}"

    echo "[${arch}] Building ext4 image (${img_mib} MiB): ${out_img}"
    truncate -s "${img_mib}M" "${tmp_img}"
    mkfs.ext4 -q -F -O ^has_journal,^metadata_csum -L "${fs_label}" -d "${stage_dir}" "${tmp_img}"
    mv -f "${tmp_img}" "${out_img}"

    local logical_size disk_usage
    logical_size="$(ls -lh "${out_img}" | awk '{print $5}')"
    disk_usage="$(du -h "${out_img}" | awk '{print $1}')"

    echo "[${arch}] Done. logical=${logical_size}, disk=${disk_usage}"
}

for cmd in tar mkfs.ext4 perl mktemp truncate du awk mv; do
    have_cmd "${cmd}" || die "Missing command: ${cmd}"
done

TARGET="${1:-${ARCH:-riscv64}}"

case "${TARGET}" in
    all)
        for arch in "${ARCHES[@]}"; do
            build_one_arch "${arch}"
        done
        ;;
    riscv64|loongarch64)
        build_one_arch "${TARGET}"
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        die "Unsupported target: ${TARGET}. Use all/riscv64/loongarch64"
        ;;
esac
