#!/usr/bin/env bash
set -euo pipefail

ROOTFS_DIR="${ROOTFS_DIR:-rootfs}"
BASE_DIR="${BASE_DIR:-${ROOTFS_DIR}/base}"
OVERLAY_DIR="${OVERLAY_DIR:-${ROOTFS_DIR}/overlay}"
EXTRAS_DIR="${EXTRAS_DIR:-${ROOTFS_DIR}/extras}"
OUTPUT_DIR="${OUTPUT_DIR:-.}"

MIN_IMG_MIB="${MIN_IMG_MIB:-512}"
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
  ./build_img.sh all
  ./build_img.sh <arch>

Env:
  ROOTFS_DIR        rootfs metadata root (default: rootfs)
  BASE_DIR          base minirootfs dir (default: rootfs/base)
  OVERLAY_DIR       overlay dir (default: rootfs/overlay)
  EXTRAS_DIR        extras archive dir (default: rootfs/extras)
  OUTPUT_DIR        output image dir (default: .)
  MIN_IMG_MIB       minimum image size in MiB when auto-sized (default: 512)
  EXTRA_MARGIN_MIB  free-space margin in MiB when auto-sized (default: 128)
  SIZE_FACTOR_PERCENT
                    auto-size multiplier in percent (default: 180)
  IMG_SIZE          fixed image size (e.g. 128M, 1G). If set, overrides auto-size
USAGE
}

die() {
    echo "Error: $*" >&2
    exit 1
}

parse_size_to_mib() {
    local raw="$1"
    local bytes
    if have_cmd numfmt; then
        bytes="$(numfmt --from=iec "${raw}")"
    else
        local n unit
        if [[ "${raw}" =~ ^([0-9]+)([KkMmGgTt]?)$ ]]; then
            n="${BASH_REMATCH[1]}"
            unit="${BASH_REMATCH[2]}"
            case "${unit}" in
                "" ) bytes="${n}" ;;
                [Kk]) bytes=$((n * 1024)) ;;
                [Mm]) bytes=$((n * 1024 * 1024)) ;;
                [Gg]) bytes=$((n * 1024 * 1024 * 1024)) ;;
                [Tt]) bytes=$((n * 1024 * 1024 * 1024 * 1024)) ;;
                * ) die "Unsupported size suffix in IMG_SIZE=${raw}" ;;
            esac
        else
            die "Cannot parse IMG_SIZE=${raw}. Examples: 128M, 1G"
        fi
    fi
    echo $(((bytes + 1024 * 1024 - 1) / (1024 * 1024)))
}

find_base_tar() {
    local arch="$1"
    local candidates=()

    # Preferred fixed names.
    candidates+=(
        "${BASE_DIR}/alpine-minirootfs-${arch}.tar.gz"
        "${BASE_DIR}/alpine-minirootfs-${arch}.tar.xz"
        "${BASE_DIR}/alpine-minirootfs-${arch}.tar.zst"
    )

    local f
    for f in "${candidates[@]}"; do
        [[ -f "${f}" ]] && { echo "${f}"; return 0; }
    done

    # Compatible with official versioned naming.
    shopt -s nullglob
    local matches=(
        "${BASE_DIR}"/alpine-minirootfs-*-${arch}.tar.*
        "${BASE_DIR}/${arch}"/alpine-minirootfs*.tar.*
    )
    shopt -u nullglob

    if (( ${#matches[@]} > 0 )); then
        printf '%s\n' "${matches[@]}" | LC_ALL=C sort | tail -n 1
        return 0
    fi

    return 1
}

list_extra_archives() {
    local arch="$1"
    local candidates=(
        "${EXTRAS_DIR}/${arch}.tar"
        "${EXTRAS_DIR}/${arch}.tar.gz"
        "${EXTRAS_DIR}/${arch}.tgz"
        "${EXTRAS_DIR}/${arch}.tar.xz"
        "${EXTRAS_DIR}/${arch}.tar.zst"
    )
    local files=()
    local f
    for f in "${candidates[@]}"; do
        [[ -f "${f}" ]] && files+=("${f}")
    done

    shopt -s nullglob
    local dir_files=(
        "${EXTRAS_DIR}/${arch}"/*.tar
        "${EXTRAS_DIR}/${arch}"/*.tar.gz
        "${EXTRAS_DIR}/${arch}"/*.tgz
        "${EXTRAS_DIR}/${arch}"/*.tar.xz
        "${EXTRAS_DIR}/${arch}"/*.tar.zst
    )
    shopt -u nullglob
    files+=("${dir_files[@]}")

    if (( ${#files[@]} > 0 )); then
        printf '%s\n' "${files[@]}" | LC_ALL=C sort
    fi
}

apply_overlay_dir() {
    local src="$1"
    local dst="$2"
    if [[ -d "${src}" ]]; then
        (
            cd "${src}"
            tar -cf - --exclude='.gitkeep' --exclude='.gitignore' .
        ) | tar -xf - -C "${dst}"
    fi
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

    # Some LoongArch64 glibc binaries resolve their default search path via
    # /usr/lib64, while this image stages the GNU libc payload in /lib64.
    # Keep both locations available by pointing /usr/lib64 back at /lib64.
    mkdir -p "${stage_dir}/usr"
    ln -sfn ../lib64 "${usr_lib64}"
}

build_one_arch() {
    local arch="$1"
    local base_tar
    base_tar="$(find_base_tar "${arch}" || true)"

    [[ -n "${base_tar}" ]] || die "Missing base tar for ${arch}. Put alpine-minirootfs under ${BASE_DIR}."

    local tmpdir
    tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/pulseos-rootfs-${arch}-XXXXXX")"
    local stage_dir="${tmpdir}/stage"
    local tmp_img="${tmpdir}/rootfs-${arch}.img"
    mkdir -p "${stage_dir}"

    cleanup_one() {
        rm -rf "${tmpdir}"
    }
    trap cleanup_one RETURN

    echo "[${arch}] Extracting base: ${base_tar}"
    tar --no-same-owner -xaf "${base_tar}" -C "${stage_dir}"

    echo "[${arch}] Applying overlay"
    apply_overlay_dir "${OVERLAY_DIR}/common" "${stage_dir}"
    apply_overlay_dir "${OVERLAY_DIR}/${arch}" "${stage_dir}"

    local extras=()
    while IFS= read -r line; do
        [[ -n "${line}" ]] && extras+=("${line}")
    done < <(list_extra_archives "${arch}" || true)

    local extra
    for extra in "${extras[@]}"; do
        echo "[${arch}] Applying extras: ${extra}"
        tar --no-same-owner -xaf "${extra}" -C "${stage_dir}"
    done

    if [[ "${arch}" == "loongarch64" ]]; then
        patch_loongarch64_musl_sched_stubs "${stage_dir}"
        ensure_loongarch64_gnu_libdir_compat "${stage_dir}"
    fi

    local img_mib
    if [[ -n "${IMG_SIZE}" ]]; then
        img_mib="$(parse_size_to_mib "${IMG_SIZE}")"
    else
        local used_kib
        used_kib="$(du -sk "${stage_dir}" | awk '{print $1}')"
        local used_mib
        used_mib=$(((used_kib + 1023) / 1024))
        img_mib=$(((used_mib * SIZE_FACTOR_PERCENT + 99) / 100 + EXTRA_MARGIN_MIB))
        (( img_mib < MIN_IMG_MIB )) && img_mib="${MIN_IMG_MIB}"
    fi

    mkdir -p "${OUTPUT_DIR}"
    local out_img="${OUTPUT_DIR}/rootfs-${arch}.img"
    local fs_label="${FS_LABEL_PREFIX}-${arch}"
    fs_label="${fs_label:0:15}"

    echo "[${arch}] Building ext4 image (${img_mib} MiB): ${out_img}"
    truncate -s "${img_mib}M" "${tmp_img}"
    mkfs.ext4 -q -F -L "${fs_label}" -d "${stage_dir}" "${tmp_img}"
    mv -f "${tmp_img}" "${out_img}"

    local logical_size disk_usage
    logical_size="$(ls -lh "${out_img}" | awk '{print $5}')"
    disk_usage="$(du -h "${out_img}" | awk '{print $1}')"

    echo "[${arch}] Done. logical=${logical_size}, disk=${disk_usage}"
}

for cmd in tar mkfs.ext4 du awk truncate ls mv cp sort tail mktemp perl; do
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
