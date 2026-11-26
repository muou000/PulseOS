#!/usr/bin/env bash
# Build the PulseOS rootfs images (riscv64/loongarch64) from the base
# tarballs provided by scripts/fetch-rootfs.sh.
# Usage: scripts/build_img.sh [all|riscv64|loongarch64]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_DIR="${REPO_ROOT}/rootfs/base"
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}}"
RISCV_PLATFORM="${RISCV_PLATFORM:-qemu-virt}"
source "${REPO_ROOT}/scripts/rootfs-archives.sh"

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
  scripts/build_img.sh [--fetch] [all|riscv64|loongarch64]   (default: \${ARCH:-riscv64})

Run scripts/fetch-rootfs.sh to cache the rootfs archives and test tools
before building offline, or pass --fetch to download missing inputs.

Env:
  OUTPUT_DIR          image output directory (default: repo root)
  RISCV_PLATFORM      qemu-virt (default, Ubuntu 26.10) or visionfive2 (RV64GC)
  ROOTFS_VARIANT      tarball variant: auto (default, prefers tests), tests, or base
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

first_cached() {
    local name
    for name in "$@"; do
        if [[ -f "${BASE_DIR}/${name}" ]]; then
            echo "${BASE_DIR}/${name}"
            return
        fi
    done
    return 1
}

# Emit the base archive, followed by the optional test overlay.
rootfs_archives() {
    local arch="$1" variant="$2" suites=""
    if [[ "${variant}" != base ]]; then
        if [[ "${arch}" == riscv64 ]]; then
            if ! suites="$(riscv_test_archive)"; then
                # Auto may use a minimal image if no test bundle was requested
                # or cached. A stale bundle must not silently drop test suites.
                [[ "${variant}" == auto && ! -e "${BASE_DIR}/${rv_tests_cache}" \
                    && ! -e "${BASE_DIR}/${rv_tests_asset}" ]] || return 1
            fi
        else
            suites="$(first_cached rootfs-tests-loongarch64.tar.{xz,gz})" || [[ "${variant}" == auto ]] || return 1
        fi
    fi
    if [[ "${arch}" == riscv64 && "${RISCV_PLATFORM}" == qemu-virt ]]; then
        verified_archive "${rv_ubuntu_sha}" "${BASE_DIR}/${rv_ubuntu}" || return 1
        if [[ -n "${suites}" ]]; then echo "${suites}"; fi
    elif [[ -n "${suites}" ]]; then
        echo "${suites}"
    elif [[ "${arch}" == loongarch64 ]]; then
        first_cached base-rootfs-loongarch64.tar.{xz,gz}
    elif [[ "${variant}" == auto ]]; then
        first_cached ubuntu-base-24.04.5-base-riscv64.tar.gz alpine-minirootfs-riscv64.tar.{gz,xz}
    else
        first_cached alpine-minirootfs-riscv64.tar.{gz,xz} ubuntu-base-24.04.5-base-riscv64.tar.gz
    fi
}

validate_riscv_elf_isa() {
    local stage_dir="$1" hit
    command -v readelf >/dev/null 2>&1 || die "Missing command: readelf (required for RISC-V ISA validation)"
    hit="$(find "${stage_dir}" -type f -exec sh -c 'readelf -A "$@" 2>/dev/null || true' _ {} + \
        | awk '
            /^File: / { cur = substr($0, 7) }
            /Tag_RISCV_arch:/ && !found {
                split($0, a, "\"")
                if (a[2] ~ /(^|_)(v[0-9]|zv)/) {
                    print cur ? cur : "<elf>"
                    found = 1
                }
            }
        ')"
    if [[ -n "${hit}" ]]; then
        die "VisionFive 2 rootfs ELF requires the unsupported RISC-V vector extension: ${hit}"
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

    # Keep /usr/lib64 available when a base tarball only stages the GNU libc
    # payload in /lib64. Standard layouts (e.g. Ubuntu) already ship a real
    # /usr/lib64 and are left untouched.
    [[ ! -e "${usr_lib64}" ]] || return 0
    mkdir -p "${stage_dir}/usr"
    ln -sfn ../lib64 "${usr_lib64}"
}

build_one_arch() (
    local arch="$1" name="$1" variant="${ROOTFS_VARIANT:-auto}"
    local inputs fetch_tools="${fetch}"
    if [[ "${arch}" == riscv64 && "${RISCV_PLATFORM}" == visionfive2 ]]; then
        name=visionfive2
    fi
    if ! inputs="$(rootfs_archives "${arch}" "${variant}")"; then
        [[ "${fetch}" == yes ]] || die "Missing ${variant} rootfs input for ${name}. Run with --fetch."
        local fetch_variant="${variant}"
        [[ "${fetch_variant}" != auto ]] || fetch_variant=tests
        "${REPO_ROOT}/scripts/fetch-rootfs.sh" "--${fetch_variant}" --arch "${arch}"
        fetch_tools=no
        inputs="$(rootfs_archives "${arch}" "${variant}")" || die "Missing archives for ${name} after fetch"
    fi
    local archives=()
    mapfile -t archives <<< "${inputs}"
    local netbench="" mmbench="" schedbench=""
    if [[ "${archives[-1]}" == */rootfs-tests-* && "${name}" != visionfive2 ]]; then
        if [[ "${fetch_tools}" == yes ]]; then
            fetch_qemu_test_overlays "${arch}"
        fi
        netbench="$(verified_archive "${netbench_sha[${arch}]}" "${BASE_DIR}/netbench-${arch}.tar.xz")" \
            || die "Missing or corrupt netbench-${arch}.tar.xz. Run scripts/fetch-rootfs.sh --tests --arch ${arch}."
        mmbench="$(verified_archive "${mmbench_sha[${arch}]}" "${BASE_DIR}/mmbench-${arch}.tar.xz")" \
            || die "Missing or corrupt mmbench-${arch}.tar.xz. Run scripts/fetch-rootfs.sh --tests --arch ${arch}."
        schedbench="$(verified_archive "${schedbench_sha[${arch}]}" "${BASE_DIR}/schedbench-${arch}.tar.xz")" \
            || die "Missing or corrupt schedbench-${arch}.tar.xz. Run scripts/fetch-rootfs.sh --tests --arch ${arch}."
    fi

    local tmpdir stage_dir tmp_img
    tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/pulseos-rootfs-${name}-XXXXXX")"
    trap 'rm -rf "${tmpdir}"' EXIT
    stage_dir="${tmpdir}/stage"
    tmp_img="${tmpdir}/rootfs-${name}.img"
    mkdir -p "${stage_dir}"

    echo "[${name}] Extracting base: ${archives[0]}"
    tar --no-same-owner -xaf "${archives[0]}" -C "${stage_dir}"
    if (( ${#archives[@]} == 2 )); then
        echo "[${name}] Installing bundled test programs from: ${archives[1]}"
        tar --no-same-owner -xaf "${archives[1]}" -C "${stage_dir}" \
            ./opt/{lmbench,ltp,sysbench,unixbench,io_uring/liburing-tests} \
            ./usr/bin/{lat_syscall,bw_pipe,lat_pipe,sysbench,fio} \
            ./usr/local/bin/sysbench ./usr/local/share/sysbench
    fi
    # Base tarballs carry restrictive modes (read-only dirs, 000 files like
    # /etc/gshadow); normalize owner rwx so patches, mkfs -d population and
    # cleanup can always access the stage. Exec bits are preserved.
    chmod -R u+rwX "${stage_dir}"

    if [[ "${archives[-1]}" == */rootfs-tests-* ]]; then
        if [[ "${fetch_tools}" == yes ]]; then
            "${REPO_ROOT}/scripts/rootfs-rocksdb.sh" fetch "${arch}"
        fi
        "${REPO_ROOT}/scripts/rootfs-rocksdb.sh" install "${arch}" "${stage_dir}"
    fi
    if [[ -n "${netbench}" ]]; then
        echo "[${name}] Installing network tools from: ${netbench}"
        tar --no-same-owner -xaf "${netbench}" -C "${stage_dir}" ./opt/netbench
        local tool
        for tool in iperf3 darkhttpd weighttp; do
            [[ -x "${stage_dir}/opt/netbench/bin/${tool}" ]] || die "Missing network tool: ${tool}"
            ln -sf "/opt/netbench/bin/${tool}" "${stage_dir}/usr/bin/${tool}"
        done
        echo "[${name}] Installing memory workload from: ${mmbench}"
        tar --no-same-owner -xaf "${mmbench}" -C "${stage_dir}" ./opt/mmbench
        for tool in speedtest1 anon_residency; do
            [[ -f "${stage_dir}/opt/mmbench/bin/${tool}" && -x "${stage_dir}/opt/mmbench/bin/${tool}" ]] \
                || die "Missing mmbench executable: ${tool}"
        done
        echo "[${name}] Installing scheduler tools from: ${schedbench}"
        tar --no-same-owner -xaf "${schedbench}" -C "${stage_dir}" ./opt/schedbench
        for tool in hackbench cyclictest; do
            [[ -x "${stage_dir}/opt/schedbench/bin/${tool}" ]] || die "Missing scheduler tool: ${tool}"
            ln -sf "/opt/schedbench/bin/${tool}" "${stage_dir}/usr/bin/${tool}"
        done
    fi

    if [[ "${arch}" == "loongarch64" ]]; then
        patch_loongarch64_musl_sched_stubs "${stage_dir}"
        ensure_loongarch64_gnu_libdir_compat "${stage_dir}"
    elif [[ "${RISCV_PLATFORM}" == visionfive2 ]]; then
        validate_riscv_elf_isa "${stage_dir}"
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
    local out_img="${OUTPUT_DIR}/rootfs-${name}.img"
    local fs_label="${FS_LABEL_PREFIX}-${name}"
    fs_label="${fs_label:0:15}"

    echo "[${name}] Building ext4 image (${img_mib} MiB): ${out_img}"
    truncate -s "${img_mib}M" "${tmp_img}"
    mkfs.ext4 -q -F -O ^has_journal,^metadata_csum -L "${fs_label}" -d "${stage_dir}" "${tmp_img}"
    mv -f "${tmp_img}" "${out_img}"

    local logical_size disk_usage
    logical_size="$(ls -lh "${out_img}" | awk '{print $5}')"
    disk_usage="$(du -h "${out_img}" | awk '{print $1}')"

    echo "[${name}] Done. logical=${logical_size}, disk=${disk_usage}"
)

for cmd in tar mkfs.ext4 perl mktemp truncate du awk mv; do
    have_cmd "${cmd}" || die "Missing command: ${cmd}"
done

case "${RISCV_PLATFORM}" in
    qemu-virt|visionfive2) ;;
    *) die "Unknown RISCV_PLATFORM '${RISCV_PLATFORM}'" ;;
esac
case "${ROOTFS_VARIANT:-auto}" in
    auto|tests|base) ;;
    *) die "Unknown ROOTFS_VARIANT '${ROOTFS_VARIANT}'" ;;
esac
fetch=no
if [[ "${1:-}" == --fetch ]]; then
    fetch=yes
    shift
fi
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
