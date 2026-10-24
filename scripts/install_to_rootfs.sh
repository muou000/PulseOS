#!/usr/bin/env bash
# Install files or directories into a PulseOS rootfs ext2/3/4 image using debugfs.
# Usage:
#   scripts/install_to_rootfs.sh [OPTIONS] <IMAGE> <HOST_SRC> <GUEST_DST>
#   scripts/install_to_rootfs.sh [OPTIONS] <IMAGE> <HOST_SRC>... <GUEST_DIR>
set -euo pipefail

usage() {
    cat << 'EOF'
Usage:
  scripts/install_to_rootfs.sh [OPTIONS] <IMAGE> <HOST_SRC> <GUEST_DST>
  scripts/install_to_rootfs.sh [OPTIONS] <IMAGE> <HOST_SRC>... <GUEST_DIR>

Arguments:
  IMAGE         Path to rootfs ext4 image (e.g. disk.img, disk-la.img)
  HOST_SRC      Source file or directory on the host
  GUEST_DST     Destination file path or directory inside the guest filesystem

Options:
  -m, --mode MODE    Explicit octal file mode (e.g., 0755 or 0644).
                     Default: auto-detected (0755 if executable on host, else 0644).
  -f, --force        Overwrite destination files if they already exist (default: enabled).
  -n, --dry-run      Print operations without modifying the image.
  -v, --verbose      Enable verbose output.
  -h, --help         Show this help message.

Examples:
  # Install single executable to /bin:
  scripts/install_to_rootfs.sh disk.img build/bw_pipe /bin/bw_pipe

  # Install multiple binaries to /usr/bin:
  scripts/install_to_rootfs.sh disk.img build/lat_pipe build/bw_pipe /usr/bin/

  # Install a host directory tree into /opt/test:
  scripts/install_to_rootfs.sh disk.img host_test_dir /opt/test
EOF
    exit 0
}

die() {
    echo "Error: $*" >&2
    exit 1
}

MODE_OVERRIDE=""
FORCE=1
VERBOSE=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--mode)
            [[ $# -ge 2 ]] || die "Option $1 requires an argument"
            MODE_OVERRIDE="$2"
            shift 2
            ;;
        -f|--force)
            FORCE=1
            shift
            ;;
        --no-force)
            FORCE=0
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -n|--dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        --)
            shift
            break
            ;;
        -*)
            die "Unknown option: $1 (run with -h for help)"
            ;;
        *)
            break
            ;;
    esac
done

[[ $# -ge 3 ]] || {
    echo "Error: Insufficient arguments." >&2
    usage
}

IMAGE="$1"
shift

# Collect source files and destination
SOURCES=()
while [[ $# -gt 1 ]]; do
    SOURCES+=("$1")
    shift
done
DEST="$1"

# Check tools
command -v debugfs >/dev/null 2>&1 || die "Missing required command: debugfs (from e2fsprogs)"
command -v sha256sum >/dev/null 2>&1 || die "Missing required command: sha256sum"

# Validate image
[[ -f "${IMAGE}" ]] || die "Image file not found: ${IMAGE}"

# Check ext2/3/4 magic number (0xef53 at offset 1080)
MAGIC=$(od -A n -N 2 -j 1080 -t x2 "${IMAGE}" 2>/dev/null | tr -d ' ' || true)
if [[ "${MAGIC}" != "ef53" ]]; then
    die "File '${IMAGE}' does not appear to be a valid raw ext2/3/4 filesystem (magic: '${MAGIC}', expected: 'ef53')"
fi

# Run debugfs command with error detection
run_debugfs() {
    local write_flag="$1"
    local req="$2"
    local cmd=(debugfs)
    if [[ "${write_flag}" == "1" ]]; then
        cmd+=(-w)
    fi
    cmd+=(-R "${req}" "${IMAGE}")

    if [[ "${VERBOSE}" == "1" ]]; then
        echo "+ ${cmd[*]}" >&2
    fi

    if [[ "${DRY_RUN}" == "1" && "${write_flag}" == "1" ]]; then
        echo "[dry-run] debugfs -w -R '${req}' '${IMAGE}'"
        return 0
    fi

    local out
    out=$("${cmd[@]}" 2>&1) || true
    if [[ "${VERBOSE}" == "1" && -n "${out}" ]]; then
        echo "${out}" >&2
    fi
    echo "${out}"
}

# Check if an inode exists in guest
guest_stat() {
    local path="$1"
    local res
    res=$(run_debugfs 0 "stat ${path}")
    if echo "${res}" | grep -q "Inode: [0-9]\+"; then
        return 0
    fi
    return 1
}

# Check if guest path is a directory
guest_is_dir() {
    local path="$1"
    local res
    res=$(run_debugfs 0 "stat ${path}")
    if echo "${res}" | grep -q "Type: directory"; then
        return 0
    fi
    return 1
}

# Ensure directory path exists in guest, creating intermediate directories as needed
guest_mkdir_p() {
    local target_dir="$1"
    # Normalize path
    target_dir=$(echo "${target_dir}" | sed 's#//*#/#g')
    [[ "${target_dir}" == "/" || -z "${target_dir}" ]] && return 0

    local IFS='/'
    read -ra PARTS <<< "${target_dir}"
    local current=""

    for part in "${PARTS[@]}"; do
        [[ -z "${part}" ]] && continue
        current="${current}/${part}"
        if ! guest_stat "${current}"; then
            if [[ "${VERBOSE}" == "1" ]]; then
                echo "Creating guest directory: ${current}"
            fi
            local out
            out=$(run_debugfs 1 "mkdir ${current}")
            if echo "${out}" | grep -iqE "error|cannot|while looking up"; then
                die "Failed to create directory '${current}' in '${IMAGE}': ${out}"
            fi
            run_debugfs 1 "set_inode_field ${current} mode 040755" >/dev/null
        fi
    done
}

# Copy a single host file into guest path
install_file() {
    local src="$1"
    local dst="$2"

    [[ -f "${src}" ]] || die "Source file not found: ${src}"

    # If dst is a directory or ends in '/', append source filename
    if [[ "${dst}" == */ ]] || guest_is_dir "${dst}"; then
        local bname
        bname="$(basename "${src}")"
        dst="${dst%/}/${bname}"
    fi

    local parent_dir
    parent_dir="$(dirname "${dst}")"
    guest_mkdir_p "${parent_dir}"

    if guest_stat "${dst}"; then
        if [[ "${FORCE}" == "1" ]]; then
            if [[ "${VERBOSE}" == "1" ]]; then
                echo "Removing existing file in guest: ${dst}"
            fi
            run_debugfs 1 "rm ${dst}" >/dev/null
        else
            die "Destination file '${dst}' already exists in '${IMAGE}' (use -f/--force to overwrite)"
        fi
    fi

    # Determine mode
    local mode
    if [[ -n "${MODE_OVERRIDE}" ]]; then
        # Format mode as 0100xxx
        local oct="${MODE_OVERRIDE#"0"}"
        oct="${oct#"0"}"
        mode="0100${oct}"
    elif [[ -x "${src}" ]]; then
        mode="0100755"
    else
        mode="0100644"
    fi

    echo "Installing: ${src} -> [${IMAGE}]:${dst} (mode: ${mode})"

    local out
    out=$(run_debugfs 1 "write \"${src}\" ${dst}")
    if echo "${out}" | grep -iqE "Ext2 file already exists|cannot|error|no space"; then
        die "Failed to write '${src}' to '${dst}' in '${IMAGE}': ${out}"
    fi

    run_debugfs 1 "set_inode_field ${dst} mode ${mode}" >/dev/null

    # Integrity verification
    if [[ "${DRY_RUN}" == "0" ]]; then
        local tmp_dump
        tmp_dump="$(mktemp "${TMPDIR:-/tmp}/guest-dump-XXXXXX")"
        run_debugfs 0 "dump ${dst} \"${tmp_dump}\"" >/dev/null
        local src_hash dst_hash
        src_hash=$(sha256sum "${src}" | awk '{print $1}')
        dst_hash=$(sha256sum "${tmp_dump}" | awk '{print $1}')
        rm -f "${tmp_dump}"

        if [[ "${src_hash}" != "${dst_hash}" ]]; then
            die "Integrity verification failed for ${dst}! (src: ${src_hash}, guest: ${dst_hash})"
        fi
    fi
}

# Recursively install a directory
install_dir() {
    local src_dir="$1"
    local dst_dir="$2"

    [[ -d "${src_dir}" ]] || die "Source directory not found: ${src_dir}"
    guest_mkdir_p "${dst_dir}"

    while IFS= read -r -d '' file; do
        local rel="${file#"${src_dir}"}"
        rel="${rel#/}"
        local target="${dst_dir%/}/${rel}"
        if [[ -d "${file}" ]]; then
            guest_mkdir_p "${target}"
        elif [[ -f "${file}" ]]; then
            install_file "${file}" "${target}"
        fi
    done < <(find "${src_dir}" -mindepth 1 -print0)
}

# Main processing loop
if [[ ${#SOURCES[@]} -gt 1 ]]; then
    # Multiple sources: destination must be treated as directory
    guest_mkdir_p "${DEST}"
    for src in "${SOURCES[@]}"; do
        if [[ -d "${src}" ]]; then
            bname="$(basename "${src}")"
            install_dir "${src}" "${DEST%/}/${bname}"
        else
            install_file "${src}" "${DEST%/}/$(basename "${src}")"
        fi
    done
else
    SRC="${SOURCES[0]}"
    if [[ -d "${SRC}" ]]; then
        install_dir "${SRC}" "${DEST}"
    else
        install_file "${SRC}" "${DEST}"
    fi
fi

echo "Successfully installed into ${IMAGE}."
