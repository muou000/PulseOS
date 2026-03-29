#!/bin/bash
set -e

ARCH=${ARCH:-riscv64}
IMG_SIZE=${IMG_SIZE:-1G}
IMG=rootfs-${ARCH}.img

BASE=https://dl-cdn.alpinelinux.org/alpine
# BASE=https://mirrors.cernet.edu.cn/alpine
REL=v3.23
URL=${BASE}/${REL}/releases/${ARCH}

# Check for required tools
check_tools() {
    local missing_tools=()
    for tool in curl sha256sum; do
        ! command -v $tool &> /dev/null && missing_tools+=("$tool")
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo "Error: Missing required tools: ${missing_tools[*]}"
        echo "Install: sudo apt install ${missing_tools[*]}"
        exit 1
    fi
}

check_tools

# Check if image already exists
if [[ -f "${IMG}" ]]; then
    echo "${IMG} already exists. Skipping creation."
    exit 0
fi

# Parse YAML and extract minirootfs info
parse_yaml() {
    echo "Fetching release information..."
    local yaml_content=$(curl -sS -L ${URL}/latest-releases.yaml)

    if [[ -z "${yaml_content}" ]]; then
        echo "Error: Failed to fetch latest-releases.yaml"
        exit 1
    fi

    # Parse YAML using python (most reliable)
    local json_data=$(echo "${yaml_content}" | python3 -c "
import sys, yaml, json
data = yaml.safe_load(sys.stdin)
minirootfs = [x for x in data if x.get('flavor') == 'alpine-minirootfs']
if minirootfs:
    print(json.dumps(minirootfs[0], default=str))
" 2>/dev/null)

    if [[ -z "${json_data}" ]]; then
        echo "Error: Failed to parse YAML data. Install: sudo apt install python3-yaml"
        exit 1
    fi

    # Extract fields using jq
    file=$(echo "${json_data}" | jq -r '.file // empty')
    sha256=$(echo "${json_data}" | jq -r '.sha256 // empty')

    if [[ -z "${file}" || -z "${sha256}" ]]; then
        echo "Error: Could not extract file or sha256 from YAML"
        exit 1
    fi
}

parse_yaml

function download() {
    if [[ -f "${file}" ]]; then
        echo "${file} already exists. Skipping download."
    else
        echo "Downloading ${file}..."
        curl -# -L -O ${URL}/${file} || { echo "Error: Failed to download"; exit 1; }
    fi

    echo "Verifying SHA256..."
    echo "${sha256}  ${file}" | sha256sum -c - || { echo "Error: SHA256 verification failed"; exit 1; }
}

function mkfs() {
    if [[ -f "${IMG}" ]]; then
        echo "${IMG} already exists. Skipping filesystem creation."
        return 0
    fi

    echo "Creating ${IMG_SIZE} ext4 image: ${IMG}..."
    fallocate -l ${IMG_SIZE} ${IMG} || { echo "Error: Failed to allocate space"; exit 1; }
    ${SUDO} mkfs.ext4 -F -q ${IMG} || { echo "Error: Failed to create filesystem"; exit 1; }
}

function extract() {
    echo "Mounting and extracting..."
    mkdir -p mnt
    ${SUDO} mount ${IMG} mnt || { echo "Error: Failed to mount"; exit 1; }

    ${SUDO} tar -xzf ${file} -C mnt || { echo "Error: Failed to extract"; ${SUDO} umount mnt; exit 1; }

    # Copy etc configs if exists
    [[ -d "etc" ]] && ${SUDO} cp -r etc/* mnt/etc/ 2>/dev/null

    # Update apk repositories
    [[ -f "mnt/etc/apk/repositories" ]] && \
        ${SUDO} sed -i "s#https\?://dl-cdn.alpinelinux.org/alpine#${BASE}#g" mnt/etc/apk/repositories

    ${SUDO} umount mnt || { echo "Error: Failed to unmount"; exit 1; }
    rmdir mnt
}

# Setup sudo if needed
SUDO=""
[[ $EUID -ne 0 ]] && command -v sudo &> /dev/null && SUDO="sudo"

# Main execution
echo "=== BuildingAlpine Linux Image for ${ARCH} ==="
download
mkfs
extract
echo "Image created successfully: ${IMG}"