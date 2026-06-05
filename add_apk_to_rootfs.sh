#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <package1> [package2] ..." >&2
    exit 1
fi

ALPINE_VER="v3.23"
ARCHES=("riscv64" "loongarch64")
REPOS=("main" "community")
PROJECT_ROOT="$(pwd)"

CACHE_DIR="/tmp/alpine-apk-cache"
mkdir -p "${CACHE_DIR}"

# Fetch and update APKINDEX
update_index() {
    local arch="$1"
    local repo="$2"
    local idx_tar="${CACHE_DIR}/APKINDEX-${arch}-${repo}.tar.gz"
    local idx_file="${CACHE_DIR}/APKINDEX-${arch}-${repo}"
    
    # Update cache if it does not exist or is older than 1 day
    if [[ ! -f "${idx_file}" || "$(find "${idx_file}" -mtime +1)" ]]; then
        echo "Updating package index for ${arch}/${repo}..."
        local url="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VER}/${repo}/${arch}/APKINDEX.tar.gz"
        if ! wget -q -O "${idx_tar}" "${url}"; then
            echo "Warning: Failed to download index from ${url}, skipping."
            return 1
        fi
        tar -xzf "${idx_tar}" -C "${CACHE_DIR}" APKINDEX
        mv -f "${CACHE_DIR}/APKINDEX" "${idx_file}"
        rm -f "${idx_tar}"
    fi
    return 0
}

# Lookup package or provider in indexed files
lookup_package() {
    local arch="$1"
    local target="$2"
    
    for repo in "${REPOS[@]}"; do
        local idx_file="${CACHE_DIR}/APKINDEX-${arch}-${repo}"
        if [[ ! -f "${idx_file}" ]]; then
            continue
        fi
        
        local pkg="" ver="" deps=""
        local lookup_res
        
        # AWK parser to query package/provider block by block (RS="")
        lookup_res=$(awk -v target="${target}" -v repo="${repo}" '
            BEGIN { RS = "" }
            {
                pkg = ""
                ver = ""
                deps = ""
                prov = ""
                split($0, lines, "\n")
                for (i in lines) {
                    line = lines[i]
                    if (sub(/^P:/, "", line)) pkg = line
                    else if (sub(/^V:/, "", line)) ver = line
                    else if (sub(/^D:/, "", line)) deps = line
                    else if (sub(/^p:/, "", line)) prov = line
                }
                
                # Exact package name match
                if (pkg == target) {
                    print pkg
                    print ver
                    print repo
                    print deps
                    exit 0
                }
                
                # Check providers matching so: / pc: / cmd:
                if (target ~ /^so:/ || target ~ /^pc:/ || target ~ /^cmd:/) {
                    split(prov, prov_arr, " ")
                    for (j in prov_arr) {
                        split(prov_arr[j], part, "=")
                        if (part[1] == target) {
                            print pkg
                            print ver
                            print repo
                            print deps
                            exit 0
                        }
                    }
                }
            }
        ' "${idx_file}" || true)
        
        if [[ -n "${lookup_res}" ]]; then
            echo "${lookup_res}"
            return 0
        fi
    done
    return 1
}

# Recursively resolve dependencies of given packages
resolve_dependencies() {
    local arch="$1"
    shift
    local initial_pkgs=("$@")
    
    local resolved=()
    local queue=("${initial_pkgs[@]}")
    local download_list=()
    
    while (( ${#queue[@]} > 0 )); do
        local current="${queue[0]}"
        queue=("${queue[@]:1}")
        
        # Check if already resolved
        local already_resolved=0
        for r in "${resolved[@]}"; do
            if [[ "${r}" == "${current}" ]]; then
                already_resolved=1
                break
            fi
        done
        [[ "${already_resolved}" -eq 1 ]] && continue
        
        # Lookup in APKINDEX
        local lookup_res
        lookup_res="$(lookup_package "${arch}" "${current}" || true)"
        if [[ -z "${lookup_res}" ]]; then
            # Ignore musl libc deps as they are already in base minirootfs
            if [[ "${current}" =~ ^so:libc\.musl ]]; then
                continue
            fi
            echo "Warning: Could not find package or provider for '${current}'" >&2
            continue
        fi
        
        # Read the multiline lookup response
        local pkg="" ver="" repo="" deps=""
        {
            read -r pkg
            read -r ver
            read -r repo
            read -r deps
        } <<< "${lookup_res}"
        
        # Mark as resolved
        resolved+=("${current}")
        resolved+=("${pkg}")
        
        # Add to downloads
        download_list+=("${pkg}|${ver}|${repo}")
        
        # Queue dependencies
        if [[ -n "${deps}" ]]; then
            for dep in ${deps}; do
                if [[ "${dep}" =~ ^so:libc\.musl ]]; then
                    continue
                fi
                local dep_resolved=0
                for r in "${resolved[@]}"; do
                    if [[ "${r}" == "${dep}" ]]; then
                        dep_resolved=1
                        break
                    fi
                done
                if [[ "${dep_resolved}" -eq 0 ]]; then
                    queue+=("${dep}")
                fi
            done
        fi
    done
    
    # Deduplicate download list
    local unique_downloads=()
    for item in "${download_list[@]}"; do
        local dup=0
        for u in "${unique_downloads[@]}"; do
            if [[ "${u}" == "${item}" ]]; then
                dup=1
                break
            fi
        done
        [[ "${dup}" -eq 0 ]] && unique_downloads+=("${item}")
    done
    
    for item in "${unique_downloads[@]}"; do
        echo "${item}"
    done
}

download_and_extract() {
    local arch="$1"
    shift
    local items=("$@")
    
    local dest_dir="${PROJECT_ROOT}/rootfs/overlay/${arch}"
    mkdir -p "${dest_dir}"
    
    local temp_dir
    temp_dir="$(mktemp -d "/tmp/pulse-apk-download-${arch}-XXXXXX")"
    cd "${temp_dir}"
    
    echo "Downloading and extracting packages for ${arch}..."
    for item in "${items[@]}"; do
        local pkg="" ver="" repo=""
        IFS='|' read -r pkg ver repo <<< "${item}"
        
        local apk_file="${pkg}-${ver}.apk"
        local url="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VER}/${repo}/${arch}/${apk_file}"
        
        echo "  Downloading ${apk_file}..."
        if ! wget -q "${url}"; then
            echo "Error: Failed to download ${url}" >&2
            exit 1
        fi
        
        echo "  Extracting ${apk_file}..."
        tar -xzf "${apk_file}"
    done
    
    echo "  Installing to overlay..."
    # Copy bin, sbin, lib, usr, etc if they exist in extracted files
    for dir in bin sbin lib usr etc; do
        if [[ -d "${dir}" ]]; then
            cp -rP "${dir}" "${dest_dir}/"
        fi
    done
    
    cd "${PROJECT_ROOT}"
    rm -rf "${temp_dir}"
}

# Primary execution flow
PACKAGES_INPUT=("$@")

for arch in "${ARCHES[@]}"; do
    echo "=== Processing Architecture: ${arch} ==="
    
    # Update indices
    for repo in "${REPOS[@]}"; do
        update_index "${arch}" "${repo}" || true
    done
    
    # Resolve all package downloads (including dependencies)
    echo "Resolving dependencies for: ${PACKAGES_INPUT[*]}"
    RESOLVED_ITEMS=()
    while IFS= read -r line; do
        [[ -n "${line}" ]] && RESOLVED_ITEMS+=("${line}")
    done < <(resolve_dependencies "${arch}" "${PACKAGES_INPUT[@]}")
    
    if (( ${#RESOLVED_ITEMS[@]} == 0 )); then
        echo "Error: No packages resolved." >&2
        exit 1
    fi
    
    echo "Resolved download list:"
    for item in "${RESOLVED_ITEMS[@]}"; do
        echo "  - ${item}"
    done
    
    # Download and extract the packages
    download_and_extract "${arch}" "${RESOLVED_ITEMS[@]}"
    echo "=== Done ${arch} ==="
done

echo "Successfully added packages and dependencies to rootfs overlays!"
echo "Run 'make test' to rebuild the filesystem images."
