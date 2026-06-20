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
    if [[ ! -f "${idx_file}" || "$(find "${idx_file}" -mtime +1 2>/dev/null)" ]]; then
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
        
        local lookup_res
        # 改用逐行扫描状态机，完美兼容各种 awk 版本和换行符
        lookup_res=$(awk -v target="${target}" -v repo="${repo}" '
            function reset_block() {
                pkg = ""; ver = ""; deps = ""; prov = "";
            }
            function check_and_print() {
                # 1. 精确匹配包名
                if (pkg == target) {
                    print pkg; print ver; print repo; print deps;
                    found = 1; exit 0;
                }
                # 2. 匹配 provider (so:, pc:, cmd:)
                if (target ~ /^(so|pc|cmd):/) {
                    split(prov, prov_arr, " ")
                    for (j in prov_arr) {
                        split(prov_arr[j], part, "=")
                        if (part[1] == target) {
                            print pkg; print ver; print repo; print deps;
                            found = 1; exit 0;
                        }
                    }
                }
            }
            BEGIN { reset_block(); found = 0; }
            {
                # 去除可能存在的 Windows 换行符 \r
                sub(/\r$/, "")
                
                if ($0 == "") {
                    check_and_print();
                    reset_block();
                } else {
                    key = substr($0, 1, 2);
                    val = substr($0, 3);
                    if (key == "P:") pkg = val;
                    else if (key == "V:") ver = val;
                    else if (key == "D:") deps = val;
                    else if (key == "p:") prov = val;
                }
            }
            END {
                if (!found) { check_and_print(); }
            }
        ' "${idx_file}" || true)
        
        # 调试日志：输出匹配状态
        if [[ -n "${lookup_res}" ]]; then
            local lines_count
            lines_count=$(echo "${lookup_res}" | wc -l)
            echo "  [DEBUG] Found '${target}' in ${repo} (${lines_count} lines)" >&2
            echo "${lookup_res}"
            return 0
        fi
    done
    
    echo "  [DEBUG] Not found '${target}' in any repo" >&2
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
                # 清理版本依赖限定符，例如将 "pcre2>=10.42" 转换为 "pcre2"
                local clean_dep="${dep%%[<>=!~]*}"

                if [[ "${clean_dep}" =~ ^so:libc\.musl ]]; then
                    continue
                fi
                
                local dep_resolved=0
                for r in "${resolved[@]}"; do
                    if [[ "${r}" == "${clean_dep}" ]]; then
                        dep_resolved=1
                        break
                    fi
                done
                if [[ "${dep_resolved}" -eq 0 ]]; then
                    queue+=("${clean_dep}")
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
        tar -xzf "${apk_file}" 2>/dev/null || true
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
    
    # 临时关闭严苛模式，防止子进程管道因 set -e 导致的主线程静默退出
    set +e
    set +o pipefail
    
    tmp_res_file="$(mktemp)"
    resolve_dependencies "${arch}" "${PACKAGES_INPUT[@]}" > "${tmp_res_file}"
    res_code=$?
    
    # 恢复严格模式
    set -e
    set -o pipefail
    
    if [[ ${res_code} -ne 0 ]]; then
        echo "Warning: Dependency resolver exited with code ${res_code}" >&2
    fi

    # 从安全文件中读取解析结果
    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ -n "${line}" ]] && RESOLVED_ITEMS+=("${line}")
    done < "${tmp_res_file}"
    rm -f "${tmp_res_file}"
    
    if (( ${#RESOLVED_ITEMS[@]} == 0 )); then
        echo "Error: No packages resolved for architecture ${arch}." >&2
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
echo "Run 'make img_all' to rebuild the filesystem images."