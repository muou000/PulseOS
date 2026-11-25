# Archive names and checksum verification shared by the rootfs downloader and builder.
rv_ubuntu=ubuntu-base-26.10-base-riscv64.tar.gz
rv_ubuntu_sha=d01d55da8ce09227df55fa867d8d8b95076c2c088c6884e0702dc7f7640765f6
rv_tests_asset=rootfs-tests-riscv64.tar.xz
rv_tests_cache=rootfs-tests-20261120-riscv64.tar.xz
rv_tests_sha=1a95dc30d246a71e6d8a79d52d75e4942c6a958687ca289c7067ead258066285

verified_archive() {
    local digest="$1" file
    shift
    for file in "$@"; do
        if [[ -f "${file}" ]] && echo "${digest}  ${file}" | sha256sum -c --status -; then
            echo "${file}"
            return
        fi
    done
    return 1
}

riscv_test_archive() {
    # 20261116 used the same asset name before fio and liburing were bundled.
    verified_archive "${rv_tests_sha}" "${BASE_DIR}/${rv_tests_cache}" "${BASE_DIR}/${rv_tests_asset}"
}

release_url=https://github.com/muou000/PulseOS/releases/download

# Checksum-pinned QEMU test overlays for the download and offline image paths.
netbench_tag=rootfs-tests-20261125
declare -A netbench_sha=(
    [riscv64]=11bb69183987613cee96b899f9851fc3650716947ef6481984b944cab7fa2679
    [loongarch64]=41b3e5863040ed7f6a157e45a74d50d8c95eefc49cfb762ac50ca776ebcc83df
)
mmbench_tag=rootfs-mm-tests-20261125
declare -A mmbench_sha=(
    [riscv64]=3634bfea154b71763a100375acdd5e3f23971c1fa7c752622b006d3e7dc5a3b3
    [loongarch64]=6633409363a52131e434ba374eaf53d89398318632d586eabae04a660f199875
)

# Atomically cache a release asset. Both the full rootfs downloader and an
# incremental image build use this path so a failed fetch preserves the cache.
fetch_one() (
    local asset="$1" out="$2" sum="$3" base_url="$4"
    if verified_archive "${sum}" "${BASE_DIR}/${out}" >/dev/null; then
        echo "Verified ${out}"
        return
    fi
    echo "Downloading ${asset} -> rootfs/base/${out}"
    local tmp
    tmp="$(mktemp "${BASE_DIR}/${out}.XXXXXX")"
    trap 'rm -f "${tmp}"' EXIT
    curl -fL --retry 3 -o "${tmp}" "${base_url}/${asset}"
    echo "${sum}  ${tmp}" | sha256sum -c -
    mv -f "${tmp}" "${BASE_DIR}/${out}"
)

fetch_qemu_test_overlays() {
    local arch="$1"
    fetch_one "netbench-${arch}.tar.xz" "netbench-${arch}.tar.xz" "${netbench_sha[${arch}]}" \
        "${release_url}/${netbench_tag}"
    fetch_one "mmbench-${arch}.tar.xz" "mmbench-${arch}.tar.xz" "${mmbench_sha[${arch}]}" \
        "${release_url}/${mmbench_tag}"
}
