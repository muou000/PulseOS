# Pinned source archives for the QEMU and VisionFive 2 rootfs builders.
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
