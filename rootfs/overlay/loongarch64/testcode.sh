mkdir -p /fs
mount -t ext4 device0 /fs

run_first_tier_ltp() {
    libc="$1"
    case_dir="/fs/$libc/ltp/testcases/bin"
    if [ ! -d "$case_dir" ]; then
        echo "LTP CASE DIRECTORY MISSING $libc: $case_dir"
        return 1
    fi

    (
        cd "$case_dir" || exit 1
        PATH="$PWD:$PATH"
        export PATH
        LTPROOT="/fs/$libc/ltp"
        export LTPROOT
        LHOST_IFACES="eth0"
        export LHOST_IFACES
        status=0
        # setrlimit(164) is not part of the LoongArch64 Linux ABI.
        for file in \
            adjtimex01 adjtimex02 adjtimex03 \
            fchmodat01 fchmodat02 \
            timer_getoverrun01; do
            if [ ! -f "./$file" ]; then
                echo "LTP CASE MISSING $libc/$file"
                status=1
                continue
            fi
            echo "RUN FIRST-TIER LTP CASE $libc/$file"
            "./$file"
            ret=$?
            echo "RESULT FIRST-TIER LTP CASE $libc/$file : $ret"
            if [ "$ret" -ne 0 ]; then
                status=1
            fi
        done
        exit "$status"
    )
}

ltp_status=0
run_first_tier_ltp musl || ltp_status=1
run_first_tier_ltp glibc || ltp_status=1

exit "$ltp_status"
