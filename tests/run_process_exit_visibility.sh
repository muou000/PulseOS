#!/bin/sh

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

python3 /process_exit_visibility.py \
    --iterations "${EXIT_VISIBILITY_ITERATIONS:-512}" \
    --directory /work
result=$?

if [ "$result" -eq 0 ]; then
    echo "PROCESS_EXIT_VISIBILITY_RESULT PASS"
else
    echo "PROCESS_EXIT_VISIBILITY_RESULT FAIL rc=$result"
fi

sync
poweroff -f 2>/dev/null || halt -f 2>/dev/null || true
exit "$result"
