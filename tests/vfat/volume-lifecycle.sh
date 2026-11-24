#!/bin/sh
# Invoked after the guest has closed and unmounted its FAT32 scratch volume.
set -eu
disk=/dev/vdb
first=/tmp/vfat-volume-one
second=/tmp/vfat-volume-two
mkdir -p "$first" "$second"

sync_ready=/tmp/vfat-sync-ready-$$
trap 'rm -f "$sync_ready"' EXIT
start_syncs() {
    rm -f "$sync_ready"
    (
        : > "$sync_ready"
        for round in 1 2 3 4 5 6 7 8; do sync; done
    ) &
    sync_pid=$!
    while [ ! -e "$sync_ready" ]; do kill -0 "$sync_pid"; done
}

# The next probe must read the boot sector even if the retired FAT volume
# cached ordinary files. Only the disposable scratch disk is changed.
mount -t vfat "$disk" "$first"
printf 'checkpoint\n' > "$first/sync.txt"
start_syncs
umount "$first"
dd if="$disk" of=/tmp/vfat-boot.bin bs=512 count=1 status=none
dd if=/dev/zero of="$disk" bs=512 count=1 conv=notrunc status=none
if mount -t vfat "$disk" "$first"; then
    echo 'vfat reused a volume after its boot sector was erased' >&2
    exit 1
fi
dd if=/tmp/vfat-boot.bin of="$disk" bs=512 count=1 conv=notrunc status=none
mount -t vfat "$disk" "$first"
[ -f "$first/Scratch Directory/Offset Data.bin" ]
[ "$(cat "$first/sync.txt")" = checkpoint ]
rm "$first/sync.txt"
umount "$first"
wait "$sync_pid"
echo VFAT_REPROBE_OK

# util-linux versions differ on whether losetup requires LOOP_CONFIGURE.
# Exercise the existing LOOP_SET_FD and LOOP_CLR_FD interfaces explicitly.
loop_control() {
    case "$1" in
        attach) printf a | /vfat-probe 3<>/dev/loop0 4<>"$2" ;;
        busy)   printf l | /vfat-probe 3<>/dev/loop0 ;;
        detach) printf d | /vfat-probe 3<>/dev/loop0 ;;
        *) return 1 ;;
    esac
}

cp /vfat-loop.img /tmp/vfat-loop-A.img
cp /vfat-loop.img /tmp/vfat-loop-B.img
loop_control attach /tmp/vfat-loop-A.img
mount -t vfat /dev/loop0 "$first"
mount -t vfat /dev/loop0 "$second"
printf 'volume A\n' > "$first/marker.txt"
[ "$(cat "$second/marker.txt")" = 'volume A' ]
umount "$first"
loop_control busy
printf 'retained A\n' > "$second/marker.txt"
start_syncs
umount "$second"
loop_control detach

loop_control attach /tmp/vfat-loop-B.img
mount -t vfat /dev/loop0 "$first"
[ ! -e "$first/marker.txt" ]
printf 'volume B\n' > "$first/marker.txt"
wait "$sync_pid"
umount "$first"
loop_control detach

loop_control attach /tmp/vfat-loop-A.img
mount -t vfat /dev/loop0 "$first"
[ "$(cat "$first/marker.txt")" = 'retained A' ]
umount "$first"
loop_control detach
echo VFAT_LOOP_REBIND_OK
