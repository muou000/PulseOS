#!/bin/sh
# The standard rootfs supplies util-linux, coreutils and fio on both targets.
set -eu

mount_dir=/tmp/vfat-probe
wrong_dir=/tmp/vfat-wrong-format
mkdir -p "$mount_dir" "$wrong_dir"
grep -F ' / ext4 ' /proc/mounts
dir="$mount_dir/Scratch Directory"
file="$dir/Offset Data.bin"

verify_persisted_file() {
    ls -1 "$dir" | grep -Fx 'Offset Data.bin'
    [ "$(wc -c < "$file")" -eq 515 ]
    [ "$(dd if="$file" bs=1 skip=511 count=4 status=none)" = 'XYa!' ]
}

if [ "${1:-}" = cold-read ]; then
    mount -t vfat /dev/vdb "$mount_dir"
    verify_persisted_file
    rm "$file"
    rmdir "$dir"
    umount "$mount_dir"
    echo VFAT_COLD_READ_OK
    exit 0
fi

if mount -t vfat /dev/vda "$wrong_dir"; then
    echo "mounted the ext4 root device as vfat" >&2
    exit 1
fi
echo VFAT_WRONG_FORMAT_OK

mount -t vfat /dev/vdb "$mount_dir"
grep -F " $mount_dir vfat " /proc/mounts
[ "$(stat -f -c %t "$mount_dir")" = 4d44 ]
mkdir "$dir"
printf 'XY' | dd of="$file" bs=1 seek=511 conv=notrunc,fsync status=none
printf 'ab' >> "$file"
truncate -s 514 "$file"
[ "$(wc -c < "$file")" -eq 514 ]
[ "$(dd if="$file" bs=1 skip=510 count=4 status=none | od -An -tx1 | xargs)" = '00 58 59 61' ]
echo VFAT_OFFSET_APPEND_TRUNCATE_OK

# Keep the open description across a directory rename of its file.
printf 'pinned node\n' > "$dir/Original Name.txt"
pinned_inode=$(stat -c %i "$dir/Original Name.txt")
exec 3< "$dir/Original Name.txt"
mv "$dir/Original Name.txt" "$dir/Renamed File.txt"
[ "$(stat -c %i "$dir/renamed file.TXT")" = "$pinned_inode" ]
printf 'shared' | dd of="$dir/renamed file.TXT" bs=1 conv=notrunc status=none &
writer=$!
wait "$writer"
IFS= read -r pinned <&3
[ "$pinned" = 'shared node' ]
exec 3<&-
ls -1 "$dir" | grep -Fx 'Renamed File.txt'
[ -f "$dir/renamed file.TXT" ]
printf 'remove\n' > "$dir/Discard.txt"
rm "$dir/Discard.txt"
[ ! -e "$dir/Discard.txt" ]
echo VFAT_DIRECTORY_LIFETIME_OK

# Two writers use separate descriptions of one file and interleaved ranges.
parallel_file="$dir/Parallel.bin"
dd if=/dev/zero of="$parallel_file" bs=4096 count=2 status=none
write_ranges() {
    i=$1
    value=$2
    while [ "$i" -lt 16 ]; do
        printf '%s' "$value" | dd of="$parallel_file" bs=1 seek=$((i * 512 + 511)) conv=notrunc status=none
        i=$((i + 2))
    done
}
write_ranges 0 A &
writer=$!
write_ranges 1 B &
second=$!
wait "$writer"
wait "$second"
for i in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    case $((i % 2)) in 0) value=A ;; 1) value=B ;; esac
    [ "$(dd if="$parallel_file" bs=1 skip=$((i * 512 + 511)) count=1 status=none)" = "$value" ]
done
echo VFAT_TWO_WRITERS_OK

/usr/bin/fio --name=vfat-verify --filename="$dir/Fio.bin" --size=64k --bs=4k \
    --ioengine=sync --rw=write --verify=crc32c --fsync_on_close=1 --thread=1 \
    --output=/tmp/vfat-fio.log || { cat /tmp/vfat-fio.log; exit 1; }
echo VFAT_FIO_VERIFY_OK

# dd conv=fsync issues fsync on the open descriptor. Verify data after a fresh mount.
printf '!' | dd of="$file" bs=1 seek=514 conv=notrunc,fsync status=none
umount "$mount_dir"
[ ! -e "$file" ]
mount -t vfat /dev/vdb "$mount_dir"
verify_persisted_file
[ "$(cat "$dir/Renamed File.txt")" = 'shared node' ]
rm "$parallel_file" "$dir/Renamed File.txt" "$dir/Fio.bin"
umount "$mount_dir"
echo VFAT_REMOUNT_OK
echo VFAT_PASS
