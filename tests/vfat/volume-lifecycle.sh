#!/bin/sh
# Invoked after the guest has closed and unmounted its FAT32 scratch volume.
set -eu
disk=/dev/vdb
first=/tmp/vfat-volume-one
second=/tmp/vfat-volume-two
mkdir -p "$first" "$second"

# The next probe must read the boot sector even if the retired FAT volume
# cached ordinary files. Only the disposable scratch disk is changed.
dd if="$disk" of=/tmp/vfat-boot.bin bs=512 count=1 status=none
dd if=/dev/zero of="$disk" bs=512 count=1 conv=notrunc status=none
if mount -t vfat "$disk" "$first"; then
    echo 'vfat reused a volume after its boot sector was erased' >&2
    exit 1
fi
dd if=/tmp/vfat-boot.bin of="$disk" bs=512 count=1 conv=notrunc status=none
mount -t vfat "$disk" "$first"
[ -f "$first/Scratch Directory/Offset Data.bin" ]
umount "$first"
echo VFAT_REPROBE_OK

# util-linux versions differ on whether losetup requires LOOP_CONFIGURE.
# Exercise the existing LOOP_SET_FD and LOOP_CLR_FD interfaces explicitly.
loop_control() {
    perl -e '
        use Fcntl qw(O_RDWR);
        use Errno qw(EBUSY);
        my ($action, $file) = @ARGV;
        sysopen(my $loop, "/dev/loop0", O_RDWR) or die "open loop0: $!";
        if ($action eq "attach") {
            sysopen(my $backing, $file, O_RDWR) or die "open $file: $!";
            ioctl($loop, 0x4c00, fileno($backing)) or die "LOOP_SET_FD: $!";
        } elsif ($action eq "busy") {
            die "cleared mounted loop" if ioctl($loop, 0x4c01, 0);
            die "LOOP_CLR_FD: $!" unless $! == EBUSY;
        } else {
            ioctl($loop, 0x4c01, 0) or die "LOOP_CLR_FD: $!";
        }
    ' "$@"
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
umount "$second"
loop_control detach

loop_control attach /tmp/vfat-loop-B.img
mount -t vfat /dev/loop0 "$first"
[ ! -e "$first/marker.txt" ]
printf 'volume B\n' > "$first/marker.txt"
umount "$first"
loop_control detach

loop_control attach /tmp/vfat-loop-A.img
mount -t vfat /dev/loop0 "$first"
[ "$(cat "$first/marker.txt")" = 'volume A' ]
umount "$first"
loop_control detach
echo VFAT_LOOP_REBIND_OK
