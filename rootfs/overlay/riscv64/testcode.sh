mkdir -p /fs
mount -t ext4 device0 /fs

cd /fs/musl
sh ./basic_testcode.sh
sh ./busybox_testcode.sh
sh ./lua_testcode.sh
sh ./cyclictest_testcode.sh
sh ./libctest_testcode.sh
sh ./libcbench_testcode.sh
# sh ./iozone_testcode.sh
# sh ./iperf_testcode.sh
# sh ./lmbench_testcode.sh
# sh ./netperf_testcode.sh

cd /fs/glibc
sh ./basic_testcode.sh
sh ./busybox_testcode.sh
sh ./lua_testcode.sh
sh ./cyclictest_testcode.sh
sh ./libcbench_testcode.sh
# sh ./iozone_testcode.sh
# sh ./iperf_testcode.sh
# sh ./lmbench_testcode.sh
# sh ./ltp_testcode.sh
# sh ./netperf_testcode.sh

cd /fs/musl
timeout 1800 sh ./ltp_testcode.sh

exit 0