mkdir -p /fs
mount -t ext4 device0 /fs

chmod +x /fs/musl/basic/run-all.sh
chmod +x /fs/glibc/basic/run-all.sh


cd /fs/musl
sh ./basic_testcode.sh
sh ./busybox_testcode.sh
sh ./lua_testcode.sh
sh ./cyclictest_testcode.sh
sh ./libctest_testcode.sh
sh ./libcbench_testcode.sh
sh ./iozone_testcode.sh
sh ./iperf_testcode.sh
ENOUGH=50000 sh ./lmbench_testcode.sh
# sh ./netperf_testcode.sh

cd /fs/glibc
sh ./basic_testcode.sh
sh ./busybox_testcode.sh
sh ./lua_testcode.sh
sh ./cyclictest_testcode.sh
sh ./libcbench_testcode.sh
sh ./iozone_testcode.sh
sh ./iperf_testcode.sh
ENOUGH=50000 sh ./lmbench_testcode.sh
sh ./netperf_testcode.sh

cd /
sh ./ltp_musl_testcode.sh
sh ./ltp_glibc_testcode.sh

exit 0