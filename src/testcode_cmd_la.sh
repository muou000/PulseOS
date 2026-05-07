mkdir -p /fs &&
mount -t ext4 device0 /fs &&

cd /fs/musl &&
sh ./basic_testcode.sh &&
/fs/musl/busybox sh /fs/musl/busybox_testcode.sh&&
sh ./lua_testcode.sh &&
sh ./cyclictest_testcode.sh &&
sh ./libctest_testcode.sh &&
# sh ./iozone_testcode.sh &&
# sh ./iperf_testcode.sh &&
# sh ./libcbench_testcode.sh &&
# sh ./lmbench_testcode.sh 
# sh ./ltp_testcode.sh &&
# sh ./netperf_testcode.sh &&

cd /fs/glibc &&
sh ./basic_testcode.sh &&
/fs/glibc/busybox sh /fs/glibc/busybox_testcode.sh &&
sh ./lua_testcode.sh &&
sh ./cyclictest_testcode.sh 
# sh ./iozone_testcode.sh &&
# sh ./iperf_testcode.sh &&
# sh ./libcbench_testcode.sh
# sh ./lmbench_testcode.sh &&
# sh ./ltp_testcode.sh &&
# sh ./netperf_testcode.sh