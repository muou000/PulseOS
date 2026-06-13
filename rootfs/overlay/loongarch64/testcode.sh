mkdir -p /fs
mount -t ext4 device0 /fs

# chmod +x /fs/musl/basic/run-all.sh
# chmod +x /fs/glibc/basic/run-all.sh


# cd /fs/musl
# sh ./basic_testcode.sh
# sh ./busybox_testcode.sh
# sh ./lua_testcode.sh
# sh ./cyclictest_testcode.sh
# sh ./libctest_testcode.sh
# sh ./libcbench_testcode.sh
# sh ./iozone_testcode.sh
# sh ./iperf_testcode.sh
# ENOUGH=50000 sh ./lmbench_testcode.sh
# sh ./netperf_testcode.sh

# cd /fs/glibc
# sh ./basic_testcode.sh
# sh ./busybox_testcode.sh
# sh ./lua_testcode.sh
# sh ./cyclictest_testcode.sh
# sh ./libcbench_testcode.sh
# sh ./iozone_testcode.sh
# sh ./iperf_testcode.sh
# ENOUGH=50000 sh ./lmbench_testcode.sh
# sh ./netperf_testcode.sh

# cd /
# sh ./ltp_musl_testcode.sh
# sh ./ltp_glibc_testcode.sh

cd /fs/musl/ltp/testcases/bin

./clone05
./clone08
./clone09
./clone301
./clone303

# ./shm_comm
# ./shm_test
# ./shmat01
# ./shmat1
# ./shmctl01
# ./shmctl02
# ./shmctl03
# ./shmctl04
# ./shmctl05
# ./shmctl06
# ./shmem_2nstest
# ./shmget02
# ./shmget03
# ./shmget04
# ./shmget05
# ./shmget06
# ./shmt02
# ./shmt09


exit 0