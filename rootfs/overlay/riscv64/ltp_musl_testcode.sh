#!/bin/bash

cd /fs/musl/ltp/testcases/bin

test_list="
abort01
abs01
access01
access03
alarm02
alarm03
alarm05
alarm06
alarm07
asapi_01
atof01
brk01
brk02
chdir04
chmod01
chown01
chown02
chown05
clock_getres01
clock_gettime02
clock_nanosleep01
clock_nanosleep04
clone01
clone03
clone04
clone06
clone07
clone302
close01
close02
confstr01
crash01
crash02
creat01
creat03
creat05
cve-2017-17052
data_space
diotest1
dup01
dup02
dup03
dup04
dup06
dup07
dup201
dup202
dup203
dup204
dup205
dup206
dup207
dup3_01
dup3_02
epoll-ltp
epoll_create02
execve03
exit01
exit02
exit_group01
faccessat01
faccessat02
faccessat202
fchmodat01
fchmodat02
fchownat01
fcntl02
fcntl02_64
fcntl03
fcntl03_64
fcntl05
fcntl05_64
fcntl08
fcntl08_64
fcntl09
fcntl09_64
fcntl10
fcntl10_64
fcntl29
fcntl29_64
fcntl34
fcntl34_64
fcntl36
fcntl36_64
flock06
fork01
fork03
fork04
fork07
fork08
fork09
fork10
fork_procs
fpathconf01
fptest01
fptest02
fstat03
fstat03_64
fstatat01
fstatfs02
fstatfs02_64
fsx-linux
ftruncate01
ftruncate01_64
futex_cmp_requeue02
futex_wake01
getcwd01
getcwd02
getdents02
getdomainname01
getegid02
getegid02_16
geteuid01
geteuid02
getgid01
getgid03
gethostname01
getitimer02
getpagesize01
getpgid01
getpgrp01
getpid02
getppid02
getrandom01
getrandom02
getrandom03
getrandom04
getrandom05
getrlimit01
getrlimit02
getrlimit03
gettid02
gettimeofday01
gettimeofday02
getuid01
getuid03
growfiles
in6_01
inode01
inode02
ioctl_ns07
kill02
kill05
"

echo "#### OS COMP TEST GROUP START ltp-musl ####"

# 定义目标目录
target_dir="ltp/testcases/bin"

# 遍历目录下的所有文件
for file in $test_list; do
  # 跳过目录，仅处理文件
  if [ -f "$file" ]; then
    # 输出文件名
    echo "RUN LTP CASE $file"

    "./$file"
    ret=$?

    # 输出文件名和返回值
    echo "FAIL LTP CASE $file : $ret"
  fi
done


echo "#### OS COMP TEST GROUP END ltp-musl ####"