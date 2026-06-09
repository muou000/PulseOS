#!/bin/bash

cd /fs/glibc/ltp/testcases/bin
PATH="$PWD:$PATH"
export LTPROOT=/fs/glibc/ltp
export LHOST_IFACES="eth0"
test_list=$(cat /testlist)

echo "#### OS COMP TEST GROUP START ltp-glibc ####"

# 定义目标目录
target_dir="ltp/testcases/bin"

# 遍历目录下的所有文件
for file in $test_list; do
  # 跳过目录，仅处理文件
  if [ -f "$file" ]; then
    # 输出文件名
    echo "RUN LTP CASE $file"

    if [ "$file" = "fork13" ]; then
      LTP_RUNTIME_MUL=0.01 "./$file"
    elif [ "$file" = "read_all" ]; then
      "./$file" -d /fs
    else
      "./$file"
    fi
    ret=$?

    # 输出文件名和返回值
    echo "FAIL LTP CASE $file : $ret"
  fi
done

echo "#### OS COMP TEST GROUP END ltp-glibc ####"
