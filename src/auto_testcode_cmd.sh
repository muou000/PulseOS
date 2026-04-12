cd /fs/musl && ./basic_testcode.sh &&\
/fs/musl/busybox sh -c 'cd /fs/musl && sh /fs/musl/busybox_testcode.sh' &&\
\
cd /fs/glibc && ./basic_testcode.sh &&\
/fs/glibc/busybox sh -c 'cd /fs/glibc && sh /fs/glibc/busybox_testcode.sh'
