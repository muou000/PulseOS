/* Freestanding Linux syscall regression for #157, shared by RV64 and LA64. */
typedef unsigned long usize;
enum {
    SYS_eventfd2 = 19, SYS_epoll_create1 = 20, SYS_epoll_ctl = 21,
    SYS_fcntl = 25, SYS_close = 57, SYS_write = 64, SYS_ppoll = 73,
    SYS_exit_group = 94, SYS_nanosleep = 101, SYS_rt_sigaction = 134,
    SYS_reboot = 142, SYS_semget = 190, SYS_semctl = 191, SYS_semtimedop = 192,
    SYS_socket = 198, SYS_bind = 200, SYS_setsockopt = 208,
    SYS_munmap = 215, SYS_mmap = 222, SYS_mprotect = 226,
    EBADF = 9, EFAULT = 14, EINVAL = 22, EAFNOSUPPORT = 97,
};

static long syscall6(long nr, usize x0, usize x1, usize x2, usize x3, usize x4, usize x5)
{
    register usize a0 __asm__("a0") = x0;
    register usize a1 __asm__("a1") = x1;
    register usize a2 __asm__("a2") = x2;
    register usize a3 __asm__("a3") = x3;
    register usize a4 __asm__("a4") = x4;
    register usize a5 __asm__("a5") = x5;
    register usize a7 __asm__("a7") = nr;
#ifdef __riscv
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a7) : "memory");
#else
    __asm__ volatile("syscall 0" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a7) : "memory");
#endif
    return a0;
}
#define CALL(n, a, b, c) syscall6(n, (usize)(a), (usize)(b), (usize)(c), 0, 0, 0)
#define CALL4(n, a, b, c, d) syscall6(n, (usize)(a), (usize)(b), (usize)(c), (usize)(d), 0, 0)
#define CALL5(n, a, b, c, d, e) syscall6(n, (usize)(a), (usize)(b), (usize)(c), (usize)(d), (usize)(e), 0)

static void text(const char *s)
{
    usize len = 0;
    while (s[len]) ++len;
    CALL(SYS_write, 1, s, len);
}

static void number(long n)
{
    char buf[24];
    usize i = sizeof(buf);
    usize value = n < 0 ? (usize)-n : (usize)n;
    do { buf[--i] = '0' + value % 10; value /= 10; } while (value);
    if (n < 0) buf[--i] = '-';
    CALL(SYS_write, 1, buf + i, sizeof(buf) - i);
}

__attribute__((noreturn)) static void fail(const char *name, long got, long want)
{
    text("ABI_READS_FAIL "); text(name); text(" got="); number(got);
    text(" want="); number(want); text("\n");
    CALL(SYS_exit_group, 1, 0, 0);
    for (;;) {}
}

static void expect(const char *name, long got, long want)
{
    if (got != want) fail(name, got, want);
    text("ABI_READS_OK "); text(name); text("\n");
}

static long descriptor(const char *name, long fd)
{
    if (fd < 0) fail(name, fd, 0);
    return fd;
}

struct Timespec { long sec, nsec; };
struct SignalAction { usize handler, flags, mask; };
struct Flock { short type, whence; long start, len; int pid; };
struct EpollEvent { unsigned events; usize data; };
struct SemBuf { unsigned short num; short op, flags; };
_Static_assert(sizeof(struct SignalAction) == 24, "kernel sigaction ABI");
_Static_assert(sizeof(struct Flock) == 32, "kernel flock ABI");
_Static_assert(sizeof(struct EpollEvent) == 16, "RV64/LA64 epoll_event ABI");

__attribute__((noreturn)) void _start(void)
{
    long mapping = syscall6(SYS_mmap, 0, 8192, 3, 0x22, (usize)-1, 0);
    if (mapping < 0) fail("mmap", mapping, 0);
    unsigned char *page = (unsigned char *)mapping;
    for (usize i = 0; i < 4096; ++i) page[i] = 0;
    expect("protect-second-page", CALL(SYS_mprotect, page + 4096, 4096, 0), 0);
    void *short8 = page + 4088;
    *(long *)short8 = -1;

    /* FD validation wins; a complete malformed flock retains EINVAL. */
    struct Flock lock = { .type = 0, .whence = 99, .start = 0, .len = 0, .pid = 0 };
    expect("fcntl-fd-before-address", CALL(SYS_fcntl, -1, 5, 1), -EBADF);
    expect("fcntl-invalid-address", CALL(SYS_fcntl, 1, 5, 1), -EFAULT);
    expect("fcntl-short-copy", CALL(SYS_fcntl, 1, 5, short8), -EFAULT);
    expect("fcntl-invalid-whence", CALL(SYS_fcntl, 1, 5, &lock), -EINVAL);

    long socket = descriptor("socket", CALL(SYS_socket, 2, 2, 0));
    expect("sockopt-fd-before-address", CALL5(SYS_setsockopt, -1, 1, 2, 1, 4), -EBADF);
    expect("sockopt-length-before-address", CALL5(SYS_setsockopt, socket, 1, 2, 1, 3), -EINVAL);
    expect("sockopt-invalid-address", CALL5(SYS_setsockopt, socket, 1, 2, 1, 4), -EFAULT);
    expect("sockopt-short-scalar", CALL5(SYS_setsockopt, socket, 1, 2, page + 4094, 4), -EFAULT);
    expect("sockopt-short-timeval", CALL5(SYS_setsockopt, socket, 1, 20, short8, 16), -EFAULT);
    unsigned short wrong_family = 0xffff;
    expect("sockaddr-invalid-family", CALL(SYS_bind, socket, &wrong_family, 16), -EAFNOSUPPORT);
    *(unsigned short *)short8 = 2;
    expect("sockaddr-short-structure", CALL(SYS_bind, socket, short8, 16), -EFAULT);
    CALL(SYS_close, socket, 0, 0);

    struct Timespec invalid = { -1, 0 };
    expect("nanosleep-invalid-seconds", CALL(SYS_nanosleep, &invalid, 0, 0), -EINVAL);
    invalid.sec = 0; invalid.nsec = 1000000000;
    expect("nanosleep-invalid-nanoseconds", CALL(SYS_nanosleep, &invalid, 0, 0), -EINVAL);
    *(long *)short8 = -1;
    expect("nanosleep-short-before-value", CALL(SYS_nanosleep, short8, 0, 0), -EFAULT);
    expect("ppoll-timeout-before-fds", CALL5(SYS_ppoll, 1, 1, &invalid, 0, 0), -EINVAL);
    expect("ppoll-short-timeout", CALL5(SYS_ppoll, 1, 1, short8, 0, 0), -EFAULT);

    struct SignalAction action = { 1, 0, 0 }, old = { 0, 0, 0 };
    expect("sigaction-ignore", CALL4(SYS_rt_sigaction, 10, &action, 0, 8), 0);
    expect("sigaction-read-ignore", CALL4(SYS_rt_sigaction, 10, 0, &old, 8), 0);
    expect("sigaction-ignore-roundtrip", old.handler, 1);
    expect("sigaction-short-input", CALL4(SYS_rt_sigaction, 10, short8, 0, 8), -EFAULT);
    action.handler = 0;
    expect("sigaction-default", CALL4(SYS_rt_sigaction, 10, &action, &old, 8), 0);
    expect("sigaction-fault-preserved-ignore", old.handler, 1);
    expect("sigaction-read-default", CALL4(SYS_rt_sigaction, 10, 0, &old, 8), 0);
    expect("sigaction-default-roundtrip", old.handler, 0);

    struct SemBuf operation = { 0, 0, 0 };
    expect("semop-count-before-address", CALL4(SYS_semtimedop, -1, 1, 0, 0), -EINVAL);
    expect("semop-address-before-id", CALL4(SYS_semtimedop, -1, 1, 1, 0), -EFAULT);
    expect("semop-short-structure", CALL4(SYS_semtimedop, -1, page + 4092, 1, 0), -EFAULT);
    expect("semop-complete-before-id", CALL4(SYS_semtimedop, -1, &operation, 1, 0), -EINVAL);
    long semid = descriptor("semget", CALL(SYS_semget, 0, 1, 0600));
    expect("semop-valid-zero", CALL4(SYS_semtimedop, semid, &operation, 1, 0), 0);
    expect("semctl-remove", CALL4(SYS_semctl, semid, 0, 0, 0), 0);

    long epoll = descriptor("epoll-create", CALL(SYS_epoll_create1, 0, 0, 0));
    long eventfd = descriptor("eventfd", CALL(SYS_eventfd2, 0, 0, 0));
    struct EpollEvent event = { 1, 0x1234 };
    expect("epoll-fd-before-address", CALL4(SYS_epoll_ctl, -1, 1, eventfd, 1), -EBADF);
    expect("epoll-invalid-address", CALL4(SYS_epoll_ctl, epoll, 1, eventfd, 1), -EFAULT);
    expect("epoll-short-structure", CALL4(SYS_epoll_ctl, epoll, 1, eventfd, short8), -EFAULT);
    expect("epoll-fault-did-not-register", CALL4(SYS_epoll_ctl, epoll, 1, eventfd, &event), 0);
    expect("epoll-delete-ignores-address", CALL4(SYS_epoll_ctl, epoll, 2, eventfd, 1), 0);
    CALL(SYS_close, epoll, 0, 0); CALL(SYS_close, eventfd, 0, 0);
    CALL(SYS_munmap, page, 8192, 0);

    text("ABI_READS_PASS\n");
    CALL(SYS_reboot, 0xfee1dead, 672274793, 0x4321fedc);
    fail("poweroff-returned", 0, 1);
}
