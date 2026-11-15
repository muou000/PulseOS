/* Freestanding output ABI regression for #158, shared by RV64 and LA64. */
typedef unsigned long usize;
enum {
    SYS_eventfd2 = 19, SYS_epoll_create1 = 20, SYS_epoll_ctl = 21, SYS_epoll_pwait = 22,
    SYS_fcntl = 25, SYS_unlinkat = 35, SYS_openat = 56, SYS_close = 57, SYS_write = 64,
    SYS_exit_group = 94, SYS_getitimer = 102, SYS_clock_gettime = 113,
    SYS_sched_getparam = 121, SYS_sigaltstack = 132, SYS_reboot = 142, SYS_sysinfo = 179,
    SYS_semget = 190, SYS_semctl = 191, SYS_socket = 198, SYS_bind = 200,
    SYS_getsockname = 204, SYS_sendto = 206,
    SYS_getsockopt = 209, SYS_recvmsg = 212,
    SYS_munmap = 215, SYS_mmap = 222, SYS_mprotect = 226,
    EFAULT = 14,
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
    text("ABI_WRITES_FAIL "); text(name); text(" got="); number(got);
    text(" want="); number(want); text("\n");
    CALL(SYS_exit_group, 1, 0, 0);
    for (;;) {}
}

static void expect(const char *name, long got, long want)
{
    if (got != want) fail(name, got, want);
    text("ABI_WRITES_OK "); text(name); text("\n");
}

static long descriptor(const char *name, long fd)
{
    if (fd < 0) fail(name, fd, 0);
    return fd;
}

static void fill(void *address, usize n, unsigned char value)
{
    unsigned char *p = address;
    for (usize i = 0; i < n; ++i) p[i] = value;
}

static void expect_fill(const char *name, const void *address, usize n, unsigned char value)
{
    const unsigned char *p = address;
    for (usize i = 0; i < n; ++i) if (p[i] != value) fail(name, p[i], value);
    expect(name, 0, 0);
}

struct Timespec { long sec, nsec; };
struct Flock { short type, whence; long start, len; int pid; };
struct EpollEvent { unsigned events; usize data; };
struct Iovec { void *base; usize len; };
struct MessageHeader {
    void *name; unsigned namelen; struct Iovec *iov; usize iovlen;
    void *control; usize controllen; unsigned flags;
};
_Static_assert(sizeof(struct Flock) == 32, "kernel flock ABI");
_Static_assert(sizeof(struct EpollEvent) == 16, "RV64/LA64 epoll_event ABI");
_Static_assert(sizeof(struct MessageHeader) == 56, "RV64/LA64 msghdr ABI");

__attribute__((noreturn)) void _start(void)
{
    long mapping = syscall6(SYS_mmap, 0, 8192, 3, 0x22, (usize)-1, 0);
    if (mapping < 0) fail("mmap", mapping, 0);
    unsigned char *page = (unsigned char *)mapping;
    expect("protect-second-page", CALL(SYS_mprotect, page + 4096, 4096, 0), 0);
    unsigned char output[136] __attribute__((aligned(8)));

    /* File output: named fields are valid while input padding is poisoned. */
    const char path[] = "/tmp/pulse-abi-write-lock";
    long fd = descriptor("open-lock-file", CALL4(SYS_openat, -100, path, 0x242, 0600));
    fill(output, sizeof(output), 0xa5);
    struct Flock *lock = (struct Flock *)output;
    lock->type = 0; lock->whence = 0; lock->start = 0x1234; lock->len = 17; lock->pid = 0;
    expect("fcntl-getlk", CALL(SYS_fcntl, fd, 5, lock), 0);
    expect("fcntl-unlocked", lock->type, 2);
    expect("fcntl-native-start", lock->start, 0x1234);
    expect_fill("fcntl-inner-padding", output + 4, 4, 0);
    expect_fill("fcntl-tail-padding", output + 28, 4, 0);
    expect_fill("fcntl-output-length", output + 32, 8, 0xa5);
    /* A readable, read-only second page lets input succeed and output fault. */
    expect("flock-enable-input", CALL(SYS_mprotect, page + 4096, 4096, 3), 0);
    struct Flock *split = (struct Flock *)(page + 4080);
    fill(split, 32, 0xa5);
    split->type = 0; split->whence = 0; split->start = 0x1234; split->len = 17; split->pid = 0;
    expect("flock-read-only-tail", CALL(SYS_mprotect, page + 4096, 4096, 1), 0);
    expect("fcntl-output-fault", CALL(SYS_fcntl, fd, 5, split), -EFAULT);
    expect("fcntl-output-prefix", split->type, 2);
    expect_fill("fcntl-fault-padding", (unsigned char *)split + 4, 4, 0);
    expect("fcntl-readonly-tail-unchanged", split->len, 17);
    expect_fill("fcntl-readonly-padding-unchanged", (unsigned char *)split + 28, 4, 0xa5);
    expect("restore-inaccessible-tail", CALL(SYS_mprotect, page + 4096, 4096, 0), 0);
    CALL(SYS_close, fd, 0, 0); CALL(SYS_unlinkat, -100, path, 0);

    /* sysinfo has interior and trailing Rust padding in its 112-byte ABI. */
    fill(output, sizeof(output), 0xa5);
    expect("sysinfo", CALL(SYS_sysinfo, output, 0, 0), 0);
    expect("sysinfo-mem-unit", *(unsigned *)(output + 104), 1);
    expect_fill("sysinfo-inner-padding", output + 84, 4, 0);
    expect_fill("sysinfo-tail-padding", output + 108, 4, 0);
    expect_fill("sysinfo-output-length", output + 112, 8, 0xa5);
    expect("sysinfo-invalid-address", CALL(SYS_sysinfo, 1, 0, 0), -EFAULT);
    fill(page + 4008, 88, 0xa5);
    expect("sysinfo-output-fault", CALL(SYS_sysinfo, page + 4008, 0, 0), -EFAULT);
    expect("sysinfo-fault-procs", *(unsigned short *)(page + 4088), 1);
    expect_fill("sysinfo-fault-padding", page + 4092, 4, 0);

    /* Network scalar and padded message-header output. */
    long socket = descriptor("socket", CALL(SYS_socket, 2, 2, 0));
    unsigned len = 4;
    fill(output, sizeof(output), 0xa5);
    expect("getsockopt", CALL5(SYS_getsockopt, socket, 1, 7, output, &len), 0);
    expect("getsockopt-native-value", *(unsigned *)output, 65536);
    expect("getsockopt-native-length", len, 4);
    expect_fill("getsockopt-output-length", output + 4, 4, 0xa5);
    expect("getsockopt-invalid-output", CALL5(SYS_getsockopt, socket, 1, 7, 1, &len), -EFAULT);
    fill(page + 4094, 2, 0xa5);
    expect("getsockopt-output-fault", CALL5(SYS_getsockopt, socket, 1, 7, page + 4094, &len), -EFAULT);
    expect_fill("getsockopt-fault-prefix", page + 4094, 2, 0);
    CALL(SYS_close, socket, 0, 0);
    long receiver = descriptor("udp-receiver", CALL(SYS_socket, 2, 2, 0));
    long sender = descriptor("udp-sender", CALL(SYS_socket, 2, 2, 0));
    unsigned char address[16] __attribute__((aligned(4))) = { 2, 0, 0, 0, 127, 0, 0, 1 };
    expect("udp-bind", CALL(SYS_bind, receiver, address, sizeof(address)), 0);
    len = sizeof(address);
    expect("udp-name", CALL(SYS_getsockname, receiver, address, &len), 0);
    expect("udp-name-length", len, sizeof(address));
    unsigned char sent = 0x6b, received = 0;
    struct Iovec iov = { &received, 1 };
    struct MessageHeader *message = (struct MessageHeader *)output;
    fill(output, sizeof(output), 0xa5);
    message->name = 0; message->namelen = 0; message->iov = &iov; message->iovlen = 1;
    message->control = 0; message->controllen = 0; message->flags = 0;
    expect("udp-send", syscall6(SYS_sendto, sender, (usize)&sent, 1, 0, (usize)address, sizeof(address)), 1);
    expect("recvmsg", CALL(SYS_recvmsg, receiver, message, 0), 1);
    expect("recvmsg-payload", received, sent);
    expect_fill("recvmsg-inner-padding", output + 12, 4, 0);
    expect_fill("recvmsg-tail-padding", output + 52, 4, 0);
    expect_fill("recvmsg-output-length", output + 56, 8, 0xa5);
    CALL(SYS_close, receiver, 0, 0); CALL(SYS_close, sender, 0, 0);

    /* Time output: inactive timer is a deterministic all-zero record. */
    fill(output, sizeof(output), 0xa5);
    expect("getitimer", CALL(SYS_getitimer, 0, output, 0), 0);
    expect_fill("getitimer-zero-value", output, 32, 0);
    expect_fill("getitimer-output-length", output + 32, 8, 0xa5);
    expect("getitimer-invalid-output", CALL(SYS_getitimer, 0, 1, 0), -EFAULT);
    fill(page + 4088, 8, 0xa5);
    expect("getitimer-output-fault", CALL(SYS_getitimer, 0, page + 4088, 0), -EFAULT);
    expect_fill("getitimer-fault-prefix", page + 4088, 8, 0);
    struct Timespec now;
    expect("clock-gettime", CALL(SYS_clock_gettime, 1, &now, 0), 0);
    expect("clock-native-fields", now.sec >= 0 && now.nsec >= 0 && now.nsec < 1000000000, 1);

    /* Task output: altstack has four padding bytes before its size. */
    fill(output, sizeof(output), 0xa5);
    expect("sigaltstack", CALL(SYS_sigaltstack, 0, output, 0), 0);
    expect_fill("sigaltstack-padding", output + 12, 4, 0);
    expect_fill("sigaltstack-output-length", output + 24, 8, 0xa5);
    expect("sigaltstack-invalid-output", CALL(SYS_sigaltstack, 0, 1, 0), -EFAULT);
    fill(page + 4080, 16, 0xa5);
    expect("sigaltstack-output-fault", CALL(SYS_sigaltstack, 0, page + 4080, 0), -EFAULT);
    expect_fill("sigaltstack-fault-padding", page + 4092, 4, 0);
    expect("sched-getparam-invalid-output", CALL(SYS_sched_getparam, 0, 1, 0), -EFAULT);

    /* Preserve existing semid_ds layout and element-prefix behavior of GETALL. */
    long semid = descriptor("semget", CALL(SYS_semget, 0, 2, 0600));
    expect("semctl-set-first", CALL4(SYS_semctl, semid, 0, 16, 0x1234), 0);
    expect("semctl-set-second", CALL4(SYS_semctl, semid, 1, 16, 0x5678), 0);
    fill(output, sizeof(output), 0xa5);
    expect("semctl-stat", CALL4(SYS_semctl, semid, 0, 2, output), 0);
    expect_fill("semctl-stat-padding", output + 36, 4, 0);
    expect("semctl-stat-nsems", *(usize *)(output + 56), 2);
    expect_fill("semctl-stat-output-length", output + 80, 8, 0xa5);
    expect("semctl-stat-invalid-output", CALL4(SYS_semctl, semid, 0, 2, 1), -EFAULT);
    fill(output, sizeof(output), 0xa5);
    expect("semctl-getall", CALL4(SYS_semctl, semid, 0, 13, output), 0);
    expect("semctl-first-native-value", *(unsigned short *)output, 0x1234);
    expect("semctl-second-native-value", *(unsigned short *)(output + 2), 0x5678);
    expect_fill("semctl-getall-output-length", output + 4, 4, 0xa5);
    fill(page + 4093, 3, 0xa5);
    expect("semctl-getall-fault", CALL4(SYS_semctl, semid, 0, 13, page + 4093), -EFAULT);
    const unsigned short values[2] = { 0x1234, 0x5678 };
    const unsigned char *native = (const unsigned char *)values;
    expect("semctl-getall-prefix-0", page[4093], native[0]);
    expect("semctl-getall-prefix-1", page[4094], native[1]);
    expect("semctl-getall-prefix-2", page[4095], native[2]);
    expect("semctl-remove", CALL4(SYS_semctl, semid, 0, 0, 0), 0);

    /* Readiness output: live eventfd stays ready for each faulting wait. */
    long epoll = descriptor("epoll-create", CALL(SYS_epoll_create1, 0, 0, 0));
    long eventfd = descriptor("eventfd", CALL(SYS_eventfd2, 1, 0, 0));
    struct EpollEvent event = { 1, 0x123456789abcdefUL };
    expect("epoll-add", CALL4(SYS_epoll_ctl, epoll, 1, eventfd, &event), 0);
    fill(output, sizeof(output), 0xa5);
    expect("epoll-output", CALL5(SYS_epoll_pwait, epoll, output, 1, 0, 0), 1);
    expect("epoll-native-events", ((struct EpollEvent *)output)->events, 1);
    expect("epoll-native-data", ((struct EpollEvent *)output)->data, event.data);
    expect_fill("epoll-padding", output + 4, 4, 0);
    expect_fill("epoll-output-length", output + 16, 8, 0xa5);
    expect("epoll-invalid-output", CALL5(SYS_epoll_pwait, epoll, 1, 1, 0, 0), -EFAULT);
    fill(page + 4088, 8, 0xa5);
    expect("epoll-output-fault", CALL5(SYS_epoll_pwait, epoll, page + 4088, 1, 0, 0), -EFAULT);
    expect("epoll-fault-events", *(unsigned *)(page + 4088), 1);
    expect_fill("epoll-fault-padding", page + 4092, 4, 0);
    CALL(SYS_close, epoll, 0, 0); CALL(SYS_close, eventfd, 0, 0);
    CALL(SYS_munmap, page, 8192, 0);

    text("ABI_WRITES_PASS\n");
    CALL(SYS_reboot, 0xfee1dead, 672274793, 0x4321fedc);
    fail("poweroff-returned", 0, 1);
}
