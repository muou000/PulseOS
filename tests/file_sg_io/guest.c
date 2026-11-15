/* Real Linux-ABI I/O observations for #136, shared by RV64 and LA64. */
typedef unsigned long usize;
typedef unsigned long u64;
enum {
    SYS_fcntl = 25, SYS_openat = 56, SYS_close = 57, SYS_pipe2 = 59,
    SYS_lseek = 62, SYS_read = 63, SYS_write = 64, SYS_readv = 65,
    SYS_writev = 66, SYS_pread64 = 67, SYS_pwrite64 = 68,
    SYS_preadv = 69, SYS_pwritev = 70, SYS_ftruncate = 46,
    SYS_fstat = 80,
    SYS_exit = 93, SYS_exit_group = 94, SYS_clock_gettime = 113, SYS_reboot = 142,
    SYS_prctl = 167, SYS_getpid = 172, SYS_munmap = 215, SYS_clone = 220,
    SYS_mmap = 222, SYS_mprotect = 226, SYS_wait4 = 260,
    SYS_preadv2 = 286, SYS_pwritev2 = 287,
    AT_FDCWD = -100, O_RDWR = 2, O_CREAT = 64, O_TRUNC = 512,
    O_APPEND = 1024, O_DIRECT = 16384,
    EFAULT = 14, EINVAL = 22, SIGCHLD = 17,
};
#define PAGE 4096UL
#ifndef SG_SUITE
#define SG_SUITE 1
#endif
#ifndef SG_SAMPLES
#define SG_SAMPLES 5
#endif
#ifndef SG_ITERATIONS
#define SG_ITERATIONS 16
#endif
#ifndef SG_DISK_BYTES
#define SG_DISK_BYTES 0UL
#endif

struct Iovec { void *base; usize len; };
struct Timespec { long sec, nsec; };
struct Counters {
    u64 version, position_acquires, operations, pin_peak_pages, staged_bytes;
};

/* CLONE_VM enters C on the child stack, never through a parent C frame. */
extern long sg_spawn_vm(usize, void *, void (*)(void *), void *);
#ifdef __riscv
__asm__(
    ".text\n.global sg_spawn_vm\n.type sg_spawn_vm,@function\nsg_spawn_vm:\n"
    "addi a1,a1,-16\nsd a2,0(a1)\nsd a3,8(a1)\n"
    "li a2,0\nli a3,0\nli a4,0\nli a7,220\necall\n"
    "bnez a0,1f\nld t0,0(sp)\nld a0,8(sp)\njalr t0\n"
    "li a0,127\nli a7,93\necall\n1:\nret\n"
);
#else
__asm__(
    ".text\n.global sg_spawn_vm\n.type sg_spawn_vm,@function\nsg_spawn_vm:\n"
    "addi.d $a1,$a1,-16\nst.d $a2,$a1,0\nst.d $a3,$a1,8\n"
    "addi.d $a2,$zero,0\naddi.d $a3,$zero,0\naddi.d $a4,$zero,0\n"
    "addi.d $a7,$zero,220\nsyscall 0\nbnez $a0,1f\n"
    "ld.d $t0,$sp,0\nld.d $a0,$sp,8\njirl $ra,$t0,0\n"
    "addi.d $a0,$zero,127\naddi.d $a7,$zero,93\nsyscall 0\n"
    "1:\njirl $zero,$ra,0\n"
);
#endif

static long syscall6(long nr, usize x0, usize x1, usize x2,
                     usize x3, usize x4, usize x5)
{
    register usize a0 __asm__("a0") = x0;
    register usize a1 __asm__("a1") = x1;
    register usize a2 __asm__("a2") = x2;
    register usize a3 __asm__("a3") = x3;
    register usize a4 __asm__("a4") = x4;
    register usize a5 __asm__("a5") = x5;
    register usize a7 __asm__("a7") = nr;
#ifdef __riscv
    __asm__ volatile("ecall" : "+r"(a0)
                     : "r"(a1), "r"(a2), "r"(a3), "r"(a4),
                       "r"(a5), "r"(a7) : "memory");
#else
    __asm__ volatile("syscall 0" : "+r"(a0)
                     : "r"(a1), "r"(a2), "r"(a3), "r"(a4),
                       "r"(a5), "r"(a7) : "memory");
#endif
    return a0;
}
#define CALL(n,a,b,c) syscall6(n,(usize)(a),(usize)(b),(usize)(c),0,0,0)
#define CALL4(n,a,b,c,d) syscall6(n,(usize)(a),(usize)(b),(usize)(c),(usize)(d),0,0)
#define CALL5(n,a,b,c,d,e) syscall6(n,(usize)(a),(usize)(b),(usize)(c),(usize)(d),(usize)(e),0)

static void text(const char *s)
{
    usize n = 0;
    while (s[n]) ++n;
    CALL(SYS_write, 1, s, n);
}

static void number(long value)
{
    char buf[24];
    usize i = sizeof(buf), n = value < 0 ? -(usize)value : (usize)value;
    do { buf[--i] = '0' + n % 10; n /= 10; } while (n);
    if (value < 0) buf[--i] = '-';
    CALL(SYS_write, 1, buf + i, sizeof(buf) - i);
}

__attribute__((noreturn)) static void exit_process(int status)
{
    CALL(SYS_exit_group, status, 0, 0);
    for (;;) {}
}

__attribute__((noreturn)) static void fail(const char *name, long got, long want)
{
    text("SG_FAIL "); text(name); text(" got="); number(got);
    text(" want="); number(want); text("\n");
    exit_process(1);
}

static void check(const char *name, long got, long want)
{
    if (got != want) fail(name, got, want);
}

static void passed(const char *name)
{
    text("SG_OK "); text(name); text("\n");
}

static long open_file(const char *path, usize flags)
{
    long fd = CALL4(SYS_openat, AT_FDCWD, path, flags, 0600);
    if (fd < 0) fail(path, fd, 0);
    return fd;
}

static unsigned char *mapping(usize len)
{
    long address = syscall6(SYS_mmap, 0, len, 3, 0x22, (usize)-1, 0);
    if (address < 0) fail("mmap", address, 0);
    return (unsigned char *)address;
}

static unsigned char pattern(usize i)
{
    return (unsigned char)(i * 37 + 11);
}

static void fill_pattern(unsigned char *buf, usize len)
{
    for (usize i = 0; i < len; ++i) buf[i] = pattern(i);
}

static void verify_pattern(const char *name, const unsigned char *buf, usize len)
{
    for (usize i = 0; i < len; ++i)
        if (buf[i] != pattern(i)) fail(name, i, -1);
}

/* A test-only observation; no RESET means benchmark counters stay disabled. */
static usize physical_breaks(unsigned char *buf, usize len)
{
    long breaks = CALL5(SYS_prctl, 0x50534749, 3, buf, len, 0);
    if (breaks < 0) fail("PSGI-layout-query-needs-file-io-test", breaks, 0);
    return (usize)breaks;
}

struct Fixture { unsigned char *buf; unsigned char *filler; usize len, breaks; };

static struct Fixture fixture(usize len, int fragmented)
{
    struct Fixture f = { mapping(len), 0, len, 0 };
    if (fragmented) {
        f.filler = mapping(len * 2);
        /* Anonymous faults may populate four pages at once. Keep all future
         * pages inaccessible until their own turn so each target allocation
         * is separated by live filler allocations. */
        check("fragment-protect-target", CALL(SYS_mprotect, f.buf, len, 0), 0);
        check("fragment-protect-filler", CALL(SYS_mprotect, f.filler, len * 2, 0), 0);
    }
    for (usize page = 0; page < len / PAGE; ++page) {
        if (fragmented)
            check("fragment-enable-target", CALL(SYS_mprotect, f.buf + page * PAGE, PAGE, 3), 0);
        ((volatile unsigned char *)f.buf)[page * PAGE] = 1;
        if (f.filler) {
            check("fragment-enable-filler",
                  CALL(SYS_mprotect, f.filler + page * PAGE * 2, PAGE * 2, 3), 0);
            /* Keep the intervening pages live throughout every sample. */
            ((volatile unsigned char *)f.filler)[page * PAGE * 2] = 2;
            ((volatile unsigned char *)f.filler)[page * PAGE * 2 + PAGE] = 3;
        }
    }
    fill_pattern(f.buf, len);
    f.breaks = physical_breaks(f.buf, len);
    if (fragmented && f.breaks != len / PAGE - 1)
        fail("fragment-fixture-needs-every-neighbour-discontinuous",
             f.breaks, len / PAGE - 1);
    text("SG_LAYOUT layout="); text(fragmented ? "fragmented" : "natural");
    text(" bytes="); number(len); text(" pages="); number(len / PAGE);
    text(" discontinuities="); number(f.breaks); text("\n");
    return f;
}

static void destroy_fixture(struct Fixture *f)
{
    check("unmap-buffer", CALL(SYS_munmap, f->buf, f->len, 0), 0);
    if (f->filler)
        check("unmap-filler", CALL(SYS_munmap, f->filler, f->len * 2, 0), 0);
}

static u64 now_ns(void)
{
    struct Timespec ts;
    check("clock-monotonic", CALL(SYS_clock_gettime, 1, &ts, 0), 0);
    return (u64)ts.sec * 1000000000UL + ts.nsec;
}

static long transfer(long fd, unsigned char *buf, usize len, int write, int vector)
{
    if (!vector) return CALL(write ? SYS_write : SYS_read, fd, buf, len);
    struct Iovec iov[64];
    for (usize i = 0; i < 64; ++i) {
        iov[i].base = buf + i * (len / 64);
        iov[i].len = len / 64;
    }
    return CALL(write ? SYS_writev : SYS_readv, fd, iov, 64);
}

static void benchmark(int small)
{
    long fd = open_file("/sg-benchmark.data", O_CREAT | O_TRUNC | O_RDWR);
    for (int fragmented = 0; fragmented < (small ? 1 : 2); ++fragmented) {
        for (usize len = small ? PAGE : 65536; len <= (small ? PAGE : 262144); len *= 4) {
            struct Fixture f = fixture(len, fragmented);
            check("seed-file", CALL4(SYS_pwrite64, fd, f.buf, len, 0), len);
            for (int write = 0; write < 2; ++write) {
                for (int vector = 0; vector < 2; ++vector) {
                    /* The measured cases are explicitly warm-cache. */
                    check("warm-seek", CALL(SYS_lseek, fd, 0, 0), 0);
                    check("warm-transfer", transfer(fd, f.buf, len, write, vector), len);
                    for (int sample = 0; sample < SG_SAMPLES; ++sample) {
                        if (!write)
                            for (usize i = 0; i < len; ++i) f.buf[i] ^= 0xff;
                        u64 elapsed = 0;
                        for (int iteration = 0; iteration < SG_ITERATIONS; ++iteration) {
                            check("bench-seek", CALL(SYS_lseek, fd, 0, 0), 0);
                            u64 before = now_ns();
                            long n = transfer(fd, f.buf, len, write, vector);
                            elapsed += now_ns() - before;
                            check("bench-transfer", n, len);
                        }
                        verify_pattern("benchmark-sample-content", f.buf, len);
                        text("SG_BENCH layout="); text(fragmented ? "fragmented" : "natural");
                        text(" operation="); text(write ? "write" : "read");
                        if (vector) text("v");
                        text(" bytes="); number(len);
                        text(" sample="); number(sample);
                        text(" iterations="); number(SG_ITERATIONS);
                        text(" elapsed_ns="); number(elapsed);
                        text(" discontinuities="); number(f.breaks); text("\n");
                    }
                    verify_pattern("benchmark-content", f.buf, len);
                }
            }
            destroy_fixture(&f);
        }
    }
    check("bench-close", CALL(SYS_close, fd, 0, 0), 0);
    passed("benchmark-matrix");
}

/* A single append writev is a record, even when its 64 iovecs race with another
 * open file description. A short successful record is also a failure here. */
static void append_records(int independent)
{
    enum { WORKERS = 4, RECORDS = 40, PARTS = 64, PART_SIZE = 256,
           RECORD_SIZE = PARTS * PART_SIZE };
    const char *path = independent == 1 ? "/sg-append-independent" :
                       independent == 2 ? "/sg-shared-write" : "/sg-append-shared";
    long fd = open_file(path, O_CREAT | O_TRUNC | O_RDWR);
    check("append-close-seed", CALL(SYS_close, fd, 0, 0), 0);
    fd = open_file(path, O_RDWR | (independent == 2 ? 0 : O_APPEND));
    int gate[2];
    check("append-pipe", CALL(SYS_pipe2, gate, 0, 0), 0);
    long children[WORKERS];
    for (int worker = 0; worker < WORKERS; ++worker) {
        long child = CALL(SYS_clone, SIGCHLD, 0, 0);
        if (child < 0) fail("append-fork", child, 0);
        if (child == 0) {
            unsigned char *buf = mapping(RECORD_SIZE);
            struct Iovec iov[PARTS];
            for (usize i = 0; i < RECORD_SIZE; ++i) buf[i] = 'A' + worker;
            for (usize i = 0; i < PARTS; ++i) {
                iov[i].base = buf + i * PART_SIZE;
                iov[i].len = PART_SIZE;
            }
            if (independent == 1) {
                check("child-close-inherited", CALL(SYS_close, fd, 0, 0), 0);
                fd = open_file(path, O_RDWR | O_APPEND);
            }
            char go;
            check("append-gate", CALL(SYS_read, gate[0], &go, 1), 1);
            for (int record = 0; record < RECORDS; ++record)
                check("append-writev", CALL(SYS_writev, fd, iov, PARTS), RECORD_SIZE);
            exit_process(0);
        }
        children[worker] = child;
    }
    check("release-append-workers", CALL(SYS_write, gate[1], "go!!", WORKERS), WORKERS);
    for (int worker = 0; worker < WORKERS; ++worker) {
        int status = -1;
        check("append-wait", CALL4(SYS_wait4, children[worker], &status, 0, 0),
              children[worker]);
        check("append-child-status", status, 0);
    }
    if (independent != 1)
        check("shared-write-final-position", CALL(SYS_lseek, fd, 0, 1),
              WORKERS * RECORDS * RECORD_SIZE);
    check("append-file-size", CALL(SYS_lseek, fd, 0, 2),
          WORKERS * RECORDS * RECORD_SIZE);
    check("append-rewind", CALL(SYS_lseek, fd, 0, 0), 0);
    unsigned char *record = mapping(RECORD_SIZE);
    int counts[WORKERS] = { 0, 0, 0, 0 };
    for (int i = 0; i < WORKERS * RECORDS; ++i) {
        check("append-read-record", CALL(SYS_read, fd, record, RECORD_SIZE), RECORD_SIZE);
        unsigned char tag = record[0];
        if (tag < 'A' || tag >= 'A' + WORKERS) fail("append-record-tag", tag, 'A');
        for (usize byte = 0; byte < RECORD_SIZE; ++byte)
            if (record[byte] != tag)
                fail(independent == 1 ? "append-independent-record-interleaved" :
                     independent == 2 ? "shared-write-record-interleaved" :
                     "append-shared-record-interleaved", i * RECORD_SIZE + byte, -1);
        ++counts[tag - 'A'];
    }
    for (int worker = 0; worker < WORKERS; ++worker)
        check("append-worker-record-count", counts[worker], RECORDS);
    check("append-close", CALL(SYS_close, fd, 0, 0), 0);
    CALL(SYS_close, gate[0], 0, 0); CALL(SYS_close, gate[1], 0, 0);
    CALL(SYS_munmap, record, RECORD_SIZE, 0);
    passed(independent == 1 ? "append-independent-records" :
           independent == 2 ? "shared-write-records" : "append-shared-records");
}

static long vector_at(long fd, struct Iovec *iov, usize count, int write,
                      long offset, int version2)
{
    return syscall6(version2 ? (write ? SYS_pwritev2 : SYS_preadv2) :
                    (write ? SYS_pwritev : SYS_preadv), fd, (usize)iov,
                    count, offset, offset < 0 ? (usize)-1 : 0, 0);
}

/* The pristine kernel can run the same semantic probe without test hooks.
 * With hooks present, SNAPSHOT also asserts that every pin has been released. */
static int observe_begin(void)
{
    long n = CALL5(SYS_prctl, 0x50534749, 0, 0, 0, 0);
    if (n == -EINVAL) return 0;
    check("observe-reset", n, 0);
    return 1;
}

static void observe_end(int active)
{
    if (!active) return;
    struct Counters counters;
    long snapshot = CALL5(SYS_prctl, 0x50534749, 1, &counters, sizeof(counters), 0);
    long disabled = CALL5(SYS_prctl, 0x50534749, 2, 0, 0, 0);
    check("observe-disable", disabled, 0);
    check("observe-no-outstanding-pins", snapshot, 0);
    check("observe-version", counters.version, 1);
}

/* Assert actual progress, not that every accessible prefix must be copied. */
static void partial_fault(long fd, int write, int vector, int positioned)
{
    unsigned char *buf = mapping(PAGE * 2), *verify = mapping(PAGE * 2);
    fill_pattern(verify, PAGE * 2);
    check("fault-seed", CALL4(SYS_pwrite64, fd, verify, PAGE * 2, 0), PAGE * 2);
    for (usize i = 0; i < PAGE; ++i) buf[i] = write ? 0x5a : 0xcc;
    check("fault-protect", CALL(SYS_mprotect, buf + PAGE, PAGE, 0), 0);
    check("fault-set-position", CALL(SYS_lseek, fd, positioned ? 123 : 0, 0),
          positioned ? 123 : 0);
    unsigned char *start = buf + PAGE - 256;
    struct Iovec iov[3] = { { start, 256 }, { buf + PAGE, 256 }, { buf, 256 } };
    int observed = observe_begin();
    long n;
    if (vector)
        n = positioned ? vector_at(fd, iov, 3, write, 0, 0) :
            CALL(write ? SYS_writev : SYS_readv, fd, iov, 3);
    else
        n = positioned ? CALL4(write ? SYS_pwrite64 : SYS_pread64, fd, start, 512, 0) :
            CALL(write ? SYS_write : SYS_read, fd, start, 512);
    observe_end(observed);
    if (n != -EFAULT && (n < 0 || n > 256)) fail("partial-fault-return", n, 256);
    usize completed = n < 0 ? 0 : (usize)n;
    check("partial-fault-position", CALL(SYS_lseek, fd, 0, 1),
          positioned ? 123 : (long)completed);
    if (write) {
        check("fault-verify-file", CALL4(SYS_pread64, fd, verify, PAGE * 2, 0), PAGE * 2);
        for (usize i = 0; i < PAGE * 2; ++i)
            if (verify[i] != (i < completed ? 0x5a : pattern(i)))
                fail("partial-write-content", i, -1);
    } else {
        for (usize i = 0; i < 256; ++i)
            if (start[i] != (i < completed ? pattern(i) : 0xcc))
                fail("partial-read-content", i, -1);
        for (usize i = 0; i < PAGE - 256; ++i)
            if (buf[i] != 0xcc) fail("partial-read-canary-or-skipped-fault", i, -1);
    }
    long before_fault = CALL(SYS_lseek, fd, 0, 1);
    struct Iovec bad = { buf + PAGE, 1 };
    observed = observe_begin();
    if (vector)
        n = positioned ? vector_at(fd, &bad, 1, write, 0, 0) :
            CALL(write ? SYS_writev : SYS_readv, fd, &bad, 1);
    else
        n = positioned ? CALL4(write ? SYS_pwrite64 : SYS_pread64,
                                fd, buf + PAGE, 1, 0) :
            CALL(write ? SYS_write : SYS_read, fd, buf + PAGE, 1);
    observe_end(observed);
    check("first-byte-fault", n, -EFAULT);
    check("first-byte-fault-position", CALL(SYS_lseek, fd, 0, 1), before_fault);
    CALL(SYS_munmap, buf, PAGE * 2, 0); CALL(SYS_munmap, verify, PAGE * 2, 0);
    passed(write ? "partial-write-content-position" : "partial-read-content-position");
}

static void semantic_io(void)
{
    const char *path = "/sg-semantics.data";
    long fd = open_file(path, O_CREAT | O_TRUNC | O_RDWR);
    unsigned char *buf = mapping(65536), *out = mapping(65536);
    fill_pattern(buf, 65536);
    check("semantic-seed", CALL(SYS_write, fd, buf, 65536), 65536);
    check("semantic-seek", CALL(SYS_lseek, fd, 777, 0), 777);
    struct Iovec iov[4] = { { out, 17 }, { (void *)1, 0 },
                            { out + 17, 5001 }, { out + 5018, 60518 } };
    check("preadv-unaligned-and-empty", vector_at(fd, iov, 4, 0, 0, 0), 65536);
    check("preadv-keeps-position", CALL(SYS_lseek, fd, 0, 1), 777);
    verify_pattern("preadv-data", out, 65536);
    for (usize i = 0; i < 65536; ++i) out[i] = 0xa7;
    int observed = observe_begin();
    long short_read = CALL4(SYS_pread64, fd, out, 65536, 65500);
    observe_end(observed);
    check("pread-eof-short-read", short_read, 36);
    check("pread-eof-position", CALL(SYS_lseek, fd, 0, 1), 777);
    for (usize i = 0; i < 65536; ++i)
        if (out[i] != (i < 36 ? pattern(65500 + i) : 0xa7))
            fail("pread-eof-canary", i, -1);
    check("preadv2-explicit", vector_at(fd, iov, 4, 0, 0, 1), 65536);
    check("preadv2-keeps-position", CALL(SYS_lseek, fd, 0, 1), 777);
    check("v2-shared-rewind", CALL(SYS_lseek, fd, 0, 0), 0);
    check("preadv2-shared", vector_at(fd, iov, 4, 0, -1, 1), 65536);
    check("preadv2-shared-position", CALL(SYS_lseek, fd, 0, 1), 65536);
    check("read-eof", CALL(SYS_read, fd, out, 1), 0);
    check("zero-readv", CALL(SYS_readv, fd, (void *)1, 0), 0);
    check("zero-writev", CALL(SYS_writev, fd, (void *)1, 0), 0);
    for (int write = 0; write < 2; ++write)
        for (int vector = 0; vector < 2; ++vector)
            for (int positioned = 0; positioned < 2; ++positioned)
                partial_fault(fd, write, vector, positioned);
    check("semantic-close", CALL(SYS_close, fd, 0, 0), 0);

    fd = open_file(path, O_RDWR | O_APPEND);
    long end = CALL(SYS_lseek, fd, 0, 2);
    if (end < 0) fail("append-current-end", end, 0);
    check("positioned-append-seek", CALL(SYS_lseek, fd, 321, 0), 321);
    struct Iovec append_iov[2] = { { buf, 1000 }, { buf + 1000, 2000 } };
    check("pwritev-append", vector_at(fd, append_iov, 2, 1, 0, 0), 3000);
    check("pwritev-append-position", CALL(SYS_lseek, fd, 0, 1), 321);
    check("pwritev-append-end", CALL(SYS_lseek, fd, 0, 2), end + 3000);
    check("pwritev-append-content", CALL4(SYS_pread64, fd, out, 3000, end), 3000);
    verify_pattern("pwritev-append-bytes", out, 3000);
    check("positioned-append-close", CALL(SYS_close, fd, 0, 0), 0);

    fd = open_file(path, O_RDWR | O_DIRECT);
    check("direct-valid-pwrite", CALL4(SYS_pwrite64, fd, buf, PAGE, 0), PAGE);
    check("direct-valid-pread", CALL4(SYS_pread64, fd, out, PAGE, 0), PAGE);
    verify_pattern("direct-content", out, PAGE);
    check("direct-misaligned-source", CALL4(SYS_pwrite64, fd, buf + 1, PAGE, 0), -EINVAL);
    check("direct-misaligned-offset", CALL4(SYS_pread64, fd, out, PAGE, 1), -EINVAL);
    struct Iovec empty_bad = { (void *)1, 0 }, empty_aligned = { buf, 0 };
    check("direct-zero-iov-read-base", CALL(SYS_readv, fd, &empty_bad, 1), -EINVAL);
    check("direct-zero-iov-write-base", CALL(SYS_writev, fd, &empty_bad, 1), -EINVAL);
    check("direct-seek-misaligned", CALL(SYS_lseek, fd, 1, 0), 1);
    check("direct-zero-iov-read-position", CALL(SYS_readv, fd, &empty_aligned, 1), -EINVAL);
    check("direct-zero-iov-write-position", CALL(SYS_writev, fd, &empty_aligned, 1), -EINVAL);
    check("direct-zero-iov-pread-position", vector_at(fd, &empty_aligned, 1, 0, 1, 0), -EINVAL);
    check("direct-zero-iov-pwrite-position", vector_at(fd, &empty_aligned, 1, 1, 1, 0), -EINVAL);
    check("direct-zero-scalar-read", CALL(SYS_read, fd, (void *)1, 0), 0);
    check("direct-zero-scalar-write", CALL(SYS_write, fd, (void *)1, 0), 0);
    check("direct-close", CALL(SYS_close, fd, 0, 0), 0);
    struct Iovec bad_alignment = { buf + 1, PAGE };
    fd = open_file(path, O_DIRECT);
    check("direct-write-alignment-before-access", CALL(SYS_writev, fd, &bad_alignment, 1), -EINVAL);
    CALL(SYS_close, fd, 0, 0);
    fd = open_file(path, 1 | O_DIRECT);
    check("direct-read-alignment-before-access", CALL(SYS_readv, fd, &bad_alignment, 1), -EINVAL);
    CALL(SYS_close, fd, 0, 0);
    CALL(SYS_munmap, buf, 65536, 0); CALL(SYS_munmap, out, 65536, 0);
    passed("positioned-v2-direct-and-empty");
}

static void mapping_io(void)
{
    const char *path = "/sg-mapping.data";
    const usize len = 262144;
    unsigned char *seed = mapping(len), *out = mapping(len);
    fill_pattern(seed, len);
    long fd = open_file(path, O_CREAT | O_TRUNC | O_RDWR);
    check("mapping-seed", CALL(SYS_write, fd, seed, len), len);

    /* Later target segments overlap earlier ones. Observable ordering is
     * iovec ordering, not frame address ordering. */
    for (usize i = 0; i < 300; ++i) out[i] = 0xcc;
    struct Iovec overlap[2] = { { out + 100, 80 }, { out + 140, 80 } };
    int observed = observe_begin();
    long read = vector_at(fd, overlap, 2, 0, 0, 0);
    observe_end(observed);
    check("overlap-preadv", read, 160);
    for (usize i = 0; i < 300; ++i) {
        unsigned char expected = 0xcc;
        if (i >= 100 && i < 140) expected = pattern(i - 100);
        if (i >= 140 && i < 220) expected = pattern(i - 140 + 80);
        if (out[i] != expected) fail("overlap-ordered-content", i, -1);
    }
    passed("overlap-read-order");

    /* Reading into the child's inherited anonymous memory must resolve CoW
     * before handing any writable destination to the file cache. */
    for (usize i = 0; i < 65536; ++i) out[i] = 0x33;
    long child = CALL(SYS_clone, SIGCHLD, 0, 0);
    if (child < 0) fail("cow-fork", child, 0);
    if (child == 0) {
        struct Iovec dest[2] = { { out, 17001 }, { out + 17001, 48535 } };
        observed = observe_begin();
        read = vector_at(fd, dest, 2, 0, 0, 0);
        observe_end(observed);
        check("cow-child-preadv", read, 65536);
        verify_pattern("cow-child-data", out, 65536);
        exit_process(0);
    }
    int status = -1;
    check("cow-wait", CALL4(SYS_wait4, child, &status, 0, 0), child);
    check("cow-child-status", status, 0);
    for (usize i = 0; i < 65536; ++i)
        if (out[i] != 0x33) fail("cow-parent-preserved", i, -1);
    passed("cow-destination-isolated");

    check("mapping-seed-close", CALL(SYS_close, fd, 0, 0), 0);
    fd = open_file(path, O_RDWR | O_APPEND);
    for (int vector = 0; vector < 2; ++vector) {
        /* The mapping stays unfaulted until the I/O operation reaches it.
         * Crossing 64 KiB catches recursively taking a file's I/O lock while
         * preparing the next window from that same file. */
        long address = syscall6(SYS_mmap, 0, len, 1, 2, fd, 0);
        if (address < 0) fail("same-file-mmap", address, 0);
        unsigned char *mapped = (unsigned char *)address;
        observed = observe_begin();
        long written = transfer(fd, mapped, len, 1, vector);
        observe_end(observed);
        check("same-file-cross-window-append", written, len);
        check("same-file-append-size", CALL(SYS_lseek, fd, 0, 2), len * (vector + 2));
        check("same-file-appended-read", CALL4(SYS_pread64, fd, out, len, len * (vector + 1)), len);
        verify_pattern("same-file-append-data", out, len);
        check("same-file-unmap", CALL(SYS_munmap, mapped, len, 0), 0);
    }
    check("mapping-close", CALL(SYS_close, fd, 0, 0), 0);
    CALL(SYS_munmap, seed, len, 0); CALL(SYS_munmap, out, len, 0);
    passed("same-file-mmap-cross-window-append");
}

static void measured_transfer(long fd, struct Fixture *f, int write, int vector,
                              int positioned, int direct, int append, int cold)
{
    check("counter-start-position", CALL(SYS_lseek, fd, positioned ? PAGE : 0, 0),
          positioned ? PAGE : 0);
    struct Iovec iov[64];
    usize count = f->len / PAGE;
    for (usize i = 0; i < count; ++i) {
        iov[i].base = f->buf + i * PAGE;
        iov[i].len = PAGE;
    }
    struct Counters counters;
    check("counter-reset", CALL5(SYS_prctl, 0x50534749, 0, 0, 0, 0), 0);
    long result;
    if (vector)
        result = positioned ? vector_at(fd, iov, count, write, 0, 0) :
            CALL(write ? SYS_writev : SYS_readv, fd, iov, count);
    else
        result = positioned ? CALL4(write ? SYS_pwrite64 : SYS_pread64,
                                     fd, f->buf, f->len, 0) :
            CALL(write ? SYS_write : SYS_read, fd, f->buf, f->len);
    long snapshot = CALL5(SYS_prctl, 0x50534749, 1, &counters, sizeof(counters), 0);
    long disabled = CALL5(SYS_prctl, 0x50534749, 2, 0, 0, 0);
    check("counter-disable", disabled, 0);
    check("counter-snapshot", snapshot, 0);
    check("counted-transfer-result", result, f->len);
    check("counter-version", counters.version, 1);
    text("SG_COUNT layout="); text(f->filler ? "fragmented" : "natural");
    text(" operation="); text(write ? "write" : "read");
    if (vector) text("v");
    text(" bytes="); number(f->len);
    text(" positional="); number(positioned); text(" direct="); number(direct);
    text(" append="); number(append); text(" cold="); number(cold);
    text(" position_acquires="); number(counters.position_acquires);
    text(" operations="); number(counters.operations);
    text(" pin_peak_pages="); number(counters.pin_peak_pages);
    text(" staged_bytes="); number(counters.staged_bytes); text("\n");
    check("single-position-acquisition", counters.position_acquires, positioned ? 0 : 1);
    check("single-file-operation", counters.operations, 1);
    if (!counters.pin_peak_pages || counters.pin_peak_pages > 32)
        fail("bounded-pin-window", counters.pin_peak_pages, 32);
    check("staged-payload-byte-count", counters.staged_bytes, f->len);
    if (positioned)
        check("counted-positioned-offset", CALL(SYS_lseek, fd, 0, 1), PAGE);
    if (!write) verify_pattern("counted-read-data", f->buf, f->len);
}

static void counted_io(void)
{
    const char *path = "/sg-count.data";
    long fd = open_file(path, O_CREAT | O_TRUNC | O_RDWR);
    unsigned char *seed = mapping(262144);
    fill_pattern(seed, 262144);
    check("count-seed", CALL(SYS_write, fd, seed, 262144), 262144);
    check("count-seed-close", CALL(SYS_close, fd, 0, 0), 0);
    int cold_index = 0;
    for (int fragmented = 0; fragmented < 2; ++fragmented) {
        for (usize len = 65536; len <= 262144; len *= 4) {
            struct Fixture f = fixture(len, fragmented);
            for (int direct = 0; direct < 2; ++direct) {
                fd = open_file(path, O_RDWR | (direct ? O_DIRECT : 0));
                for (int write = 0; write < 2; ++write)
                    for (int vector = 0; vector < 2; ++vector)
                        for (int positioned = 0; positioned < 2; ++positioned)
                            measured_transfer(fd, &f, write, vector, positioned, direct, 0, 0);
                CALL(SYS_close, fd, 0, 0);
                for (int vector = 0; vector < 2; ++vector) {
                    /* Every fixture was injected before boot, and has not
                     * passed through File's page cache before this read. */
                    char cold_path[] = "/sg-cold-00";
                    cold_path[9] = '0' + cold_index / 10;
                    cold_path[10] = '0' + cold_index % 10;
                    ++cold_index;
                    fd = open_file(cold_path, direct ? O_DIRECT : 0);
                    measured_transfer(fd, &f, 0, vector, 0, direct, 0, 1);
                    CALL(SYS_close, fd, 0, 0);
                }
            }
            fd = open_file(path, O_RDWR | O_APPEND);
            measured_transfer(fd, &f, 1, 1, 0, 0, 1, 0);
            measured_transfer(fd, &f, 1, 1, 1, 0, 1, 0);
            CALL(SYS_close, fd, 0, 0);
            destroy_fixture(&f);
        }
    }
    CALL(SYS_munmap, seed, 262144, 0);
    passed("position-operation-counter-matrix");
}

struct UnmapRace {
    unsigned char *target, *replacement;
    usize len, delay;
    int start, io_done, error;
};

static void unmap_worker(void *opaque)
{
    struct UnmapRace *race = opaque;
    while (!__atomic_load_n(&race->start, __ATOMIC_ACQUIRE)) {}
    for (volatile usize spin = 0; spin < race->delay; ++spin) {}
    if (CALL(SYS_munmap, race->target, race->len, 0) != 0) race->error = 1;
    long replacement = syscall6(SYS_mmap, (usize)race->replacement, race->len,
                                3, 0x32, (usize)-1, 0);
    if (replacement != (long)race->replacement) {
        race->error = 2;
    } else {
        for (usize i = 0; i < race->len; ++i) race->replacement[i] = 0x6d;
    }
    while (!__atomic_load_n(&race->io_done, __ATOMIC_ACQUIRE)) {}
    if (replacement == (long)race->replacement)
        for (usize i = 0; i < race->len; ++i)
            if (race->replacement[i] != 0x6d) { race->error = 3; break; }
    CALL(SYS_exit, 0, 0, 0);
    for (;;) {}
}

static void unmap_race(void)
{
    const usize len = 262144;
    unsigned char *seed = mapping(len), *stack = mapping(65536);
    unsigned char *replacement = mapping(len);
    fill_pattern(seed, len);
    long fd = open_file("/sg-unmap.data", O_CREAT | O_TRUNC | O_RDWR);
    check("race-seed", CALL(SYS_write, fd, seed, len), len);
    usize full = 0, partial = 0, faults = 0;
    for (usize round = 0; round < 32; ++round) {
        unsigned char *target = mapping(len);
        for (usize page = 0; page < len / PAGE; ++page)
            ((volatile unsigned char *)target)[page * PAGE] = 0;
        check("race-rewind", CALL(SYS_lseek, fd, 0, 0), 0);
        struct UnmapRace race;
        race.target = target; race.replacement = replacement; race.len = len;
        race.delay = (round % 8) * 1000;
        race.start = 0; race.io_done = 0; race.error = 0;
        long child = sg_spawn_vm(0x100 | SIGCHLD, stack + 65536, unmap_worker, &race);
        if (child < 0) fail("race-clone-vm", child, 0);
        int observed = observe_begin();
        __atomic_store_n(&race.start, 1, __ATOMIC_RELEASE);
        long n = transfer(fd, target, len, 0, round & 1);
        __atomic_store_n(&race.io_done, 1, __ATOMIC_RELEASE);
        observe_end(observed);
        int status = -1;
        check("race-wait", CALL4(SYS_wait4, child, &status, 0, 0), child);
        check("race-child-status", status, 0);
        check("race-no-reused-frame-corruption", race.error, 0);
        if (n != -EFAULT && (n < 0 || (usize)n > len)) fail("race-read-result", n, len);
        check("race-progress-position", CALL(SYS_lseek, fd, 0, 1), n < 0 ? 0 : n);
        if (n == (long)len) ++full;
        else if (n > 0) ++partial;
        else ++faults;
    }
    text("SG_RACE full="); number(full); text(" partial="); number(partial);
    text(" faults="); number(faults); text("\n");
    CALL(SYS_close, fd, 0, 0);
    CALL(SYS_munmap, seed, len, 0); CALL(SYS_munmap, stack, 65536, 0);
    CALL(SYS_munmap, replacement, len, 0);
    passed("concurrent-unmap-frame-reuse-and-progress");
}

static void shared_read_records(void)
{
    enum { WORKERS = 4, RECORDS = 40, SIZE = 16384 };
    long fd = open_file("/sg-shared-read", O_CREAT | O_TRUNC | O_RDWR);
    unsigned char *buf = mapping(SIZE);
    for (int record = 0; record < WORKERS * RECORDS; ++record) {
        for (usize i = 0; i < SIZE; ++i) buf[i] = record;
        check("shared-read-seed", CALL(SYS_write, fd, buf, SIZE), SIZE);
    }
    check("shared-read-rewind", CALL(SYS_lseek, fd, 0, 0), 0);
    int gate[2], results[2];
    check("shared-read-gate", CALL(SYS_pipe2, gate, 0, 0), 0);
    check("shared-read-results", CALL(SYS_pipe2, results, 0, 0), 0);
    long children[WORKERS];
    for (int worker = 0; worker < WORKERS; ++worker) {
        long child = CALL(SYS_clone, SIGCHLD, 0, 0);
        if (child < 0) fail("shared-read-fork", child, 0);
        if (child == 0) {
            char go;
            check("shared-read-start", CALL(SYS_read, gate[0], &go, 1), 1);
            for (int record = 0; record < RECORDS; ++record) {
                check("shared-readv-record", transfer(fd, buf, SIZE, 0, 1), SIZE);
                unsigned char tag = buf[0];
                if (tag >= WORKERS * RECORDS) fail("shared-read-tag", tag, -1);
                for (usize i = 0; i < SIZE; ++i)
                    if (buf[i] != tag) fail("shared-read-record-interleaved", i, -1);
                check("shared-read-report", CALL(SYS_write, results[1], &tag, 1), 1);
            }
            exit_process(0);
        }
        children[worker] = child;
    }
    check("shared-read-release", CALL(SYS_write, gate[1], "go!!", WORKERS), WORKERS);
    for (int worker = 0; worker < WORKERS; ++worker) {
        int status = -1;
        check("shared-read-wait", CALL4(SYS_wait4, children[worker], &status, 0, 0),
              children[worker]);
        check("shared-read-child-status", status, 0);
    }
    unsigned char *seen = mapping(PAGE);
    for (int i = 0; i < WORKERS * RECORDS; ++i) seen[i] = 0;
    for (int i = 0; i < WORKERS * RECORDS; ++i) {
        unsigned char tag;
        check("shared-read-collect", CALL(SYS_read, results[0], &tag, 1), 1);
        if (tag >= WORKERS * RECORDS || seen[tag])
            fail("shared-read-duplicate-record", tag, -1);
        seen[tag] = 1;
    }
    check("shared-read-position", CALL(SYS_lseek, fd, 0, 1), WORKERS * RECORDS * SIZE);
    CALL(SYS_close, fd, 0, 0);
    CALL(SYS_close, gate[0], 0, 0); CALL(SYS_close, gate[1], 0, 0);
    CALL(SYS_close, results[0], 0, 0); CALL(SYS_close, results[1], 0, 0);
    CALL(SYS_munmap, buf, SIZE, 0); CALL(SYS_munmap, seen, PAGE, 0);
    passed("shared-read-records-once-and-position");
}

static void backend_checks(void)
{
    check("controlled-backend-guest-checks", CALL5(SYS_prctl, 0x50534749, 4, 0, 0, 0), 0);
    passed("controlled-backend-progress-errors-and-zero");
}

static void device_eof(void)
{
    struct DeviceStat {
        usize dev, ino;
        unsigned mode, nlink, uid, gid;
        usize rdev, pad1;
        long size;
        int blksize, pad2;
        long blocks, atime;
        usize atime_ns;
        long mtime;
        usize mtime_ns;
        long ctime;
        usize ctime_ns;
        unsigned unused4, unused5;
    };
    _Static_assert(sizeof(struct DeviceStat) == 128, "RV64/LA64 stat ABI");
    const char *paths[] = { "/dev/vda", "/dev/sda", "/dev/vdb", "/dev/hda", "/dev/blk0" };
    for (usize i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        long fd = CALL4(SYS_openat, AT_FDCWD, paths[i], 1, 0);
        if (fd < 0) continue;
        struct DeviceStat info;
        long stat_result = CALL(SYS_fstat, fd, &info, 0);
        if (stat_result || (info.mode & 0170000) != 0060000 ||
            !SG_DISK_BYTES || info.size != (long)SG_DISK_BYTES) {
            CALL(SYS_close, fd, 0, 0);
            continue;
        }
        text("SG_DEVICE path="); text(paths[i]);
        text(" confirmed_eof="); number(info.size); text("\n");
        /* Both fstat and the runner's exact raw-image size identify this as
         * EOF. No write in this test can target a valid disk byte. */
        const unsigned char byte = 0xa5;
        check("nonfile-eof-write-is-eio", CALL4(SYS_pwrite64, fd, &byte, 1, info.size), -5);
        CALL(SYS_close, fd, 0, 0);
        passed("nonfile-device-eof");
        return;
    }
    text("SG_SKIP nonfile-device-no-confirmed-block-size\n");
}

__attribute__((noreturn)) void _start(void)
{
    if (SG_SUITE == 1) benchmark(0);
    if (SG_SUITE == 2) { append_records(0); append_records(1); }
    if (SG_SUITE == 3) semantic_io();
    if (SG_SUITE == 4) mapping_io();
    if (SG_SUITE == 5) counted_io();
    if (SG_SUITE == 6) benchmark(1);
    if (SG_SUITE == 7) unmap_race();
    if (SG_SUITE == 8) { append_records(2); shared_read_records(); }
    if (SG_SUITE == 9) backend_checks();
    if (SG_SUITE == 10) device_eof();
    text("SG_PASS\n");
    CALL(SYS_reboot, 0xfee1dead, 672274793, 0x4321fedc);
    fail("poweroff-returned", 0, 1);
}
