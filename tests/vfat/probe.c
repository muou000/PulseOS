/* Linux syscall checks for exact FAT device errors and active-file lifetimes. */
typedef unsigned long usize;

enum {
    ioctl = 29, unlinkat = 35, openat = 56, close = 57, read = 63,
    write = 64, pread64 = 67, sync = 81, fsync = 82, exit_group = 94, munmap = 215,
    mmap = 222, renameat2 = 276, AT_FDCWD = -100, O_RDWR = 2, O_CREAT = 64,
    LOOP_SET_FD = 0x4c00, LOOP_CLR_FD = 0x4c01,
    PROT_READ = 1, MAP_SHARED = 1, EBUSY = 16, EIO = 5,
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

#define CALL3(n, a, b, c) syscall6(n, (usize)(a), (usize)(b), (usize)(c), 0, 0, 0)
#define CALL4(n, a, b, c, d) syscall6(n, (usize)(a), (usize)(b), (usize)(c), (usize)(d), 0, 0)

static void say(const char *s)
{
    usize len = 0;
    while (s[len]) ++len;
    CALL3(write, 1, s, len);
}

__attribute__((noreturn)) static void finish(int status)
{
    CALL3(exit_group, status, 0, 0);
    __builtin_unreachable();
}

static void expect(const char *step, long result, long want)
{
    if (result == want) return;
    char digits[32];
    usize pos = sizeof(digits);
    unsigned long n = result < 0 ? -result : result;
    do { digits[--pos] = '0' + n % 10; n /= 10; } while (n);
    if (result < 0) digits[--pos] = '-';
    say("VFAT_FAIL "); say(step); say(" returned ");
    CALL3(write, 1, digits + pos, sizeof(digits) - pos);
    say("\n");
    finish(1);
}

static const char fixture[] = "/tmp/vfat-probe/PROBE.BIN";
static const char source[] = "/tmp/vfat-probe/SOURCE.BIN";
static unsigned char page[4096];

static long open_file(const char *name, int flags)
{
    long fd = CALL4(openat, AT_FDCWD, name, flags, 0600);
    if (fd < 0) expect("open", fd, 0);
    return fd;
}

static long replace(void)
{
    return syscall6(renameat2, AT_FDCWD, (usize)source, AT_FDCWD, (usize)fixture, 0, 0);
}

static void check_busy(void)
{
    expect("unlink live target", CALL3(unlinkat, AT_FDCWD, fixture, 0), -EBUSY);
    expect("replace live target", replace(), -EBUSY);
}

static void lifetimes(void)
{
    long fd = open_file(fixture, O_RDWR | O_CREAT);
    long other = open_file(source, O_RDWR | O_CREAT);
    expect("write victim", CALL3(write, fd, "V", 1), 1);
    expect("write source", CALL3(write, other, "S", 1), 1);
    expect("close source", CALL3(close, other, 0, 0), 0);
    check_busy();
    expect("read retained fd", CALL4(pread64, fd, page, 1, 0), 1);
    expect("retained fd content", page[0], 'V');
    long mapping = syscall6(mmap, 0, sizeof(page), PROT_READ, MAP_SHARED, fd, 0);
    if (mapping < 0) expect("map", mapping, 0);
    expect("close mapped file", CALL3(close, fd, 0, 0), 0);
    check_busy();
    expect("mapped victim readable", *(volatile unsigned char *)mapping, 'V');
    expect("unmap", CALL3(munmap, mapping, sizeof(page), 0), 0);
    expect("replace released target", replace(), 0);
    fd = open_file(fixture, 0);
    expect("read replacement", CALL3(read, fd, page, 1), 1);
    expect("replacement content", page[0], 'S');
    expect("close replacement", CALL3(close, fd, 0, 0), 0);
    expect("unlink released target", CALL3(unlinkat, AT_FDCWD, fixture, 0), 0);
    say("VFAT_BUSY_FD_AND_MMAP_OK\n");
}

static void seed(void)
{
    long fd = open_file(fixture, O_RDWR | O_CREAT);
    for (usize i = 0; i < sizeof(page); ++i) page[i] = 0x5a;
    expect("seed", CALL3(write, fd, page, sizeof(page)), sizeof(page));
    expect("seed fsync", CALL3(fsync, fd, 0, 0), 0);
    expect("seed close", CALL3(close, fd, 0, 0), 0);
}

static void fault(char mode)
{
    long fd = open_file(fixture, O_RDWR);
    if (mode == 'r') {
        expect("read", CALL3(read, fd, page, sizeof(page)), -EIO);
        say("VFAT_READ_EIO\n");
    } else if (mode == 'w') {
        long observer = open_file(fixture, O_RDWR);
        expect("cached write", CALL3(write, fd, page, sizeof(page)), sizeof(page));
        /* The global sync or a preceding background writeback now consumes the
           one-shot device fault. Either way, no fsync has run on these fds. */
        long result = CALL3(sync, 0, 0, 0);
        if (result != 0) expect("global sync", result, -EIO);
        long later = open_file(fixture, O_RDWR);
        expect("fsync after writeback error", CALL3(fsync, fd, 0, 0), -EIO);
        expect("fsync retry", CALL3(fsync, fd, 0, 0), 0);
        expect("fsync on earlier open", CALL3(fsync, observer, 0, 0), -EIO);
        expect("fsync on later open", CALL3(fsync, later, 0, 0), 0);
        expect("close earlier open", CALL3(close, observer, 0, 0), 0);
        expect("close later open", CALL3(close, later, 0, 0), 0);
        say("VFAT_WRITEBACK_EIO\n");
    } else {
        expect("cached write", CALL3(write, fd, page, sizeof(page)), sizeof(page));
        expect("fsync", CALL3(fsync, fd, 0, 0), -EIO);
        say("VFAT_FLUSH_EIO\n");
    }
    expect("close", CALL3(close, fd, 0, 0), 0);
    long root = open_file("/etc/passwd", 0);
    expect("root remains readable", CALL3(read, root, page, 1), 1);
    expect("close root", CALL3(close, root, 0, 0), 0);
}

__attribute__((noreturn)) void _start(void)
{
    char mode = 0;
    expect("mode", CALL3(read, 0, &mode, 1), 1);
    /* The loop-control shell opens the loop device on fd 3 and its backing
       on fd 4 for attach; detach checks the driver's exact errno. */
    if (mode == 'a') expect("attach loop", CALL3(ioctl, 3, LOOP_SET_FD, 4), 0);
    else if (mode == 'l' || mode == 'd')
        expect("detach loop", CALL3(ioctl, 3, LOOP_CLR_FD, 0), mode == 'l' ? -EBUSY : 0);
    else if (mode == 'b') lifetimes();
    else if (mode == 's') seed();
    else if (mode == 'r' || mode == 'w' || mode == 'f') fault(mode);
    else finish(1);
    say("VFAT_PROBE_PASS\n");
    finish(0);
}
