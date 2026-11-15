/* Ordinary mount/unmount consistency regression for #160 (RV64 and LA64). */
typedef unsigned long usize;
enum {
    SYS_mkdirat = 34, SYS_umount2 = 39, SYS_mount = 40, SYS_openat = 56,
    SYS_close = 57, SYS_read = 63, SYS_write = 64, SYS_exit_group = 94,
    SYS_reboot = 142,
    ENOENT = 2, EBUSY = 16, EINVAL = 22,
    AT_FDCWD = -100, O_CREAT = 64, O_EXCL = 128, O_RDWR = 2,
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
    usize i = sizeof(buf), value = n < 0 ? (usize)-n : (usize)n;
    do { buf[--i] = '0' + value % 10; value /= 10; } while (value);
    if (n < 0) buf[--i] = '-';
    CALL(SYS_write, 1, buf + i, sizeof(buf) - i);
}

__attribute__((noreturn)) static void fail(const char *name, long got, long want)
{
    text("ABI_MOUNTS_FAIL "); text(name); text(" got="); number(got);
    text(" want="); number(want); text("\n");
    CALL(SYS_exit_group, 1, 0, 0);
    for (;;) {}
}

static void expect(const char *name, long got, long want)
{
    if (got != want) fail(name, got, want);
    text("ABI_MOUNTS_OK "); text(name); text("\n");
}

static long open_file(const char *path, usize flags)
{
    long fd = CALL4(SYS_openat, AT_FDCWD, path, flags, 0600);
    if (fd < 0) fail(path, fd, 0);
    return fd;
}

static void create_file(const char *path, char value)
{
    long fd = open_file(path, O_CREAT | O_EXCL | O_RDWR);
    expect("create-file-write", CALL(SYS_write, fd, &value, 1), 1);
    expect("create-file-close", CALL(SYS_close, fd, 0, 0), 0);
}

static long read_byte(const char *path)
{
    char value = 0;
    long fd = open_file(path, 0);
    expect("read-file-size", CALL(SYS_read, fd, &value, 1), 1);
    expect("read-file-close", CALL(SYS_close, fd, 0, 0), 0);
    return value;
}

/* Open a fresh /proc/mounts snapshot after every transition. */
static long mount_rows(const char *target)
{
    static char contents[16384];
    usize len = 0, target_len = 0;
    while (target[target_len]) ++target_len;
    long fd = open_file("/proc/mounts", 0);
    for (;;) {
        long n = CALL(SYS_read, fd, contents + len, sizeof(contents) - len);
        if (n < 0) fail("read-mounts", n, 0);
        if (!n) break;
        len += (usize)n;
        if (len == sizeof(contents)) fail("mounts-buffer-full", len, 0);
    }
    expect("mounts-close", CALL(SYS_close, fd, 0, 0), 0);
    long rows = 0;
    for (usize i = 0; i + target_len + 1 < len; ++i) {
        if (contents[i] != ' ') continue;
        usize j = 0;
        while (j < target_len && contents[i + 1 + j] == target[j]) ++j;
        if (j == target_len && contents[i + 1 + j] == ' ') ++rows;
    }
    return rows;
}

__attribute__((noreturn)) void _start(void)
{
    const char *target = "/tmp/pulse-mount160";
    const char *failed = "/tmp/pulse-mount160-failed";
    const char *child = "/tmp/pulse-mount160/child";
    const char *underlying = "/tmp/pulse-mount160/underlying";
    const char *mounted = "/tmp/pulse-mount160/mounted";
    expect("mkdir-target", CALL(SYS_mkdirat, AT_FDCWD, target, 0755), 0);
    expect("mkdir-failed-probe-target", CALL(SYS_mkdirat, AT_FDCWD, failed, 0755), 0);
    create_file(underlying, 'B');
    expect("initial-mount-list", mount_rows(target), 0);

    expect("tmpfs-mount", CALL5(SYS_mount, "mount160", target, "tmpfs", 0, 0), 0);
    expect("mounted-list", mount_rows(target), 1);
    expect("underlying-file-hidden", CALL4(SYS_openat, AT_FDCWD, underlying, 0, 0), -ENOENT);
    create_file(mounted, 'M');
    expect("mounted-file-readable", read_byte(mounted), 'M');
    expect("duplicate-target-busy", CALL5(SYS_mount, "duplicate", target, "tmpfs", 0, 0), -EBUSY);
    expect("duplicate-kept-one-row", mount_rows(target), 1);
    expect("duplicate-kept-filesystem", read_byte(mounted), 'M');

    expect("failed-probe", CALL5(SYS_mount, "/dev/mount160-missing", failed, "ext4", 0, 0), -ENOENT);
    expect("failed-probe-no-row", mount_rows(failed), 0);
    create_file("/tmp/pulse-mount160-failed/still-underlying", 'F');
    expect("failed-probe-kept-directory", read_byte("/tmp/pulse-mount160-failed/still-underlying"), 'F');

    expect("mkdir-child", CALL(SYS_mkdirat, AT_FDCWD, child, 0755), 0);
    expect("mount-child", CALL5(SYS_mount, "child160", child, "tmpfs", 0, 0), 0);
    expect("parent-with-child-busy", CALL(SYS_umount2, target, 0, 0), -EBUSY);
    expect("busy-parent-kept-row", mount_rows(target), 1);
    expect("busy-parent-kept-filesystem", read_byte(mounted), 'M');
    expect("unmount-child", CALL(SYS_umount2, child, 0, 0), 0);
    expect("unmounted-child-no-row", mount_rows(child), 0);
    expect("unmount-parent", CALL(SYS_umount2, target, 0, 0), 0);
    expect("unmounted-parent-no-row", mount_rows(target), 0);
    expect("underlying-file-restored", read_byte(underlying), 'B');
    expect("mounted-file-gone", CALL4(SYS_openat, AT_FDCWD, mounted, 0, 0), -ENOENT);
    expect("second-unmount-invalid", CALL(SYS_umount2, target, 0, 0), -EINVAL);

    text("ABI_MOUNTS_PASS\n");
    CALL(SYS_reboot, 0xfee1dead, 672274793, 0x4321fedc);
    fail("poweroff-returned", 0, 1);
}
