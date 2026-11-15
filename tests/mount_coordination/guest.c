/* Mount coordination regressions for #160 and #161 (RV64 and LA64). */
typedef unsigned long usize;
enum {
    SYS_mkdirat = 34, SYS_umount2 = 39, SYS_mount = 40, SYS_openat = 56,
    SYS_close = 57, SYS_read = 63, SYS_write = 64, SYS_exit_group = 94,
    SYS_reboot = 142,
    ENOENT = 2, EBUSY = 16, EINVAL = 22, EROFS = 30,
    AT_FDCWD = -100, O_CREAT = 64, O_EXCL = 128, O_RDWR = 2,
    MS_RDONLY = 1, MS_BIND = 4096, MS_SLAVE = 1 << 19, MS_SHARED = 1 << 20,
    MNT_DETACH = 2,
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
static long mount_rows_matching(const char *target, const char *option)
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
        if (j != target_len || contents[i + 1 + j] != ' ') continue;
        if (!option) {
            ++rows;
            continue;
        }
        /* Skip the filesystem type, then match a complete mount option. */
        usize p = i + 2 + j;
        while (p < len && contents[p] != ' ' && contents[p] != '\n') ++p;
        if (p == len || contents[p] != ' ') continue;
        ++p;
        while (p < len && contents[p] != ' ' && contents[p] != '\n') {
            usize k = 0;
            while (p + k < len && option[k] && contents[p + k] == option[k]) ++k;
            if (!option[k] && p + k < len &&
                (contents[p + k] == ',' || contents[p + k] == ' ')) {
                ++rows;
                break;
            }
            while (p < len && contents[p] != ',' && contents[p] != ' ' && contents[p] != '\n') ++p;
            if (p < len && contents[p] == ',') ++p;
        }
    }
    return rows;
}

static long mount_rows(const char *target)
{
    return mount_rows_matching(target, 0);
}

static void readonly_bind(void)
{
    const char *source = "/tmp/pulse-mount161-ro-source";
    const char *target = "/tmp/pulse-mount161-ro-bind";
    expect("mkdir-ro-source", CALL(SYS_mkdirat, AT_FDCWD, source, 0755), 0);
    expect("mkdir-ro-bind", CALL(SYS_mkdirat, AT_FDCWD, target, 0755), 0);
    expect("readonly-source-mount", CALL5(SYS_mount, "readonly161", source, "tmpfs", MS_RDONLY, 0), 0);
    expect("readonly-source-listed-ro", mount_rows_matching(source, "ro"), 1);
    expect("readonly-source-bind", CALL5(SYS_mount, source, target, 0, MS_BIND, 0), 0);
    expect("readonly-bind-inherited", CALL4(SYS_openat, AT_FDCWD,
           "/tmp/pulse-mount161-ro-bind/denied", O_CREAT | O_RDWR, 0600), -EROFS);
    expect("readonly-bind-listed-ro", mount_rows_matching(target, "ro"), 1);
    expect("readonly-bind-listed-bind", mount_rows_matching(target, "bind"), 1);
    expect("readonly-bind-unmount", CALL(SYS_umount2, target, 0, 0), 0);
    expect("readonly-bind-record-removed", mount_rows(target), 0);
    expect("readonly-source-unmount", CALL(SYS_umount2, source, 0, 0), 0);
    expect("readonly-source-record-removed", mount_rows(source), 0);
}

static void propagated_mounts(void)
{
    const char *parents[] = {
        "/tmp/pulse-mount161-a", "/tmp/pulse-mount161-b", "/tmp/pulse-mount161-c",
    };
    const char *slots[] = {
        "/tmp/pulse-mount161-a/slot", "/tmp/pulse-mount161-b/slot", "/tmp/pulse-mount161-c/slot",
    };
    const char *payloads[] = {
        "/tmp/pulse-mount161-a/slot/value", "/tmp/pulse-mount161-b/slot/value",
        "/tmp/pulse-mount161-c/slot/value",
    };
    const char *nested[] = {
        "/tmp/pulse-mount161-a/slot/child", "/tmp/pulse-mount161-b/slot/child",
        "/tmp/pulse-mount161-c/slot/child",
    };
    const char *nested_payloads[] = {
        "/tmp/pulse-mount161-a/slot/child/value", "/tmp/pulse-mount161-b/slot/child/value",
        "/tmp/pulse-mount161-c/slot/child/value",
    };
    const char *ordinary[] = {
        "/tmp/pulse-mount161-a/ordinary", "/tmp/pulse-mount161-b/ordinary",
        "/tmp/pulse-mount161-c/ordinary",
    };
    const char *source = "/tmp/pulse-mount161-source";
    const char *source_child = "/tmp/pulse-mount161-source/child";
    for (usize i = 0; i < 3; ++i)
        expect("mkdir-propagation-parent", CALL(SYS_mkdirat, AT_FDCWD, parents[i], 0755), 0);
    expect("mkdir-bind-source", CALL(SYS_mkdirat, AT_FDCWD, source, 0755), 0);
    expect("mount-shared-parent", CALL5(SYS_mount, "parent161", parents[0], "tmpfs", 0, 0), 0);
    expect("mkdir-bind-slot", CALL(SYS_mkdirat, AT_FDCWD, slots[0], 0755), 0);
    expect("mkdir-ordinary-slot", CALL(SYS_mkdirat, AT_FDCWD, ordinary[0], 0755), 0);
    expect("mkdir-slave-local-slot", CALL(SYS_mkdirat, AT_FDCWD, "/tmp/pulse-mount161-a/local", 0755), 0);
    expect("make-shared-parent", CALL5(SYS_mount, 0, parents[0], 0, MS_SHARED, 0), 0);
    expect("bind-shared-peer", CALL5(SYS_mount, parents[0], parents[1], 0, MS_BIND, 0), 0);
    expect("bind-slave-parent", CALL5(SYS_mount, parents[1], parents[2], 0, MS_BIND, 0), 0);
    expect("make-slave-parent", CALL5(SYS_mount, 0, parents[2], 0, MS_SLAVE, 0), 0);
    expect("mount-bind-source", CALL5(SYS_mount, "source161", source, "tmpfs", 0, 0), 0);
    create_file("/tmp/pulse-mount161-source/value", 'P');
    expect("mkdir-source-child", CALL(SYS_mkdirat, AT_FDCWD, source_child, 0755), 0);
    expect("mount-source-child", CALL5(SYS_mount, "child161", source_child, "tmpfs", 0, 0), 0);
    create_file("/tmp/pulse-mount161-source/child/value", 'N');

    /* The primary, peer and slave expose the same content and effective flags. */
    expect("bind-readonly-under-shared-parent", CALL5(SYS_mount, source, slots[0], 0, MS_BIND | MS_RDONLY, 0), 0);
    for (usize i = 0; i < 3; ++i) {
        expect("propagated-bind-record", mount_rows(slots[i]), 1);
        expect("propagated-bind-listed-ro", mount_rows_matching(slots[i], "ro"), 1);
        expect("propagated-bind-listed-bind", mount_rows_matching(slots[i], "bind"), 1);
        expect("propagated-bind-content", read_byte(payloads[i]), 'P');
        expect("propagated-bind-readonly", CALL4(SYS_openat, AT_FDCWD, payloads[i], O_RDWR, 0), -EROFS);
        expect("nested-shadow-record", mount_rows(nested[i]), 1);
        expect("nested-shadow-retains-rw", mount_rows_matching(nested[i], "rw"), 1);
        expect("nested-shadow-content", read_byte(nested_payloads[i]), 'N');
    }
    create_file("/tmp/pulse-mount161-c/slot/child/writable", 'W');
    expect("nested-shadow-writes-share-source", read_byte("/tmp/pulse-mount161-source/child/writable"), 'W');
    expect("normal-unmount-nested-shadow", CALL(SYS_umount2, nested[0], 0, 0), 0);
    for (usize i = 0; i < 3; ++i) {
        expect("normal-nested-shadow-record-removed", mount_rows(nested[i]), 0);
        expect("normal-nested-shadow-content-removed", CALL4(SYS_openat, AT_FDCWD, nested_payloads[i], 0, 0), -ENOENT);
    }
    expect("source-child-record-retained", mount_rows(source_child), 1);
    expect("normal-unmount-propagated-bind", CALL(SYS_umount2, slots[0], 0, 0), 0);
    for (usize i = 0; i < 3; ++i) {
        expect("normal-shadow-record-removed", mount_rows(slots[i]), 0);
        expect("normal-shadow-content-removed", CALL4(SYS_openat, AT_FDCWD, payloads[i], 0, 0), -ENOENT);
    }

    /* A slave receives events but does not publish them back to its master. */
    expect("bind-under-slave", CALL5(SYS_mount, source, "/tmp/pulse-mount161-c/local", 0, MS_BIND, 0), 0);
    expect("slave-local-record", mount_rows("/tmp/pulse-mount161-c/local"), 1);
    expect("slave-local-content", read_byte("/tmp/pulse-mount161-c/local/value"), 'P');
    expect("slave-no-master-record", mount_rows("/tmp/pulse-mount161-a/local"), 0);
    expect("slave-no-peer-record", mount_rows("/tmp/pulse-mount161-b/local"), 0);
    expect("slave-no-master-content", CALL4(SYS_openat, AT_FDCWD, "/tmp/pulse-mount161-a/local/value", 0, 0), -ENOENT);
    expect("slave-no-peer-content", CALL4(SYS_openat, AT_FDCWD, "/tmp/pulse-mount161-b/local/value", 0, 0), -ENOENT);
    expect("lazy-unmount-slave-local", CALL(SYS_umount2, "/tmp/pulse-mount161-c/local", MNT_DETACH, 0), 0);
    expect("lazy-slave-record-removed", mount_rows("/tmp/pulse-mount161-c/local"), 0);
    expect("lazy-slave-child-record-removed", mount_rows("/tmp/pulse-mount161-c/local/child"), 0);

    /* Ordinary mounts use the same peer/slave lifecycle as binds. */
    expect("ordinary-mount-under-shared-parent", CALL5(SYS_mount, "ordinary161", ordinary[0], "tmpfs", 0, 0), 0);
    create_file("/tmp/pulse-mount161-a/ordinary/value", 'O');
    expect("ordinary-peer-content", read_byte("/tmp/pulse-mount161-b/ordinary/value"), 'O');
    expect("ordinary-slave-content", read_byte("/tmp/pulse-mount161-c/ordinary/value"), 'O');
    for (usize i = 0; i < 3; ++i)
        expect("ordinary-propagated-record", mount_rows(ordinary[i]), 1);
    expect("unmount-ordinary-propagation", CALL(SYS_umount2, ordinary[0], 0, 0), 0);
    for (usize i = 0; i < 3; ++i)
        expect("ordinary-shadow-record-removed", mount_rows(ordinary[i]), 0);

    /* Detaching a subtree must remove every primary and shadow listing row. */
    expect("bind-subtree-for-lazy-detach", CALL5(SYS_mount, source, slots[0], 0, MS_BIND, 0), 0);
    for (usize i = 0; i < 3; ++i) {
        expect("lazy-fixture-shadow-record", mount_rows(slots[i]), 1);
        expect("lazy-fixture-nested-record", mount_rows(nested[i]), 1);
    }
    expect("lazy-unmount-propagated-subtree", CALL(SYS_umount2, slots[0], MNT_DETACH, 0), 0);
    for (usize i = 0; i < 3; ++i) {
        expect("lazy-shadow-record-removed", mount_rows(slots[i]), 0);
        expect("lazy-nested-shadow-record-removed", mount_rows(nested[i]), 0);
        expect("lazy-shadow-content-removed", CALL4(SYS_openat, AT_FDCWD, payloads[i], 0, 0), -ENOENT);
    }
    expect("source-child-survives-shadow-cleanup", read_byte("/tmp/pulse-mount161-source/child/value"), 'N');
    expect("cleanup-source-child", CALL(SYS_umount2, source_child, 0, 0), 0);
    expect("cleanup-source", CALL(SYS_umount2, source, 0, 0), 0);
    for (usize i = 3; i > 0; --i) {
        expect("cleanup-propagation-parent", CALL(SYS_umount2, parents[i - 1], 0, 0), 0);
        expect("cleanup-parent-record-removed", mount_rows(parents[i - 1]), 0);
    }
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

    readonly_bind();
    propagated_mounts();

    text("ABI_MOUNTS_PASS\n");
    CALL(SYS_reboot, 0xfee1dead, 672274793, 0x4321fedc);
    fail("poweroff-returned", 0, 1);
}
