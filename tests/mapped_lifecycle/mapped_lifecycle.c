/*
 * Issue #67 user-visible mapped-page lifecycle probes. Only libc + pthreads.
 * Build: cc -std=c11 -O2 -Wall -Wextra -Werror -pthread mapped_lifecycle.c -o payload
 * Guest: use a static Linux-ABI RISC-V64/LoongArch64 libc toolchain instead of cc.
 *
 * Pipes order fork observations; barriers order thread observations. Reads during
 * replacement accept either backing; reads AFTER replacement must see the new
 * backing. Concurrent start does not prove a particular kernel prepare/commit
 * or writeback interleaving. A blocking integration FileNode is needed for that.
 * Reopen/pread checks cache-visible readback, NOT power-loss storage durability.
 *
 * Storage-error/reset seam (intentionally SKIP, never a fake PASS): wrap
 * FileNodeOps::write_at and NodeOps::sync with an in-memory durable byte store,
 * independently arm VfsError::Io and a latch before writeback completion. Dirty a
 * real shared mapping, block an old checkpoint, publish a newer write, then
 * release/fail it. Assert msync/fsync/raw SYS_sync report EIO; failed write_at
 * retains dirty publication, while failed durability sync retains pending bytes
 * in the mock store. Retry must persist the newest bytes to the durable store.
 * With authorized guest CAP_SYS_BOOT, call the reboot syscall against a mock
 * platform power hook: EIO/ETIMEDOUT must return and the reset/off call count
 * must remain zero. Clearing the fault must allow a later successful flush.
 * EPERM, ENOSYS, invalid arguments and libc's void sync() are not this evidence.
 * This ordinary userspace binary has no way to arm those kernel hooks and NEVER
 * attempts a real reset. --require-fault-injection makes this gap a hard failure.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>

static size_t page_size;
static unsigned iterations = 32;
static unsigned case_timeout = 60;
static const char *case_name = "setup";

static void fail(const char *what, int line)
{
    int saved = errno;
    fprintf(stderr, "MLC FAIL %s line=%d assertion=%s errno=%d (%s)\n",
            case_name, line, what, saved, strerror(saved));
    exit(1);
}
#define CHECK(expr) do { if (!(expr)) fail(#expr, __LINE__); } while (0)
#define PCALL(expr) do { int error_ = (expr); if (error_) { \
    errno = error_; fail(#expr, __LINE__); } } while (0)

static void watchdog(int sig)
{
    static const char message[] = "MLC FAIL watchdog case deadline exceeded\n";
    (void)sig;
    ssize_t written = write(STDERR_FILENO, message, sizeof(message) - 1);
    (void)written;
    _exit(124);
}

static void checkpoint(void)
{
    /* libc sync() discards the return value; PulseOS can return a storage error. */
    CHECK(syscall(SYS_sync) == 0);
}

static void put_at(int fd, const void *buf, size_t size, off_t offset)
{
    const unsigned char *p = buf;
    while (size) {
        ssize_t n = pwrite(fd, p, size, offset);
        if (n < 0 && errno == EINTR)
            continue;
        CHECK(n > 0);
        p += n;
        size -= (size_t)n;
        offset += n;
    }
}

static void get_at(int fd, void *buf, size_t size, off_t offset)
{
    unsigned char *p = buf;
    while (size) {
        ssize_t n = pread(fd, p, size, offset);
        if (n < 0 && errno == EINTR)
            continue;
        CHECK(n > 0);
        p += n;
        size -= (size_t)n;
        offset += n;
    }
}

struct fixture {
    int fd;
    char path[32];
};

static struct fixture make_file(unsigned pages, unsigned char seed)
{
    struct fixture f;
    unsigned char *buf = malloc(page_size);
    CHECK(buf != NULL);
    strcpy(f.path, "mlc-XXXXXX");
    f.fd = mkstemp(f.path);
    CHECK(f.fd >= 0);
    CHECK(ftruncate(f.fd, (off_t)(pages * page_size)) == 0);
    for (unsigned i = 0; i < pages; ++i) {
        memset(buf, seed + i, page_size);
        put_at(f.fd, buf, page_size, (off_t)(i * page_size));
    }
    CHECK(fsync(f.fd) == 0);
    free(buf);
    return f;
}

static void remove_file(struct fixture *f)
{
    if (f->fd >= 0)
        CHECK(close(f->fd) == 0);
    CHECK(unlink(f->path) == 0);
}

static unsigned char *map_file(int fd, unsigned pages, int flags, off_t offset)
{
    void *p = mmap(NULL, pages * page_size, PROT_READ | PROT_WRITE, flags, fd, offset);
    CHECK(p != MAP_FAILED);
    return p;
}

static void check_bytes(const unsigned char *p, size_t size, unsigned char value)
{
    for (size_t i = 0; i < size; ++i) {
        if (p[i] != value) {
            fprintf(stderr, "MLC DETAIL %s byte=%zu actual=%u expected=%u\n",
                    case_name, i, p[i], value);
            CHECK(p[i] == value);
        }
    }
}

static void check_file_page(const struct fixture *f, unsigned page, unsigned char value)
{
    /* Reopen deliberately; the kernel may still satisfy this from its cache. */
    int fd = open(f->path, O_RDONLY);
    unsigned char *buf = malloc(page_size);
    CHECK(fd >= 0 && buf != NULL);
    get_at(fd, buf, page_size, (off_t)(page * page_size));
    check_bytes(buf, page_size, value);
    free(buf);
    CHECK(close(fd) == 0);
}

struct channel { int to_child[2]; int to_parent[2]; };
static struct channel make_channel(void)
{
    struct channel c;
    CHECK(pipe(c.to_child) == 0);
    CHECK(pipe(c.to_parent) == 0);
    return c;
}
static void child_channel(struct channel *c)
{
    CHECK(close(c->to_child[1]) == 0);
    CHECK(close(c->to_parent[0]) == 0);
    alarm(case_timeout);
}
static void parent_channel(struct channel *c)
{
    CHECK(close(c->to_child[0]) == 0);
    CHECK(close(c->to_parent[1]) == 0);
}
static void send_token(int fd)
{
    char token = 'x';
    ssize_t n;
    do { n = write(fd, &token, 1); } while (n < 0 && errno == EINTR);
    CHECK(n == 1);
}
static void recv_token(int fd)
{
    struct pollfd p = { .fd = fd, .events = POLLIN };
    int ready;
    do { ready = poll(&p, 1, (int)case_timeout * 1000); }
    while (ready < 0 && errno == EINTR);
    CHECK(ready == 1 && (p.revents & POLLIN));
    char token;
    ssize_t n;
    do { n = read(fd, &token, 1); } while (n < 0 && errno == EINTR);
    CHECK(n == 1 && token == 'x');
}
static int wait_child(pid_t pid)
{
    int status;
    pid_t got;
    do { got = waitpid(pid, &status, 0); } while (got < 0 && errno == EINTR);
    CHECK(got == pid);
    return status;
}
static void finish_child(pid_t pid, struct channel *c)
{
    int status = wait_child(pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(close(c->to_child[1]) == 0);
    CHECK(close(c->to_parent[0]) == 0);
}

static void shared_visibility_readback(void)
{
    struct fixture f = make_file(2, 0x20);
    unsigned char *a = map_file(f.fd, 2, MAP_SHARED, 0);
    unsigned char *b = map_file(f.fd, 2, MAP_SHARED, 0);
    check_bytes(a, page_size, 0x20);
    check_bytes(b + page_size, page_size, 0x21);
    memset(a, 0x40, page_size);
    check_bytes(b, page_size, 0x40); /* visibility before msync */
    memset(b + page_size, 0x41, page_size);
    check_bytes(a + page_size, page_size, 0x41);
    unsigned char byte = 0x42;
    put_at(f.fd, &byte, 1, 17);
    CHECK(a[17] == 0x42 && b[17] == 0x42);
    a[17] = 0x40;
    CHECK(msync(a, 2 * page_size, MS_SYNC) == 0);
    CHECK(fsync(f.fd) == 0);
    CHECK(munmap(a, 2 * page_size) == 0);
    CHECK(munmap(b, 2 * page_size) == 0);
    check_file_page(&f, 0, 0x40);
    check_file_page(&f, 1, 0x41);
    remove_file(&f);
}

static void private_file_isolation(void)
{
    struct fixture f = make_file(1, 0x25);
    unsigned char *shared = map_file(f.fd, 1, MAP_SHARED, 0);
    unsigned char *private = map_file(f.fd, 1, MAP_PRIVATE, 0);
    check_bytes(private, page_size, 0x25); /* fault first, then COW */
    memset(private, 0x65, page_size);
    check_bytes(private, page_size, 0x65);
    check_bytes(shared, page_size, 0x25);
    CHECK(msync(private, page_size, MS_SYNC) == 0);
    CHECK(fsync(f.fd) == 0);
    check_file_page(&f, 0, 0x25);
    CHECK(munmap(private, page_size) == 0);
    private = map_file(f.fd, 1, MAP_PRIVATE, 0);
    check_bytes(private, page_size, 0x25);
    CHECK(munmap(private, page_size) == 0);
    CHECK(munmap(shared, page_size) == 0);
    remove_file(&f);
}

static void fork_shared_private_cow(void)
{
    struct fixture f = make_file(3, 0x30);
    unsigned char *shared = map_file(f.fd, 1, MAP_SHARED, 0);
    unsigned char *dirty = map_file(f.fd, 1, MAP_PRIVATE, (off_t)page_size);
    unsigned char *clean = map_file(f.fd, 1, MAP_PRIVATE, (off_t)(2 * page_size));
    check_bytes(shared, page_size, 0x30); /* published shared frame exists at fork */
    check_bytes(clean, page_size, 0x32);
    memset(dirty, 0x43, page_size); /* private COW already present at fork */
    struct channel c = make_channel();
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        child_channel(&c);
        memset(shared, 0x51, page_size);
        memset(dirty, 0x52, page_size);
        memset(clean, 0x53, page_size); /* first private COW after fork */
        send_token(c.to_parent[1]);
        recv_token(c.to_child[0]);
        check_bytes(shared, page_size, 0x61);
        check_bytes(dirty, page_size, 0x52);
        check_bytes(clean, page_size, 0x53);
        _exit(0);
    }
    parent_channel(&c);
    recv_token(c.to_parent[0]);
    check_bytes(shared, page_size, 0x51);
    check_bytes(dirty, page_size, 0x43);
    check_bytes(clean, page_size, 0x32);
    memset(shared, 0x61, page_size);
    memset(dirty, 0x62, page_size);
    memset(clean, 0x63, page_size);
    send_token(c.to_child[1]);
    finish_child(pid, &c);
    check_bytes(dirty, page_size, 0x62);
    check_bytes(clean, page_size, 0x63);
    CHECK(msync(shared, page_size, MS_SYNC) == 0);
    CHECK(fsync(f.fd) == 0);
    CHECK(munmap(shared, page_size) == 0);
    CHECK(munmap(dirty, page_size) == 0);
    CHECK(munmap(clean, page_size) == 0);
    check_file_page(&f, 0, 0x61);
    check_file_page(&f, 1, 0x31);
    check_file_page(&f, 2, 0x32);
    remove_file(&f);
}

static void expect_unmapped_fault(unsigned char *hole)
{
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        alarm(case_timeout);
        volatile unsigned char value = *(volatile unsigned char *)hole;
        (void)value;
        _exit(99);
    }
    int status = wait_child(pid);
    CHECK(WIFSIGNALED(status));
    CHECK(WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS);
}

static void partial_munmap(void)
{
    struct fixture f = make_file(3, 0x20);
    unsigned char *p = map_file(f.fd, 3, MAP_SHARED, 0);
    for (unsigned i = 0; i < 3; ++i)
        check_bytes(p + i * page_size, page_size, (unsigned char)(0x20 + i));
    struct channel c = make_channel();
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        child_channel(&c);
        for (unsigned i = 0; i < 3; ++i)
            memset(p + i * page_size, 0x40 + i, page_size);
        CHECK(munmap(p + page_size, page_size) == 0);
        expect_unmapped_fault(p + page_size);
        send_token(c.to_parent[1]);
        recv_token(c.to_child[0]);
        check_bytes(p, page_size, 0x50);
        check_bytes(p + 2 * page_size, page_size, 0x52);
        memset(p, 0x60, page_size);
        memset(p + 2 * page_size, 0x62, page_size);
        _exit(0);
    }
    parent_channel(&c);
    recv_token(c.to_parent[0]);
    for (unsigned i = 0; i < 3; ++i)
        check_bytes(p + i * page_size, page_size, (unsigned char)(0x40 + i));
    memset(p, 0x50, page_size);
    memset(p + 2 * page_size, 0x52, page_size);
    send_token(c.to_child[1]);
    finish_child(pid, &c);
    check_bytes(p, page_size, 0x60);
    check_bytes(p + 2 * page_size, page_size, 0x62);
    CHECK(munmap(p + page_size, page_size) == 0);
    expect_unmapped_fault(p + page_size);
    void *replacement = mmap(p + page_size, page_size, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK(replacement == p + page_size);
    memset(replacement, 0x7a, page_size);
    CHECK(msync(p, page_size, MS_SYNC) == 0);
    CHECK(msync(p + 2 * page_size, page_size, MS_SYNC) == 0);
    CHECK(fsync(f.fd) == 0);
    CHECK(munmap(p, 3 * page_size) == 0);
    check_file_page(&f, 0, 0x60);
    check_file_page(&f, 1, 0x41); /* anonymous replacement must not dirty file */
    check_file_page(&f, 2, 0x62); /* split backend retains its file offset */
    remove_file(&f);
}

static void process_exit_writeback(void)
{
    struct fixture f = make_file(2, 0x30);
    CHECK(close(f.fd) == 0);
    f.fd = -1; /* no inherited descriptor/mapping keeping the child's cache alive */
    struct channel c = make_channel();
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        child_channel(&c);
        int fd = open(f.path, O_RDWR);
        CHECK(fd >= 0);
        unsigned char *shared = map_file(fd, 1, MAP_SHARED, 0);
        unsigned char *private = map_file(fd, 1, MAP_PRIVATE, (off_t)page_size);
        memset(shared, 0x70, page_size);
        memset(private, 0x71, page_size);
        send_token(c.to_parent[1]);
        recv_token(c.to_child[0]);
        _exit(0); /* intentionally no msync, munmap, or close */
    }
    parent_channel(&c);
    recv_token(c.to_parent[0]);
    send_token(c.to_child[1]);
    finish_child(pid, &c);
    checkpoint();
    f.fd = open(f.path, O_RDWR);
    CHECK(f.fd >= 0);
    CHECK(fsync(f.fd) == 0);
    check_file_page(&f, 0, 0x70);
    check_file_page(&f, 1, 0x31);
    remove_file(&f);
}

#define READERS 4
struct threaded {
    pthread_barrier_t barrier;
    unsigned char *mapping;
    size_t length;
};
struct reader_arg { struct threaded *t; unsigned id; };
static void barrier(struct threaded *t)
{
    int rc = pthread_barrier_wait(&t->barrier);
    CHECK(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
}
static void init_threads(struct threaded *t, unsigned count)
{
    PCALL(pthread_barrier_init(&t->barrier, NULL, count));
}
static void pin_reader(unsigned id)
{
    /* Best effort: guest/host affinity availability is reported, not assumed. */
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
        printf("MLC NOTE %s affinity unavailable errno=%d\n", case_name, errno);
        return;
    }
    unsigned count = (unsigned)CPU_COUNT(&allowed);
    if (!count)
        return;
    unsigned pick = id % count;
    for (unsigned cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &allowed) && pick-- == 0) {
            cpu_set_t one;
            CPU_ZERO(&one);
            CPU_SET(cpu, &one);
            int rc = pthread_setaffinity_np(pthread_self(), sizeof(one), &one);
            printf("MLC NOTE %s reader=%u cpu=%u affinity_rc=%d\n",
                   case_name, id, cpu, rc);
            return;
        }
    }
}

static void *tlb_reader(void *opaque)
{
    struct reader_arg *arg = opaque;
    struct threaded *t = arg->t;
    volatile unsigned char *p = t->mapping;
    pin_reader(arg->id);
    for (unsigned i = 0; i < iterations; ++i) {
        unsigned char old = (i % 2 == 0) ? 0x21 : 0x51;
        unsigned char next = (i % 2 == 0) ? 0x51 : 0x21;
        barrier(t);
        CHECK(p[0] == old && p[page_size - 1] == old); /* warm each CPU's TLB */
        barrier(t);
        barrier(t); /* main's MAP_FIXED has returned */
        CHECK(p[0] == next && p[page_size - 1] == next);
        p[arg->id + 1] = (unsigned char)(0x80 + i % 64);
        barrier(t);
    }
    return NULL;
}

static void map_fixed_tlb_visibility(void)
{
    struct fixture files[2] = { make_file(1, 0x21), make_file(1, 0x51) };
    struct threaded t = { .mapping = map_file(files[0].fd, 1, MAP_SHARED, 0),
                          .length = page_size };
    pthread_t threads[READERS];
    struct reader_arg args[READERS];
    unsigned char expected[2][READERS];
    memset(expected[0], 0x21, READERS);
    memset(expected[1], 0x51, READERS);
    init_threads(&t, READERS + 1);
    for (unsigned j = 0; j < READERS; ++j) {
        args[j] = (struct reader_arg){ .t = &t, .id = j };
        PCALL(pthread_create(&threads[j], NULL, tlb_reader, &args[j]));
    }
    for (unsigned i = 0; i < iterations; ++i) {
        unsigned target = (i + 1) % 2;
        barrier(&t);
        barrier(&t);
        CHECK(mmap(t.mapping, page_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_FIXED, files[target].fd, 0) == t.mapping);
        barrier(&t);
        barrier(&t);
        memset(expected[target], (int)(0x80 + i % 64), READERS);
        CHECK(msync(t.mapping, page_size, MS_SYNC) == 0);
        for (unsigned k = 0; k < 2; ++k) {
            unsigned char actual[READERS];
            get_at(files[k].fd, actual, READERS, 1);
            CHECK(memcmp(actual, expected[k], READERS) == 0);
        }
    }
    for (unsigned j = 0; j < READERS; ++j)
        PCALL(pthread_join(threads[j], NULL));
    PCALL(pthread_barrier_destroy(&t.barrier));
    CHECK(munmap(t.mapping, page_size) == 0);
    remove_file(&files[0]);
    remove_file(&files[1]);
}

static void *fault_reader(void *opaque)
{
    struct reader_arg *arg = opaque;
    struct threaded *t = arg->t;
    volatile unsigned char *p = t->mapping;
    pin_reader(arg->id);
    for (unsigned i = 0; i < iterations; ++i) {
        unsigned char final = (i % 2 == 0) ? 0x51 : 0x21;
        barrier(t); /* fresh PTEs: fault preparation races same-VA replacement */
        for (size_t off = arg->id * page_size; off < t->length;
             off += READERS * page_size) {
            unsigned char a = p[off], b = p[off + page_size - 1];
            CHECK(a == 0x21 || a == 0x51);
            CHECK(b == 0x21 || b == 0x51);
        }
        barrier(t); /* both readers and replacement have finished */
        for (size_t off = arg->id * page_size; off < t->length;
             off += READERS * page_size)
            CHECK(p[off] == final && p[off + page_size - 1] == final);
        barrier(t);
    }
    return NULL;
}

static void fault_replacement_race(void)
{
    const unsigned pages = 16;
    struct fixture files[2] = { make_file(pages, 0x21), make_file(pages, 0x51) };
    /* Uniform page markers make any wrong-generation publication observable. */
    unsigned char *buf = malloc(page_size);
    CHECK(buf != NULL);
    for (unsigned k = 0; k < 2; ++k) {
        memset(buf, k ? 0x51 : 0x21, page_size);
        for (unsigned j = 0; j < pages; ++j)
            put_at(files[k].fd, buf, page_size, (off_t)(j * page_size));
    }
    free(buf);
    struct threaded t = { .mapping = map_file(files[0].fd, pages, MAP_SHARED, 0),
                          .length = pages * page_size };
    pthread_t threads[READERS];
    struct reader_arg args[READERS];
    init_threads(&t, READERS + 1);
    for (unsigned j = 0; j < READERS; ++j) {
        args[j] = (struct reader_arg){ .t = &t, .id = j };
        PCALL(pthread_create(&threads[j], NULL, fault_reader, &args[j]));
    }
    for (unsigned i = 0; i < iterations; ++i) {
        CHECK(mmap(t.mapping, t.length, PROT_READ,
                   MAP_SHARED | MAP_FIXED, files[i % 2].fd, 0) == t.mapping);
        barrier(&t);
        CHECK(mmap(t.mapping, t.length, PROT_READ,
                   MAP_SHARED | MAP_FIXED, files[(i + 1) % 2].fd, 0) == t.mapping);
        barrier(&t);
        barrier(&t);
    }
    for (unsigned j = 0; j < READERS; ++j)
        PCALL(pthread_join(threads[j], NULL));
    PCALL(pthread_barrier_destroy(&t.barrier));
    CHECK(munmap(t.mapping, t.length) == 0);
    remove_file(&files[0]);
    remove_file(&files[1]);
    puts("MLC NOTE fault_replacement_race bounded stress; in-kernel overlap requires mock latch");
}

static void *mapped_writer(void *opaque)
{
    struct threaded *t = opaque;
    for (unsigned i = 0; i < iterations; ++i) {
        unsigned char old = (unsigned char)(0x20 + i % 32);
        unsigned char next = (unsigned char)(0x60 + i % 32);
        memset(t->mapping, old, t->length);
        barrier(t); /* old generation exists before the checkpoint starts */
        barrier(t); /* launch newer mapped writes and checkpoint together */
        memset(t->mapping, next, t->length);
        barrier(t); /* quiescent final generation */
        barrier(t); /* final flush/readback completed before next generation */
    }
    return NULL;
}

static void mapped_write_checkpoint_race(void)
{
    const unsigned pages = 8;
    struct fixture f = make_file(pages, 0x10);
    struct threaded t = { .mapping = map_file(f.fd, pages, MAP_SHARED, 0),
                          .length = pages * page_size };
    pthread_t writer;
    init_threads(&t, 2);
    PCALL(pthread_create(&writer, NULL, mapped_writer, &t));
    for (unsigned i = 0; i < iterations; ++i) {
        barrier(&t);
        barrier(&t);
        if (i % 3 == 0)
            CHECK(msync(t.mapping, t.length, MS_SYNC) == 0);
        else if (i % 3 == 1)
            CHECK(fsync(f.fd) == 0);
        else
            checkpoint();
        barrier(&t);
        /* An older checkpoint must not erase newer dirty publication. */
        CHECK(msync(t.mapping, t.length, MS_SYNC) == 0);
        CHECK(fsync(f.fd) == 0);
        for (unsigned j = 0; j < pages; ++j)
            check_file_page(&f, j, (unsigned char)(0x60 + i % 32));
        barrier(&t);
    }
    PCALL(pthread_join(writer, NULL));
    PCALL(pthread_barrier_destroy(&t.barrier));
    CHECK(munmap(t.mapping, t.length) == 0);
    checkpoint();
    remove_file(&f);
    puts("MLC NOTE mapped_write_checkpoint_race cache-visible readback; durability/overlap need mock store");
}

static unsigned number(const char *value, unsigned max)
{
    char *end;
    errno = 0;
    unsigned long n = strtoul(value, &end, 10);
    CHECK(!errno && *value && !*end && n >= 1 && n <= max);
    return (unsigned)n;
}

int main(int argc, char **argv)
{
    int require_faults = 0;
    const char *dir = ".";
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--help")) {
            puts("Usage: payload [--dir DIR] [--iterations 1..1024] [--timeout 1..600]"
                 " [--require-fault-injection]\n"
                 "8 functional cases; storage failure/reset refusal explicitly SKIP without kernel hooks.");
            return 0;
        } else if (!strcmp(argv[i], "--require-fault-injection")) {
            require_faults = 1;
        } else if (i + 1 < argc && !strcmp(argv[i], "--dir")) {
            dir = argv[++i];
        } else if (i + 1 < argc && !strcmp(argv[i], "--iterations")) {
            iterations = number(argv[++i], 1024);
        } else if (i + 1 < argc && !strcmp(argv[i], "--timeout")) {
            case_timeout = number(argv[++i], 600);
        } else {
            errno = EINVAL;
            fail("unknown option or missing value", __LINE__);
        }
    }
    CHECK(chdir(dir) == 0);
    long size = sysconf(_SC_PAGESIZE);
    CHECK(size >= 1024 && size <= 1024 * 1024);
    page_size = (size_t)size;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = watchdog;
    CHECK(sigemptyset(&sa.sa_mask) == 0);
    CHECK(sigaction(SIGALRM, &sa, NULL) == 0);
    CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    struct test { const char *name; void (*run)(void); } tests[] = {
        { "shared_visibility_readback", shared_visibility_readback },
        { "private_file_isolation", private_file_isolation },
        { "fork_shared_private_cow", fork_shared_private_cow },
        { "partial_munmap", partial_munmap },
        { "process_exit_writeback", process_exit_writeback },
        { "map_fixed_tlb_visibility", map_fixed_tlb_visibility },
        { "fault_replacement_race", fault_replacement_race },
        { "mapped_write_checkpoint_race", mapped_write_checkpoint_race },
    };
    size_t count = sizeof(tests) / sizeof(tests[0]);
    printf("MLC START version=1 page_size=%zu iterations=%u case_timeout=%u\n",
           page_size, iterations, case_timeout);
    for (size_t i = 0; i < count; ++i) {
        case_name = tests[i].name;
        printf("MLC BEGIN %s\n", case_name);
        alarm(case_timeout);
        tests[i].run();
        alarm(0);
        printf("MLC PASS %s\n", case_name);
    }
    puts("MLC SKIP sync_failure_reset_refusal no integration FileNode fault/power hook");
    printf("MLC SUMMARY pass=%zu fail=%d skip=1\n", count, require_faults ? 1 : 0);
    if (require_faults) {
        puts("MLC FAIL sync_failure_reset_refusal required seam unavailable");
        puts("MLC RESULT FAIL");
        return 1;
    }
    puts("MLC RESULT PASS functional_only=1");
    return 0;
}
