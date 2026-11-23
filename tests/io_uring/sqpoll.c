/* Direct SQ/CQ acceptance for behavior hidden by liburing's automatic enters. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/io_uring.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "sqpoll:%d: %s (errno=%d)\n", __LINE__, #expr, errno); exit(1); \
} } while (0)

struct ring {
    int fd;
    unsigned enters;
    struct io_uring_params p;
    char *sq, *cq;
    struct io_uring_sqe *sqes;
    size_t sqsz, cqsz;
};

#define SQ(r, field) ((unsigned *)((r)->sq + (r)->p.sq_off.field))
#define CQ(r, field) ((unsigned *)((r)->cq + (r)->p.cq_off.field))
#define load(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define publish(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)

static struct ring setup(unsigned flags, unsigned idle_ms, unsigned cpu)
{
    struct ring r = { .p = { .flags = flags, .sq_thread_idle = idle_ms, .sq_thread_cpu = cpu } };
    r.fd = syscall(SYS_io_uring_setup, 4, &r.p);
    CHECK(r.fd >= 0);
    r.sqsz = r.p.sq_off.array + r.p.sq_entries * sizeof(unsigned);
    r.cqsz = r.p.cq_off.cqes + r.p.cq_entries * sizeof(struct io_uring_cqe);
    if ((r.p.features & IORING_FEAT_SINGLE_MMAP) && r.sqsz < r.cqsz)
        r.sqsz = r.cqsz;
    r.sq = mmap(NULL, r.sqsz, PROT_READ | PROT_WRITE, MAP_SHARED, r.fd, IORING_OFF_SQ_RING);
    r.cq = (r.p.features & IORING_FEAT_SINGLE_MMAP) ? r.sq :
        mmap(NULL, r.cqsz, PROT_READ | PROT_WRITE, MAP_SHARED, r.fd, IORING_OFF_CQ_RING);
    r.sqes = mmap(NULL, r.p.sq_entries * sizeof(*r.sqes), PROT_READ | PROT_WRITE,
                  MAP_SHARED, r.fd, IORING_OFF_SQES);
    CHECK(r.sq != MAP_FAILED && r.cq != MAP_FAILED && r.sqes != MAP_FAILED);
    return r;
}

static void destroy(struct ring *r)
{
    CHECK(munmap(r->sqes, r->p.sq_entries * sizeof(*r->sqes)) == 0);
    if (r->cq != r->sq)
        CHECK(munmap(r->cq, r->cqsz) == 0);
    CHECK(munmap(r->sq, r->sqsz) == 0);
    CHECK(close(r->fd) == 0);
}

static void enter(struct ring *r, unsigned n, unsigned min, unsigned flags)
{
    __atomic_fetch_add(&r->enters, 1, __ATOMIC_RELAXED);
    CHECK(syscall(SYS_io_uring_enter, r->fd, n, min, flags, NULL, 0) == n);
}

/* This test uses one producer at a time, including across fork and thread handoff. */
static void submit(struct ring *r, const struct io_uring_sqe *sqes, unsigned n)
{
    unsigned tail = load(SQ(r, tail));
    CHECK(tail - load(SQ(r, head)) + n <= r->p.sq_entries);
    for (unsigned i = 0; i < n; i++) {
        unsigned slot = (tail + i) & (r->p.sq_entries - 1);
        r->sqes[slot] = sqes[i];
        SQ(r, array)[slot] = slot;
    }
    publish(SQ(r, tail), tail + n);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

static void kick_if_asleep(struct ring *r)
{
    if (load(SQ(r, flags)) & IORING_SQ_NEED_WAKEUP)
        enter(r, 0, 0, IORING_ENTER_SQ_WAKEUP);
}

static struct io_uring_cqe reap(struct ring *r)
{
    unsigned head = load(CQ(r, head));
    while (head == load(CQ(r, tail))) {
        /* During the measured interval poll the shared CQ without a syscall. */
    }
    struct io_uring_cqe *cqes = (void *)(r->cq + r->p.cq_off.cqes);
    struct io_uring_cqe cqe = cqes[head & (r->p.cq_entries - 1)];
    publish(CQ(r, head), head + 1);
    return cqe;
}

static void expect(struct ring *r, uint64_t id, int res)
{
    struct io_uring_cqe cqe = reap(r);
    if (cqe.user_data != id || cqe.res != res)
        fprintf(stderr, "expected id=%llu res=%d got id=%llu res=%d\n",
                (unsigned long long)id, res, (unsigned long long)cqe.user_data, cqe.res);
    CHECK(cqe.user_data == id && cqe.res == res);
}

static void wait_asleep(struct ring *r)
{
    while (!(load(SQ(r, flags)) & IORING_SQ_NEED_WAKEUP))
        sched_yield();
}

/* Eight online CPUs, with 6 and 7 reserved and only 7 serving SQPOLL. */
static void reserved_cpu(void)
{
    cpu_set_t allowed, one;
    CHECK(sched_getaffinity(0, sizeof(allowed), &allowed) == 0);
    CHECK(CPU_COUNT(&allowed) == 6);
    for (int cpu = 0; cpu < 6; cpu++)
        CHECK(CPU_ISSET(cpu, &allowed));
    CPU_ZERO(&one);
    CPU_SET(7, &one);
    CHECK(sched_setaffinity(0, sizeof(one), &one) == -1 && errno == EINVAL);
    CPU_CLR(7, &one);
    CPU_SET(0, &one);
    CHECK(sched_setaffinity(0, sizeof(one), &one) == 0 && sched_getcpu() == 0);
    puts("SQPOLL user mask=0x3f bind7=EINVAL producer=0");

    unsigned flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
    const unsigned invalid[] = { 1, 6, 8, UINT_MAX };
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        struct io_uring_params p = { .flags = flags, .sq_thread_cpu = invalid[i] };
        CHECK(syscall(SYS_io_uring_setup, 4, &p) == -1 && errno == EINVAL);
    }
    puts("SQPOLL rejected disallowed=1 reserved=6 absent=8 out_of_range=UINT_MAX");

    struct ring r = setup(flags, 2000, 7);
    struct io_uring_sqe nop = { .opcode = IORING_OP_NOP, .user_data = 0 };
    submit(&r, &nop, 1);
    enter(&r, 0, 1, IORING_ENTER_SQ_WAKEUP | IORING_ENTER_GETEVENTS);
    expect(&r, 0, 0);

    unsigned before = r.enters;
    for (unsigned batch = 0; batch < 8; batch++) {
        unsigned first = 1 + 4 * batch;
        struct io_uring_sqe nops[4] = {};
        for (unsigned i = 0; i < 4; i++) {
            nops[i].opcode = IORING_OP_NOP;
            nops[i].user_data = first + i;
        }
        submit(&r, nops, 4);
        unsigned seen = 0;
        for (unsigned i = 0; i < 4; i++) {
            struct io_uring_cqe cqe = reap(&r);
            CHECK(cqe.res == 0 && cqe.user_data >= first && cqe.user_data < first + 4);
            seen |= 1u << (cqe.user_data - first);
        }
        CHECK(seen == 0xf);
    }
    CHECK(r.enters == before);
    printf("SQPOLL reserved active batches=8 unique=32 enters=%u\n", r.enters - before);
    wait_asleep(&r);
    /* Wake an empty SQ. The poller must acknowledge the kick before it can see ID 33. */
    enter(&r, 0, 0, IORING_ENTER_SQ_WAKEUP);
    while (load(SQ(&r, flags)) & IORING_SQ_NEED_WAKEUP)
        sched_yield();
    nop.user_data = 33;
    submit(&r, &nop, 1);
    kick_if_asleep(&r);
    expect(&r, 33, 0);
    CHECK(load(CQ(&r, head)) == load(CQ(&r, tail)));
    puts("SQPOLL reserved NEED_WAKEUP resumed user_data=33");
    destroy(&r);
}

static void ordinary_and_invalid(void)
{
    struct io_uring_params p = { .flags = IORING_SETUP_SQ_AFF };
    CHECK(syscall(SYS_io_uring_setup, 4, &p) == -1 && errno == EINVAL);
    p.flags |= IORING_SETUP_SQPOLL;
    p.sq_thread_cpu = UINT_MAX;
    CHECK(syscall(SYS_io_uring_setup, 4, &p) == -1 && errno == EINVAL);
    cpu_set_t allowed, restricted;
    CHECK(sched_getaffinity(0, sizeof(allowed), &allowed) == 0);
    CHECK(CPU_ISSET(0, &allowed) && CPU_ISSET(1, &allowed));
    CPU_ZERO(&restricted);
    CPU_SET(0, &restricted);
    CHECK(sched_setaffinity(0, sizeof(restricted), &restricted) == 0);
    p.sq_thread_cpu = 1;
    CHECK(syscall(SYS_io_uring_setup, 4, &p) == -1 && errno == EINVAL);
    CHECK(sched_setaffinity(0, sizeof(allowed), &allowed) == 0);

    struct ring r = setup(0, 0, 0);
    CHECK(r.p.features & IORING_FEAT_SQPOLL_NONFIXED);
    struct io_uring_sqe nop = { .user_data = 99 };
    submit(&r, &nop, 1);
    enter(&r, 1, 1, IORING_ENTER_SQ_WAIT | IORING_ENTER_SQ_WAKEUP | IORING_ENTER_GETEVENTS);
    expect(&r, 99, 0);
    destroy(&r);
}

static const char contents[] = "PulseOS SQPOLL";

static int known_file(void)
{
    char path[] = "/tmp/sqpoll-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0 && unlink(path) == 0 && write(fd, contents, sizeof(contents)) == sizeof(contents));
    return fd;
}

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void measure_reads(int sqpoll)
{
    struct ring r = sqpoll ? setup(IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF, 2000, 1) :
                             setup(0, 0, 0);
    if (sqpoll)
        CHECK(r.p.features & IORING_FEAT_SQPOLL_NONFIXED);
    int fd = known_file();
    CHECK(syscall(SYS_io_uring_register, r.fd, IORING_REGISTER_FILES, &fd, 1) == 0);
    struct io_uring_sqe warm = { .user_data = 99 };
    submit(&r, &warm, 1);
    enter(&r, sqpoll ? 0 : 1, 1, (sqpoll ? IORING_ENTER_SQ_WAKEUP : 0) | IORING_ENTER_GETEVENTS);
    expect(&r, 99, 0);

    unsigned before = r.enters;
    uint64_t start = monotonic_ns();
    for (unsigned batch = 0; batch < 8; batch++) {
        char buf[4][sizeof(contents)] = {};
        struct io_uring_sqe reads[4] = {};
        for (unsigned i = 0; i < 4; i++) {
            reads[i] = (struct io_uring_sqe){ .opcode = IORING_OP_READ,
                .flags = i % 2 ? IOSQE_FIXED_FILE : 0, .fd = i % 2 ? 0 : fd,
                .addr = (uintptr_t)buf[i], .len = sizeof(contents), .user_data = batch * 4 + i };
        }
        submit(&r, reads, 4);
        if (!sqpoll)
            enter(&r, 4, 0, 0);
        unsigned seen = 0;
        for (unsigned i = 0; i < 4; i++) {
            struct io_uring_cqe cqe = reap(&r);
            CHECK(cqe.user_data / 4 == batch && cqe.res == sizeof(contents));
            unsigned slot = cqe.user_data % 4;
            CHECK(!(seen & (1u << slot)) && memcmp(buf[slot], contents, sizeof(contents)) == 0);
            seen |= 1u << slot;
        }
    }
    uint64_t elapsed = monotonic_ns() - start;
    CHECK(r.enters - before == (sqpoll ? 0 : 8) && load(CQ(&r, head)) == load(CQ(&r, tail)));
    printf("SQPOLL %s batches=8 unique=32 ordinary_reads=16 fixed_reads=16 enters=%u elapsed_us=%llu\n",
           sqpoll ? "active" : "baseline", r.enters - before, (unsigned long long)(elapsed / 1000));
    close(fd);
    destroy(&r);
}

static void foreign_submitter(void)
{
    struct ring r = setup(IORING_SETUP_SQPOLL, 2, UINT_MAX);
    int fd = known_file();
    char buf[sizeof(contents)] = {};
    wait_asleep(&r);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        /* Make both the child's file table and its COW buffer distinguishable. */
        int other = open("/dev/null", O_RDONLY);
        CHECK(other >= 0 && dup2(other, fd) == fd);
        memset(buf, 0x5a, sizeof(buf));
        struct io_uring_sqe read = { .opcode = IORING_OP_READ, .fd = fd,
            .addr = (uintptr_t)buf, .len = sizeof(contents), .user_data = 42 };
        submit(&r, &read, 1);
        enter(&r, 0, 1, IORING_ENTER_SQ_WAKEUP | IORING_ENTER_GETEVENTS);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    expect(&r, 42, sizeof(contents));
    CHECK(memcmp(buf, contents, sizeof(contents)) == 0);
    close(fd);
    destroy(&r);
}

static void ordinary_close_after_unshare(void)
{
    int pipefd[2];
    CHECK(pipe2(pipefd, O_NONBLOCK) == 0);
    struct ring r = setup(0, 0, 0);
    CHECK(syscall(SYS_io_uring_register, r.fd, IORING_REGISTER_FILES, pipefd + 1, 1) == 0);
    CHECK(close(pipefd[1]) == 0);
    struct io_uring_sqe poll = { .opcode = IORING_OP_POLL_ADD, .fd = pipefd[0],
        .poll32_events = POLLIN, .user_data = 1 };
    submit(&r, &poll, 1);
    enter(&r, 1, 0, 0);
    CHECK(load(CQ(&r, head)) == load(CQ(&r, tail)));
    CHECK(unshare(CLONE_FILES) == 0);
    destroy(&r);
    /* The cancelled poll must not keep the old fd table and its ring alive. */
    char byte;
    CHECK(read(pipefd[0], &byte, 1) == 0);
    CHECK(close(pipefd[0]) == 0);
}

static void unshared_files(void)
{
    int sentinel[2];
    CHECK(pipe(sentinel) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int fd = known_file();
        struct ring r = setup(IORING_SETUP_SQPOLL, 10, 0);
        int empty = -1;
        CHECK(syscall(SYS_io_uring_register, r.fd, IORING_REGISTER_FILES, &empty, 1) == 0);
        CHECK(unshare(CLONE_FILES) == 0);
        CHECK(close(sentinel[1]) == 0);
        int other = open("/dev/null", O_RDONLY);
        CHECK(other >= 0 && dup2(other, fd) == fd && close(other) == 0);

        char buf[sizeof(contents)] = {};
        struct io_uring_sqe read = { .opcode = IORING_OP_READ, .fd = fd,
            .addr = (uintptr_t)buf, .len = sizeof(buf), .user_data = 1 };
        submit(&r, &read, 1);
        kick_if_asleep(&r);
        expect(&r, 1, sizeof(buf));
        CHECK(memcmp(buf, contents, sizeof(buf)) == 0);

        struct io_uring_sqe update = { .opcode = IORING_OP_FILES_UPDATE, .flags = IOSQE_ASYNC,
            .addr = (uintptr_t)&fd, .len = 1, .user_data = 2 };
        submit(&r, &update, 1);
        kick_if_asleep(&r);
        expect(&r, 2, 1);
        memset(buf, 0, sizeof(buf));
        read.flags = IOSQE_FIXED_FILE;
        read.fd = 0;
        submit(&r, &read, 1);
        kick_if_asleep(&r);
        expect(&r, 1, sizeof(buf));
        CHECK(memcmp(buf, contents, sizeof(buf)) == 0);

        struct io_uring_sqe sock = { .opcode = IORING_OP_SOCKET, .flags = IOSQE_ASYNC,
            .fd = AF_INET, .off = SOCK_STREAM, .user_data = 3 };
        submit(&r, &sock, 1);
        kick_if_asleep(&r);
        struct io_uring_cqe cqe = reap(&r);
        CHECK(cqe.user_data == 3 && cqe.res >= 0);
        CHECK(fcntl(cqe.res, F_GETFD) == -1 && errno == EBADF);
        destroy(&r);
        _exit(0);
    }
    CHECK(close(sentinel[1]) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    char byte;
    CHECK(read(sentinel[0], &byte, 1) == 0);
    CHECK(close(sentinel[0]) == 0);
}

static void *wake_full(void *arg)
{
    struct ring *r = arg;
    usleep(25000);
    CHECK(load(SQ(r, tail)) - load(SQ(r, head)) == r->p.sq_entries);
    enter(r, 0, 0, IORING_ENTER_SQ_WAKEUP);
    return NULL;
}

static void wake_and_wait(void)
{
    struct ring r = setup(IORING_SETUP_SQPOLL, 4, 0);
    struct io_uring_sqe nops[4] = {};
    for (unsigned i = 0; i < 4; i++)
        nops[i].user_data = i;
    wait_asleep(&r);
    /* A plain SQPOLL enter reports to_submit even though the sleeping SQ is empty. */
    enter(&r, 9, 0, 0);
    usleep(30000); /* Allow the sleep-side final recheck to finish before filling the SQ. */
    wait_asleep(&r);
    submit(&r, nops, 4);
    pthread_t waker;
    CHECK(pthread_create(&waker, NULL, wake_full, &r) == 0);
    enter(&r, 0, 0, IORING_ENTER_SQ_WAIT);
    CHECK(load(SQ(&r, tail)) - load(SQ(&r, head)) < r.p.sq_entries);
    CHECK(pthread_join(waker, NULL) == 0);
    for (unsigned i = 0; i < 4; i++)
        expect(&r, i, 0);
    for (unsigned i = 0; i < 64; i++) {
        usleep(1000 + (i % 7) * 1000);
        nops[0].user_data = i + 4;
        submit(&r, nops, 1);
        kick_if_asleep(&r);
        expect(&r, i + 4, 0);
    }

    unsigned count = r.p.cq_entries + 1;
    for (unsigned i = 0; i < count; i++) {
        while (load(SQ(&r, tail)) - load(SQ(&r, head)) == r.p.sq_entries)
            sched_yield();
        nops[0].user_data = i;
        submit(&r, nops, 1);
        kick_if_asleep(&r);
    }
    unsigned both = IORING_SQ_NEED_WAKEUP | IORING_SQ_CQ_OVERFLOW;
    while ((load(SQ(&r, flags)) & both) != both)
        sched_yield();
    enter(&r, 0, 0, IORING_ENTER_SQ_WAKEUP);
    CHECK(load(SQ(&r, flags)) & IORING_SQ_CQ_OVERFLOW);
    for (unsigned i = 0; i < r.p.cq_entries; i++)
        expect(&r, i, 0);
    enter(&r, 0, 1, IORING_ENTER_GETEVENTS);
    expect(&r, count - 1, 0);
    destroy(&r);
}

enum poller_state { ACTIVE, ASLEEP, INFLIGHT };

static void lifecycle(enum poller_state state, int explicit_close)
{
    int sentinel[2];
    CHECK(pipe(sentinel) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        struct ring r = setup(IORING_SETUP_SQPOLL, state == ASLEEP ? 2 : 2000, 0);
        CHECK(syscall(SYS_io_uring_register, r.fd, IORING_REGISTER_FILES, sentinel + 1, 1) == 0);
        CHECK(close(sentinel[1]) == 0);
        char byte;
        struct io_uring_sqe batch[] = {
            { .opcode = IORING_OP_READ, .fd = sentinel[0], .addr = (uintptr_t)&byte,
              .len = 1, .user_data = 1 },
            { .user_data = 2 },
        };
        if (state == INFLIGHT)
            submit(&r, batch, 2);
        else
            submit(&r, &batch[1], 1);
        kick_if_asleep(&r);
        expect(&r, 2, 0);
        if (state == ASLEEP)
            wait_asleep(&r);
        if (explicit_close) {
            destroy(&r);
            CHECK(read(sentinel[0], &byte, 1) == 0);
        }
        _exit(0);
    }
    close(sentinel[1]);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    /* Only the ring held the writer. EOF proves its registered files were reclaimed. */
    char byte;
    CHECK(read(sentinel[0], &byte, 1) == 0);
    close(sentinel[0]);
}

int main(int argc, char **argv)
{
    alarm(40);
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && strcmp(argv[1], "--reserved-cpu") == 0) {
        reserved_cpu();
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--ordinary-baseline") == 0) {
        measure_reads(0);
        return 0;
    }
    CHECK(argc == 1);
    ordinary_and_invalid();
    puts("SQPOLL ordinary flags, feature and affinity errors PASS");
    measure_reads(1);
    foreign_submitter();
    puts("SQPOLL foreign fd table, address space and wakeup PASS");
    ordinary_close_after_unshare();
    puts("SQPOLL regression ordinary ring unshare and close released writer PASS");
    unshared_files();
    puts("SQPOLL unshare lookup, FILES_UPDATE, socket install and old table release PASS");
    wake_and_wait();
    puts("SQPOLL full SQ_WAIT, sleep boundary and CQ overflow coexistence PASS");
    for (int state = ACTIVE; state <= INFLIGHT; state++)
        for (int close_ring = 0; close_ring <= 1; close_ring++)
            lifecycle(state, close_ring);
    puts("SQPOLL active/asleep/inflight close and exit reclaimed fixed writers PASS");
    puts("SQPOLL_RESULT PASS");
    return 0;
}
