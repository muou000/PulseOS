/* Direct SQ/CQ acceptance for behavior hidden by liburing's automatic enters. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/io_uring.h>
#include <netinet/in.h>
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

static void pin_to_cpu(int cpu)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    CHECK(sched_setaffinity(0, sizeof(mask), &mask) == 0 && sched_getcpu() == cpu);
}

struct competitor {
    struct ring *ordinary;
    unsigned stop, calls;
};

static void *drive_ordinary_ring(void *arg)
{
    struct competitor *c = arg;
    pin_to_cpu(1);
    while (!load(&c->stop)) {
        enter(c->ordinary, 0, 0, IORING_ENTER_GETEVENTS);
        __atomic_add_fetch(&c->calls, 1, __ATOMIC_RELEASE);
    }
    return NULL;
}

static struct io_uring_sqe poll_readable(int fd, uint64_t id)
{
    return (struct io_uring_sqe){ .opcode = IORING_OP_POLL_ADD, .fd = fd,
        .poll32_events = POLLIN, .user_data = id };
}

static const struct timespec zero_delay = {0};

static struct io_uring_sqe timeout_after(const struct timespec *delay, uint64_t id)
{
    return (struct io_uring_sqe){ .opcode = IORING_OP_TIMEOUT, .fd = -1,
        .addr = (uintptr_t)delay, .len = 1, .user_data = id };
}

/* Wait for the driver to poll the following timer before writing or cancelling. */
static void arm_reserved_poll(struct ring *r, int reader, uint64_t id)
{
    struct io_uring_sqe pair[] = { poll_readable(reader, id), timeout_after(&zero_delay, id + 1) };
    submit(r, pair, 2);
    kick_if_asleep(r);
    expect(r, id + 1, -ETIME);
}

/* Let SQPOLL finish dispatching before the worker completes the Path 3 read. */
static void dependent_timeout(struct ring *r, int *pipefd, int linked, uint64_t id)
{
    char byte = 0;
    struct io_uring_sqe pair[] = {
        { .opcode = IORING_OP_READ, .flags = IOSQE_ASYNC | (linked ? IOSQE_IO_LINK : 0),
          .fd = pipefd[0], .addr = (uintptr_t)&byte, .len = 1, .user_data = id },
        timeout_after(&zero_delay, id + 1),
    };
    pair[1].flags = linked ? 0 : IOSQE_IO_DRAIN;
    submit(r, pair, 2);
    kick_if_asleep(r);
    while (load(SQ(r, head)) != load(SQ(r, tail)))
        sched_yield();
    wait_asleep(r);
    CHECK(load(CQ(r, head)) == load(CQ(r, tail)));
    CHECK(write(pipefd[1], "w", 1) == 1);
    expect(r, id, 1);
    expect(r, id + 1, -ETIME);
    CHECK(byte == 'w');
}

static void reserved_futures(void)
{
    int signal_pipe[2], work_pipe[2], sentinel[2];
    CHECK(pipe(signal_pipe) == 0 && pipe(work_pipe) == 0 && pipe(sentinel) == 0);
    pin_to_cpu(0);
    puts("FUTURE_CPU_BEGIN");
    struct ring r = setup(IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF, 1, 7);
    struct ring ordinary = setup(0, 0, 0);
    struct io_uring_sqe poll = poll_readable(signal_pipe[0], 101);
    submit(&ordinary, &poll, 1);
    enter(&ordinary, 1, 0, 0);
    arm_reserved_poll(&r, signal_pipe[0], 1);

    struct competitor c = { .ordinary = &ordinary };
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, drive_ordinary_ring, &c) == 0);
    while (!load(&c.calls))
        sched_yield();
    CHECK(sched_getcpu() == 0 && write(signal_pipe[1], "a", 1) == 1);
    expect(&r, 1, POLLIN);
    expect(&ordinary, 101, POLLIN);
    publish(&c.stop, 1);
    CHECK(pthread_join(thread, NULL) == 0);

    /* The second ordinary request can only resume in a global background driver. */
    char byte;
    CHECK(read(signal_pipe[0], &byte, 1) == 1);
    poll.user_data = 102;
    submit(&ordinary, &poll, 1);
    enter(&ordinary, 1, 0, 0);
    CHECK(write(signal_pipe[1], "b", 1) == 1);
    expect(&ordinary, 102, POLLIN);

    dependent_timeout(&r, work_pipe, 1, 3);
    dependent_timeout(&r, work_pipe, 0, 5);

    /* Only the ring retains the sentinel writer. EOF after close proves release. */
    CHECK(syscall(SYS_io_uring_register, r.fd, IORING_REGISTER_FILES, sentinel + 1, 1) == 0);
    CHECK(close(sentinel[1]) == 0);
    arm_reserved_poll(&r, work_pipe[0], 7);
    struct io_uring_sqe cancel = { .opcode = IORING_OP_POLL_REMOVE, .fd = -1, .addr = 7, .user_data = 9 };
    submit(&r, &cancel, 1);
    kick_if_asleep(&r);
    expect(&r, 7, -ECANCELED);
    expect(&r, 9, 0);
    CHECK(write(work_pipe[1], "c", 1) == 1);
    arm_reserved_poll(&r, sentinel[0], 10);
    CHECK(load(CQ(&r, head)) == load(CQ(&r, tail)));
    CHECK(load(CQ(&ordinary, head)) == load(CQ(&ordinary, tail)));
    destroy(&r);
    destroy(&ordinary);
    CHECK(read(sentinel[0], &byte, 1) == 0);
    CHECK(close(sentinel[0]) == 0);
    CHECK(close(work_pipe[0]) == 0 && close(work_pipe[1]) == 0);
    CHECK(close(signal_pipe[0]) == 0 && close(signal_pipe[1]) == 0);
    /* stdout shares the serial port with the per-poll kernel traces. */
    printf("FUTURE_CPU wake_cpu=0 GETEVENTS_cpu=1 calls=%u\n", c.calls);
    puts("FUTURE_CPU CQ order, unique completions, close and writer release PASS");
}

static void reserved_recv_and_timeout(struct ring *r)
{
    int sock[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sock) == 0);
    char received = 0;
    struct timespec delay = { .tv_nsec = 250000000 };
    struct io_uring_sqe batch[] = {
        { .opcode = IORING_OP_RECV, .fd = sock[0], .len = 1,
          .addr = (uintptr_t)&received, .user_data = 203 },
        timeout_after(&delay, 204),
    };
    submit(r, batch, 2);
    kick_if_asleep(r);
    expect(r, 204, -ETIME);
    CHECK(sched_getcpu() == 0 && send(sock[1], "r", 1, 0) == 1);
    expect(r, 203, 1);
    CHECK(received == 'r' && load(CQ(r, head)) == load(CQ(r, tail)));
    CHECK(close(sock[0]) == 0 && close(sock[1]) == 0);
}

static void reserved_file_position(struct ring *r)
{
    char path[] = "/root/future-offset-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0 && unlink(path) == 0);
    char data[2];
    CHECK(write(fd, "az", 2) == 2 && pread(fd, data, 2, 0) == 2);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    char src = 'x', dst = 0;
    struct io_uring_sqe batch[] = {
        { .opcode = IORING_OP_WRITE, .fd = fd, .off = UINT64_MAX,
          .addr = (uintptr_t)&src, .len = 1, .user_data = 201 },
        { .opcode = IORING_OP_READ, .fd = fd, .off = UINT64_MAX,
          .addr = (uintptr_t)&dst, .len = 1, .user_data = 202 },
    };
    submit(r, batch, 2);
    kick_if_asleep(r);
    unsigned seen = 0;
    for (unsigned i = 0; i < 2; i++) {
        struct io_uring_cqe cqe = reap(r);
        CHECK(cqe.res == 1 && (cqe.user_data == 201 || cqe.user_data == 202));
        seen |= 1u << (cqe.user_data - 201);
    }
    CHECK(seen == 3 && dst == 'z' && lseek(fd, 0, SEEK_CUR) == 2);
    CHECK(pread(fd, data, 2, 0) == 2 && memcmp(data, "xz", 2) == 0);
    CHECK(close(fd) == 0);
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

/* The host acknowledges scheduler events over the guest console. A delay cannot
 * distinguish a sleeping or retired worker from a worker still waiting to run. */
static void worker_ack(const char *word)
{
    struct pollfd input = { .fd = STDIN_FILENO, .events = POLLIN };
    char line[24];
    CHECK(poll(&input, 1, 12000) == 1 && (input.revents & POLLIN));
    CHECK(fgets(line, sizeof(line), stdin) && strcmp(line, word) == 0);
}

static void worker_submit(struct ring *r, struct io_uring_sqe sqe)
{
    submit(r, &sqe, 1);
    if (r->p.flags & IORING_SETUP_SQPOLL)
        kick_if_asleep(r);
    else
        enter(r, 1, 0, 0);
}

static struct io_uring_sqe worker_read(int fd, void *dst, unsigned len, uint64_t id)
{
    return (struct io_uring_sqe){ .opcode = IORING_OP_READ, .flags = IOSQE_ASYNC,
        .fd = fd, .addr = (uintptr_t)dst, .len = len, .user_data = id };
}

struct dedicated_work {
    struct ring *ring;
    int file, pipe_writer;
    int reader_cpu, wake_cpu;
    unsigned ready, read_turn, reads_done;
};

static void *dedicated_waker(void *arg)
{
    struct dedicated_work *w = arg;
    pin_to_cpu(2);
    __atomic_add_fetch(&w->ready, 1, __ATOMIC_RELEASE);
    /* The host sends this only after seeing this ring's POLL_ADD return Pending. */
    worker_ack("pending\n");
    w->wake_cpu = sched_getcpu();
    CHECK(w->wake_cpu == 2 && write(w->pipe_writer, "p", 1) == 1);
    return NULL;
}

static void *dedicated_reads(void *arg)
{
    struct dedicated_work *w = arg;
    pin_to_cpu(1);
    w->reader_cpu = sched_getcpu();
    char cached[2] = {}, forced[2] = {};
    struct io_uring_sqe reads[] = {
        worker_read(w->file, cached, sizeof(cached), 2001),
        worker_read(w->file, forced, sizeof(forced), 2002),
    };
    reads[0].flags = 0;
    __atomic_add_fetch(&w->ready, 1, __ATOMIC_RELEASE);
    /* Acquire exclusive ownership of both rings after CPU 0 reaps its POLL_ADD. */
    while (!load(&w->read_turn)) {}
    submit(w->ring, reads, 2);
    unsigned seen = 0;
    for (unsigned i = 0; i < 2; i++) {
        struct io_uring_cqe cqe = reap(w->ring);
        CHECK(cqe.res == 2 && (cqe.user_data == 2001 || cqe.user_data == 2002));
        unsigned bit = 1U << (cqe.user_data - 2001);
        CHECK(!(seen & bit));
        seen |= bit;
    }
    CHECK(seen == 3 && !memcmp(cached, "7\n", 2) && !memcmp(forced, "7\n", 2));
    publish(&w->reads_done, 1);
    return NULL;
}

static void dedicated_ring(void)
{
    cpu_set_t allowed;
    CHECK(sched_getaffinity(0, sizeof(allowed), &allowed) == 0 && CPU_COUNT(&allowed) == 7);
    for (int cpu = 0; cpu < 7; cpu++)
        CHECK(CPU_ISSET(cpu, &allowed));
    pin_to_cpu(0);
    int submit_cpu = sched_getcpu();
    puts("DEDICATED_RING_BEGIN");
    struct ring r = setup(IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF, 2000, 7);

    /* Read the regular rootfs fixture into cache before exercising the inline path. */
    int fd = open("/etc/pulse-kernel-cpus", O_RDONLY);
    char bytes[2];
    CHECK(fd >= 0 && pread(fd, bytes, sizeof(bytes), 0) == 2 && !memcmp(bytes, "7\n", 2));
    int signal_pipe[2], sentinel[2];
    CHECK(pipe(signal_pipe) == 0 && pipe2(sentinel, O_NONBLOCK) == 0);
    CHECK(syscall(SYS_io_uring_register, r.fd, IORING_REGISTER_FILES, sentinel + 1, 1) == 0);
    CHECK(close(sentinel[1]) == 0 && read(sentinel[0], bytes, 1) == -1 && errno == EAGAIN);
    struct dedicated_work w = { .ring = &r, .file = fd, .pipe_writer = signal_pipe[1] };
    pthread_t reader, waker;
    CHECK(pthread_create(&reader, NULL, dedicated_reads, &w) == 0);
    CHECK(pthread_create(&waker, NULL, dedicated_waker, &w) == 0);
    while (load(&w.ready) != 2)
        sched_yield();

    struct io_uring_sqe nop = { .opcode = IORING_OP_NOP, .user_data = 0 };
    submit(&r, &nop, 1);
    enter(&r, 0, 1, IORING_ENTER_SQ_WAKEUP | IORING_ENTER_GETEVENTS);
    expect(&r, 0, 0);
    unsigned before = r.enters;
    struct io_uring_sqe poll = poll_readable(signal_pipe[0], 1001);
    uint64_t start = monotonic_ns();
    submit(&r, &poll, 1);
    expect(&r, 1001, POLLIN);
    publish(&w.read_turn, 1);
    while (!load(&w.reads_done)) {}
    uint64_t end = monotonic_ns();
    unsigned active_enters = r.enters - before;
    CHECK(!active_enters && load(CQ(&r, head)) == load(CQ(&r, tail)));
    CHECK(pthread_join(reader, NULL) == 0 && pthread_join(waker, NULL) == 0);

    wait_asleep(&r);
    before = r.enters;
    enter(&r, 0, 0, IORING_ENTER_SQ_WAKEUP);
    while (load(SQ(&r, flags)) & IORING_SQ_NEED_WAKEUP)
        sched_yield();
    nop.user_data = 3001;
    submit(&r, &nop, 1);
    expect(&r, 3001, 0);
    unsigned idle_enters = r.enters - before;
    CHECK(idle_enters == 1 && load(CQ(&r, head)) == load(CQ(&r, tail)));
    destroy(&r);
    CHECK(read(sentinel[0], bytes, 1) == 0 && close(sentinel[0]) == 0);
    CHECK(close(fd) == 0 && close(signal_pipe[0]) == 0 && close(signal_pipe[1]) == 0);

    printf("DEDICATED_RING active_start_ns=%llu active_end_ns=%llu\n",
           (unsigned long long)start, (unsigned long long)end);
    printf("DEDICATED_RING active unique=3 enters=%u producer0_cpu=%d producer1_cpu=%d wake_cpu=%d\n",
           active_enters, submit_cpu, w.reader_cpu, w.wake_cpu);
    printf("DEDICATED_RING idle need_wakeup=1 enters=%u unique=1\n", idle_enters);
    puts("DEDICATED_RING close writer_eof=1 PASS");
}

static int worker_result(struct ring *r, uint64_t id)
{
    uint64_t deadline = monotonic_ns() + 8000000000ULL;
    while (load(CQ(r, head)) == load(CQ(r, tail))) {
        CHECK(monotonic_ns() < deadline);
        usleep(1000);
    }
    struct io_uring_cqe cqe = reap(r);
    CHECK(cqe.user_data == id);
    return cqe.res;
}

static void *worker_connector(void *arg)
{
    const struct sockaddr_in *address = arg;
    pin_to_cpu(1);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    CHECK(connect(fd, (const struct sockaddr *)address, sizeof(*address)) == 0);
    CHECK(close(fd) == 0);
    return NULL;
}

static void accept_while_reading(struct ring *a, struct ring *b, struct ring *ordinary, int fd)
{
    struct sockaddr_in address = { .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t len = sizeof(address);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listener >= 0 && bind(listener, (struct sockaddr *)&address, len) == 0);
    CHECK(listen(listener, 4) == 0);
    CHECK(getsockname(listener, (struct sockaddr *)&address, &len) == 0 && address.sin_port);
    worker_submit(a, (struct io_uring_sqe){ .opcode = IORING_OP_ACCEPT, .flags = IOSQE_ASYNC,
        .fd = listener, .user_data = 1001 });
    worker_ack("blocked\n");

    char selected[sizeof(contents)] = {}, other[sizeof(contents)] = {};
    worker_submit(b, worker_read(fd, selected, sizeof(selected), 2001));
    worker_submit(ordinary, worker_read(fd, other, sizeof(other), 3001));
    CHECK(worker_result(b, 2001) == sizeof(selected) && !memcmp(selected, contents, sizeof(selected)));
    CHECK(worker_result(ordinary, 3001) == sizeof(other) && !memcmp(other, contents, sizeof(other)));
    CHECK(load(CQ(a, head)) == load(CQ(a, tail)));

    pthread_t connector;
    CHECK(pthread_create(&connector, NULL, worker_connector, &address) == 0);
    int accepted = worker_result(a, 1001);
    CHECK(accepted >= 0 && pthread_join(connector, NULL) == 0);
    CHECK(close(accepted) == 0 && close(listener) == 0);
}

static void worker_file_position(struct ring *b, struct ring *ordinary)
{
    enum { size = 128 * 1024 + 1 };
    static char source[size + 1], result[size];
    for (unsigned i = 0; i < sizeof(source); i++)
        source[i] = i % 127;
    char path[] = "/root/worker-offset-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0 && unlink(path) == 0 && write(fd, source, sizeof(source)) == sizeof(source));
    CHECK(lseek(fd, 0, SEEK_SET) == 0);

    char first = -1;
    struct io_uring_sqe head = worker_read(fd, &first, 1, 3002);
    head.off = UINT64_MAX;
    worker_submit(ordinary, head); /* enter has reserved the first position ticket */
    struct io_uring_sqe rest = worker_read(fd, result, size, 2002);
    rest.off = UINT64_MAX;
    rest.flags = 0; /* The transfer size alone must select the multi-window worker path. */
    worker_submit(b, rest);
    CHECK(worker_result(ordinary, 3002) == 1 && first == source[0]);
    CHECK(worker_result(b, 2002) == size && !memcmp(result, source + 1, size));
    CHECK(lseek(fd, 0, SEEK_CUR) == sizeof(source) && close(fd) == 0);
}

static void cancel_and_close_queued_reads(struct ring *b, struct ring *ordinary)
{
    int stream[2], sentinel[2];
    char first = 0, cancelled = 0, abandoned = 0;
    CHECK(pipe(stream) == 0 && pipe2(sentinel, O_NONBLOCK) == 0);
    CHECK(syscall(SYS_io_uring_register, ordinary->fd, IORING_REGISTER_FILES, sentinel + 1, 1) == 0);
    CHECK(close(sentinel[1]) == 0);

    worker_submit(b, worker_read(stream[0], &first, 1, 2003));
    worker_ack("pipe\n"); /* The selected worker now owns the pipe's serial key. */
    worker_submit(ordinary, worker_read(stream[0], &cancelled, 1, 3003));
    worker_submit(ordinary, (struct io_uring_sqe){ .opcode = IORING_OP_ASYNC_CANCEL,
        .fd = -1, .addr = 3003, .user_data = 3004 });
    CHECK(worker_result(ordinary, 3003) == -ECANCELED && worker_result(ordinary, 3004) == 0);
    worker_submit(ordinary, worker_read(stream[0], &abandoned, 1, 3005));
    CHECK(load(CQ(ordinary, head)) == load(CQ(ordinary, tail)));
    destroy(ordinary);
    char byte;
    CHECK(read(sentinel[0], &byte, 1) == 0 && close(sentinel[0]) == 0);
    CHECK(write(stream[1], "x", 1) == 1 && worker_result(b, 2003) == 1);
    CHECK(first == 'x' && cancelled == 0 && abandoned == 0);
    CHECK(close(stream[0]) == 0 && close(stream[1]) == 0);
}

static void reserved_workers(void)
{
    pin_to_cpu(0);
    puts("WORKER_CPU_BEGIN");
    unsigned flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
    struct ring a = setup(flags, 1, 7), b = setup(flags, 1, 7);
    struct ring ordinary = setup(0, 0, 0);
    int fd = known_file();
    accept_while_reading(&a, &b, &ordinary, fd);
    worker_file_position(&b, &ordinary);

    /* Read the ext4 root disk's superblock magic. Its devfs block node routes
     * even a two-byte, single-window read without IOSQE_ASYNC to Path 3. */
    int disk = open("/dev/vda", O_RDONLY);
    unsigned char magic[2] = {};
    CHECK(disk >= 0);
    struct io_uring_sqe block_read = worker_read(disk, magic, sizeof(magic), 1002);
    block_read.flags = 0;
    block_read.off = 1024 + 56;
    worker_submit(&a, block_read);
    CHECK(worker_result(&a, 1002) == 2 && magic[0] == 0x53 && magic[1] == 0xef);
    CHECK(close(disk) == 0);

    cancel_and_close_queued_reads(&b, &ordinary);
    worker_ack("idle\n");
    /* Report the connector's checked affinity once the serial port is quiet. */
    puts("WORKER_CPU_CONNECT cpu=1");
    char buf[sizeof(contents)] = {};
    worker_submit(&b, worker_read(fd, buf, sizeof(buf), 2004));
    CHECK(worker_result(&b, 2004) == sizeof(buf) && !memcmp(buf, contents, sizeof(buf)));
    CHECK(load(CQ(&a, head)) == load(CQ(&a, tail)) && load(CQ(&b, head)) == load(CQ(&b, tail)));
    destroy(&a);
    destroy(&b);
    CHECK(close(fd) == 0);
    worker_ack("finished\n");
    puts("WORKER_CPU_PASS");
}

/* With eight CPUs the shared pool permits 16 workers and eight jobs per ring.
 * Keep each pipe empty until a specific permit should become available. */
static void worker_limits(void)
{
    enum { per_ring = 8, selected_count = per_ring + 3, pipe_count = selected_count + per_ring };
    unsigned flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
    struct ring a = setup(flags, 1, 7), b = setup(0, 0, 0), c = setup(flags, 1, 6);
    struct ring other = setup(0, 0, 0);
    int pipes[pipe_count][2], fd = known_file();
    char bytes[pipe_count] = {}, positions[3] = {}, dropped[3] = {}, probe = 0, reused = 0;
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    puts("WORKER_LIMITS_BEGIN");
    for (unsigned i = 0; i < pipe_count; i++) {
        struct ring *r = i < selected_count ? &a : &b;
        CHECK(pipe(pipes[i]) == 0);
        while (load(SQ(r, tail)) - load(SQ(r, head)) == r->p.sq_entries)
            sched_yield();
        worker_submit(r, worker_read(pipes[i][0], bytes + i, 1, 5001 + i));
    }
    worker_ack("full\n");

    /* B is at its quota. Later work on A must not take the same file's
     * serial key while waiting for either of B's earlier position tickets. */
    for (unsigned i = 0; i < 3; i++) {
        struct io_uring_sqe read = worker_read(fd, positions + i, 1, 5100 + i);
        read.off = UINT64_MAX;
        worker_submit(i == 2 ? &a : &b, read);
        if (i == 0) {
            /* Cancel a middle ticket, then close with two tickets between B's reads. */
            for (unsigned j = 0; j < 3; j++) {
                struct io_uring_sqe queued = worker_read(fd, dropped + j, 1, 5201 + j);
                queued.off = UINT64_MAX;
                worker_submit(&other, queued);
            }
        }
    }
    worker_submit(&other, (struct io_uring_sqe){ .opcode = IORING_OP_ASYNC_CANCEL,
        .fd = -1, .addr = 5202, .user_data = 5204 });
    CHECK(worker_result(&other, 5202) == -ECANCELED && worker_result(&other, 5204) == 0);
    worker_submit(&c, worker_read(fd, &probe, 1, 6001));
    worker_submit(&c, (struct io_uring_sqe){ .opcode = IORING_OP_NOP, .user_data = 6002 });
    CHECK(worker_result(&c, 6002) == 0);
    worker_submit(&other, worker_read(fd, &reused, 1, 5205));
    puts("WORKER_LIMITS_RELEASE");
    for (unsigned i = 0; i < selected_count; i++) {
        CHECK(write(pipes[i][1], "a", 1) == 1 && worker_result(&a, 5001 + i) == 1);
        if (i == 2) {
            CHECK(worker_result(&c, 6001) == 1 && probe == contents[0]);
            CHECK(worker_result(&other, 5205) == 1 && reused == contents[0]);
            destroy(&other);
        }
    }
    CHECK(load(CQ(&a, head)) == load(CQ(&a, tail)));

    /* Releasing one B permit lets it consume both consecutive tickets.
     * A must then finish without any further pipe wakeup. */
    CHECK(write(pipes[selected_count][1], "a", 1) == 1);
    CHECK(worker_result(&b, 5001 + selected_count) == 1);
    CHECK(worker_result(&b, 5100) == 1 && worker_result(&b, 5101) == 1);
    CHECK(worker_result(&a, 5102) == 1);
    CHECK(!memcmp(positions, contents, sizeof(positions)) && lseek(fd, 0, SEEK_CUR) == 3);
    CHECK(!dropped[0] && !dropped[1] && !dropped[2]);
    for (unsigned i = selected_count + 1; i < pipe_count; i++)
        CHECK(write(pipes[i][1], "a", 1) == 1 && worker_result(&b, 5001 + i) == 1);
    for (unsigned i = 0; i < pipe_count; i++)
        CHECK(bytes[i] == 'a' && close(pipes[i][0]) == 0 && close(pipes[i][1]) == 0);
    destroy(&a);
    destroy(&b);
    destroy(&c);
    CHECK(close(fd) == 0);
    puts("WORKER_LIMITS_PASS");
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
    if (argc == 2 && strcmp(argv[1], "--dedicated-ring") == 0) {
        dedicated_ring();
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--reserved-workers") == 0) {
        reserved_workers();
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--reserved-cpu") == 0) {
        reserved_cpu();
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--reserved-futures") == 0) {
        reserved_futures();
        puts("FUTURE_CPU_NATIVE_IO_BEGIN");
        struct ring r = setup(IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF, 1, 7);
        reserved_recv_and_timeout(&r);
        reserved_file_position(&r);
        destroy(&r);
        puts("FUTURE_CPU socket recv, timeout and shared offset write/read PASS");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--worker-limits") == 0) {
        worker_limits();
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
