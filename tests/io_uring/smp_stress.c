#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif
#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif

#define PULSE_IORING_OFF_SQ_RING 0ULL
#define PULSE_IORING_OFF_CQ_RING 0x8000000ULL
#define PULSE_IORING_OFF_SQES 0x10000000ULL

#define PULSE_IORING_FEAT_SINGLE_MMAP (1U << 0)

#define PULSE_IORING_ENTER_GETEVENTS (1U << 0)
#define PULSE_IORING_ENTER_EXT_ARG (1U << 3)

#define PULSE_IORING_REGISTER_BUFFERS 0U
#define PULSE_IORING_UNREGISTER_BUFFERS 1U
#define PULSE_IORING_REGISTER_FILES 2U
#define PULSE_IORING_UNREGISTER_FILES 3U

#define PULSE_IORING_OP_NOP 0
#define PULSE_IORING_OP_READ_FIXED 4
#define PULSE_IORING_OP_POLL_ADD 6
#define PULSE_IORING_OP_TIMEOUT 11
#define PULSE_IORING_OP_ASYNC_CANCEL 14
#define PULSE_IORING_OP_READ 22
#define PULSE_IORING_OP_WRITE 23

#define PULSE_IOSQE_FIXED_FILE (1U << 0)

struct pulse_sqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t flags;
    uint32_t dropped;
    uint32_t array;
    uint32_t resv1;
    uint64_t user_addr;
};

struct pulse_cqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t overflow;
    uint32_t cqes;
    uint32_t flags;
    uint32_t resv1;
    uint64_t user_addr;
};

struct pulse_uring_params {
    uint32_t sq_entries;
    uint32_t cq_entries;
    uint32_t flags;
    uint32_t sq_thread_cpu;
    uint32_t sq_thread_idle;
    uint32_t features;
    uint32_t wq_fd;
    uint32_t resv[3];
    struct pulse_sqring_offsets sq_off;
    struct pulse_cqring_offsets cq_off;
};

struct pulse_uring_sqe {
    uint8_t opcode;
    uint8_t flags;
    uint16_t ioprio;
    int32_t fd;
    union {
        uint64_t off;
        uint64_t addr2;
    };
    union {
        uint64_t addr;
        uint64_t splice_off_in;
    };
    uint32_t len;
    union {
        uint32_t rw_flags;
        uint32_t fsync_flags;
        uint16_t poll_events;
        uint32_t poll32_events;
        uint32_t sync_range_flags;
        uint32_t msg_flags;
        uint32_t timeout_flags;
        uint32_t accept_flags;
        uint32_t cancel_flags;
        uint32_t open_flags;
        uint32_t statx_flags;
        uint32_t fadvise_advice;
        uint32_t splice_flags;
    };
    uint64_t user_data;
    union {
        uint16_t buf_index;
        uint16_t buf_group;
    } __attribute__((packed));
    uint16_t personality;
    union {
        int32_t splice_fd_in;
        uint32_t file_index;
    };
    uint64_t addr3;
    uint64_t __pad2[1];
};

struct pulse_uring_cqe {
    uint64_t user_data;
    int32_t res;
    uint32_t flags;
};

struct pulse_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

struct pulse_getevents_arg {
    uint64_t sigmask;
    uint32_t sigmask_sz;
    uint32_t pad;
    uint64_t ts;
};

_Static_assert(sizeof(struct pulse_uring_params) == 120, "io_uring_params size");
_Static_assert(sizeof(struct pulse_uring_sqe) == 64, "io_uring_sqe size");
_Static_assert(sizeof(struct pulse_uring_cqe) == 16, "io_uring_cqe size");
_Static_assert(sizeof(struct pulse_getevents_arg) == 24, "getevents_arg size");

struct raw_ring {
    int fd;
    void *sq_ptr;
    size_t sq_sz;
    void *cq_ptr;
    size_t cq_sz;
    struct pulse_uring_sqe *sqes;
    size_t sqes_sz;
    _Atomic uint32_t *sq_head;
    _Atomic uint32_t *sq_tail;
    uint32_t *sq_array;
    uint32_t sq_mask;
    _Atomic uint32_t *cq_head;
    _Atomic uint32_t *cq_tail;
    struct pulse_uring_cqe *cqes;
    uint32_t cq_mask;
};

static int sys_io_uring_setup(uint32_t entries, struct pulse_uring_params *p)
{
    return (int)syscall(__NR_io_uring_setup, entries, p);
}

static int sys_io_uring_enter(int fd, uint32_t to_submit, uint32_t min_complete,
                              uint32_t flags, const void *arg, size_t argsz)
{
    return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, arg, argsz);
}

static int sys_io_uring_register(int fd, unsigned int opcode, const void *arg, unsigned int nr_args)
{
    return (int)syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

static int ring_init(struct raw_ring *r, uint32_t entries)
{
    struct pulse_uring_params p;
    memset(r, 0, sizeof(*r));
    memset(&p, 0, sizeof(p));

    r->fd = sys_io_uring_setup(entries, &p);
    if (r->fd < 0)
        return -errno;

    r->sq_sz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    r->cq_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct pulse_uring_cqe);
    if (p.features & PULSE_IORING_FEAT_SINGLE_MMAP) {
        if (r->cq_sz > r->sq_sz)
            r->sq_sz = r->cq_sz;
        r->cq_sz = r->sq_sz;
    }

    r->sq_ptr = mmap(NULL, r->sq_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                     r->fd, PULSE_IORING_OFF_SQ_RING);
    if (r->sq_ptr == MAP_FAILED) {
        int err = -errno;
        close(r->fd);
        return err;
    }

    if (p.features & PULSE_IORING_FEAT_SINGLE_MMAP) {
        r->cq_ptr = r->sq_ptr;
    } else {
        r->cq_ptr = mmap(NULL, r->cq_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                         r->fd, PULSE_IORING_OFF_CQ_RING);
        if (r->cq_ptr == MAP_FAILED) {
            int err = -errno;
            munmap(r->sq_ptr, r->sq_sz);
            close(r->fd);
            return err;
        }
    }

    r->sqes_sz = (size_t)p.sq_entries * sizeof(struct pulse_uring_sqe);
    r->sqes = mmap(NULL, r->sqes_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                   r->fd, PULSE_IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) {
        int err = -errno;
        if (r->cq_ptr != r->sq_ptr)
            munmap(r->cq_ptr, r->cq_sz);
        munmap(r->sq_ptr, r->sq_sz);
        close(r->fd);
        return err;
    }

    r->sq_head = (_Atomic uint32_t *)((char *)r->sq_ptr + p.sq_off.head);
    r->sq_tail = (_Atomic uint32_t *)((char *)r->sq_ptr + p.sq_off.tail);
    r->sq_array = (uint32_t *)((char *)r->sq_ptr + p.sq_off.array);
    r->sq_mask = *(uint32_t *)((char *)r->sq_ptr + p.sq_off.ring_mask);

    r->cq_head = (_Atomic uint32_t *)((char *)r->cq_ptr + p.cq_off.head);
    r->cq_tail = (_Atomic uint32_t *)((char *)r->cq_ptr + p.cq_off.tail);
    r->cqes = (struct pulse_uring_cqe *)((char *)r->cq_ptr + p.cq_off.cqes);
    r->cq_mask = *(uint32_t *)((char *)r->cq_ptr + p.cq_off.ring_mask);
    return 0;
}

static void ring_destroy(struct raw_ring *r, int close_fd)
{
    if (r->sqes && r->sqes != MAP_FAILED)
        munmap(r->sqes, r->sqes_sz);
    if (r->cq_ptr && r->cq_ptr != MAP_FAILED && r->cq_ptr != r->sq_ptr)
        munmap(r->cq_ptr, r->cq_sz);
    if (r->sq_ptr && r->sq_ptr != MAP_FAILED)
        munmap(r->sq_ptr, r->sq_sz);
    if (close_fd && r->fd >= 0)
        close(r->fd);
}

static void push_sqe_locked(struct raw_ring *r, const struct pulse_uring_sqe *sqe)
{
    uint32_t tail = atomic_load_explicit(r->sq_tail, memory_order_relaxed);
    uint32_t idx = tail & r->sq_mask;
    r->sqes[idx] = *sqe;
    r->sq_array[idx] = idx;
    atomic_store_explicit(r->sq_tail, tail + 1, memory_order_release);
}

#define MT_THREADS 4
#define MT_ROUNDS 100
#define MT_OPS_PER_ROUND 5
#define MT_TOTAL_OPS (MT_THREADS * MT_ROUNDS * MT_OPS_PER_ROUND)

struct mt_ctx {
    struct raw_ring *ring;
    pthread_mutex_t sq_lock;
    pthread_mutex_t cq_lock;
    pthread_mutex_t start_lock;
    pthread_cond_t start_cond;
    int start_state; /* 0 = wait, 1 = go, -1 = abort */
    uint8_t seen[MT_TOTAL_OPS];
    _Atomic uint32_t total_reaped;
    _Atomic int error;
};

struct mt_worker_arg {
    struct mt_ctx *ctx;
    int tid;
};

static void record_cqe(struct mt_ctx *ctx, const struct pulse_uring_cqe *cqe)
{
    uint64_t ud = cqe->user_data;
    if (ud >= MT_TOTAL_OPS) {
        fprintf(stderr, "mt: unexpected user_data=%llu\n", (unsigned long long)ud);
        atomic_store_explicit(&ctx->error, 1, memory_order_release);
        return;
    }
    if (ctx->seen[ud] != 0) {
        fprintf(stderr, "mt: duplicate CQE user_data=%llu\n", (unsigned long long)ud);
        atomic_store_explicit(&ctx->error, 1, memory_order_release);
        return;
    }
    uint64_t kind = ud % MT_OPS_PER_ROUND;
    if (kind == 0 && cqe->res != 0) {
        fprintf(stderr, "mt: NOP bad res=%d\n", cqe->res);
        atomic_store_explicit(&ctx->error, 1, memory_order_release);
    } else if ((kind == 1 || kind == 2) && cqe->res != 4) {
        fprintf(stderr, "mt: pipe rw bad res=%d\n", cqe->res);
        atomic_store_explicit(&ctx->error, 1, memory_order_release);
    } else if (kind == 3 && cqe->res != -ECANCELED && cqe->res != -ETIME) {
        fprintf(stderr, "mt: cancelled timeout bad res=%d\n", cqe->res);
        atomic_store_explicit(&ctx->error, 1, memory_order_release);
    } else if (kind == 4 && cqe->res != 0 && cqe->res != -ENOENT && cqe->res != -EALREADY) {
        fprintf(stderr, "mt: cancel op bad res=%d\n", cqe->res);
        atomic_store_explicit(&ctx->error, 1, memory_order_release);
    }
    ctx->seen[ud] = 1;
    atomic_fetch_add_explicit(&ctx->total_reaped, 1, memory_order_release);
}

static void drain_cqes(struct mt_ctx *ctx)
{
    pthread_mutex_lock(&ctx->cq_lock);
    uint32_t head = atomic_load_explicit(ctx->ring->cq_head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(ctx->ring->cq_tail, memory_order_acquire);
    while (head != tail) {
        record_cqe(ctx, &ctx->ring->cqes[head & ctx->ring->cq_mask]);
        head++;
    }
    atomic_store_explicit(ctx->ring->cq_head, head, memory_order_release);
    pthread_mutex_unlock(&ctx->cq_lock);
}

static int wait_sq_space(struct mt_ctx *ctx, uint32_t needed)
{
    for (int tries = 0; tries < 10000; tries++) {
        uint32_t head = atomic_load_explicit(ctx->ring->sq_head, memory_order_acquire);
        uint32_t tail = atomic_load_explicit(ctx->ring->sq_tail, memory_order_relaxed);
        uint32_t used = tail - head;
        if (used + needed <= ctx->ring->sq_mask + 1)
            return 0;
        pthread_mutex_unlock(&ctx->sq_lock);
        sched_yield();
        pthread_mutex_lock(&ctx->sq_lock);
    }
    return -1;
}

static void *mt_worker(void *argp)
{
    struct mt_worker_arg *arg = (struct mt_worker_arg *)argp;
    struct mt_ctx *ctx = arg->ctx;
    int pfd[2];
    if (pipe(pfd) != 0) {
        atomic_store_explicit(&ctx->error, 1, memory_order_release);
        return NULL;
    }

    pthread_mutex_lock(&ctx->start_lock);
    while (ctx->start_state == 0)
        pthread_cond_wait(&ctx->start_cond, &ctx->start_lock);
    int go = ctx->start_state;
    pthread_mutex_unlock(&ctx->start_lock);
    if (go < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return NULL;
    }

    struct pulse_timespec long_ts = { .tv_sec = 5, .tv_nsec = 0 };
    for (int r = 0; r < MT_ROUNDS; r++) {
        uint64_t base = ((uint64_t)arg->tid * MT_ROUNDS + (uint64_t)r) * MT_OPS_PER_ROUND;
        uint32_t wbuf = (uint32_t)(base + 1);
        uint32_t rbuf = 0;

        /* Submit NOP + pipe write + pipe read + long timeout together. */
        pthread_mutex_lock(&ctx->sq_lock);
        if (wait_sq_space(ctx, 4) != 0) {
            pthread_mutex_unlock(&ctx->sq_lock);
            atomic_store_explicit(&ctx->error, 1, memory_order_release);
            break;
        }
        struct pulse_uring_sqe sqe;

        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = PULSE_IORING_OP_NOP;
        sqe.user_data = base + 0;
        push_sqe_locked(ctx->ring, &sqe);

        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = PULSE_IORING_OP_WRITE;
        sqe.fd = pfd[1];
        sqe.addr = (uint64_t)(uintptr_t)&wbuf;
        sqe.len = sizeof(wbuf);
        sqe.off = (uint64_t)-1ULL;
        sqe.user_data = base + 1;
        push_sqe_locked(ctx->ring, &sqe);

        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = PULSE_IORING_OP_READ;
        sqe.fd = pfd[0];
        sqe.addr = (uint64_t)(uintptr_t)&rbuf;
        sqe.len = sizeof(rbuf);
        sqe.off = (uint64_t)-1ULL;
        sqe.user_data = base + 2;
        push_sqe_locked(ctx->ring, &sqe);

        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = PULSE_IORING_OP_TIMEOUT;
        sqe.fd = -1;
        sqe.addr = (uint64_t)(uintptr_t)&long_ts;
        sqe.len = 1;
        sqe.user_data = base + 3;
        push_sqe_locked(ctx->ring, &sqe);
        pthread_mutex_unlock(&ctx->sq_lock);

        int ret = sys_io_uring_enter(ctx->ring->fd, 4, 0, 0, NULL, 0);
        if (ret < 0) {
            fprintf(stderr, "mt: enter batch1 err=%d\n", errno);
            atomic_store_explicit(&ctx->error, 1, memory_order_release);
            break;
        }

        /* Now submit ASYNC_CANCEL targeting the 5s timeout. */
        pthread_mutex_lock(&ctx->sq_lock);
        if (wait_sq_space(ctx, 1) != 0) {
            pthread_mutex_unlock(&ctx->sq_lock);
            atomic_store_explicit(&ctx->error, 1, memory_order_release);
            break;
        }
        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = PULSE_IORING_OP_ASYNC_CANCEL;
        sqe.fd = -1;
        sqe.addr = base + 3;
        sqe.user_data = base + 4;
        push_sqe_locked(ctx->ring, &sqe);
        pthread_mutex_unlock(&ctx->sq_lock);

        ret = sys_io_uring_enter(ctx->ring->fd, 1, 0, 0, NULL, 0);
        if (ret < 0) {
            fprintf(stderr, "mt: enter cancel err=%d\n", errno);
            atomic_store_explicit(&ctx->error, 1, memory_order_release);
            break;
        }

        drain_cqes(ctx);
        /* Wait until pipe read completes so stack buffer `rbuf` stays alive. */
        while (atomic_load_explicit(&ctx->total_reaped, memory_order_acquire) < MT_TOTAL_OPS) {
            pthread_mutex_lock(&ctx->cq_lock);
            int done = ctx->seen[base + 1] && ctx->seen[base + 2];
            pthread_mutex_unlock(&ctx->cq_lock);
            if (done)
                break;
            int wrc = sys_io_uring_enter(ctx->ring->fd, 0, 1, PULSE_IORING_ENTER_GETEVENTS, NULL, 0);
            if (wrc < 0 && errno != EINTR) {
                fprintf(stderr, "mt: wait pipe err=%d\n", errno);
                atomic_store_explicit(&ctx->error, 1, memory_order_release);
                break;
            }
            drain_cqes(ctx);
        }
    }

    close(pfd[0]);
    close(pfd[1]);
    return NULL;
}

static int test_mt_shared_ring_submit_cancel_reap(void)
{
    struct raw_ring r;
    if (ring_init(&r, 128) != 0) {
        fprintf(stderr, "mt: ring_init failed\n");
        return 1;
    }

    struct mt_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        ring_destroy(&r, 1);
        return 1;
    }
    ctx->ring = &r;
    pthread_mutex_init(&ctx->sq_lock, NULL);
    pthread_mutex_init(&ctx->cq_lock, NULL);
    pthread_mutex_init(&ctx->start_lock, NULL);
    pthread_cond_init(&ctx->start_cond, NULL);

    pthread_t threads[MT_THREADS];
    struct mt_worker_arg args[MT_THREADS];
    for (int i = 0; i < MT_THREADS; i++) {
        args[i].ctx = ctx;
        args[i].tid = i;
        if (pthread_create(&threads[i], NULL, mt_worker, &args[i]) != 0) {
            fprintf(stderr, "mt: pthread_create failed\n");
            pthread_mutex_lock(&ctx->start_lock);
            ctx->start_state = -1;
            pthread_cond_broadcast(&ctx->start_cond);
            pthread_mutex_unlock(&ctx->start_lock);
            for (int j = 0; j < i; j++)
                pthread_join(threads[j], NULL);
            pthread_cond_destroy(&ctx->start_cond);
            pthread_mutex_destroy(&ctx->start_lock);
            pthread_mutex_destroy(&ctx->sq_lock);
            pthread_mutex_destroy(&ctx->cq_lock);
            free(ctx);
            ring_destroy(&r, 1);
            return 1;
        }
    }
    pthread_mutex_lock(&ctx->start_lock);
    ctx->start_state = 1;
    pthread_cond_broadcast(&ctx->start_cond);
    pthread_mutex_unlock(&ctx->start_lock);
    for (int i = 0; i < MT_THREADS; i++)
        pthread_join(threads[i], NULL);

    while (atomic_load_explicit(&ctx->total_reaped, memory_order_acquire) < MT_TOTAL_OPS) {
        drain_cqes(ctx);
        if (atomic_load_explicit(&ctx->total_reaped, memory_order_acquire) >= MT_TOTAL_OPS)
            break;
        int rc = sys_io_uring_enter(r.fd, 0, 1, PULSE_IORING_ENTER_GETEVENTS, NULL, 0);
        if (rc < 0 && errno != EINTR) {
            fprintf(stderr, "mt: final wait err=%d\n", errno);
            atomic_store_explicit(&ctx->error, 1, memory_order_release);
            break;
        }
    }
    drain_cqes(ctx);

    int err_flag = atomic_load_explicit(&ctx->error, memory_order_acquire);
    int missing = 0;
    for (uint32_t i = 0; i < MT_TOTAL_OPS; i++) {
        if (ctx->seen[i] != 1)
            missing++;
    }
    int fail = err_flag || missing != 0 ||
               atomic_load_explicit(&ctx->total_reaped, memory_order_acquire) != MT_TOTAL_OPS;
    if (fail) {
        fprintf(stderr, "mt: FAIL error=%d missing=%d reaped=%u/%u\n",
                err_flag, missing,
                atomic_load_explicit(&ctx->total_reaped, memory_order_acquire),
                (unsigned)MT_TOTAL_OPS);
    } else {
        printf("SMP_STRESS CASE test_mt_shared_ring_submit_cancel_reap ops=%u PASS\n",
               (unsigned)MT_TOTAL_OPS);
    }

    pthread_cond_destroy(&ctx->start_cond);
    pthread_mutex_destroy(&ctx->start_lock);
    pthread_mutex_destroy(&ctx->sq_lock);
    pthread_mutex_destroy(&ctx->cq_lock);
    free(ctx);
    ring_destroy(&r, 1);
    return fail;
}

static int test_inflight_munmap_close_teardown(void)
{
    const size_t buf_len = 3 * 4096;
    for (int iter = 0; iter < 16; iter++) {
        int pfd[2];
        if (pipe(pfd) != 0)
            return 1;

        void *buf_reg = mmap(NULL, buf_len, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        void *buf_fixed = mmap(NULL, buf_len, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (buf_reg == MAP_FAILED || buf_fixed == MAP_FAILED)
            return 1;
        memset(buf_reg, 0x11, buf_len);
        memset(buf_fixed, 0x22, buf_len);

        struct raw_ring r;
        if (ring_init(&r, 16) != 0)
            return 1;

        struct iovec iov = { .iov_base = buf_fixed, .iov_len = buf_len };
        if (sys_io_uring_register(r.fd, PULSE_IORING_REGISTER_BUFFERS, &iov, 1) != 0) {
            fprintf(stderr, "munmap_close: register_buffers failed errno=%d\n", errno);
            return 1;
        }

        struct pulse_timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
        struct pulse_uring_sqe sqe;

        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = PULSE_IORING_OP_READ;
        sqe.fd = pfd[0];
        sqe.addr = (uint64_t)(uintptr_t)buf_reg;
        sqe.len = (uint32_t)buf_len;
        sqe.off = (uint64_t)-1ULL;
        sqe.user_data = 1;
        push_sqe_locked(&r, &sqe);

        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = PULSE_IORING_OP_READ_FIXED;
        sqe.fd = pfd[0];
        sqe.addr = (uint64_t)(uintptr_t)buf_fixed;
        sqe.len = (uint32_t)buf_len;
        sqe.off = (uint64_t)-1ULL;
        sqe.buf_index = 0;
        sqe.user_data = 2;
        push_sqe_locked(&r, &sqe);

        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = PULSE_IORING_OP_POLL_ADD;
        sqe.fd = pfd[0];
        sqe.poll32_events = POLLIN;
        sqe.user_data = 3;
        push_sqe_locked(&r, &sqe);

        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = PULSE_IORING_OP_TIMEOUT;
        sqe.fd = -1;
        sqe.addr = (uint64_t)(uintptr_t)&ts;
        sqe.len = 1;
        sqe.user_data = 4;
        push_sqe_locked(&r, &sqe);

        int sub = sys_io_uring_enter(r.fd, 4, 0, 0, NULL, 0);
        if (sub != 4) {
            fprintf(stderr, "munmap_close: submit=%d errno=%d\n", sub, errno);
            return 1;
        }

        /* Unmap user buffers AND close ring_fd while all 4 ops remain inflight. */
        if (munmap(buf_reg, buf_len) != 0 || munmap(buf_fixed, buf_len) != 0)
            return 1;
        int close_rc = close(r.fd);
        ring_destroy(&r, 0);
        close(pfd[0]);
        close(pfd[1]);
        if (close_rc != 0)
            return 1;
    }

    printf("SMP_STRESS CASE test_inflight_munmap_close_teardown iters=16 PASS\n");
    return 0;
}

static volatile sig_atomic_t g_usr1_count = 0;
static void usr1_handler(int sig)
{
    (void)sig;
    g_usr1_count++;
}

struct sig_sender_arg {
    pthread_t target;
};

static void *sig_sender(void *argp)
{
    struct sig_sender_arg *arg = (struct sig_sender_arg *)argp;
    struct timespec req = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000L };
    nanosleep(&req, NULL);
    pthread_kill(arg->target, SIGUSR1);
    return NULL;
}

static int test_signal_eintr_precedence(void)
{
    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = usr1_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* Explicitly NO SA_RESTART */
    if (sigaction(SIGUSR1, &sa, &old_sa) != 0)
        return 1;

    struct raw_ring r;
    if (ring_init(&r, 16) != 0)
        return 1;

    g_usr1_count = 0;
    struct pulse_timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
    struct pulse_uring_sqe sqe;
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = PULSE_IORING_OP_TIMEOUT;
    sqe.fd = -1;
    sqe.addr = (uint64_t)(uintptr_t)&ts;
    sqe.len = 1;
    sqe.user_data = 100;
    push_sqe_locked(&r, &sqe);
    if (sys_io_uring_enter(r.fd, 1, 0, 0, NULL, 0) != 1)
        return 1;

    /* Subcase A: min_complete=1 wait interrupted by SIGUSR1 -> -EINTR, never restarted. */
    pthread_t sender;
    struct sig_sender_arg sarg = { .target = pthread_self() };
    if (pthread_create(&sender, NULL, sig_sender, &sarg) != 0)
        return 1;
    int rc = sys_io_uring_enter(r.fd, 0, 1, PULSE_IORING_ENTER_GETEVENTS, NULL, 0);
    int saved_err = errno;
    pthread_join(sender, NULL);
    if (rc != -1 || saved_err != EINTR || g_usr1_count < 1) {
        fprintf(stderr, "eintr A failed: rc=%d errno=%d sigs=%d\n",
                rc, saved_err, (int)g_usr1_count);
        ring_destroy(&r, 1);
        sigaction(SIGUSR1, &old_sa, NULL);
        return 1;
    }

    /* Subcase B: submitted > 0 wins over -EINTR when EXT_ARG unblocks a pending SIGUSR1. */
    sigset_t block_set, empty_set, old_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGUSR1);
    sigemptyset(&empty_set);
    if (pthread_sigmask(SIG_BLOCK, &block_set, &old_set) != 0)
        return 1;
    pthread_kill(pthread_self(), SIGUSR1);

    for (uint64_t i = 0; i < 4; i++) {
        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = PULSE_IORING_OP_NOP;
        sqe.user_data = 200 + i;
        push_sqe_locked(&r, &sqe);
    }
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = PULSE_IORING_OP_TIMEOUT;
    sqe.fd = -1;
    sqe.addr = (uint64_t)(uintptr_t)&ts;
    sqe.len = 1;
    sqe.user_data = 204;
    push_sqe_locked(&r, &sqe);

    struct pulse_getevents_arg ext = {
        .sigmask = (uint64_t)(uintptr_t)&empty_set,
        .sigmask_sz = 8,
        .pad = 0,
        .ts = 0,
    };
    int before_sigs = (int)g_usr1_count;
    rc = sys_io_uring_enter(r.fd, 5, 5,
                            PULSE_IORING_ENTER_GETEVENTS | PULSE_IORING_ENTER_EXT_ARG,
                            &ext, sizeof(ext));
    saved_err = errno;
    pthread_sigmask(SIG_SETMASK, &old_set, NULL);
    if (rc != 5 || (int)g_usr1_count != before_sigs + 1) {
        fprintf(stderr, "eintr B failed: rc=%d errno=%d before=%d after=%d\n",
                rc, saved_err, before_sigs, (int)g_usr1_count);
        ring_destroy(&r, 1);
        sigaction(SIGUSR1, &old_sa, NULL);
        return 1;
    }

    uint32_t head = atomic_load_explicit(r.cq_head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(r.cq_tail, memory_order_acquire);
    int nops = 0;
    while (head != tail) {
        struct pulse_uring_cqe *c = &r.cqes[head & r.cq_mask];
        if (c->user_data >= 200 && c->user_data < 204 && c->res == 0)
            nops++;
        head++;
    }
    atomic_store_explicit(r.cq_head, head, memory_order_release);
    if (nops != 4) {
        fprintf(stderr, "eintr B missing NOP CQEs: %d\n", nops);
        ring_destroy(&r, 1);
        sigaction(SIGUSR1, &old_sa, NULL);
        return 1;
    }

    ring_destroy(&r, 1);
    sigaction(SIGUSR1, &old_sa, NULL);
    printf("SMP_STRESS CASE test_signal_eintr_precedence PASS\n");
    return 0;
}

static int test_abnormal_exit_teardown(void)
{
    const size_t buf_len = 3 * 4096;
    for (int iter = 0; iter < 16; iter++) {
        int do_kill = (iter % 2) == 0;
        int sync_pipe[2], io_pipe[2];
        if (pipe(sync_pipe) != 0 || pipe(io_pipe) != 0)
            return 1;

        pid_t pid = fork();
        if (pid < 0)
            return 1;
        if (pid == 0) {
            close(sync_pipe[0]);
            struct raw_ring r;
            if (ring_init(&r, 16) != 0)
                _exit(10);

            void *buf = mmap(NULL, buf_len, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (buf == MAP_FAILED)
                _exit(11);
            memset(buf, 0x55, buf_len);

            struct iovec iov = { .iov_base = buf, .iov_len = buf_len };
            if (sys_io_uring_register(r.fd, PULSE_IORING_REGISTER_BUFFERS, &iov, 1) != 0)
                _exit(12);
            if (sys_io_uring_register(r.fd, PULSE_IORING_REGISTER_FILES, &io_pipe[0], 1) != 0)
                _exit(13);

            struct pulse_timespec ts = { .tv_sec = 5, .tv_nsec = 0 };
            struct pulse_uring_sqe sqe;

            memset(&sqe, 0, sizeof(sqe));
            sqe.opcode = PULSE_IORING_OP_READ_FIXED;
            sqe.flags = PULSE_IOSQE_FIXED_FILE;
            sqe.fd = 0;
            sqe.addr = (uint64_t)(uintptr_t)buf;
            sqe.len = (uint32_t)buf_len;
            sqe.off = (uint64_t)-1ULL;
            sqe.buf_index = 0;
            sqe.user_data = 1;
            push_sqe_locked(&r, &sqe);

            memset(&sqe, 0, sizeof(sqe));
            sqe.opcode = PULSE_IORING_OP_POLL_ADD;
            sqe.fd = io_pipe[0];
            sqe.poll32_events = POLLIN;
            sqe.user_data = 2;
            push_sqe_locked(&r, &sqe);

            memset(&sqe, 0, sizeof(sqe));
            sqe.opcode = PULSE_IORING_OP_TIMEOUT;
            sqe.fd = -1;
            sqe.addr = (uint64_t)(uintptr_t)&ts;
            sqe.len = 1;
            sqe.user_data = 3;
            push_sqe_locked(&r, &sqe);

            if (sys_io_uring_enter(r.fd, 3, 0, 0, NULL, 0) != 3)
                _exit(14);

            char ch = 'R';
            if (write(sync_pipe[1], &ch, 1) != 1)
                _exit(15);

            if (do_kill) {
                for (;;)
                    pause();
            }
            /* Exit without unmapping or closing ring_fd / io_pipe. */
            _exit(42);
        }

        close(sync_pipe[1]);
        char ch = 0;
        if (read(sync_pipe[0], &ch, 1) != 1 || ch != 'R') {
            fprintf(stderr, "abnormal_exit: child handshake failed iter=%d\n", iter);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            return 1;
        }
        if (do_kill)
            kill(pid, SIGKILL);

        int status = 0;
        if (waitpid(pid, &status, 0) != pid)
            return 1;
        if (do_kill) {
            if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
                fprintf(stderr, "abnormal_exit: expected SIGKILL status=0x%x\n", status);
                return 1;
            }
        } else {
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 42) {
                fprintf(stderr, "abnormal_exit: expected exit 42 status=0x%x\n", status);
                return 1;
            }
        }
        close(sync_pipe[0]);
        close(io_pipe[0]);
        close(io_pipe[1]);
    }

    printf("SMP_STRESS CASE test_abnormal_exit_teardown iters=16 PASS\n");
    return 0;
}

int main(void)
{
    int rc = 0;
    rc |= test_mt_shared_ring_submit_cancel_reap();
    rc |= test_inflight_munmap_close_teardown();
    rc |= test_signal_eintr_precedence();
    rc |= test_abnormal_exit_teardown();
    if (rc == 0) {
        printf("SMP_STRESS_RESULT PASS\n");
    } else {
        printf("SMP_STRESS_RESULT FAIL\n");
    }
    return rc ? 1 : 0;
}
