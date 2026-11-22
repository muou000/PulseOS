#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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
#define PULSE_IORING_REGISTER_BUFFERS 0U
#define PULSE_IORING_REGISTER_FILES 2U
#define PULSE_IORING_OP_READ_FIXED 4
#define PULSE_IORING_OP_READ 22
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
    uint64_t off;
    uint64_t addr;
    uint32_t len;
    uint32_t rw_flags;
    uint64_t user_data;
    uint16_t buf_index;
    uint16_t personality;
    uint32_t file_index;
    uint64_t addr3;
    uint64_t __pad2[1];
};

struct pulse_uring_cqe {
    uint64_t user_data;
    int32_t res;
    uint32_t flags;
};

_Static_assert(sizeof(struct pulse_uring_params) == 120, "io_uring_params size");
_Static_assert(sizeof(struct pulse_uring_sqe) == 64, "io_uring_sqe size");
_Static_assert(sizeof(struct pulse_uring_cqe) == 16, "io_uring_cqe size");

struct raw_ring {
    int fd;
    void *sq_ptr;
    size_t sq_sz;
    void *cq_ptr;
    size_t cq_sz;
    struct pulse_uring_sqe *sqes;
    size_t sqes_sz;
    _Atomic uint32_t *sq_tail;
    uint32_t *sq_array;
    uint32_t sq_mask;
    _Atomic uint32_t *cq_head;
    _Atomic uint32_t *cq_tail;
    struct pulse_uring_cqe *cqes;
    uint32_t cq_mask;
};

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void ring_destroy(struct raw_ring *r);

static int ring_init(struct raw_ring *r, uint32_t entries)
{
    struct pulse_uring_params p;
    memset(r, 0, sizeof(*r));
    r->fd = -1;
    memset(&p, 0, sizeof(p));
    r->fd = (int)syscall(__NR_io_uring_setup, entries, &p);
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
        int err = errno;
        ring_destroy(r);
        return -err;
    }
    r->cq_ptr = (p.features & PULSE_IORING_FEAT_SINGLE_MMAP)
                    ? r->sq_ptr
                    : mmap(NULL, r->cq_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                           r->fd, PULSE_IORING_OFF_CQ_RING);
    if (r->cq_ptr == MAP_FAILED) {
        int err = errno;
        ring_destroy(r);
        return -err;
    }

    r->sqes_sz = (size_t)p.sq_entries * sizeof(struct pulse_uring_sqe);
    r->sqes = mmap(NULL, r->sqes_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                   r->fd, PULSE_IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) {
        int err = errno;
        ring_destroy(r);
        return -err;
    }

    r->sq_tail = (_Atomic uint32_t *)((char *)r->sq_ptr + p.sq_off.tail);
    r->sq_array = (uint32_t *)((char *)r->sq_ptr + p.sq_off.array);
    r->sq_mask = *(uint32_t *)((char *)r->sq_ptr + p.sq_off.ring_mask);
    r->cq_head = (_Atomic uint32_t *)((char *)r->cq_ptr + p.cq_off.head);
    r->cq_tail = (_Atomic uint32_t *)((char *)r->cq_ptr + p.cq_off.tail);
    r->cqes = (struct pulse_uring_cqe *)((char *)r->cq_ptr + p.cq_off.cqes);
    r->cq_mask = *(uint32_t *)((char *)r->cq_ptr + p.cq_off.ring_mask);
    return 0;
}

static void ring_destroy(struct raw_ring *r)
{
    if (r->sqes && r->sqes != MAP_FAILED)
        munmap(r->sqes, r->sqes_sz);
    if (r->cq_ptr && r->cq_ptr != MAP_FAILED && r->cq_ptr != r->sq_ptr)
        munmap(r->cq_ptr, r->cq_sz);
    if (r->sq_ptr && r->sq_ptr != MAP_FAILED)
        munmap(r->sq_ptr, r->sq_sz);
    if (r->fd >= 0)
        close(r->fd);
}

static uint32_t lcg_next(uint32_t *state)
{
    *state = (*state * 1664525U) + 1013904223U;
    return *state;
}

static int run_psync_bench(const char *label, const char *path, int direct, int random_io,
                           uint64_t total_blocks, size_t bs, uint64_t *out_syscalls)
{
    int flags = O_RDONLY | (direct ? O_DIRECT : 0);
    int fd = open(path, flags);
    if (fd < 0) {
        perror("open psync");
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)bs) {
        fprintf(stderr, "%s: invalid file size for %s\n", label, path);
        close(fd);
        return 1;
    }
    uint64_t file_blocks = (uint64_t)st.st_size / (uint64_t)bs;
    void *buf = NULL;
    if (posix_memalign(&buf, 4096, bs) != 0) {
        close(fd);
        return 1;
    }

    uint32_t rng = 0x12345678U;
    uint64_t syscalls = 0;
    uint64_t t0 = now_ns();
    for (uint64_t i = 0; i < total_blocks; i++) {
        uint64_t blk = random_io ? (lcg_next(&rng) % file_blocks) : (i % file_blocks);
        off_t off = (off_t)(blk * bs);
        ssize_t n = pread(fd, buf, bs, off);
        syscalls++;
        if (n != (ssize_t)bs) {
            fprintf(stderr, "%s: pread short/err n=%zd errno=%d\n", label, n, errno);
            free(buf);
            close(fd);
            return 1;
        }
    }
    uint64_t t1 = now_ns();
    double ms = (double)(t1 - t0) / 1e6;
    double mib_s = ((double)total_blocks * (double)bs / (1024.0 * 1024.0)) / ((double)(t1 - t0) / 1e9);
    printf("SYSCALL_BENCH case=%s ios=%llu syscalls=%llu io_per_syscall=%.2f wall_ms=%.3f bw_mib_s=%.2f\n",
           label, (unsigned long long)total_blocks, (unsigned long long)syscalls,
           (double)total_blocks / (double)syscalls, ms, mib_s);
    *out_syscalls = syscalls;
    free(buf);
    close(fd);
    return 0;
}

static int run_uring_bench(const char *label, const char *path, int direct, int random_io,
                           uint32_t depth, int use_fixed, uint64_t total_blocks, size_t bs,
                           uint64_t *out_syscalls)
{
    int flags = O_RDONLY | (direct ? O_DIRECT : 0);
    int fd = open(path, flags);
    if (fd < 0) {
        perror("open uring");
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)bs) {
        fprintf(stderr, "%s: invalid file size for %s\n", label, path);
        close(fd);
        return 1;
    }
    uint64_t file_blocks = (uint64_t)st.st_size / (uint64_t)bs;

    struct raw_ring r;
    if (ring_init(&r, depth < 8 ? 8 : depth * 2) != 0) {
        close(fd);
        return 1;
    }

    size_t pool_bytes = (size_t)depth * bs;
    void *pool = NULL;
    if (posix_memalign(&pool, 4096, pool_bytes) != 0) {
        ring_destroy(&r);
        close(fd);
        return 1;
    }
    memset(pool, 0, pool_bytes);

    if (use_fixed) {
        struct iovec *iovs = calloc(depth, sizeof(*iovs));
        for (uint32_t i = 0; i < depth; i++) {
            iovs[i].iov_base = (char *)pool + (size_t)i * bs;
            iovs[i].iov_len = bs;
        }
        int reg_b = (int)syscall(__NR_io_uring_register, r.fd, PULSE_IORING_REGISTER_BUFFERS, iovs, depth);
        free(iovs);
        if (reg_b != 0) {
            fprintf(stderr, "%s: register buffers err=%d\n", label, errno);
            free(pool);
            ring_destroy(&r);
            close(fd);
            return 1;
        }
        if (syscall(__NR_io_uring_register, r.fd, PULSE_IORING_REGISTER_FILES, &fd, 1) != 0) {
            fprintf(stderr, "%s: register files err=%d\n", label, errno);
            free(pool);
            ring_destroy(&r);
            close(fd);
            return 1;
        }
    }

    uint32_t rng = 0x12345678U;
    uint64_t submitted = 0, completed = 0, syscalls = 0;
    uint32_t inflight = 0;
    uint32_t free_slots[64];
    if (depth == 0 || depth > 64) {
        fprintf(stderr, "%s: invalid depth=%u\n", label, depth);
        free(pool);
        ring_destroy(&r);
        close(fd);
        return 1;
    }
    for (uint32_t i = 0; i < depth; i++)
        free_slots[i] = i;
    uint32_t free_top = depth;

    uint64_t t0 = now_ns();
    while (completed < total_blocks) {
        uint32_t to_submit = 0;
        uint32_t tail = atomic_load_explicit(r.sq_tail, memory_order_relaxed);
        while (inflight < depth && submitted < total_blocks && free_top > 0) {
            uint32_t slot = free_slots[--free_top];
            uint64_t blk = random_io ? (lcg_next(&rng) % file_blocks) : (submitted % file_blocks);
            uint32_t idx = tail & r.sq_mask;
            struct pulse_uring_sqe *sqe = &r.sqes[idx];
            memset(sqe, 0, sizeof(*sqe));
            sqe->opcode = use_fixed ? PULSE_IORING_OP_READ_FIXED : PULSE_IORING_OP_READ;
            sqe->flags = use_fixed ? PULSE_IOSQE_FIXED_FILE : 0;
            sqe->fd = use_fixed ? 0 : fd;
            sqe->off = blk * (uint64_t)bs;
            sqe->addr = (uint64_t)(uintptr_t)((char *)pool + (size_t)slot * bs);
            sqe->len = (uint32_t)bs;
            sqe->buf_index = (uint16_t)slot;
            sqe->user_data = slot;
            r.sq_array[idx] = idx;
            tail++;
            submitted++;
            inflight++;
            to_submit++;
        }
        if (to_submit > 0)
            atomic_store_explicit(r.sq_tail, tail, memory_order_release);

        uint32_t min_wait = (to_submit == 0 || inflight >= depth || submitted == total_blocks) ? 1U : 0U;
        uint32_t enter_flags = min_wait ? PULSE_IORING_ENTER_GETEVENTS : 0U;
        int ret = (int)syscall(__NR_io_uring_enter, r.fd, to_submit, min_wait, enter_flags, NULL, 0);
        syscalls++;
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "%s: io_uring_enter err=%d\n", label, errno);
            free(pool);
            ring_destroy(&r);
            close(fd);
            return 1;
        }

        uint32_t head = atomic_load_explicit(r.cq_head, memory_order_relaxed);
        uint32_t cq_tail = atomic_load_explicit(r.cq_tail, memory_order_acquire);
        while (head != cq_tail) {
            struct pulse_uring_cqe *c = &r.cqes[head & r.cq_mask];
            if (c->res != (int32_t)bs) {
                fprintf(stderr, "%s: CQE short/err res=%d\n", label, c->res);
                free(pool);
                ring_destroy(&r);
                close(fd);
                return 1;
            }
            if (c->user_data >= depth || free_top >= depth) {
                fprintf(stderr, "%s: invalid CQE user_data=%llu (depth=%u free_top=%u)\n",
                        label, (unsigned long long)c->user_data, depth, free_top);
                free(pool);
                ring_destroy(&r);
                close(fd);
                return 1;
            }
            free_slots[free_top++] = (uint32_t)c->user_data;
            inflight--;
            completed++;
            head++;
        }
        atomic_store_explicit(r.cq_head, head, memory_order_release);
    }
    uint64_t t1 = now_ns();
    double ms = (double)(t1 - t0) / 1e6;
    double mib_s = ((double)total_blocks * (double)bs / (1024.0 * 1024.0)) / ((double)(t1 - t0) / 1e9);
    printf("SYSCALL_BENCH case=%s ios=%llu syscalls=%llu io_per_syscall=%.2f wall_ms=%.3f bw_mib_s=%.2f\n",
           label, (unsigned long long)total_blocks, (unsigned long long)syscalls,
           (double)total_blocks / (double)syscalls, ms, mib_s);
    *out_syscalls = syscalls;

    free(pool);
    ring_destroy(&r);
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    const char *direct_path = argc > 1 ? argv[1] : "/root/fio-uring-bench";
    const char *cached_path = argc > 2 ? argv[2] : direct_path;
    const size_t bs = 4096;
    const uint64_t total_blocks = 16384; /* 64 MiB = 16,384 x 4 KiB */

    uint64_t sc_psync_dir = 0, sc_qd1_dir = 0, sc_qd16_dir = 0;
    uint64_t sc_psync_cache = 0, sc_qd32_cache = 0;

    if (run_psync_bench("direct_psync_randread", direct_path, 1, 1, total_blocks, bs, &sc_psync_dir))
        return 1;
    if (run_uring_bench("direct_uring_qd1_randread", direct_path, 1, 1, 1, 0, total_blocks, bs, &sc_qd1_dir))
        return 1;
    if (run_uring_bench("direct_uring_qd16_randread", direct_path, 1, 1, 16, 1, total_blocks, bs, &sc_qd16_dir))
        return 1;

    /* Pre-warm file into page cache before cached read comparison. */
    int warm_fd = open(cached_path, O_RDONLY);
    if (warm_fd >= 0) {
        char *wbuf = malloc(1024 * 1024);
        if (wbuf) {
            while (read(warm_fd, wbuf, 1024 * 1024) > 0) {}
            free(wbuf);
        }
        close(warm_fd);
    }

    if (run_psync_bench("cached_psync_read", cached_path, 0, 0, total_blocks, bs, &sc_psync_cache))
        return 1;
    if (run_uring_bench("cached_uring_qd32_read", cached_path, 0, 0, 32, 1, total_blocks, bs, &sc_qd32_cache))
        return 1;

    double red_dir_psync = (double)sc_psync_dir / (double)sc_qd16_dir;
    double red_dir_qd1 = (double)sc_qd1_dir / (double)sc_qd16_dir;
    double red_cache_psync = (double)sc_psync_cache / (double)sc_qd32_cache;

    printf("SYSCALL_REDUCTION direct_qd16_vs_psync=%.2fx direct_qd16_vs_qd1=%.2fx cached_qd32_vs_psync=%.2fx\n",
           red_dir_psync, red_dir_qd1, red_cache_psync);

    if (red_dir_psync < 4.0 || red_dir_qd1 < 4.0 || red_cache_psync < 4.0) {
        fprintf(stderr, "SYSCALL_BENCH_RESULT FAIL (reduction < 4.0x)\n");
        return 1;
    }
    printf("SYSCALL_BENCH_RESULT PASS\n");
    return 0;
}
