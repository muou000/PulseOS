#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* #248 exercises one to eight vCPUs with the Linux affinity ABI. */
static void fail(const char *operation)
{
    perror(operation);
    exit(1);
}

static void expect_mask(unsigned long expected)
{
    unsigned long mask = 0;
    if (syscall(SYS_sched_getaffinity, 0, sizeof(mask), &mask) < 0)
        fail("sched_getaffinity");
    if (mask != expected) {
        fprintf(stderr, "affinity mask=%#lx expected=%#lx\n", mask, expected);
        exit(1);
    }
}

static void bind_mask(unsigned long mask)
{
    if (syscall(SYS_sched_setaffinity, 0, sizeof(mask), &mask) < 0)
        fail("sched_setaffinity");
}

static void expect_cpu(int expected)
{
    unsigned cpu;
    if (syscall(SYS_getcpu, &cpu, NULL, NULL) < 0)
        fail("getcpu");
    if (cpu != (unsigned)expected) {
        fprintf(stderr, "running cpu=%u expected=%d\n", cpu, expected);
        exit(1);
    }
}

struct worker {
    unsigned long allowed;
    int inherited_cpu;
    int offset;
};

static void *exercise_placement(void *arg)
{
    const struct worker *worker = arg;
    expect_mask(1UL << worker->inherited_cpu);
    expect_cpu(worker->inherited_cpu);
    /* Rebind through each allowed CPU while the other threads do the same. */
    for (int i = 0; i < 16; i++) {
        int cpu = (i + worker->offset) % 8;
        if (!(worker->allowed & (1UL << cpu)))
            continue;
        bind_mask(1UL << cpu);
        expect_cpu(cpu);
        if (usleep(2000) || sched_yield())
            fail("sleep/yield");
        expect_cpu(cpu);
    }
    return NULL;
}

static void run_workers(unsigned long allowed, int inherited_cpu)
{
    struct worker work = { allowed, inherited_cpu, getpid() % 8 };
    struct worker peer = { allowed, inherited_cpu, (work.offset + 3) % 8 };
    pthread_t tid;
    int err = pthread_create(&tid, NULL, exercise_placement, &peer);
    if (err) {
        errno = err;
        fail("pthread_create");
    }
    exercise_placement(&work);
    err = pthread_join(tid, NULL);
    if (err) {
        errno = err;
        fail("pthread_join");
    }
}

int main(int argc, char **argv)
{
    if (argc != 3 && argc != 4)
        return 2;
    int cpus = atoi(argv[1]), reserved = atoi(argv[2]);
    if (cpus < 1 || cpus > 8 || reserved < -1 || reserved >= cpus)
        return 2;
    unsigned long online = (1UL << cpus) - 1;
    unsigned long excluded = reserved < 0 ? 0 : 1UL << reserved;
    unsigned long allowed = online & ~excluded;
    if (!allowed)
        return 2;
    int target = 63 - __builtin_clzl(allowed);
    unsigned long singleton = 1UL << target;
    if (argc == 4) {
        /* exec preserves the restricted mask inherited at fork. */
        run_workers(allowed, target);
        return 0;
    }
    expect_mask(allowed);
    if (excluded) {
        bind_mask(singleton | excluded);
        expect_mask(singleton);
        if (syscall(SYS_sched_setaffinity, 0, sizeof(excluded), &excluded) != -1 ||
            errno != EINVAL) {
            fprintf(stderr, "reserved-only affinity request did not return EINVAL\n");
            return 1;
        }
        expect_mask(singleton);
    }
    bind_mask(singleton);
    expect_cpu(target);
    printf("AFFINITY allowed=%#lx mixed=%#lx reserved_only=%s pinned_cpu=%d\n",
           allowed, singleton | excluded, excluded ? "EINVAL" : "n/a", target);
    fflush(stdout);
    enum { children = 4 };
    for (int i = 0; i < children; i++) {
        pid_t pid = fork();
        if (pid < 0)
            fail("fork");
        if (pid == 0) {
            expect_mask(singleton);
            expect_cpu(target);
            execl(argv[0], argv[0], argv[1], argv[2], "child", (char *)NULL);
            fail("exec");
        }
    }
    for (int i = 0; i < children; i++) {
        int status;
        if (wait(&status) < 0)
            fail("wait");
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "affinity worker failed: status=%d\n", status);
            return 1;
        }
    }
    puts("AFFINITY PASS fork_exec=4 threads=8 sleep_yield=ok");
    return 0;
}
