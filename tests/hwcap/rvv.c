/* Linux userspace acceptance for the RISC-V V extension. */
#define _GNU_SOURCE
#include <asm/hwprobe.h>
#include <elf.h>
#include <stdbool.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct progress {
    uint32_t ready, acknowledged;
};
struct vector_csrs {
    uint64_t vl, vtype, vcsr, vstart;
};

extern size_t vector_bytes(void);
extern void vector_round(const void *, void *, struct vector_csrs *, int,
                         struct progress *, struct progress *, unsigned int);

static int worker(int id, struct progress *progress)
{
    cpu_set_t target, actual;
    CPU_ZERO(&target);
    CPU_SET(0, &target);
    if (sched_setaffinity(0, sizeof(target), &target) ||
        sched_getaffinity(0, sizeof(actual), &actual) ||
        !CPU_EQUAL(&actual, &target) || sched_getcpu() != 0) {
        fprintf(stderr, "RVV worker %d failed to pin to hart 0\n", id);
        return 1;
    }
    size_t vlenb = vector_bytes();
    if (vlenb < 16 || vlenb > 8192)
        return 1;
    size_t bytes = 32 * vlenb;
    unsigned char *in = malloc(bytes), *out = malloc(bytes);
    if (!in || !out)
        return 1;

    const struct vector_csrs expected = id ? (struct vector_csrs){3, 0xc8, 4, 2} :
                                             (struct vector_csrs){5, 0x00, 3, 1};
    int failed = 0;
    for (unsigned round = 1; round <= 8; ++round) {
        for (size_t i = 0; i < bytes; ++i) {
            in[i] = (i / vlenb) * 11 + (i % vlenb) * 17 + id * 131 + round;
            out[i] = ~in[i];
        }
        struct vector_csrs result = {0};
        vector_round(in, out, &result, id, &progress[id], &progress[1-id], round);
        if (memcmp(in, out, bytes) || memcmp(&result, &expected, sizeof(result)))
            failed = 1;
    }
    printf("RVV worker=%d hart=0 rounds=8 vlenb=%zu state=%s\n",
           id, vlenb, failed ? "FAIL" : "PASS");
    free(in);
    free(out);
    return failed;
}

static int check_preemption(void)
{
    struct progress *progress = mmap(NULL, 2 * sizeof(*progress), PROT_READ | PROT_WRITE,
                                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (progress == MAP_FAILED)
        return 1;
    memset(progress, 0, 2 * sizeof(*progress));
    fflush(stdout);
    pid_t child = fork();
    if (child < 0)
        return 1;
    if (child == 0)
        exit(worker(1, progress));
    int failed = worker(0, progress);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        failed = 1;
    munmap(progress, 2 * sizeof(*progress));
    return failed;
}

int main(int argc, char **argv, char **envp)
{
    if (argc != 2 || (strcmp(argv[1], "on") && strcmp(argv[1], "off")))
        return 2;
    bool enabled = !strcmp(argv[1], "on");
    while (*envp)
        ++envp;
    const Elf64_auxv_t *aux = (const Elf64_auxv_t *)(envp + 1);
    while (aux->a_type && aux->a_type != AT_HWCAP)
        ++aux;

    /* The runner uses eight identical harts. Exercise the intersection for
       all online CPUs and for a subset excluding the boot CPU. */
    unsigned long cpu1 = 1UL << 1;
    struct riscv_hwprobe all = { .key = RISCV_HWPROBE_KEY_IMA_EXT_0 };
    struct riscv_hwprobe subset = { .key = RISCV_HWPROBE_KEY_IMA_EXT_0 };
    if (syscall(SYS_riscv_hwprobe, &all, 1, 0, NULL, 0) != 0 ||
        syscall(SYS_riscv_hwprobe, &subset, 1, sizeof(cpu1), &cpu1, 0) != 0) {
        perror("riscv_hwprobe");
        return 1;
    }
    printf("RVV hwcap=%#lx ima_ext_0=%#llx cpu1_ima_ext_0=%#llx\n",
           (unsigned long)aux->a_un.a_val, (unsigned long long)all.value,
           (unsigned long long)subset.value);
    if (aux->a_type != AT_HWCAP || all.key != RISCV_HWPROBE_KEY_IMA_EXT_0 ||
        subset.key != all.key || subset.value != all.value || !(all.value & RISCV_HWPROBE_IMA_C) ||
        !!(aux->a_un.a_val & (1UL << ('V' - 'A'))) != enabled ||
        !!(all.value & RISCV_HWPROBE_IMA_V) != enabled)
        return 1;
    if (enabled && check_preemption())
        return 1;
    puts("RVV PASS");
    return 0;
}
