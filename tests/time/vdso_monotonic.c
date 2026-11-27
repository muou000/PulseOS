#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifdef __GLIBC__
#include <gnu/libc-version.h>
#endif

typedef int (*vdso_clock_gettime_fn)(clockid_t clk_id, struct timespec *ts);

struct vdso_resolver {
    uintptr_t ehdr_addr;
    uintptr_t load_offset;
    const Elf64_Sym *symtab;
    const char *strtab;
    const Elf64_Word *hash;
    const Elf64_Versym *versym;
    const Elf64_Verdef *verdef;
    Elf64_Word nbucket;
    const Elf64_Word *bucket;
    const Elf64_Word *chain;
    bool valid;
};

static const char *default_vdso_version(void) {
#if defined(__riscv)
    return "LINUX_4.15";
#elif defined(__loongarch__)
    return "LINUX_5.10";
#elif defined(__x86_64__)
    return "LINUX_2.6";
#elif defined(__aarch64__)
    return "LINUX_2.6.39";
#else
    return "LINUX_2.6";
#endif
}

static unsigned long elf_sysv_hash(const char *name) {
    unsigned long h = 0;
    const unsigned char *p = (const unsigned char *)name;
    while (*p != '\0') {
        h = (h << 4) + *p++;
        unsigned long g = h & 0xf0000000UL;
        if (g != 0) {
            h ^= g >> 24;
        }
        h &= ~g;
    }
    return h;
}

static uintptr_t dyn_ptr(uintptr_t val, uintptr_t ehdr_addr, uintptr_t load_offset) {
    if (val >= ehdr_addr) {
        return val;
    }
    return load_offset + val;
}

static struct vdso_resolver init_vdso_from_ehdr(uintptr_t base) {
    struct vdso_resolver r;
    memset(&r, 0, sizeof(r));
    if (base == 0) {
        return r;
    }

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)base;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        return r;
    }

    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(base + ehdr->e_phoff);
    const Elf64_Dyn *dyn = NULL;
    bool found_load = false;

    r.ehdr_addr = base;
    for (Elf64_Half i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && !found_load) {
            found_load = true;
            r.load_offset = base - (uintptr_t)phdrs[i].p_vaddr;
        } else if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn = (const Elf64_Dyn *)(base + phdrs[i].p_offset);
        }
    }
    if (!found_load || dyn == NULL) {
        return r;
    }

    for (size_t i = 0; dyn[i].d_tag != DT_NULL; i++) {
        uintptr_t p = (uintptr_t)dyn[i].d_un.d_ptr;
        switch (dyn[i].d_tag) {
        case DT_STRTAB:
            r.strtab = (const char *)dyn_ptr(p, r.ehdr_addr, r.load_offset);
            break;
        case DT_SYMTAB:
            r.symtab = (const Elf64_Sym *)dyn_ptr(p, r.ehdr_addr, r.load_offset);
            break;
        case DT_HASH:
            r.hash = (const Elf64_Word *)dyn_ptr(p, r.ehdr_addr, r.load_offset);
            break;
        case DT_VERSYM:
            r.versym = (const Elf64_Versym *)dyn_ptr(p, r.ehdr_addr, r.load_offset);
            break;
        case DT_VERDEF:
            r.verdef = (const Elf64_Verdef *)dyn_ptr(p, r.ehdr_addr, r.load_offset);
            break;
        default:
            break;
        }
    }

    if (r.strtab == NULL || r.symtab == NULL || r.hash == NULL) {
        return r;
    }
    if (r.verdef == NULL) {
        r.versym = NULL;
    }

    r.nbucket = r.hash[0];
    if (r.nbucket == 0) {
        return r;
    }
    r.bucket = &r.hash[2];
    r.chain = &r.hash[2 + r.nbucket];
    r.valid = true;
    return r;
}

static bool match_sym_version(const struct vdso_resolver *r, Elf64_Versym ver, const char *version,
                              unsigned long ver_hash) {
    if (r->verdef == NULL) {
        return true;
    }
    ver &= 0x7fff;
    const Elf64_Verdef *def = r->verdef;
    for (;;) {
        if ((def->vd_flags & VER_FLG_BASE) == 0 && (def->vd_ndx & 0x7fff) == ver) {
            break;
        }
        if (def->vd_next == 0) {
            return false;
        }
        def = (const Elf64_Verdef *)((const char *)def + def->vd_next);
    }
    const Elf64_Verdaux *aux = (const Elf64_Verdaux *)((const char *)def + def->vd_aux);
    return def->vd_hash == ver_hash && strcmp(version, r->strtab + aux->vda_name) == 0;
}

static void *resolve_vdso_sym(const struct vdso_resolver *r, const char *version, const char *name) {
    if (!r->valid) {
        return NULL;
    }
    unsigned long name_hash = elf_sysv_hash(name);
    unsigned long ver_hash = elf_sysv_hash(version);
    for (Elf64_Word idx = r->bucket[name_hash % r->nbucket]; idx != STN_UNDEF; idx = r->chain[idx]) {
        const Elf64_Sym *sym = &r->symtab[idx];
        unsigned char st_type = ELF64_ST_TYPE(sym->st_info);
        unsigned char st_bind = ELF64_ST_BIND(sym->st_info);
        if (st_type != STT_FUNC) {
            continue;
        }
        if (st_bind != STB_GLOBAL && st_bind != STB_WEAK) {
            continue;
        }
        if (sym->st_shndx == SHN_UNDEF) {
            continue;
        }
        if (strcmp(name, r->strtab + sym->st_name) != 0) {
            continue;
        }
        if (r->versym != NULL && !match_sym_version(r, r->versym[idx], version, ver_hash)) {
            continue;
        }
        return (void *)(r->load_offset + (uintptr_t)sym->st_value);
    }
    return NULL;
}

static inline int64_t ts_to_ns(struct timespec ts) {
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static inline struct timespec ns_to_ts(int64_t ns) {
    struct timespec ts;
    ts.tv_sec = (time_t)(ns / 1000000000LL);
    ts.tv_nsec = (long)(ns % 1000000000LL);
    return ts;
}

static inline int raw_clock_gettime(clockid_t clk, struct timespec *ts) {
    return (int)syscall(SYS_clock_gettime, clk, ts);
}

struct sample_record {
    bool valid;
    int iter;
    int rc;
    int64_t target;
    int64_t raw_before;
    int64_t fast;
    int64_t raw_after;
    int64_t fast_minus_before;
    int64_t after_minus_fast;
    int64_t fast_minus_target;
};

struct step_tracker {
    bool has_prev;
    int64_t prev;
    int64_t min_step_ns;
    int regressions;
};

struct bracket_stats {
    int below_raw;
    int above_raw;
    int64_t min_minus_before_ns;
    int64_t min_after_minus_ns;
    struct sample_record worst_before;
    struct sample_record worst_after;
};

struct thread_config {
    int cpu;
    int iters;
    int64_t period_ns;
    vdso_clock_gettime_fn vdso_fn;
};

struct thread_result {
    struct thread_config cfg;
    int err;
    int nonzero_rc;
    int last_rc;
    int cycles;

    int early_raw;
    int early_libc;
    int early_vdso;

    int64_t min_raw_target_ns;
    int64_t min_libc_target_ns;
    int64_t min_vdso_target_ns;

    struct step_tracker raw_steps;
    struct step_tracker libc_steps;
    struct step_tracker vdso_steps;

    struct bracket_stats libc_bracket;
    struct bracket_stats vdso_bracket;
};

static void step_tracker_init(struct step_tracker *t) {
    t->has_prev = false;
    t->prev = 0;
    t->min_step_ns = INT64_MAX;
    t->regressions = 0;
}

static void step_tracker_record(struct step_tracker *t, int64_t cur) {
    if (t->has_prev) {
        int64_t step = cur - t->prev;
        if (step < t->min_step_ns) {
            t->min_step_ns = step;
        }
        if (step < 0) {
            t->regressions++;
        }
    }
    t->prev = cur;
    t->has_prev = true;
}

static void bracket_stats_init(struct bracket_stats *s) {
    memset(s, 0, sizeof(*s));
    s->min_minus_before_ns = INT64_MAX;
    s->min_after_minus_ns = INT64_MAX;
}

static void record_sample(struct sample_record *dst, int iter, int rc, int64_t target,
                          int64_t raw_before, int64_t fast, int64_t raw_after) {
    dst->valid = true;
    dst->iter = iter;
    dst->rc = rc;
    dst->target = target;
    dst->raw_before = raw_before;
    dst->fast = fast;
    dst->raw_after = raw_after;
    dst->fast_minus_before = fast - raw_before;
    dst->after_minus_fast = raw_after - fast;
    dst->fast_minus_target = fast - target;
}

static void bracket_stats_record(struct bracket_stats *s, int iter, int rc, int64_t target,
                                 int64_t raw_before, int64_t fast, int64_t raw_after) {
    int64_t diff_before = fast - raw_before;
    int64_t diff_after = raw_after - fast;
    if (diff_before < 0) {
        s->below_raw++;
    }
    if (diff_after < 0) {
        s->above_raw++;
    }
    if (diff_before < s->min_minus_before_ns) {
        s->min_minus_before_ns = diff_before;
        record_sample(&s->worst_before, iter, rc, target, raw_before, fast, raw_after);
    }
    if (diff_after < s->min_after_minus_ns) {
        s->min_after_minus_ns = diff_after;
        record_sample(&s->worst_after, iter, rc, target, raw_before, fast, raw_after);
    }
}

static void bracket_stats_merge(struct bracket_stats *dst, const struct bracket_stats *src) {
    dst->below_raw += src->below_raw;
    dst->above_raw += src->above_raw;
    if (src->min_minus_before_ns < dst->min_minus_before_ns) {
        dst->min_minus_before_ns = src->min_minus_before_ns;
        dst->worst_before = src->worst_before;
    }
    if (src->min_after_minus_ns < dst->min_after_minus_ns) {
        dst->min_after_minus_ns = src->min_after_minus_ns;
        dst->worst_after = src->worst_after;
    }
}

static int pin_current_thread(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) < 0) {
        return errno;
    }
    return 0;
}

static void *worker_main(void *arg) {
    struct thread_result *r = (struct thread_result *)arg;
    r->min_raw_target_ns = INT64_MAX;
    r->min_libc_target_ns = INT64_MAX;
    r->min_vdso_target_ns = INT64_MAX;
    step_tracker_init(&r->raw_steps);
    step_tracker_init(&r->libc_steps);
    step_tracker_init(&r->vdso_steps);
    bracket_stats_init(&r->libc_bracket);
    bracket_stats_init(&r->vdso_bracket);

    r->err = pin_current_thread(r->cfg.cpu);
    if (r->err != 0) {
        return NULL;
    }

    struct timespec start_ts;
    if (raw_clock_gettime(CLOCK_MONOTONIC, &start_ts) < 0) {
        r->err = errno;
        return NULL;
    }
    int64_t start_raw = ts_to_ns(start_ts);
    step_tracker_record(&r->raw_steps, start_raw);

    int64_t target = start_raw + r->cfg.period_ns;

    for (int iter = 0; iter < r->cfg.iters; iter++) {
        struct timespec req = ns_to_ts(target);
        int rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &req, NULL);
        if (rc != 0) {
            r->nonzero_rc++;
            r->last_rc = rc;
        }

        struct timespec raw_b1_ts, libc_ts, raw_a1_ts;
        struct timespec raw_b2_ts, vdso_ts, raw_a2_ts;
        if (raw_clock_gettime(CLOCK_MONOTONIC, &raw_b1_ts) < 0 ||
            clock_gettime(CLOCK_MONOTONIC, &libc_ts) < 0 ||
            raw_clock_gettime(CLOCK_MONOTONIC, &raw_a1_ts) < 0 ||
            raw_clock_gettime(CLOCK_MONOTONIC, &raw_b2_ts) < 0 ||
            r->cfg.vdso_fn(CLOCK_MONOTONIC, &vdso_ts) < 0 ||
            raw_clock_gettime(CLOCK_MONOTONIC, &raw_a2_ts) < 0) {
            r->err = errno != 0 ? errno : EINVAL;
            break;
        }

        int64_t raw_b1 = ts_to_ns(raw_b1_ts);
        int64_t libc_ns = ts_to_ns(libc_ts);
        int64_t raw_a1 = ts_to_ns(raw_a1_ts);
        int64_t raw_b2 = ts_to_ns(raw_b2_ts);
        int64_t vdso_ns = ts_to_ns(vdso_ts);
        int64_t raw_a2 = ts_to_ns(raw_a2_ts);

        step_tracker_record(&r->raw_steps, raw_b1);
        step_tracker_record(&r->raw_steps, raw_a1);
        step_tracker_record(&r->raw_steps, raw_b2);
        step_tracker_record(&r->raw_steps, raw_a2);
        step_tracker_record(&r->libc_steps, libc_ns);
        step_tracker_record(&r->vdso_steps, vdso_ns);

        if (rc == 0) {
            int64_t d_raw = raw_b1 - target;
            int64_t d_libc = libc_ns - target;
            int64_t d_vdso = vdso_ns - target;
            if (d_raw < 0) {
                r->early_raw++;
            }
            if (d_libc < 0) {
                r->early_libc++;
            }
            if (d_vdso < 0) {
                r->early_vdso++;
            }
            if (d_raw < r->min_raw_target_ns) {
                r->min_raw_target_ns = d_raw;
            }
            if (d_libc < r->min_libc_target_ns) {
                r->min_libc_target_ns = d_libc;
            }
            if (d_vdso < r->min_vdso_target_ns) {
                r->min_vdso_target_ns = d_vdso;
            }
        }

        bracket_stats_record(&r->libc_bracket, iter, rc, target, raw_b1, libc_ns, raw_a1);
        bracket_stats_record(&r->vdso_bracket, iter, rc, target, raw_b2, vdso_ns, raw_a2);

        r->cycles++;
        target += r->cfg.period_ns;
        while (target < raw_a2) {
            target += r->cfg.period_ns;
        }
    }

    return NULL;
}

static int run_bench_channel(const char *name, int (*fn)(clockid_t, struct timespec *),
                             int iters, int *regressions_out) {
    struct timespec t0, t1, cur;
    if (raw_clock_gettime(CLOCK_MONOTONIC, &t0) < 0) {
        return errno;
    }
    struct step_tracker steps;
    step_tracker_init(&steps);

    for (int i = 0; i < iters; i++) {
        if (fn(CLOCK_MONOTONIC, &cur) < 0) {
            return errno != 0 ? errno : EINVAL;
        }
        step_tracker_record(&steps, ts_to_ns(cur));
    }
    if (raw_clock_gettime(CLOCK_MONOTONIC, &t1) < 0) {
        return errno;
    }

    int64_t elapsed = ts_to_ns(t1) - ts_to_ns(t0);
    double per_call = iters > 0 ? (double)elapsed / (double)iters : 0.0;
    printf("bench channel=%s iters=%d total_ns=%" PRId64 " ns_per_call=%.2f regressions=%d min_step_ns=%" PRId64 "\n",
           name, iters, elapsed, per_call, steps.regressions,
           steps.min_step_ns == INT64_MAX ? 0 : steps.min_step_ns);
    *regressions_out = steps.regressions;
    return 0;
}

static int libc_clock_gettime_wrapper(clockid_t clk, struct timespec *ts) {
    return clock_gettime(clk, ts);
}

static void print_worst_sample(const char *label, const struct sample_record *s) {
    if (!s->valid) {
        printf("worst %s: none\n", label);
        return;
    }
    printf("worst %s: iter=%d rc=%d target=%" PRId64 " raw_before=%" PRId64
           " fast=%" PRId64 " raw_after=%" PRId64 " fast_minus_before=%" PRId64
           " after_minus_fast=%" PRId64 " fast_minus_target=%" PRId64 "\n",
           label, s->iter, s->rc, s->target, s->raw_before, s->fast, s->raw_after,
           s->fast_minus_before, s->after_minus_fast, s->fast_minus_target);
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [--threads N] [--cpu C] [--iters M] [--period-ns P] "
            "[--bench-iters B] [--fail-on-violation]\n",
            prog);
}

int main(int argc, char **argv) {
    int threads = 1;
    int base_cpu = 0;
    int iters = 1500;
    int64_t period_ns = 1000000LL;
    int bench_iters = 0;
    bool fail_on_violation = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            threads = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--cpu") == 0 && i + 1 < argc) {
            base_cpu = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
            iters = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--period-ns") == 0 && i + 1 < argc) {
            period_ns = strtoll(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--bench-iters") == 0 && i + 1 < argc) {
            bench_iters = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--fail-on-violation") == 0) {
            fail_on_violation = true;
        } else {
            print_usage(argv[0]);
            return 2;
        }
    }

    if (threads <= 0 || threads > 64 || base_cpu < 0 || iters < 0 || period_ns <= 0 || bench_iters < 0) {
        print_usage(argv[0]);
        return 2;
    }

    uintptr_t ehdr = (uintptr_t)getauxval(AT_SYSINFO_EHDR);
    if (ehdr == 0) {
        fprintf(stderr, "AT_SYSINFO_EHDR is missing\n");
        return 3;
    }
    const char *ver = default_vdso_version();
    struct vdso_resolver resolver = init_vdso_from_ehdr(ehdr);
    vdso_clock_gettime_fn vdso_fn =
        (vdso_clock_gettime_fn)resolve_vdso_sym(&resolver, ver, "__vdso_clock_gettime");
    if (vdso_fn == NULL) {
        fprintf(stderr, "failed to resolve __vdso_clock_gettime@%s from AT_SYSINFO_EHDR=0x%" PRIxPTR "\n",
                ver, ehdr);
        return 4;
    }

#ifdef __GLIBC__
    const char *libc_ver = gnu_get_libc_version();
#else
    const char *libc_ver = "non-glibc";
#endif
    uintptr_t vdso_addr = (uintptr_t)vdso_fn;
    uintptr_t libc_addr = (uintptr_t)(int (*)(clockid_t, struct timespec *))clock_gettime;
    printf("channel_id raw=syscall(%ld) libc=clock_gettime@%p(glibc=%s) "
           "vdso=__vdso_clock_gettime@%s(ehdr=0x%" PRIxPTR ",addr=0x%" PRIxPTR ",offset=0x%" PRIxPTR ")\n",
           (long)SYS_clock_gettime, (void *)libc_addr, libc_ver, ver, ehdr, vdso_addr,
           vdso_addr - ehdr);
    printf("config threads=%d base_cpu=%d iters=%d period_ns=%" PRId64 " bench_iters=%d fail_on_violation=%d\n",
           threads, base_cpu, iters, period_ns, bench_iters, fail_on_violation ? 1 : 0);

    bool any_violation = false;

    if (bench_iters > 0) {
        int pin_err = pin_current_thread(base_cpu);
        if (pin_err != 0) {
            fprintf(stderr, "pin cpu=%d failed: %s\n", base_cpu, strerror(pin_err));
            return 1;
        }
        int r_raw = 0, r_libc = 0, r_vdso = 0;
        if (run_bench_channel("raw", raw_clock_gettime, bench_iters, &r_raw) != 0 ||
            run_bench_channel("libc", libc_clock_gettime_wrapper, bench_iters, &r_libc) != 0 ||
            run_bench_channel("vdso", vdso_fn, bench_iters, &r_vdso) != 0) {
            fprintf(stderr, "benchmark failed\n");
            return 1;
        }
        if (r_raw > 0 || r_libc > 0 || r_vdso > 0) {
            any_violation = true;
        }
    }

    if (iters > 0) {
        pthread_t tids[64];
        struct thread_result results[64];
        memset(results, 0, sizeof(results));

        for (int i = 0; i < threads; i++) {
            results[i].cfg.cpu = base_cpu + i;
            results[i].cfg.iters = iters;
            results[i].cfg.period_ns = period_ns;
            results[i].cfg.vdso_fn = vdso_fn;
            int rc = pthread_create(&tids[i], NULL, worker_main, &results[i]);
            if (rc != 0) {
                fprintf(stderr, "pthread_create failed: %s\n", strerror(rc));
                return 1;
            }
        }
        for (int i = 0; i < threads; i++) {
            int rc = pthread_join(tids[i], NULL);
            if (rc != 0) {
                fprintf(stderr, "pthread_join failed: %s\n", strerror(rc));
                return 1;
            }
        }

        int total_cycles = 0, total_nonzero_rc = 0;
        int total_early_raw = 0, total_early_libc = 0, total_early_vdso = 0;
        int total_reg_raw = 0, total_reg_libc = 0, total_reg_vdso = 0;
        int64_t g_min_raw_step = INT64_MAX;
        int64_t g_min_libc_step = INT64_MAX;
        int64_t g_min_vdso_step = INT64_MAX;
        int64_t g_min_raw_target = INT64_MAX;
        int64_t g_min_libc_target = INT64_MAX;
        int64_t g_min_vdso_target = INT64_MAX;

        struct bracket_stats total_libc_bracket, total_vdso_bracket;
        bracket_stats_init(&total_libc_bracket);
        bracket_stats_init(&total_vdso_bracket);

        for (int i = 0; i < threads; i++) {
            const struct thread_result *r = &results[i];
            printf("cpu=%d err=%d C=%d nonzero_rc=%d last_rc=%d "
                   "early_raw=%d early_libc=%d early_vdso=%d "
                   "reg_raw=%d reg_libc=%d reg_vdso=%d "
                   "min_raw_step_ns=%" PRId64 " min_libc_step_ns=%" PRId64 " min_vdso_step_ns=%" PRId64 " "
                   "libc_below=%d libc_above=%d vdso_below=%d vdso_above=%d "
                   "min_raw_target_ns=%" PRId64 " min_libc_target_ns=%" PRId64
                   " min_vdso_target_ns=%" PRId64 " min_libc_minus_before_ns=%" PRId64
                   " min_after_minus_libc_ns=%" PRId64 " min_vdso_minus_before_ns=%" PRId64
                   " min_after_minus_vdso_ns=%" PRId64 "\n",
                   r->cfg.cpu, r->err, r->cycles, r->nonzero_rc, r->last_rc,
                   r->early_raw, r->early_libc, r->early_vdso,
                   r->raw_steps.regressions, r->libc_steps.regressions, r->vdso_steps.regressions,
                   r->raw_steps.min_step_ns, r->libc_steps.min_step_ns, r->vdso_steps.min_step_ns,
                   r->libc_bracket.below_raw, r->libc_bracket.above_raw,
                   r->vdso_bracket.below_raw, r->vdso_bracket.above_raw,
                   r->min_raw_target_ns, r->min_libc_target_ns, r->min_vdso_target_ns,
                   r->libc_bracket.min_minus_before_ns, r->libc_bracket.min_after_minus_ns,
                   r->vdso_bracket.min_minus_before_ns, r->vdso_bracket.min_after_minus_ns);

            if (r->err != 0 || r->cycles != iters || r->nonzero_rc != 0 ||
                r->early_raw != 0 || r->early_libc != 0 || r->early_vdso != 0 ||
                r->raw_steps.regressions != 0 || r->libc_steps.regressions != 0 ||
                r->vdso_steps.regressions != 0 ||
                r->libc_bracket.below_raw != 0 || r->libc_bracket.above_raw != 0 ||
                r->vdso_bracket.below_raw != 0 || r->vdso_bracket.above_raw != 0) {
                any_violation = true;
            }

            total_cycles += r->cycles;
            total_nonzero_rc += r->nonzero_rc;
            total_early_raw += r->early_raw;
            total_early_libc += r->early_libc;
            total_early_vdso += r->early_vdso;
            total_reg_raw += r->raw_steps.regressions;
            total_reg_libc += r->libc_steps.regressions;
            total_reg_vdso += r->vdso_steps.regressions;
            if (r->raw_steps.min_step_ns < g_min_raw_step) g_min_raw_step = r->raw_steps.min_step_ns;
            if (r->libc_steps.min_step_ns < g_min_libc_step) g_min_libc_step = r->libc_steps.min_step_ns;
            if (r->vdso_steps.min_step_ns < g_min_vdso_step) g_min_vdso_step = r->vdso_steps.min_step_ns;
            if (r->min_raw_target_ns < g_min_raw_target) g_min_raw_target = r->min_raw_target_ns;
            if (r->min_libc_target_ns < g_min_libc_target) g_min_libc_target = r->min_libc_target_ns;
            if (r->min_vdso_target_ns < g_min_vdso_target) g_min_vdso_target = r->min_vdso_target_ns;

            bracket_stats_merge(&total_libc_bracket, &r->libc_bracket);
            bracket_stats_merge(&total_vdso_bracket, &r->vdso_bracket);
        }

        printf("total C=%d nonzero_rc=%d early_raw=%d early_libc=%d early_vdso=%d "
               "reg_raw=%d reg_libc=%d reg_vdso=%d "
               "min_raw_step_ns=%" PRId64 " min_libc_step_ns=%" PRId64 " min_vdso_step_ns=%" PRId64 " "
               "libc_below=%d libc_above=%d vdso_below=%d vdso_above=%d "
               "min_raw_target_ns=%" PRId64 " min_libc_target_ns=%" PRId64
               " min_vdso_target_ns=%" PRId64 " min_libc_minus_before_ns=%" PRId64
               " min_after_minus_libc_ns=%" PRId64 " min_vdso_minus_before_ns=%" PRId64
               " min_after_minus_vdso_ns=%" PRId64 "\n",
               total_cycles, total_nonzero_rc, total_early_raw, total_early_libc, total_early_vdso,
               total_reg_raw, total_reg_libc, total_reg_vdso,
               g_min_raw_step, g_min_libc_step, g_min_vdso_step,
               total_libc_bracket.below_raw, total_libc_bracket.above_raw,
               total_vdso_bracket.below_raw, total_vdso_bracket.above_raw,
               g_min_raw_target, g_min_libc_target, g_min_vdso_target,
               total_libc_bracket.min_minus_before_ns, total_libc_bracket.min_after_minus_ns,
               total_vdso_bracket.min_minus_before_ns, total_vdso_bracket.min_after_minus_ns);
        print_worst_sample("libc_before", &total_libc_bracket.worst_before);
        print_worst_sample("libc_after", &total_libc_bracket.worst_after);
        print_worst_sample("vdso_before", &total_vdso_bracket.worst_before);
        print_worst_sample("vdso_after", &total_vdso_bracket.worst_after);
    }

    return (fail_on_violation && any_violation) ? 1 : 0;
}
