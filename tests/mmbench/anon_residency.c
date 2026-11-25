#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

enum { REGION_BYTES = 16 * 1024 * 1024, STRIDE_BYTES = 64 * 1024 };

static void fail(const char *operation)
{
    perror(operation);
    exit(EXIT_FAILURE);
}

static uint64_t monotonic_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        fail("clock_gettime(CLOCK_MONOTONIC)");
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static void report(const char *phase, void *region, size_t pages,
                   size_t pages_accessed, unsigned char *residency, uint64_t touch_ns)
{
    size_t resident = 0;
    if (region) {
        if (mincore(region, REGION_BYTES, residency) < 0)
            fail("mincore");
        for (size_t i = 0; i < pages; ++i)
            resident += residency[i] & 1;
    }

    FILE *status = fopen("/proc/self/status", "r");
    if (!status)
        fail("fopen /proc/self/status");
    long vm_size = -1, vm_rss = -1;
    char line[256];
    while (fgets(line, sizeof(line), status)) {
        if (sscanf(line, "VmSize: %ld kB", &vm_size) == 1)
            continue;
        if (sscanf(line, "VmRSS: %ld kB", &vm_rss) == 1)
            continue;
    }
    if (ferror(status))
        fail("read /proc/self/status");
    if (fclose(status) != 0)
        fail("fclose /proc/self/status");
    if (vm_size < 0 || vm_rss < 0) {
        fprintf(stderr, "/proc/self/status is missing VmSize or VmRSS\n");
        exit(EXIT_FAILURE);
    }
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0)
        fail("getrusage");
    printf("phase=%s mapped_pages=%zu accessed_pages=%zu resident_pages=%zu "
           "vm_size_kib=%ld vm_rss_kib=%ld maxrss_kib=%ld minflt=%ld majflt=%ld "
           "touch_ns=%" PRIu64 "\n",
           phase, pages, pages_accessed, resident, vm_size, vm_rss,
           usage.ru_maxrss, usage.ru_minflt, usage.ru_majflt, touch_ns);
}

int main(void)
{
    errno = 0;
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        if (errno)
            fail("sysconf(_SC_PAGESIZE)");
        fprintf(stderr, "page size unavailable\n");
        return EXIT_FAILURE;
    }
    if (STRIDE_BYTES % page_size != 0) {
        fprintf(stderr, "page size %ld does not divide stride %d\n",
                page_size, STRIDE_BYTES);
        return EXIT_FAILURE;
    }
    size_t pages = REGION_BYTES / page_size;
    unsigned char *residency = malloc(pages);
    if (!residency)
        fail("malloc residency vector");
    memset(residency, 0, pages);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("region_bytes=%d stride_bytes=%d page_bytes=%ld\n",
           REGION_BYTES, STRIDE_BYTES, page_size);
    (void)monotonic_ns();
    report("warmup", NULL, 0, 0, residency, 0);
    report("baseline", NULL, 0, 0, residency, 0);

    void *region = mmap(NULL, REGION_BYTES, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED)
        fail("mmap");
    volatile unsigned char *bytes = region;
    report("reserved", region, pages, 0, residency, 0);

    uint64_t start = monotonic_ns();
    for (size_t offset = 0; offset < REGION_BYTES; offset += STRIDE_BYTES)
        bytes[offset] = 1;
    uint64_t elapsed = monotonic_ns() - start;
    report("sparse", region, pages, REGION_BYTES / STRIDE_BYTES, residency, elapsed);

    start = monotonic_ns();
    for (size_t offset = 0; offset < REGION_BYTES; offset += page_size)
        bytes[offset] = 1;
    elapsed = monotonic_ns() - start;
    report("dense", region, pages, pages, residency, elapsed);

    if (madvise(region, REGION_BYTES, MADV_DONTNEED) != 0)
        fail("madvise(MADV_DONTNEED)");
    report("discarded", region, pages, 0, residency, 0);
    start = monotonic_ns();
    for (size_t offset = 0; offset < REGION_BYTES; offset += page_size) {
        if (bytes[offset] != 0) {
            fprintf(stderr, "page at offset %zu retained data after discard\n", offset);
            return EXIT_FAILURE;
        }
    }
    elapsed = monotonic_ns() - start;
    report("zero_readback", region, pages, pages, residency, elapsed);
    if (munmap(region, REGION_BYTES) != 0)
        fail("munmap");
    report("unmapped", NULL, 0, 0, residency, 0);
    free(residency);
    return EXIT_SUCCESS;
}
