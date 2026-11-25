/* Build with the target's Linux C compiler and -static, then run as guest root. */
#define _GNU_SOURCE
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char table[65536];
static char target[128];
static int mounted;

static void cleanup(void)
{
    if (mounted && umount(target) < 0)
        warn("umount");
    if (rmdir(target) < 0)
        warn("rmdir");
}

static int open_mounts(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        err(1, "open %s", path);
    return fd;
}

static void check_short_reads(const char *path, size_t length)
{
    char chunk[7];
    size_t offset = 0;
    int fd = open_mounts(path);
    ssize_t n;
    while ((n = read(fd, chunk, sizeof(chunk))) > 0) {
        if ((size_t)n > length - offset || memcmp(table + offset, chunk, n))
            errx(1, "%s differs from /proc/mounts at offset %zu", path, offset);
        offset += n;
    }
    if (n < 0)
        err(1, "read %s", path);
    if (offset != length)
        errx(1, "%s reached EOF at %zu of %zu bytes", path, offset, length);
    close(fd);
    printf("PASS %s (%zu bytes, 7-byte reads)\n", path, length);
}

static void check_directory_entry(const char *path, const char *name, unsigned char type)
{
    DIR *dir = opendir(path);
    if (!dir)
        err(1, "opendir %s", path);
    unsigned int matches = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, name)) {
            if (entry->d_type != type)
                errx(1, "wrong type for %s/%s", path, name);
            matches++;
        }
    }
    if (errno)
        err(1, "readdir %s", path);
    closedir(dir);
    if (matches != 1)
        errx(1, "found %u entries for %s/%s", matches, path, name);
    printf("PASS %s lists %s once\n", path, name);
}

static void check_rows(const char *expected_prefix)
{
    char *line = table;
    int matches = 0;
    while (*line) {
        char *end = strchr(line, '\n');
        if (!end)
            errx(1, "unterminated mount row");
        *end = '\0';
        int dump, pass;
        char extra;
        if (sscanf(line, "%*s %*s %*s %*s %d %d %c", &dump, &pass, &extra) != 2 ||
            dump != 0 || pass != 0)
            errx(1, "invalid six-field mount row: %s", line);
        if (!strncmp(line, expected_prefix, strlen(expected_prefix)))
            matches++;
        line = end + 1;
    }
    if (matches != 1)
        errx(1, "found %d rows with expected escaped source and target", matches);
    puts("PASS complete six-field rows and mount field escapes");
}

int main(void)
{
    const int pid = getpid();
    snprintf(target, sizeof(target), "/tmp/proc-mounts-%d #\t\n\\", pid);
    if (mkdir(target, 0700) < 0)
        err(1, "mkdir mount target");
    atexit(cleanup);
    if (mount("#source \t\n\\", target, "tmpfs", 0, NULL) < 0)
        err(1, "mount tmpfs");
    mounted = 1;

    int fd = open_mounts("/proc/mounts");
    ssize_t length = read(fd, table, sizeof(table) - 1);
    if (length < 0)
        err(1, "read /proc/mounts");
    char byte;
    if (!length || read(fd, &byte, 1) != 0)
        errx(1, "/proc/mounts did not fit in one nonempty read");
    close(fd);

    check_short_reads("/proc/mounts", length);
    check_short_reads("/proc/self/mounts", length);
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mounts", pid);
    check_short_reads(path, length);
    check_short_reads("/proc/1/mounts", length);
    check_directory_entry("/proc", "1", DT_DIR);
    check_directory_entry("/proc/self", "mounts", DT_REG);

    /* Holding the pipe open keeps the numeric child path live during reads. */
    int gate[2];
    if (pipe(gate) < 0)
        err(1, "pipe");
    pid_t child = fork();
    if (child < 0)
        err(1, "fork");
    if (!child) {
        close(gate[1]);
        _exit(read(gate[0], &byte, 1) == 0 ? 0 : 1);
    }
    close(gate[0]);
    snprintf(path, sizeof(path), "/proc/%d/mounts", child);
    check_short_reads(path, length);
    close(gate[1]);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        errx(1, "child did not exit normally");
    if (open(path, O_RDONLY) != -1 || errno != ENOENT)
        errx(1, "expected ENOENT for reaped %s", path);
    printf("PASS reaped %s returned ENOENT\n", path);

    char expected_prefix[192];
    snprintf(expected_prefix, sizeof(expected_prefix),
             "\\043source\\040\\011\\012\\134 /tmp/proc-mounts-%d\\040#\\011\\012\\134 tmpfs ", pid);
    check_rows(expected_prefix);
    return 0;
}
