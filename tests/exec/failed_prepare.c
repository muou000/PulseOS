#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The same two threads rendezvous before execve and again after it returns. */
static pthread_barrier_t barrier;

static void check_pthread(int error, const char *operation)
{
    if (error) {
        fprintf(stderr, "%s: %s\n", operation, strerror(error));
        exit(1);
    }
}

static void rendezvous(void)
{
    int result = pthread_barrier_wait(&barrier);
    if (result != PTHREAD_BARRIER_SERIAL_THREAD)
        check_pthread(result, "pthread_barrier_wait");
}

static void *sibling(void *cookie)
{
    rendezvous();
    rendezvous();
    return cookie;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s ELF-WITH-MISSING-INTERPRETER\n", argv[0]);
        return 2;
    }
    struct stat target;
    if (stat(argv[1], &target) || !S_ISREG(target.st_mode) || access(argv[1], X_OK)) {
        fprintf(stderr, "expected an executable regular file at %s\n", argv[1]);
        return 1;
    }
    alarm(15);
    pthread_t thread;
    check_pthread(pthread_barrier_init(&barrier, NULL, 2), "pthread_barrier_init");
    check_pthread(pthread_create(&thread, NULL, sibling, &thread), "pthread_create");
    rendezvous();

    char *const args[] = {argv[1], NULL};
    char *const env[] = {NULL};
    if (execve(argv[1], args, env) != -1 || errno != ENOENT) {
        perror("expected execve to fail with ENOENT");
        return 1;
    }

    rendezvous();
    void *reply;
    check_pthread(pthread_join(thread, &reply), "pthread_join");
    if (reply != &thread) {
        fputs("sibling failed to acknowledge the execve return\n", stderr);
        return 1;
    }
    puts("EXEC_PREPARE PASS");
    return 0;
}
