/* Run in an RV64 or LA64 guest with assertions enabled. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>

static void wait_for_child(pid_t child)
{
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void expect_removed(int id)
{
    struct shmid_ds ds;
    assert(shmctl(id, IPC_STAT, &ds) == -1 && errno == EINVAL);
}

/* The pipe keeps the inherited attachment alive until the parent detaches. */
static void last_attachment(int explicit_detach)
{
    int gate[2];
    assert(pipe(gate) == 0);
    int id = shmget(IPC_PRIVATE, 4096, 0600);
    assert(id >= 0);
    volatile char *shared = shmat(id, NULL, 0);
    assert(shared != (void *)-1);
    assert(shmctl(id, IPC_RMID, NULL) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        char ready;
        close(gate[1]);
        assert(read(gate[0], &ready, 1) == 1);
        assert(*shared == 'p');
        *shared = 'c';
        if (explicit_detach) {
            assert(shmdt((const void *)shared) == 0);
            expect_removed(id);
        }
        _exit(0);
    }
    close(gate[0]);
    *shared = 'p';
    assert(shmdt((const void *)shared) == 0);
    struct shmid_ds ds;
    assert(shmctl(id, IPC_STAT, &ds) == 0);
    assert(write(gate[1], "!", 1) == 1);
    close(gate[1]);
    wait_for_child(child);
    expect_removed(id);
    puts(explicit_detach ? "PASS last shmdt" : "PASS last process exit");
}

static void undo_on_exit(void)
{
    int id = semget(IPC_PRIVATE, 1, 0600);
    assert(id >= 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        struct sembuf add = {0, 3, SEM_UNDO};
        assert(semop(id, &add, 1) == 0);
        assert(semop(id, &add, 1) == 0);
        assert(semctl(id, 0, GETVAL) == 6);
        _exit(0);
    }
    wait_for_child(child);
    assert(semctl(id, 0, GETVAL) == 0);
    assert(semctl(id, 0, IPC_RMID) == 0);
    puts("PASS SEM_UNDO on process exit");
}

/* The validation patch reserves this address for the first unmap attempt. */
static void retry_reserved_unmap(void)
{
    int id = shmget(IPC_PRIVATE, 4096, 0600);
    assert(id >= 0);
    void *address = (void *)0x28000000;
    char *shared = shmat(id, address, 0);
    assert(shared == address);
    assert(shmctl(id, IPC_RMID, NULL) == 0);
    *shared = 'r';
    assert(shmdt(shared) == -1 && errno == EAGAIN);
    assert(*shared == 'r');
    struct shmid_ds ds;
    assert(shmctl(id, IPC_STAT, &ds) == 0);
    assert(shmdt(shared) == 0);
    expect_removed(id);
    puts("PASS failed unmap retains attachment for retry");
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--reservation") == 0) {
        retry_reserved_unmap();
        return 0;
    }
    assert(argc == 1);
    last_attachment(1);
    last_attachment(0);
    undo_on_exit();
    return 0;
}
