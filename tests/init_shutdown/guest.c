/* Freestanding Linux-ABI probe, executed by the initial shell with exec. */
typedef unsigned long usize;

/* Linux asm-generic syscall numbers shared by RISC-V and LoongArch. */
enum {
    SYS_write = 64, SYS_exit_group = 94, SYS_set_tid_address = 96,
    SYS_kill = 129, SYS_tkill = 130, SYS_tgkill = 131, SYS_rt_sigprocmask = 135, SYS_reboot = 142,
    SYS_setuid = 146, SYS_getpgid = 155, SYS_getsid = 156,
    SYS_getpid = 172, SYS_getppid = 173, SYS_gettid = 178,
    SYS_clone = 220, SYS_wait4 = 260,
    SIGINT = 2, SIGUSR2 = 12, SIGCHLD = 17, SIG_BLOCK = 0,
    EPERM = 1, ESRCH = 3, EINVAL = 22,
};
#define REBOOT_MAGIC1 0xfee1dead
#define REBOOT_MAGIC2 672274793
#define REBOOT_POWER_OFF 0x4321fedc

static long syscall6(long nr, usize x0, usize x1, usize x2, usize x3, usize x4, usize x5)
{
    register usize a0 __asm__("a0") = x0;
    register usize a1 __asm__("a1") = x1;
    register usize a2 __asm__("a2") = x2;
    register usize a3 __asm__("a3") = x3;
    register usize a4 __asm__("a4") = x4;
    register usize a5 __asm__("a5") = x5;
#ifdef __riscv
    register usize a7 __asm__("a7") = nr;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a7) : "memory");
#else
    register usize a7 __asm__("a7") = nr;
    __asm__ volatile("syscall 0" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a7) : "memory");
#endif
    return a0;
}

#define CALL(n, a, b, c) syscall6(n, (usize)(a), (usize)(b), (usize)(c), 0, 0, 0)
#define PRINT(s) CALL(SYS_write, 1, s, sizeof(s) - 1)

__attribute__((noreturn)) static void stop(int code)
{
    CALL(SYS_exit_group, code, 0, 0);
    for (;;) {}
}

__attribute__((noreturn)) void _start(void)
{
    if (CALL(SYS_getpid, 0, 0, 0) != 1 || CALL(SYS_gettid, 0, 0, 0) != 1 ||
        CALL(SYS_set_tid_address, 0, 0, 0) != 1 || CALL(SYS_kill, 1, 0, 0) != 0 ||
        CALL(SYS_tkill, 1, 0, 0) != 0 || CALL(SYS_tgkill, 1, 1, 0) != 0 ||
        CALL(SYS_getpgid, 0, 0, 0) != 1 || CALL(SYS_getsid, 0, 0, 0) != 1 ||
        CALL(SYS_kill, 1, 65, 0) != -EINVAL || CALL(SYS_kill, 2147483647, 0, 0) != -ESRCH) {
        PRINT("IDENTITY_FAIL init PID/TID or lookup\n");
        stop(1);
    }
    PRINT("IDENTITY_INIT_PASS\n");
    usize mask = 1UL << (SIGINT - 1);
    if (syscall6(SYS_rt_sigprocmask, SIG_BLOCK, (usize)&mask, 0, sizeof(mask), 0, 0) != 0 ||
        CALL(SYS_kill, 0, SIGINT, 0) != 0) {
        PRINT("IDENTITY_FAIL process group SIGINT\n");
        stop(8);
    }
    long child = CALL(SYS_clone, SIGCHLD, 0, 0); /* clone(SIGCHLD): fork with private memory. */
    if (child == 0) {
        long pid = CALL(SYS_getpid, 0, 0, 0);
        if (pid <= 1 || CALL(SYS_gettid, 0, 0, 0) != pid || CALL(SYS_getppid, 0, 0, 0) != 1 ||
            CALL(SYS_tgkill, pid, pid, 0) != 0) {
            PRINT("IDENTITY_FAIL child PID/TID/parent\n");
            stop(2);
        }
        PRINT("IDENTITY_CHILD_PASS\n");
        CALL(SYS_kill, pid, SIGUSR2, 0); /* SIGUSR2 must retain normal child termination. */
        stop(3);
    }
    int status = 0;
    if (child <= 1 || CALL(SYS_wait4, child, &status, 0) != child || (status & 127) != SIGUSR2) {
        PRINT("IDENTITY_FAIL child SIGUSR2/wait\n");
        stop(4);
    }
    child = CALL(SYS_clone, SIGCHLD, 0, 0);
    if (child == 0) {
        if (CALL(SYS_setuid, 1000, 0, 0) != 0 || CALL(SYS_kill, 1, SIGUSR2, 0) != -EPERM) {
            PRINT("IDENTITY_FAIL unprivileged shutdown permission\n");
            stop(6);
        }
        stop(0);
    }
    if (child <= 1 || CALL(SYS_wait4, child, &status, 0) != child || status != 0) {
        PRINT("IDENTITY_FAIL unprivileged child/wait\n");
        stop(7);
    }
    PRINT("IDENTITY_PASS\n");
    /* End only after all assertions; this exercises the existing forced path. */
    CALL(SYS_reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, REBOOT_POWER_OFF);
    stop(5);
}
