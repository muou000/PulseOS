/*
 * Linux socket ABI and readiness probe for the PulseOS QEMU network audit.
 * From this directory, build for the host, RV64 or LA64 respectively:
 *   cc -std=c11 -O2 -Wall -Werror -s -static socket_probe.c -o probe
 *   riscv64-linux-gnu-gcc -march=rv64gc -mabi=lp64d -std=c11 -O2 -Wall -Werror -s -static socket_probe.c -o probe-rv
 *   loongarch64-linux-gnu-gcc -march=loongarch64 -mabi=lp64d -std=c11 -O2 -Wall -Werror -s -static socket_probe.c -o probe-la
 *
 * Run ./probe for option values and errno, ./probe footprint for guest-wide
 * MemFree before/during/after socket allocation, and ./probe ready for
 * level-triggered read readiness. Each timing covers 64 calls. Check the
 * correct count before using elapsed_ns.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static void require_success(int result, const char *operation)
{
    if (result == -1) {
        perror(operation);
        exit(2);
    }
}

static int get_int_option(int fd, int level, int option)
{
    int value = -1;
    socklen_t length = sizeof(value);

    if (getsockopt(fd, level, option, &value, &length) < 0)
        return -errno;
    return value;
}

static int set_option(int fd, int level, int option, const void *value, socklen_t length)
{
    return setsockopt(fd, level, option, value, length) < 0 ? -errno : 0;
}

static void report_buffers(int socket_type)
{
    int fd = socket(AF_INET, socket_type, 0);
    require_success(fd, "buffer socket");
    for (int receive = 0; receive < 2; ++receive) {
        int option = receive ? SO_RCVBUF : SO_SNDBUF;
        printf("buffer proto=%s opt=%s default=%d", socket_type == SOCK_STREAM ? "tcp" : "udp",
               receive ? "rx" : "tx", get_int_option(fd, SOL_SOCKET, option));
        for (int bytes = 16 * 1024; bytes <= 128 * 1024; bytes *= 8) {
            int result = set_option(fd, SOL_SOCKET, option, &bytes, sizeof(bytes));
            printf(" req=%d set=%d got=%d", bytes, result, get_int_option(fd, SOL_SOCKET, option));
        }
        puts("");
    }
    close(fd);
}

static void report_tcp_options(void)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int client = socket(AF_INET, SOCK_STREAM, 0);
    require_success(listener, "listener");
    require_success(client, "client socket");

    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr = {htonl(INADDR_LOOPBACK)}};
    socklen_t addr_len = sizeof(addr);
    int enabled = 1;
    int listener_result = set_option(listener, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
    require_success(bind(listener, (void *)&addr, sizeof(addr)), "bind");
    require_success(getsockname(listener, (void *)&addr, &addr_len), "getsockname");
    require_success(listen(listener, 4), "listen");
    require_success(connect(client, (void *)&addr, sizeof(addr)), "connect");
    int peer = accept(listener, NULL, NULL);
    require_success(peer, "accept");
    printf("nodelay listener_set=%d listener=%d child_before_set=%d", listener_result,
           get_int_option(listener, IPPROTO_TCP, TCP_NODELAY), get_int_option(peer, IPPROTO_TCP, TCP_NODELAY));
    int child_result = set_option(peer, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
    printf(" child_set=%d child_after_set=%d\n", child_result, get_int_option(peer, IPPROTO_TCP, TCP_NODELAY));

    struct timeval requested = {.tv_usec = 100000};
    struct timeval actual = {0};
    socklen_t length = sizeof(actual);
    int timeout_set = set_option(client, SOL_SOCKET, SO_RCVTIMEO, &requested, sizeof(requested));
    int timeout_get = getsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &actual, &length);
    if (timeout_get < 0)
        timeout_get = -errno;
    printf("rcvtimeo set=%d get=%d sec=%ld usec=%ld\n",
           timeout_set, timeout_get, (long)actual.tv_sec, (long)actual.tv_usec);

    /* Exchange and acknowledge data in both directions before sampling TCP_INFO. */
    char payload[512] = {0};
    for (int round = 0; round < 4; ++round) {
        if (send(client, payload, sizeof(payload), 0) != sizeof(payload) ||
            recv(peer, payload, sizeof(payload), MSG_WAITALL) != sizeof(payload) ||
            send(peer, payload, 1, 0) != 1 || recv(client, payload, 1, 0) != 1) {
            puts("roundtrip failed");
            exit(3);
        }
    }

    struct tcp_info info = {0};
    length = sizeof(info);
    int info_result = getsockopt(client, IPPROTO_TCP, TCP_INFO, &info, &length);
    if (info_result < 0)
        info_result = -errno;
    char algorithm[32] = {0};
    socklen_t algorithm_len = sizeof(algorithm);
    int algorithm_result = getsockopt(client, IPPROTO_TCP, TCP_CONGESTION, algorithm, &algorithm_len);
    if (algorithm_result < 0)
        algorithm_result = -errno;
    printf("tcp_info tx_bytes=2048 get=%d len=%u state=%u mss=%u cwnd_segs=%u "
           "rtt_us=%u total_retrans=%u congestion='%s' congestion_rc=%d\n",
           info_result, (unsigned)length, info.tcpi_state, info.tcpi_snd_mss, info.tcpi_snd_cwnd,
           info.tcpi_rtt, info.tcpi_total_retrans, algorithm, algorithm_result);

    /* The first close releases one descriptor. The second is the last reference. */
    struct linger abortive = {1, 0};
    struct linger observed = {-1, -1};
    length = sizeof(observed);
    int linger_set = set_option(client, SOL_SOCKET, SO_LINGER, &abortive, sizeof(abortive));
    int linger_get = getsockopt(client, SOL_SOCKET, SO_LINGER, &observed, &length);
    if (linger_get < 0)
        linger_get = -errno;

    int alias = dup(client);
    require_success(alias, "dup");
    close(client);
    int sent = send(alias, "x", 1, MSG_NOSIGNAL);
    int received = recv(peer, payload, 1, MSG_DONTWAIT);
    if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        struct pollfd readable = {peer, POLLIN, 0};
        if (poll(&readable, 1, 500) > 0)
            received = recv(peer, payload, 1, MSG_DONTWAIT);
    }
    if (received < 0)
        received = -errno;
    close(alias);

    struct pollfd readable = {peer, POLLIN, 0};
    int ready = poll(&readable, 1, 1000);
    int final_recv = recv(peer, payload, 1, MSG_DONTWAIT);
    if (final_recv < 0)
        final_recv = -errno;
    printf("linger set=%d get=%d onoff=%d seconds=%d dup_send=%d peer_recv=%d "
           "final_peer_poll=%d final_peer_recv=%d\n",
           linger_set, linger_get, observed.l_onoff, observed.l_linger, sent, received, ready, final_recv);
    close(peer);
    close(listener);
}

static uint64_t monotonic_ns(void)
{
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return (uint64_t)time.tv_sec * 1000000000 + time.tv_nsec;
}

static long memfree_kib(void)
{
    FILE *meminfo = fopen("/proc/meminfo", "r");
    if (!meminfo)
        return -1;
    char line[128];
    long free_kib = -1;
    while (fgets(line, sizeof(line), meminfo)) {
        if (sscanf(line, "MemFree: %ld kB", &free_kib) == 1)
            break;
    }
    fclose(meminfo);
    return free_kib;
}

static void report_footprint(int socket_type, int count)
{
    int fds[64];
    long before_kib = memfree_kib();
    for (int i = 0; i < count; ++i) {
        fds[i] = socket(AF_INET, socket_type, 0);
        require_success(fds[i], "idle socket");
    }
    long open_kib = memfree_kib();
    for (int i = 0; i < count; ++i)
        close(fds[i]);
    printf("open_idle proto=%s n=%d before_kib=%ld open_kib=%ld after_kib=%ld\n",
           socket_type == SOCK_STREAM ? "tcp" : "udp", count, before_kib, open_kib, memfree_kib());
}

static void measure_readiness(int idle, int use_tcp)
{
    const int count = idle + 1;
    const int calls = 64;
    int endpoints[65][2];
    int epfd = epoll_create1(0);
    require_success(epfd, "epoll_create1");
    struct pollfd monitored[65];
    int listener = -1;
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr = {htonl(INADDR_LOOPBACK)}};
    socklen_t length = sizeof(addr);

    if (use_tcp) {
        listener = socket(AF_INET, SOCK_STREAM, 0);
        require_success(listener, "ready listener");
        require_success(bind(listener, (void *)&addr, sizeof(addr)), "ready bind");
        require_success(getsockname(listener, (void *)&addr, &length), "ready address");
        require_success(listen(listener, 8), "ready listen");
    }
    for (int i = 0; i < count; ++i) {
        if (use_tcp) {
            endpoints[i][1] = socket(AF_INET, SOCK_STREAM, 0);
            require_success(endpoints[i][1], "ready socket");
            require_success(connect(endpoints[i][1], (void *)&addr, sizeof(addr)), "ready connect");
            endpoints[i][0] = accept(listener, NULL, NULL);
            require_success(endpoints[i][0], "ready accept");
        } else {
            require_success(pipe(endpoints[i]), "pipe");
        }
        monitored[i] = (struct pollfd){endpoints[i][0], POLLIN, 0};
        struct epoll_event interest = {.events = EPOLLIN, .data.u32 = (unsigned)i};
        require_success(epoll_ctl(epfd, EPOLL_CTL_ADD, endpoints[i][0], &interest), "epoll_ctl");
    }

    /* All writers stay open. One unread byte keeps just the last reader ready. */
    require_success(write(endpoints[idle][1], "x", 1), "write");
    if (poll(&monitored[idle], 1, 1500) != 1) {
        puts("active descriptor never became readable");
        exit(4);
    }

    for (int round = 0; round < 3; ++round) {
        for (int run = 0; run < 2; ++run) {
            int use_epoll = (round + run) % 2;
            int correct = 0;
            uint64_t start = monotonic_ns();
            for (int i = 0; i < calls; ++i) {
                if (use_epoll) {
                    struct epoll_event event;
                    int result = epoll_wait(epfd, &event, 1, 0);
                    correct += result == 1 && event.data.u32 == (unsigned)idle;
                } else {
                    int result = poll(monitored, count, 0);
                    correct += result == 1 && (monitored[idle].revents & POLLIN) != 0;
                }
            }
            printf("ready kind=%s api=%s idle=%d active=1 run=%d correct=%d/%d elapsed_ns=%llu\n",
                   use_tcp ? "tcp" : "pipe", use_epoll ? "epoll_wait" : "poll",
                   idle, round + 1, correct, calls, (unsigned long long)(monotonic_ns() - start));
        }
    }
    if (listener >= 0)
        close(listener);
    close(epfd);
    for (int i = 0; i < count; ++i) {
        close(endpoints[i][0]);
        close(endpoints[i][1]);
    }
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && strcmp(argv[1], "ready") == 0) {
        for (int use_tcp = 0; use_tcp <= 1; ++use_tcp) {
            measure_readiness(1, use_tcp);
            measure_readiness(16, use_tcp);
            measure_readiness(64, use_tcp);
        }
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "footprint") == 0) {
        report_footprint(SOCK_STREAM, 16);
        report_footprint(SOCK_DGRAM, 4);
        return 0;
    }
    report_buffers(SOCK_STREAM);
    report_buffers(SOCK_DGRAM);
    report_tcp_options();
    return 0;
}
