/*
 * cc -std=c11 -O2 -Wall -Wextra -Werror accept_nodelay.c -o accept_nodelay
 * For a guest, use its cross compiler and add -static.
 */
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int checked(int result, const char *operation)
{
    if (result < 0) {
        perror(operation);
        exit(2);
    }
    return result;
}

static void set_nodelay(int fd, int value)
{
    checked(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)), "setsockopt");
}

static int check_nodelay(int fd, const char *name, int expected)
{
    int value = -1;
    socklen_t length = sizeof(value);
    checked(getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value, &length), "getsockopt");
    if (length != sizeof(value) || value != expected) {
        printf("FAIL %s: expected %d, got %d (length %u)\n", name, expected, value, (unsigned)length);
        return 1;
    }
    return 0;
}

static int connect_to(const struct sockaddr_in *addr)
{
    int fd = checked(socket(AF_INET, SOCK_STREAM, 0), "client socket");
    checked(connect(fd, (const struct sockaddr *)addr, sizeof(*addr)), "connect");
    return fd;
}

static int check_listener(int initial)
{
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(addr);
    int listener = checked(socket(AF_INET, SOCK_STREAM, 0), "listener socket");
    set_nodelay(listener, initial);
    checked(bind(listener, (struct sockaddr *)&addr, sizeof(addr)), "bind");
    checked(listen(listener, 4), "listen");
    checked(getsockname(listener, (struct sockaddr *)&addr, &length), "getsockname");

    int failures = check_nodelay(listener, "listener before accept", initial);
    int clients[4];
    int children[4];
    for (int i = 0; i < 2; ++i) {
        clients[i] = connect_to(&addr);
        children[i] = checked(accept(listener, NULL, NULL), "accept");
        failures += check_nodelay(children[i], i == 0 ? "first accept" : "second accept", initial);
    }
    set_nodelay(children[0], !initial);
    failures += check_nodelay(children[0], "changed child", !initial);
    failures += check_nodelay(children[1], "sibling after child change", initial);
    failures += check_nodelay(listener, "listener after child change", initial);

    /* A connection already waiting for accept keeps the old listener value. */
    clients[2] = connect_to(&addr);
    struct pollfd pending = {.fd = listener, .events = POLLIN};
    if (checked(poll(&pending, 1, 5000), "poll listener") != 1 || !(pending.revents & POLLIN)) {
        fputs("listener did not become readable\n", stderr);
        exit(2);
    }
    set_nodelay(listener, !initial);
    children[2] = checked(accept(listener, NULL, NULL), "accept queued");
    failures += check_nodelay(children[2], "queued before listener change", initial);

    clients[3] = connect_to(&addr);
    children[3] = checked(accept(listener, NULL, NULL), "accept new");
    failures += check_nodelay(children[3], "connected after listener change", !initial);
    failures += check_nodelay(listener, "changed listener", !initial);
    failures += check_nodelay(children[1], "sibling after listener change", initial);

    for (int i = 0; i < 4; ++i) {
        close(children[i]);
        close(clients[i]);
    }
    close(listener);
    printf("initial TCP_NODELAY=%d: %s (%d failures)\n", initial, failures ? "FAIL" : "PASS", failures);
    return failures;
}

int main(void)
{
    int failures = check_listener(0);
    failures += check_listener(1);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
