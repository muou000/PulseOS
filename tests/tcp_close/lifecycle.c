/* Run inside the stock PulseOS QEMU user-network guest. */
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void require(int condition, const char *operation)
{
    if (!condition) {
        fprintf(stderr, "FAIL %s (errno %d)\n", operation, errno);
        exit(1);
    }
}

static int stream(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    require(fd >= 0, "socket");
    return fd;
}

static struct sockaddr_in endpoint(const char *ip)
{
    struct sockaddr_in addr = {.sin_family = AF_INET};
    require(inet_pton(AF_INET, ip, &addr.sin_addr) == 1, "inet_pton");
    return addr;
}

static void bind_ephemeral(int fd, struct sockaddr_in *addr)
{
    socklen_t size = sizeof(*addr);
    require(bind(fd, (struct sockaddr *)addr, size) == 0, "bind");
    require(getsockname(fd, (struct sockaddr *)addr, &size) == 0 && addr->sin_port,
            "getsockname");
}

/* bind_check examines all TCP handles. An explicitly bound source port
   remains busy while its detached TCP socket still occupies the socket set. */
static int port_is_free(struct sockaddr_in addr)
{
    int fd = stream();
    int rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    int err = errno;
    require(close(fd) == 0, "close bind probe");
    require(rc == 0 || err == EADDRINUSE, "probe source port");
    return rc == 0;
}

static void wait_for_release(struct sockaddr_in addr, int seconds)
{
    for (int elapsed = 0; elapsed <= seconds; ++elapsed) {
        if (port_is_free(addr)) {
            printf("released port=%u after %d one-second intervals\n", ntohs(addr.sin_port), elapsed);
            return;
        }
        sleep(1);
    }
    require(0, "source port was never released");
}

static void timeout(int fd, int option, int seconds)
{
    struct timeval tv = {.tv_sec = seconds};
    require(setsockopt(fd, SOL_SOCKET, option, &tv, sizeof(tv)) == 0, "socket timeout");
}

static void connection(int *client, int *peer, struct sockaddr_in *source)
{
    int listener = stream();
    struct sockaddr_in dest = endpoint("127.0.0.1");
    bind_ephemeral(listener, &dest);
    require(listen(listener, 1) == 0, "listen");
    *client = stream();
    *source = endpoint("127.0.0.1");
    bind_ephemeral(*client, source);
    timeout(*client, SO_SNDTIMEO, 5);
    require(connect(*client, (struct sockaddr *)&dest, sizeof(dest)) == 0, "loopback connect");
    *peer = accept(listener, NULL, NULL);
    require(*peer >= 0, "accept");
    timeout(*peer, SO_RCVTIMEO, 5);
    require(close(listener) == 0, "close listener");
}

static void drain(bool slow)
{
    int client, peer;
    struct sockaddr_in source;
    connection(&client, &peer, &source);
    int copy = dup(client);
    require(copy >= 0 && close(client) == 0, "dup and close original");

    /* Exceed the peer's 256 KiB receive window so the final close must leave
       some accepted data in the sender until this thread starts reading. */
    static unsigned char data[480 * 1024];
    const size_t size = slow ? sizeof(data) : 384 * 1024;
    for (size_t i = 0; i < size; ++i)
        data[i] = (unsigned char)(i % 251);
    size_t sent = 0;
    while (sent < size) {
        ssize_t n = send(copy, data + sent, size - sent, MSG_NOSIGNAL);
        require(n > 0, "send on duplicate");
        sent += (size_t)n;
    }
    require(close(copy) == 0, "final close");
    unsigned char buf[8192];
    size_t got = 0;
    ssize_t n;
    /* Open the window twice, with the second read after the initial 60s
       orphan deadline. ACK progress from the first read must extend it. */
    const size_t first_read = 128 * 1024;
    if (slow)
        sleep(35);
    for (;;) {
        size_t length = sizeof(buf);
        if (slow && got < first_read && first_read - got < length)
            length = first_read - got;
        n = recv(peer, buf, length, 0);
        if (n <= 0)
            break;
        require((size_t)n <= sent - got && !memcmp(buf, data + got, (size_t)n), "payload");
        got += (size_t)n;
        if (slow && got == first_read) {
            printf("read %zu bytes after 35 seconds, pausing 35 more\n", got);
            sleep(35);
        }
    }
    printf("accepted=%zu received=%zu final_recv=%zd\n", sent, got, n);
    require(n == 0 && got == sent, "complete stream followed by EOF");
    require(close(peer) == 0, "close peer");
    wait_for_release(source, 20);
}

static void orphan(void)
{
    int client, peer;
    struct sockaddr_in source;
    connection(&client, &peer, &source);
    require(close(client) == 0, "active close");
    char byte;
    require(recv(peer, &byte, 1, 0) == 0, "received FIN");
    /* Keep the peer's write side open past the orphan's deadline. */
    require(!port_is_free(source), "orphan retains its source port while waiting for peer FIN");
    sleep(65);
    require(port_is_free(source), "idle orphan released its port");
    require(close(peer) == 0, "close silent peer");
}

static void abort_connect(void)
{
    int fd = stream();
    struct sockaddr_in source = endpoint("0.0.0.0");
    bind_ephemeral(fd, &source);
    timeout(fd, SO_SNDTIMEO, 1);
    /* Unassigned IP on the QEMU user network leaves the SYN unanswered. */
    struct sockaddr_in dest = endpoint("10.0.2.250");
    dest.sin_port = htons(8080);
    require(connect(fd, (struct sockaddr *)&dest, sizeof(dest)) == -1 && errno == ETIMEDOUT,
            "connect timed out");
    require(close(fd) == 0, "close aborted connection");
    wait_for_release(source, 3);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s {drain|slow|orphan|abort}\n", argv[0]);
        return 2;
    }
    if (!strcmp(argv[1], "drain")) drain(false);
    else if (!strcmp(argv[1], "slow")) drain(true);
    else if (!strcmp(argv[1], "orphan")) orphan();
    else if (!strcmp(argv[1], "abort")) abort_connect();
    else return 2;
    printf("PASS %s\n", argv[1]);
    return 0;
}
