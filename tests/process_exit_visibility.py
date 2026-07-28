#!/usr/bin/env python3

import argparse
import os
import select
import time


OLD_MTIME_NS = 1_600_000_000_000_000_000


def prepare_path(path):
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    os.write(fd, b"before")
    os.close(fd)
    os.utime(path, ns=(OLD_MTIME_NS, OLD_MTIME_NS))


def spawn_writer(path):
    pid = os.fork()
    if pid == 0:
        fd = os.open(path, os.O_WRONLY)
        os.write(fd, b"after!")
        os._exit(0)
    return pid


def assert_exit_effects_visible(path, label):
    if os.stat(path).st_mtime_ns == OLD_MTIME_NS:
        raise AssertionError(f"{label}: mtime was not published before exit became visible")


def waitpid_case(path, timeout):
    prepare_path(path)
    pid = spawn_writer(path)
    deadline = time.monotonic() + timeout
    while True:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            if status != 0:
                raise AssertionError(f"waitpid: child status={status}")
            break
        if time.monotonic() >= deadline:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            raise TimeoutError("waitpid: child did not exit")
        time.sleep(0)
    assert_exit_effects_visible(path, "waitpid")


def pidfd_case(path, timeout):
    if not hasattr(os, "pidfd_open"):
        raise RuntimeError("pidfd: os.pidfd_open is unavailable")

    prepare_path(path)
    pid = spawn_writer(path)
    try:
        pidfd = os.pidfd_open(pid, 0)
    except OSError:
        os.waitpid(pid, 0)
        raise
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    events = poller.poll(max(1, int(timeout * 1000)))
    try:
        if not events:
            raise TimeoutError("pidfd: descriptor did not become readable")
        assert_exit_effects_visible(path, "pidfd")
    finally:
        os.close(pidfd)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=256)
    parser.add_argument("--directory", default="/tmp")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    if args.iterations <= 0:
        parser.error("--iterations must be positive")

    test_dir = os.path.join(args.directory, f"pulse-exit-visibility-{os.getpid()}")
    os.mkdir(test_dir)
    try:
        for index in range(args.iterations):
            wait_path = os.path.join(test_dir, f"wait-{index}")
            waitpid_case(wait_path, args.timeout)
            os.unlink(wait_path)

            pidfd_path = os.path.join(test_dir, f"pidfd-{index}")
            pidfd_case(pidfd_path, args.timeout)
            if os.path.exists(pidfd_path):
                os.unlink(pidfd_path)
    finally:
        for name in os.listdir(test_dir):
            os.unlink(os.path.join(test_dir, name))
        os.rmdir(test_dir)

    print(
        "PASS process_exit_visibility "
        f"waitpid_iterations={args.iterations} "
        f"pidfd_iterations={args.iterations}"
    )


if __name__ == "__main__":
    main()
