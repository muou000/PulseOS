#!/usr/bin/env python3
"""Check stock darkhttpd on a forwarded port. The document root must contain
large.bin (65,536 zero bytes) and slow.bin (2 MiB of zero bytes).
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import socket
import struct
import sys
import time

HOST = '127.0.0.1'
LARGE = 65536
SLOW = 2 * 1024 * 1024


def request(port, tag, size=LARGE, delay=0, stream=None, close=True):
    """Return the observed HTTP result, including short EOF and partial data."""
    row = dict(tag=tag, expected=size)
    body = bytearray()
    sock = stream
    try:
        if sock is None:
            sock = socket.socket()
            sock.settimeout(8)
            if delay:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            sock.connect((HOST, port))
        row['client_port'] = sock.getsockname()[1]
        page = 'large.bin' if size == LARGE else 'slow.bin'
        mode = 'close' if close else 'keep-alive'
        sock.sendall((f'GET /{page} HTTP/1.1\r\nHost: localhost\r\n'
                      f'Connection: {mode}\r\nUser-Agent: {tag}\r\n\r\n').encode())
        if delay:
            time.sleep(delay)
        with sock.makefile('rb') as reply:
            status = reply.readline()
            if not status:
                raise EOFError('peer closed before status line')
            row['status'] = int(status.split()[1])
            headers = http.client.parse_headers(reply)
            declared = int(headers.get('Content-Length', -1))
            row['content_length'] = declared
            while close or len(body) < declared:
                chunk = reply.read1(65536 if close else min(65536, declared - len(body)))
                if not chunk:
                    row['eof'] = True
                    break
                body.extend(chunk)
        if row['status'] == 200 and declared == size and body == bytes(size):
            row['outcome'] = 'ok'
        else:
            row['outcome'] = 'early EOF' if len(body) < size and row.get('eof') else 'mismatch'
    except (EOFError, OSError, ValueError, IndexError, http.client.HTTPException) as error:
        row.update(outcome=type(error).__name__, error=str(error))
    finally:
        if stream is None and sock is not None:
            sock.close()
    row.update(received=len(body), sha256=hashlib.sha256(body).hexdigest())
    return row


def abort_request(port):
    with socket.socket() as sock:
        sock.settimeout(8)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        sock.connect((HOST, port))
        sock.sendall(b'GET /slow.bin HTTP/1.1\r\nHost: localhost\r\n'
                     b'Connection: close\r\nUser-Agent: check-peer-abort\r\n\r\n')
        with sock.makefile('rb') as response:
            if not response.readline().startswith(b'HTTP/1.1 200'):
                raise RuntimeError('abort control had no HTTP 200 status')
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))


def run(port, rounds):
    rows = []
    for repeat in range(1, rounds + 1):
        for concurrency in (1, 8):
            tags = [f'check-r{repeat}-c{concurrency}-i{i}' for i in range(32)]
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                rows.extend(pool.map(lambda tag: request(port, tag), tags))
    with socket.create_connection((HOST, port), timeout=8) as stream:
        for i in range(8):
            row = request(port, f'check-persist-{i}', stream=stream, close=i == 7)
            rows.append(row)
            if row['outcome'] != 'ok':
                break
    for size in (LARGE, SLOW):
        rows.append(request(port, f'check-slow-{size}', size=size, delay=0.5))
    abort_request(port)
    rows.append(request(port, 'check-after-peer-abort'))
    return rows


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--rounds', type=int, default=3)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error('--rounds must be positive')
    results = run(args.port, args.rounds)
    print(json.dumps(results, indent=2))
    sys.exit(int(len(results) != 64 * args.rounds + 11 or
                 any(r['outcome'] != 'ok' for r in results)))
