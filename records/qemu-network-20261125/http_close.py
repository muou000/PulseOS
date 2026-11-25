#!/usr/bin/env python3
"""Check whether a fresh TCP connection delivers the complete 64 KiB fixture."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import sys

PAGE = bytes(65536)


def request(port, timeout, request_id):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    result = {"request": request_id}
    try:
        connection.request("GET", "/large.bin", headers={
            "Connection": "close",
            "User-Agent": f"pulse-net-close-{request_id}",
        })
        response = connection.getresponse()
        result.update(status=response.status, declared=response.getheader("Content-Length"))
        try:
            body = response.read()
        except http.client.IncompleteRead as error:
            return dict(result, outcome="early EOF", received=len(error.partial))
        valid = response.status == 200 and result["declared"] == str(len(PAGE)) and body == PAGE
        return dict(result, outcome="complete" if valid else "mismatch",
                    received=len(body), sha256=hashlib.sha256(body).hexdigest())
    except TimeoutError:
        return dict(result, outcome="timeout")
    except (OSError, http.client.HTTPException) as error:
        return dict(result, outcome="connection error", error=str(error))
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("-c", "--concurrency", type=int, choices=(1, 8), default=1)
    parser.add_argument("--requests", type=int, default=32)
    parser.add_argument("--timeout", type=float, default=1.5)
    args = parser.parse_args()
    if args.requests < 1 or args.timeout <= 0:
        parser.error("request count and timeout must be positive")
    with ThreadPoolExecutor(args.concurrency) as clients:
        rows = list(clients.map(lambda i: request(args.port, args.timeout, i),
                                range(args.requests)))
    counts = Counter(row["outcome"] for row in rows)
    print(json.dumps({"counts": counts, "requests": rows}, indent=2))
    return int(counts["complete"] != args.requests)


if __name__ == "__main__":
    sys.exit(main())
