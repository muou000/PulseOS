#!/usr/bin/env python3
"""Verify LoongArch QEMU block/network MSI-X using the built kernel and snapshot rootfs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import socket
import subprocess
import threading
import time


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
PROMPT = re.compile(r"(?:ba)?sh-\d+(?:\.\d+)*[#$] ?")
FAULT = re.compile(r"panicked at|Unhandled EIOINTC IRQ|common_virtio_irq_handler: no handlers found|Illegal instruction!|Failed to (?:load shell ELF|resolve shell path)")
BLOCK_MARKER = "MSIX_BLOCK_root:x:0:0:root:/root:/bin/bash"
NET_MARKER = "MSIX_NET_PULSE_MSIX_RESPONSE"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--log-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    repo = Path(__file__).resolve().parents[2]
    kernel = (args.kernel or repo / "kernel-la").resolve()
    image = (args.image or repo / "disk-la.img").resolve()
    for path in (kernel, image):
        if not path.is_file():
            parser.error(f"input is missing: {path}")
    output = args.log_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    log_path = output / "guest.log"
    summary_path = output / "summary.json"
    for path in (log_path, summary_path):
        if path.exists():
            parser.error(f"refusing to replace existing evidence: {path}")

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(args.timeout)
    port = server.getsockname()[1]
    server_result = {"listening": f"127.0.0.1:{port}", "received": None, "responded": False}

    def respond():
        try:
            connection, peer = server.accept()
            with connection:
                connection.settimeout(args.timeout)
                request = bytearray()
                while b"\n" not in request and len(request) < 256:
                    chunk = connection.recv(256)
                    if not chunk:
                        break
                    request.extend(chunk)
                server_result["peer"] = list(peer)
                server_result["received"] = request.decode("ascii", errors="replace")
                if request == b"PULSE_MSIX_REQUEST\n":
                    connection.sendall(b"PULSE_MSIX_RESPONSE\n")
                    server_result["responded"] = True
        except (TimeoutError, OSError) as error:
            server_result["error"] = str(error)

    thread = threading.Thread(target=respond, daemon=True)
    thread.start()
    command = [
        "qemu-system-loongarch64", "-machine", "virt", "-kernel", str(kernel),
        "-m", "8G", "-nographic", "-smp", "8",
        "-drive", f"file={image},if=none,format=raw,id=x0,snapshot=on",
        "-device", "virtio-blk-pci,drive=x0", "-no-reboot",
        "-device", "virtio-net-pci,netdev=net0", "-netdev", "user,id=net0",
        "-rtc", "base=utc",
    ]
    payload = (
        "IFS= read -r line < /etc/passwd; printf '\\nMSIX_BLOCK_%s\\n' \"$line\"; "
        f"if exec 3<>/dev/tcp/10.0.2.2/{port}; then "
        "printf 'PULSE_MSIX_REQUEST\\n' >&3; "
        "if IFS= read -r line <&3; then printf 'MSIX_NET_%s\\n' \"$line\"; fi; "
        "exec 3<&-; exec 3>&-; fi; printf 'MSIX_DONE_%s\\n' OK\n"
    )
    patterns = {
        "block_msix_config": re.compile(r"PCI device at 00:01\.0 configured to use MSI-X \(irq 64\)"),
        "net_msix_config": re.compile(r"PCI device at 00:02\.0 configured to use MSI-X \(irq 65\)"),
        "block_eiointc_claim": re.compile(r"EIOINTC IRQ 64\b"),
        "net_eiointc_claim": re.compile(r"EIOINTC IRQ 65\b"),
        "block_handler": re.compile(r"common_virtio_irq_handler: irq=64\b"),
        "net_handler": re.compile(r"common_virtio_irq_handler: irq=65\b"),
        "block_handler_registered": re.compile(r"common_virtio_irq_handler: found 1 handlers for irq=64\b"),
        "net_handler_registered": re.compile(r"common_virtio_irq_handler: found 1 handlers for irq=65\b"),
        "block_read": re.compile(re.escape(BLOCK_MARKER)),
        "network_roundtrip": re.compile(re.escape(NET_MARKER)),
    }
    counts = {name: 0 for name in patterns}
    excerpts = {}
    faults = []
    started = time.monotonic()
    deadline = started + args.timeout
    sent = False
    success = False
    reason = "timeout before completing block/network MSI-X checks"
    line_buffer = ""
    console_tail = ""
    proc = subprocess.Popen(command, cwd=repo, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    try:
        with selectors.DefaultSelector() as selector, log_path.open("xb") as log:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if not selector.select(timeout=0.1):
                    if proc.poll() is not None:
                        reason = f"QEMU exited unexpectedly: {proc.returncode}"
                        break
                    continue
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    reason = f"QEMU output closed: {proc.poll()}"
                    break
                log.write(chunk)
                decoded = chunk.decode("utf-8", errors="replace")
                console_tail = (console_tail + decoded)[-131072:]
                line_buffer += decoded
                lines = line_buffer.split("\n")
                line_buffer = lines.pop()
                for raw_line in lines:
                    line = ANSI.sub("", raw_line).replace("\r", "").replace("\x08", "")
                    fault = FAULT.search(raw_line) or FAULT.search(line)
                    if fault:
                        faults.append(line)
                    for name, pattern in patterns.items():
                        matches = pattern.findall(raw_line)
                        if matches:
                            counts[name] += len(matches)
                            excerpts.setdefault(name, raw_line.rstrip("\r"))
                if faults:
                    reason = "guest fault or unhandled interrupt"
                    break
                # SMP trace output may insert the prompt inside an ANSI sequence;
                # stripping ANSI first can consume its first letter as an escape code.
                if not sent and PROMPT.search(console_tail):
                    proc.stdin.write(payload.encode())
                    proc.stdin.flush()
                    sent = True
                if sent and all(counts.values()) and server_result["responded"]:
                    success = True
                    reason = "block read and TCP round trip used configured MSI-X vectors with EIOINTC claims and registered handlers"
                    break
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        proc.stdin.close()
        proc.stdout.close()
        server.close()
    summary = {
        "passed": success,
        "reason": reason,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "qemu_command": command,
        "shell_payload": payload,
        "payload_sent": sent,
        "kernel": str(kernel),
        "kernel_sha256": sha256(kernel),
        "image": str(image),
        "image_sha256": sha256(image),
        "counts": counts,
        "excerpts": excerpts,
        "faults": faults,
        "server": server_result,
        "log": str(log_path),
        "log_bytes": log_path.stat().st_size,
        "console_tail": ANSI.sub("", console_tail)[-4000:] if not success else None,
    }
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"passed": success, "reason": reason, "elapsed_seconds": summary["elapsed_seconds"],
                      "payload_sent": sent, "counts": counts, "summary": str(summary_path),
                      "log_bytes": summary["log_bytes"]}, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
