#!/usr/bin/env python3
"""Collect supplied ELF artifacts against identities in an unchanged guest capture."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
DEFAULT_ANALYZER = Path(__file__).resolve().parents[2] / "target/debug/bpf-analyzer"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def elf_build_id(data: bytes, arch: str, analyzer: Path = DEFAULT_ANALYZER) -> str | None:
    """Inspect these exact bytes with the guest/analyzer's shared note decoder."""
    process = subprocess.run([str(analyzer), "--elf-identity", arch], input=data, capture_output=True)
    if process.returncode:
        raise ValueError(process.stderr.decode("utf-8", errors="replace").strip())
    identity = json.loads(process.stdout)
    if identity["sha256"] != sha256(data):
        raise ValueError("ELF identity inspection differs from candidate bytes")
    return identity["gnu_build_id"]


def collect_artifacts(manifest: dict, bundle: Path, candidates: list[Path],
                      analyzer: Path = DEFAULT_ANALYZER) -> dict:
    """Verify supplied bytes before publishing; missing identities stay missing."""
    available = {}
    for path in candidates:
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ValueError(f"artifact exceeds collection bound: {path}")
        with path.open("rb") as source:
            data = source.read(MAX_ARTIFACT_BYTES + 1)
        if len(data) > MAX_ARTIFACT_BYTES:
            raise ValueError(f"artifact exceeds collection bound: {path}")
        available[sha256(data)] = data
    rows, outputs = [], {}
    for artifact in manifest["artifacts"]:
        digest = artifact["sha256"]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest) or artifact["path"] != f"artifacts/{digest}.elf":
            raise ValueError("invalid captured content address")
        row = {**artifact, "status": "missing", "debug_status": "not-recorded"}
        for key, id_key, suffix, status_key in (
            ("sha256", "gnu_build_id", ".elf", "status"),
            ("debug_sha256", "debug_build_id", ".elf", "debug_status"),
        ):
            expected = artifact.get(key)
            if expected is None:
                continue
            data = available.get(expected)
            if data is None:
                row[status_key] = "missing"
                continue
            actual = elf_build_id(data, manifest["arch"], analyzer)
            if actual != artifact.get(id_key):
                raise ValueError("artifact GNU build-id differs from the guest capture")
            if key == "debug_sha256" and expected != digest and (actual is None or actual != artifact["gnu_build_id"]):
                raise ValueError("external debug GNU build-id differs from executable")
            relative = f"artifacts/{expected}{suffix}"
            if key == "debug_sha256" and expected == digest:
                relative = artifact["path"]
            outputs[relative] = data
            row[status_key] = "verified"
        rows.append(row)
    for relative, data in outputs.items():
        destination = bundle / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and destination.read_bytes() != data:
            raise ValueError("existing content-addressed artifact differs")
        destination.write_bytes(data)
    known = {item["sha256"] for item in manifest["artifacts"]}
    return {"artifacts": rows, "unknown_objects": [item for item in manifest.get("objects", []) if item["sha256"] is None],
            "unavailable_artifact_identity": [item for item in manifest.get("objects", []) if item["sha256"] is not None and item["sha256"] not in known]}


def collect(capture: Path, bundle: Path, candidates: list[Path], analyzer: Path) -> dict:
    with capture.open("rb") as source:
        original = source.read()
        source_stat = os.fstat(source.fileno())
        protected = {(source_stat.st_dev, source_stat.st_ino)}
        for candidate in candidates:
            info = candidate.stat()
            protected.add((info.st_dev, info.st_ino))
        process = subprocess.run([str(analyzer), str(capture), "--artifact-manifest"], check=True, capture_output=True, text=True)
        manifest = json.loads(process.stdout)
        if manifest["capture_sha256"] != sha256(original):
            raise ValueError("capture changed before identity inspection")
        result = collect_artifacts(manifest, bundle, candidates, analyzer)
        for artifact in result["artifacts"]:
            for key, status in (("sha256", "status"), ("debug_sha256", "debug_status")):
                if artifact[status] == "verified":
                    info = (bundle / f"artifacts/{artifact[key]}.elf").stat()
                    protected.add((info.st_dev, info.st_ino))
        if capture.read_bytes() != original:
            raise ValueError("collection changed the original guest capture")
        result.update(capture_sha256=sha256(original), capture_bytes=len(original), capture_unchanged=True,
                      captured_manifest=manifest)
        encoded = json.dumps(result, indent=2) + "\n"
        bundle.mkdir(parents=True, exist_ok=True)
        report = bundle / f"{capture.stem}-collection.json"
        # Open without truncation and retain this exact descriptor through the
        # identity check and write; hardlinks, symlinks and path replacement
        # cannot redirect the checked write onto the original capture.
        descriptor = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_NONBLOCK, 0o666)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            info = os.fstat(output.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("collection report must be a regular file")
            if (info.st_dev, info.st_ino) in protected:
                raise ValueError("collection report aliases its capture or an ELF artifact")
            output.truncate(0)
            output.write(encoded)
        source.seek(0)
        if source.read() != original or capture.read_bytes() != original:
            raise ValueError("collection changed the original guest capture")
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, action="append", default=[])
    parser.add_argument("--analyzer", type=Path, default=Path("target/debug/bpf-analyzer"))
    args = parser.parse_args()
    print(json.dumps(collect(args.capture.resolve(), args.bundle.resolve(), args.candidate, args.analyzer.resolve()), indent=2))
