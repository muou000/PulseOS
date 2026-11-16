#!/usr/bin/env python3
"""Collect supplied ELF artifacts against identities in an unchanged guest capture."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def elf_build_id(data: bytes, arch: str) -> str | None:
    """Read actual bounded LE ELF64 notes; never substitute a truncated SHA."""
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("artifact is not LE ELF64")
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    if kind not in (2, 3) or machine != {"riscv64": 243, "loongarch64": 258}.get(arch) or version != 1:
        raise ValueError("ELF architecture/type mismatch")
    phoff, shoff = struct.unpack_from("<QQ", data, 32)
    ehsize, phsize, phnum, shsize, shnum = struct.unpack_from("<HHHHH", data, 52)
    if (ehsize != 64 or phnum > 4096 or shnum > 32768 or (phnum and phsize != 56)
            or (shnum and shsize != 64) or (shoff != 0 and shnum == 0)):
        raise ValueError("invalid ELF table geometry")

    def span(offset, size):
        if offset > len(data) or size > len(data) - offset:
            raise ValueError("truncated ELF table or note")
        return data[offset:offset + size]

    note_ranges = set()
    programs, sections = span(phoff, phsize * phnum), span(shoff, shsize * shnum)
    for index in range(phnum):
        row = programs[index * phsize:(index + 1) * phsize]
        if struct.unpack_from("<I", row)[0] == 4:
            note_ranges.add((struct.unpack_from("<Q", row, 8)[0], struct.unpack_from("<Q", row, 32)[0]))
    for index in range(shnum):
        row = sections[index * shsize:(index + 1) * shsize]
        if struct.unpack_from("<I", row, 4)[0] == 7:
            note_ranges.add(struct.unpack_from("<QQ", row, 24))
    ids = set()
    if sum(size for _, size in note_ranges) > 1024 * 1024:
        raise ValueError("ELF note bytes exceed bound")
    for offset, size in note_ranges:
        note, cursor = span(offset, size), 0
        while cursor < len(note):
            if len(note) - cursor < 12:
                if any(note[cursor:]):
                    raise ValueError("truncated ELF note header")
                break
            namesz, descsz, tag = struct.unpack_from("<III", note, cursor)
            name = cursor + 12
            desc = (name + namesz + 3) & ~3
            end = (desc + descsz + 3) & ~3
            if end > len(note):
                raise ValueError("truncated ELF note payload")
            if tag == 3 and note[name:name + namesz] == b"GNU\0":
                if not 1 <= descsz <= 128:
                    raise ValueError("invalid GNU build-id size")
                ids.add(note[desc:desc + descsz].hex())
            cursor = end
    if len(ids) > 1:
        raise ValueError("conflicting GNU build-id notes")
    return next(iter(ids), None)


def collect_artifacts(manifest: dict, bundle: Path, candidates: list[Path]) -> dict:
    """Verify supplied bytes before publishing; missing identities stay missing."""
    available = {}
    for path in candidates:
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ValueError(f"artifact exceeds collection bound: {path}")
        data = path.read_bytes()
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
            actual = elf_build_id(data, manifest["arch"])
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
    original = capture.read_bytes()
    process = subprocess.run([str(analyzer), str(capture), "--artifact-manifest"], check=True, capture_output=True, text=True)
    manifest = json.loads(process.stdout)
    if manifest["capture_sha256"] != sha256(original):
        raise ValueError("capture changed before identity inspection")
    result = collect_artifacts(manifest, bundle, candidates)
    if capture.read_bytes() != original:
        raise ValueError("collection changed the original guest capture")
    result.update(capture_sha256=sha256(original), capture_bytes=len(original), capture_unchanged=True,
                  captured_manifest=manifest)
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / f"{capture.stem}-collection.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, action="append", default=[])
    parser.add_argument("--analyzer", type=Path, default=Path("target/debug/bpf-analyzer"))
    args = parser.parse_args()
    print(json.dumps(collect(args.capture.resolve(), args.bundle.resolve(), args.candidate, args.analyzer.resolve()), indent=2))
