#!/usr/bin/env python3
"""Package immutable recorder runs and verify or extract their indexed bytes.

Run names such as riscv64/stacks-task share riscv64.tar.gz. Verification checks
archive integrity, not whether a recorded experiment passed its runtime oracle.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile


FORMAT = "pulse-recorder-evidence"


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return stream_digest(stream)


def stream_digest(stream) -> str:
    value = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        value.update(chunk)
    return value.hexdigest()


def safe_name(name: str) -> str:
    if (not isinstance(name, str) or not name or "\\" in name or "\0" in name
            or PurePosixPath(name).is_absolute()
            or any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError(f"unsafe evidence path: {name!r}")
    return name


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path: Path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def omission(path: Path) -> str | None:
    if path.name == "disk.img":
        return "rootfs omitted; SHA identifies the actual input bytes"
    if path.name == "bpf-analyzer":
        return "rebuildable host analyzer omitted; SHA identifies the actual consumer"
    if path.name in ("kernel", "kernel-from-elf.bin"):
        parent = path.parent
        if (parent / "kernel.elf").is_file() and (parent / "kernel.provenance.json").is_file():
            with path.open("rb") as stream:
                if stream.read(4) != b"\x7fELF":
                    return "raw boot image omitted; matching ELF and provenance retained"
    return None


def pack_runs(runs: dict[str, Path], output: Path) -> dict:
    """Snapshot every regular input file, keeping rejected experiments verbatim."""
    if not runs:
        raise ValueError("no evidence runs")
    output = output.resolve()
    if output.exists():
        raise ValueError("evidence output must be a new directory")
    index = {"format": FORMAT, "version": 1, "archives": {}, "runs": {}}
    groups = {}
    for name, raw_path in sorted(runs.items()):
        safe_name(name)
        if not all(re.fullmatch(r"[a-z0-9][a-z0-9_-]*", part) for part in name.split("/")):
            raise ValueError("run names use lowercase letters, digits, hyphens and underscores")
        if any(name != other and other.startswith(name + "/") for other in runs):
            raise ValueError("overlapping run names")
        run = raw_path.resolve(strict=True)
        if not run.is_dir() or output.is_relative_to(run):
            raise ValueError("run must be a directory outside the evidence output")
        archive = name.split("/")[0] + ".tar.gz"
        entries = groups.setdefault(archive, [])
        omitted, files = {}, 0
        for path in sorted(run.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"symlink is not self-contained evidence: {path}")
            if path.is_dir():
                continue
            if not stat.S_ISREG(path.stat().st_mode):
                raise ValueError(f"non-regular evidence file: {path}")
            relative = safe_name(path.relative_to(run).as_posix())
            metadata = {"sha256": digest(path), "bytes": path.stat().st_size,
                        "mode": 0o755 if path.stat().st_mode & 0o111 else 0o644}
            reason = omission(path)
            if reason:
                omitted[relative] = {**metadata, "reason": reason}
            else:
                entries.append((name + "/" + relative, path, metadata))
                files += 1
        if not files:
            raise ValueError(f"empty evidence run: {name}")
        index["runs"][name] = {"source": str(run), "archive": archive, "files": files,
                               "omitted": omitted,
                               "result": load(run / "result.json") if (run / "result.json").is_file() else None}
    output.mkdir(parents=True, exist_ok=False)
    for archive, entries in sorted(groups.items()):
        members, first = {}, {}
        archive_path = output / archive
        with archive_path.open("xb") as destination:
            with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as stream:
                    for name, path, metadata in sorted(entries):
                        data = path.read_bytes()
                        if len(data) != metadata["bytes"] or hashlib.sha256(data).hexdigest() != metadata["sha256"]:
                            raise ValueError(f"source changed while packaging: {path}")
                        info = tarfile.TarInfo(name)
                        info.mode, info.mtime = metadata["mode"], 0
                        key = (metadata["sha256"], metadata["bytes"], metadata["mode"])
                        if key in first:
                            info.type, info.linkname = tarfile.LNKTYPE, first[key]
                            metadata = {**metadata, "hardlink": info.linkname}
                            stream.addfile(info)
                        else:
                            info.size = len(data)
                            stream.addfile(info, io.BytesIO(data))
                            first[key] = name
                        members[name] = metadata
        index["archives"][archive] = {"sha256": digest(archive_path), "bytes": archive_path.stat().st_size,
                                       "members": members}
    (output / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
    verify_directory(output)
    return index


def verify_archive(path: Path, declared: dict, names: set[str], destination: Path | None) -> int:
    if path.is_symlink() or path.stat().st_size != declared["bytes"] or digest(path) != declared["sha256"]:
        raise ValueError(f"archive SHA/size mismatch: {path.name}")
    expected, found = declared["members"], {}
    with tarfile.open(path, "r:gz") as stream:
        for member in stream:
            name = safe_name(member.name)
            if name in names or name not in expected:
                raise ValueError(f"duplicate or unindexed member: {name}")
            metadata = expected[name]
            if member.mode != metadata["mode"] or member.mode not in (0o644, 0o755):
                raise ValueError(f"member mode mismatch: {name}")
            if member.islnk():
                target = safe_name(member.linkname)
                if member.size or target not in found or not found[target]["regular"]:
                    raise ValueError(f"hardlink must target a previous regular archive member: {name}")
                if metadata.get("hardlink") != target:
                    raise ValueError(f"hardlink differs from index: {name}")
                actual = found[target]
                if destination:
                    file = destination / name
                    file.parent.mkdir(parents=True, exist_ok=True)
                    os.link(destination / target, file)
            elif member.isfile():
                if "hardlink" in metadata or member.size != metadata["bytes"]:
                    raise ValueError(f"member size/type mismatch: {name}")
                source = stream.extractfile(member)
                if source is None:
                    raise ValueError(f"missing member bytes: {name}")
                with source:
                    if destination:
                        file = destination / name
                        file.parent.mkdir(parents=True, exist_ok=True)
                        value = hashlib.sha256()
                        with file.open("xb") as output:
                            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                                value.update(chunk)
                                output.write(chunk)
                        file.chmod(member.mode)
                        actual_sha = value.hexdigest()
                    else:
                        actual_sha = stream_digest(source)
                actual = {"sha256": actual_sha, "bytes": member.size, "mode": member.mode}
            else:
                raise ValueError(f"unsupported archive member type: {name}")
            if any(actual[key] != metadata[key] for key in ("sha256", "bytes", "mode")):
                raise ValueError(f"member SHA/size/mode mismatch: {name}")
            found[name] = {**actual, "regular": member.isfile()}
            names.add(name)
    if set(found) != set(expected):
        raise ValueError(f"missing indexed members: {path.name}")
    return len(found)


def verify_directory(directory: Path, extract: Path | None = None) -> dict:
    index = load(directory / "index.json")
    if index.get("format") != FORMAT or index.get("version") != 1 or not index.get("archives"):
        raise ValueError("unsupported or empty evidence index")
    # Validate all archives before creating an extraction tree. Never delegate
    # path/link handling to tar.extractall or trust an archive-provided symlink.
    names = set()
    for archive, declared in index["archives"].items():
        if "/" in safe_name(archive):
            raise ValueError("archive filename must not contain directories")
        verify_archive(directory / archive, declared, names, None)
    if extract is not None:
        extract.mkdir(parents=True, exist_ok=False)
        extracted_names = set()
        for archive, declared in index["archives"].items():
            verify_archive(directory / archive, declared, extracted_names, extract)
    return {"verified": True, "archives": len(index["archives"]), "members": len(names),
            "scope": "indexed byte integrity; runtime outcomes remain in original result files",
            "extracted": str(extract) if extract is not None else None}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    pack = actions.add_parser("pack")
    pack.add_argument("--run", action="append", required=True, metavar="NAME=DIR")
    pack.add_argument("--output", type=Path, required=True, help="new evidence directory")
    verify = actions.add_parser("verify")
    verify.add_argument("directory", type=Path)
    verify.add_argument("--extract", type=Path, help="new directory for portable replay")
    args = parser.parse_args()
    if args.action == "pack":
        runs = {}
        for item in args.run:
            name, separator, path = item.partition("=")
            if not separator or not path or name in runs:
                raise ValueError("expected unique --run NAME=DIR")
            runs[name] = Path(path)
        pack_runs(runs, args.output)
        result = verify_directory(args.output)
    else:
        result = verify_directory(args.directory, args.extract)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
