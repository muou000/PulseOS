#!/usr/bin/env python3
"""Bind a completed Pulse kernel to its build-time inputs and artifact hashes.

This is build evidence, not a hermetic/reproducible-build or signature claim.
External Cargo dependencies are identified by Cargo.lock; their cached contents
are not attested. Inputs must remain unchanged between start and finish.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


SOURCE_ROOTS = (
    ".cargo", "api", "crates", "modules", "platforms", "pulse_core",
    "pulse_syscalls", "src", "configs", "scripts/make", "Cargo.toml",
    "Cargo.lock", "Makefile", "rust-toolchain", "rust-toolchain.toml",
    "scripts/build_provenance.py",
)
SKIP_DIRECTORIES = {".git", "target", "__pycache__", ".pytest_cache"}
ENVIRONMENT_KEYS = (
    "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER", "AX_ARCH", "AX_PLATFORM", "AX_MODE", "AX_LOG",
    "AX_TARGET", "AX_IP", "AX_GW", "APP_FEATURES",
)


def command(repo: Path, *args: str) -> str:
    return subprocess.check_output(args, cwd=repo, text=True).strip()


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def source_snapshot(repo: Path) -> dict:
    """Hash actual local inputs, including untracked/ignored embedded files."""
    paths = []
    for name in SOURCE_ROOTS:
        root = repo / name
        if root.is_dir() and not root.is_symlink():
            for directory, dirs, files in os.walk(root):
                dirs[:] = sorted(item for item in dirs if item not in SKIP_DIRECTORIES)
                for item in dirs:
                    if (Path(directory) / item).is_symlink():
                        raise ValueError("source directory symlink is not supported")
                paths.extend(Path(directory) / item for item in files
                             if not item.endswith((".pyc", ".pyo")))
        elif root.exists() or root.is_symlink():
            paths.append(root)
    tree = hashlib.sha256(b"PulseOS source inputs v1\0")
    for path in sorted(paths):
        relative = path.relative_to(repo).as_posix().encode()
        if not path.is_file():
            raise ValueError(f"source input is not a readable file: {path}")
        # Both the link destination and the bytes reached by it affect identity.
        link = os.readlink(path).encode() if path.is_symlink() else b""
        for value in (relative, link, bytes.fromhex(digest(path))):
            tree.update(len(value).to_bytes(8, "little"))
            tree.update(value)
    return {
        "commit": command(repo, "git", "rev-parse", "HEAD"),
        "git_worktree_dirty": bool(command(repo, "git", "status", "--porcelain=v1",
                                           "--untracked-files=all", "--", *SOURCE_ROOTS)),
        "tree_sha256": tree.hexdigest(),
        "file_count": len(paths),
        "roots": list(SOURCE_ROOTS),
        "excluded_directories": sorted(SKIP_DIRECTORIES),
        "external_dependencies": "Cargo.lock identities; cache content not attested",
    }


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    temporary.replace(path)


def config_snapshot(config: Path) -> dict:
    raw = config.read_bytes()
    return {"axconfig_path": str(config.resolve()),
            "axconfig_sha256": hashlib.sha256(raw).hexdigest(),
            "axconfig_text": raw.decode("utf-8")}


def start(repo: Path, config: Path, pending: Path, manifest: Path,
          values: dict, *, toolchain: dict | None = None) -> None:
    # A failed replacement build must not leave a stale sidecar looking current.
    manifest.unlink(missing_ok=True)
    pending.unlink(missing_ok=True)
    source = source_snapshot(repo)
    configuration = {**config_snapshot(config), "values": values,
                     "environment": {key: os.environ.get(key) for key in ENVIRONMENT_KEYS}}
    write_json(pending, {
        "format": "pulse-kernel-build-provenance", "format_version": 1,
        "started_unix_ns": time.time_ns(), "source": source,
        "configuration": configuration,
        "toolchain": toolchain or {
            "rustc": command(repo, os.environ.get("RUSTC", "rustc"), "-Vv"),
            "cargo": command(repo, "cargo", "-V"),
        },
    })


def finish(repo: Path, config: Path, pending: Path, manifest: Path,
           elf: Path, binary: Path, linker: Path | None = None) -> dict:
    value = json.loads(pending.read_text())
    if source_snapshot(repo) != value["source"]:
        raise ValueError("source inputs changed during build; rebuild before recording provenance")
    if any(value["configuration"][key] != item for key, item in config_snapshot(config).items()):
        raise ValueError("configuration changed during build; rebuild before recording provenance")
    for output in (elf, binary):
        if not output.is_file() or output.stat().st_size == 0:
            raise ValueError(f"missing/empty build output: {output}")
    value["completed_unix_ns"] = time.time_ns()
    value["artifacts"] = {
        name: {"path": str(path.resolve()), "sha256": digest(path), "bytes": path.stat().st_size}
        for name, path in (("elf", elf), ("binary", binary))
    }
    if linker is not None:
        value["configuration"]["linker_script"] = {
            "path": str(linker.resolve()), "sha256": digest(linker),
        }
    write_json(manifest, value)
    pending.unlink()
    return value


def verify_manifest(path: Path, elf_path: Path, boot_path: Path) -> dict:
    """Validate the saved build identity against artifacts, never current HEAD."""
    value = json.loads(path.read_text())
    if value.get("format") != "pulse-kernel-build-provenance" or value.get("format_version") != 1:
        raise ValueError("unsupported kernel provenance version")
    try:
        if len(value["source"]["commit"]) not in (40, 64):
            raise ValueError("invalid build-time source commit")
        int(value["source"]["commit"], 16)
        if len(value["source"]["tree_sha256"]) != 64:
            raise ValueError("invalid build-time source hash")
        int(value["source"]["tree_sha256"], 16)
        raw_config = value["configuration"]["axconfig_text"].encode()
        if hashlib.sha256(raw_config).hexdigest() != value["configuration"]["axconfig_sha256"]:
            raise ValueError("configuration checksum does not match provenance")
        if value["completed_unix_ns"] < value["started_unix_ns"]:
            raise ValueError("invalid build-time window")
        elf = value["artifacts"]["elf"]
        binary = value["artifacts"]["binary"]
        if digest(elf_path) != elf["sha256"] or elf_path.stat().st_size != elf["bytes"]:
            raise ValueError("kernel ELF does not match build provenance")
        boot_hash, boot_bytes = digest(boot_path), boot_path.stat().st_size
        if not any(boot_hash == entry["sha256"] and boot_bytes == entry["bytes"]
                   for entry in (elf, binary)):
            raise ValueError("boot image does not match build provenance")
    except (KeyError, TypeError) as error:
        raise ValueError("incomplete kernel build provenance") from error
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "finish"))
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--elf", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--linker", type=Path)
    for name in ("arch", "target", "mode", "platform", "features"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    pending = Path(str(args.manifest) + ".pending")
    if args.action == "start":
        start(args.repo, args.config, pending, args.manifest,
              {name: getattr(args, name) for name in ("arch", "target", "mode", "platform", "features")})
    else:
        if args.elf is None or args.binary is None:
            parser.error("finish requires --elf and --binary")
        finish(args.repo, args.config, pending, args.manifest, args.elf, args.binary, args.linker)


if __name__ == "__main__":
    main()
