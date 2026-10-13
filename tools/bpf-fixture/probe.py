#!/usr/bin/env python3
"""BPF toolchain and cross-compiler probe.

Checks availability and versions for:
  - clang with BPF target support (`clang -target bpf`)
  - llvm-objdump with BPF disassembly and ELF inspection support
  - libbpf development files via pkg-config
  - guest cross-compilers for riscv64 and loongarch64

Exits non-zero with an actionable diagnostic message when any required tool is missing.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

GUEST_COMPILER_CANDIDATES = {
    "riscv64": (
        "riscv64-linux-musl-gcc",
        "riscv64-unknown-linux-musl-gcc",
        "riscv64-linux-gnu-gcc",
        "riscv64-unknown-linux-gnu-gcc",
    ),
    "loongarch64": (
        "loongarch64-linux-musl-gcc",
        "loongarch64-unknown-linux-musl-gcc",
        "loongarch64-linux-gnu-gcc",
        "loongarch64-unknown-linux-gnu-gcc",
    ),
}


def run_cmd(argv: List[str], env: Optional[Dict[str, str]] = None) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            env=env,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return 1, "", str(exc)


def probe_clang(clang_path: Optional[str]) -> Dict[str, Any]:
    path = shutil.which(clang_path) if clang_path else shutil.which("clang")
    if not path or not os.path.exists(path):
        return {
            "ok": False,
            "path": clang_path or "clang",
            "error": "clang binary not found. Install clang (>= 16, e.g. 'sudo apt install clang').",
        }

    code, stdout, stderr = run_cmd([path, "--version"])
    if code != 0:
        return {
            "ok": False,
            "path": path,
            "error": f"Failed to execute clang --version: {stderr.strip() or stdout.strip()}",
        }
    version_line = stdout.splitlines()[0] if stdout else ""
    version_match = re.search(r"version\s+([0-9.]+)", version_line)
    version = version_match.group(1) if version_match else version_line

    code, targets_out, _ = run_cmd([path, "-print-targets"])
    bpf_supported = "bpf" in targets_out.lower() if code == 0 else False

    # Also test compiling a trivial 1-instruction eBPF snippet
    snippet_ok = False
    if bpf_supported:
        test_code = "int test_bpf(void) { return 0; }"
        try:
            p = subprocess.run(
                [path, "-target", "bpf", "-c", "-x", "c", "-", "-o", "/dev/null"],
                input=test_code,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
            snippet_ok = (p.returncode == 0)
        except Exception:
            snippet_ok = False

    if not bpf_supported or not snippet_ok:
        return {
            "ok": False,
            "path": path,
            "version": version,
            "bpf_target_supported": False,
            "error": f"clang at {path} does not support BPF target compilation (`-target bpf`).",
        }

    return {
        "ok": True,
        "path": path,
        "version": version,
        "version_line": version_line,
        "bpf_target_supported": True,
    }


def probe_llvm_objdump(objdump_path: Optional[str], clang_path: Optional[str] = None) -> Dict[str, Any]:
    path = shutil.which(objdump_path) if objdump_path else shutil.which("llvm-objdump")
    if not path or not os.path.exists(path):
        return {
            "ok": False,
            "path": objdump_path or "llvm-objdump",
            "error": "llvm-objdump binary not found. Install llvm tools (e.g. 'sudo apt install llvm').",
        }

    code, stdout, stderr = run_cmd([path, "--version"])
    if code != 0:
        return {
            "ok": False,
            "path": path,
            "error": f"Failed to execute llvm-objdump --version: {stderr.strip() or stdout.strip()}",
        }
    version_line = stdout.splitlines()[0] if stdout else ""
    version_match = re.search(r"version\s+([0-9.]+)", version_line)
    version = version_match.group(1) if version_match else version_line

    # Verify BPF ELF inspection / disassembly capability
    bpf_disasm_ok = False
    disasm_tested = False
    clang_bin = shutil.which(clang_path) if clang_path else shutil.which("clang")
    if clang_bin:
        with tempfile.NamedTemporaryFile(suffix=".o") as tmp_obj:
            p_comp = subprocess.run(
                [clang_bin, "-target", "bpf", "-c", "-x", "c", "-", "-o", tmp_obj.name],
                input="int f(void) { return 0; }",
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
            if p_comp.returncode == 0:
                disasm_tested = True
                p_dump = subprocess.run(
                    [path, "-d", tmp_obj.name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                )
                bpf_disasm_ok = (p_dump.returncode == 0 and "exit" in p_dump.stdout.lower())

    if not disasm_tested:
        # If no BPF object could be compiled to test disassembly directly,
        # verify llvm-objdump target registration and disassembly flags
        has_bpf_target = bool(re.search(r"registered targets:.*?\bbpf\b", stdout, re.IGNORECASE | re.DOTALL))
        code_help, help_out, _ = run_cmd([path, "--help"])
        has_disasm_flag = (code_help == 0 and ("--disassemble" in help_out or "-d" in help_out))
        bpf_disasm_ok = has_bpf_target and has_disasm_flag

    if not bpf_disasm_ok:
        return {
            "ok": False,
            "path": path,
            "version": version,
            "version_line": version_line,
            "bpf_inspection_supported": False,
            "error": f"llvm-objdump at {path} does not support BPF ELF disassembly or inspection.",
        }

    return {
        "ok": True,
        "path": path,
        "version": version,
        "version_line": version_line,
        "bpf_inspection_supported": True,
    }


def probe_libbpf(env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    pkg_config = shutil.which("pkg-config")
    if not pkg_config:
        return {
            "ok": False,
            "error": "pkg-config binary not found. Install pkg-config (e.g. 'sudo apt install pkg-config').",
        }

    code, stdout, stderr = run_cmd([pkg_config, "--modversion", "libbpf"], env=env)
    if code != 0:
        return {
            "ok": False,
            "error": "libbpf development package not found via pkg-config. "
                     "Install libbpf development headers (e.g. 'sudo apt install libbpf-dev') "
                     "or configure PKG_CONFIG_PATH.",
        }
    version = stdout.strip()

    _, cflags, _ = run_cmd([pkg_config, "--cflags", "libbpf"], env=env)
    _, libs, _ = run_cmd([pkg_config, "--libs", "libbpf"], env=env)

    return {
        "ok": True,
        "version": version,
        "cflags": cflags.strip(),
        "libs": libs.strip(),
    }


def _verify_guest_compiler(path: str, arch: str) -> tuple[bool, str, str, str]:
    """Verify that the executable at path is a working compiler targeting arch.

    Returns:
        (ok, version, version_line, error_message)
    """
    code, stdout, stderr = run_cmd([path, "--version"])
    if code != 0:
        err = stderr.strip() or stdout.strip() or f"exit code {code}"
        return False, "", "", f"Guest compiler candidate at {path} failed '--version' check: {err}"

    version_line = stdout.splitlines()[0] if stdout else (stderr.splitlines()[0] if stderr else "")
    version_match = re.search(r"(\d+\.\d+(\.\d+)?)", version_line)
    version = version_match.group(1) if version_match else "unknown"

    # Verify target architecture
    # 1. Check -dumpmachine
    dm_code, dm_stdout, _ = run_cmd([path, "-dumpmachine"])
    if dm_code == 0 and dm_stdout.strip():
        dm_target = dm_stdout.strip().lower()
        if arch in dm_target:
            return True, version, version_line, ""
        else:
            return (
                False,
                version,
                version_line,
                f"Compiler at {path} targets '{dm_stdout.strip()}', but requested architecture is {arch}.",
            )

    # 2. Check -v output for Target: ...
    v_code, v_stdout, v_stderr = run_cmd([path, "-v"])
    v_combined = (v_stdout + "\n" + v_stderr).lower()
    target_match = re.search(r"(?:target:\s*|--target=)([^\s]+)", v_combined)
    if target_match:
        v_target = target_match.group(1)
        if arch in v_target:
            return True, version, version_line, ""
        else:
            return (
                False,
                version,
                version_line,
                f"Compiler at {path} targets '{v_target}', but requested architecture is {arch}.",
            )

    # 3. Check version line / banner as fallback (for mock compilers or wrappers)
    if arch in version_line.lower() and any(k in version_line.lower() for k in ("gcc", "clang", "compiler")):
        return True, version, version_line, ""

    return (
        False,
        version,
        version_line,
        f"Executable at {path} does not appear to be a compiler targeting {arch}.",
    )


def probe_guest_compiler(arch: str, custom_cc: Optional[str] = None) -> Dict[str, Any]:
    if custom_cc:
        candidates = [custom_cc]
        resolved = shutil.which(custom_cc)
        if not resolved:
            return {
                "ok": False,
                "arch": arch,
                "path": custom_cc,
                "candidates": candidates,
                "error": f"Specified guest compiler for {arch} at '{custom_cc}' was not found.",
            }
        ok, version, version_line, err = _verify_guest_compiler(resolved, arch)
        if not ok:
            return {
                "ok": False,
                "arch": arch,
                "path": resolved,
                "candidates": candidates,
                "error": err,
            }
        return {
            "ok": True,
            "arch": arch,
            "path": resolved,
            "version": version,
            "version_line": version_line,
        }

    candidates = list(GUEST_COMPILER_CANDIDATES.get(arch, ()))
    last_err = None
    for cand in candidates:
        if cand and (resolved := shutil.which(cand)):
            ok, version, version_line, err = _verify_guest_compiler(resolved, arch)
            if ok:
                return {
                    "ok": True,
                    "arch": arch,
                    "path": resolved,
                    "version": version,
                    "version_line": version_line,
                }
            last_err = err

    cand_str = ", ".join(candidates)
    base_msg = (
        f"Guest compiler for {arch} is missing/unavailable. "
        f"Checked candidates: [{cand_str}]. "
        f"Please install cross compiler (e.g. 'sudo apt install gcc-{arch}-linux-gnu') "
        f"or specify --{arch}-cc."
    )
    if last_err:
        base_msg += f" Last candidate error: {last_err}"

    return {
        "ok": False,
        "arch": arch,
        "path": None,
        "candidates": candidates,
        "error": base_msg,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe BPF toolchain and cross-compilers.")
    parser.add_argument("--clang", help="Path to clang binary")
    parser.add_argument("--llvm-objdump", help="Path to llvm-objdump binary")
    parser.add_argument("--host-only", action="store_true", help="Only probe host BPF fixture tools")
    parser.add_argument(
        "--require-guest-cc",
        choices=["riscv64", "loongarch64", "all"],
        help="Require guest cross-compiler for specified architecture",
    )
    parser.add_argument("--riscv64-cc", help="Custom RISC-V64 cross compiler path")
    parser.add_argument("--loongarch64-cc", help="Custom LoongArch64 cross compiler path")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    args = parser.parse_args()

    results: Dict[str, Any] = {}
    missing_errors: List[str] = []

    # 1. Probe Host Tools
    clang_res = probe_clang(args.clang)
    results["clang"] = clang_res
    if not clang_res["ok"]:
        missing_errors.append(f"[clang] {clang_res['error']}")

    objdump_res = probe_llvm_objdump(args.llvm_objdump, args.clang)
    results["llvm_objdump"] = objdump_res
    if not objdump_res["ok"]:
        missing_errors.append(f"[llvm-objdump] {objdump_res['error']}")

    libbpf_res = probe_libbpf()
    results["libbpf"] = libbpf_res
    if not libbpf_res["ok"]:
        missing_errors.append(f"[libbpf] {libbpf_res['error']}")

    host_ok = clang_res["ok"] and objdump_res["ok"] and libbpf_res["ok"]
    results["host_ok"] = host_ok

    # 2. Probe Guest Compilers
    guest_results: Dict[str, Any] = {}
    arches_to_check: List[str] = []
    if args.require_guest_cc:
        if args.require_guest_cc == "all":
            arches_to_check = ["riscv64", "loongarch64"]
        else:
            arches_to_check = [args.require_guest_cc]
    elif not args.host_only:
        arches_to_check = ["riscv64", "loongarch64"]

    for arch in arches_to_check:
        custom = args.riscv64_cc if arch == "riscv64" else args.loongarch64_cc
        cc_res = probe_guest_compiler(arch, custom)
        guest_results[arch] = cc_res
        if not cc_res["ok"]:
            missing_errors.append(f"[guest-cc-{arch}] {cc_res['error']}")

    results["guest_compilers"] = guest_results
    overall_ok = (len(missing_errors) == 0)
    results["ok"] = overall_ok

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("=== BPF Toolchain Probe ===")
        print(f"Host clang:        {'OK (' + clang_res.get('version', '') + ')' if clang_res['ok'] else 'FAILED'}")
        print(f"Host llvm-objdump: {'OK (' + objdump_res.get('version', '') + ')' if objdump_res['ok'] else 'FAILED'}")
        print(f"Host libbpf:       {'OK (' + libbpf_res.get('version', '') + ')' if libbpf_res['ok'] else 'FAILED'}")
        if guest_results:
            print("--- Guest Compilers ---")
            for arch, g_res in guest_results.items():
                status = f"OK ({g_res.get('version', '')} at {g_res.get('path', '')})" if g_res['ok'] else 'MISSING'
                print(f"Guest {arch}:       {status}")

        if not overall_ok:
            print("\nErrors / Missing Dependencies:")
            for err in missing_errors:
                print(f"  * {err}")

    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
