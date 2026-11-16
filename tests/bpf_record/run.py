#!/usr/bin/env python3
"""Run the real bpf-record CLI against separately launched guest workloads.

The existing bpf_smoke helpers supply image/process transport only. Captures are
the exact files written by the recorder; the host never generates their samples.
"""
from __future__ import annotations

import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re
import shlex
import shutil
import sys

from capture import clean_console, extract

BASE = Path(__file__).resolve().parent
REPO = BASE.parent.parent
spec = importlib.util.spec_from_file_location("recorder_transport", BASE.parent / "bpf_smoke/run.py")
assert spec and spec.loader
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
helpers.BASE = BASE
ARCHES = helpers.ARCHES
spec = importlib.util.spec_from_file_location("recorder_collection", REPO / "tools/bpf-record/collect.py")
assert spec and spec.loader
collection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collection)


def build_fixture(arch: str) -> Path:
    source = BASE / "fixture.rs"
    linker_script = BASE.parent / "bpf_sampling/guest.ld"
    sysroot = Path(helpers.command(["rustc", "+nightly", "--print", "sysroot"]).strip())
    version = helpers.command(["rustc", "+nightly", "-vV"])
    host = next(row.removeprefix("host: ") for row in version.splitlines() if row.startswith("host: "))
    linker = sysroot / "lib/rustlib" / host / "bin/rust-lld"
    output = BASE / "build" / arch / "record-fixture.elf"
    output.parent.mkdir(parents=True, exist_ok=True)
    command = ["rustc", "+nightly", "--edition=2024", "--crate-type=bin", "--target", ARCHES[arch]["target"],
               "-C", "panic=abort", "-C", "opt-level=2", "-C", "relocation-model=static", "-C", "force-frame-pointers=yes",
               "-C", f"linker={linker}", "-C", f"link-arg=-T{linker_script}", "-C", "link-arg=--no-relax",
               "-C", "link-arg=--build-id=sha1", "-o", str(output), str(source)]
    helpers.command(command, timeout=120)
    helpers.check_elf(output, arch)
    (output.parent / "fixture-build.json").write_text(json.dumps({
        "command": command, "rustc": version, "source_sha256": helpers.digest(source),
        "linker_sha256": helpers.digest(linker_script), "elf_sha256": helpers.digest(output),
    }, indent=2) + "\n")
    return output


def qemu_command(arch: str, kernel: Path, image: Path) -> list[str]:
    qemu = shutil.which(ARCHES[arch]["qemu"])
    if not qemu:
        raise ValueError(f"missing {ARCHES[arch]['qemu']}")
    command = [qemu, "-machine", "virt", "-kernel", str(kernel), "-m", "8G", "-nographic", "-smp", "8"]
    if arch == "riscv64":
        command += ["-cpu", "max", "-bios", "default"]
    command += ["-drive", f"file={image},if=none,format=raw,id=x0,snapshot=on"]
    if arch == "riscv64":
        command += ["-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0", "-no-reboot",
                    "-device", "virtio-net-device,netdev=net", "-netdev", "user,id=net"]
    else:
        command += ["-device", "virtio-blk-pci,drive=x0", "-no-reboot",
                    "-device", "virtio-net-pci,netdev=net0", "-netdev", "user,id=net0"]
    return command + ["-rtc", "base=utc"]


def cases_script(directory: str, suite: str, duration: int, *, kernel_elf: bool = True) -> tuple[str, list[str], list[str]]:
    """Return a reproducible script plus expected successful/failed CLI calls."""
    recorder = shlex.quote(directory + "/bpf-record")
    if kernel_elf:
        recorder += " --kernel-elf /boot/kernel.elf"
    fixture = shlex.quote(directory + "/record-fixture")
    rows = ["#!/bin/sh", "set -u", "ulimit -c 0", f"cd {shlex.quote(directory)} || exit 1"]
    captures: list[str] = []
    failures: list[str] = []

    def call(label: str, arguments: str, *, failure: bool = False, capture: bool = True) -> None:
        rows.extend([f"echo RECORD_CASE BEGIN name={label}", f"{recorder} {arguments}", "rc=$?",
                     f'echo RECORD_CASE END name={label} rc="$rc"'])
        if failure:
            failures.append(label)
        elif capture:
            captures.append(label)
            rows.append(f"{fixture} dump {label}.pbcapture {label} || exit 1")

    def stats(phase: str, point: str) -> None:
        rows.extend([f"echo BENCH_STATS BEGIN phase={phase} point={point}",
                     "cat /proc/pulse_bpf_stats || exit 1",
                     f"echo BENCH_STATS END phase={phase} point={point}"])

    def record(label: str, events: str, workload: str, *, extra: str = "", task: bool = False,
               signal: int | None = None, target_exit: bool = False, cpus: str = "all",
               period: int = 10_000_000, buffer_pages: int = 16) -> None:
        work_ms = duration + (10_000 if label == "mixed" else 1500)
        rows.extend([f"{fixture} {workload} {work_ms} {label} &", "target=$!", f"{fixture} sleep 100"])
        record_ms = max(3000, duration * 4) if signal is not None else (work_ms + 3000 if target_exit else duration)
        options = f"--events {events} --duration-ms {record_ms} --buffer-pages {buffer_pages} --output {label}.pbcapture"
        if task:
            options += ' --tid "$target"'
        if events != "task":
            options += f" --cpus {cpus}"
        if "cpu" in events or "task" in events:
            options += f" --period-ns {period}"
        if extra:
            options += " " + extra
        if signal is None:
            call(label, options)
        else:
            # A separate process sends an actual signal after the recorder has
            # had time to prepare; the recorder owns its normal shutdown path.
            rows.extend([f"echo RECORD_CASE BEGIN name={label}", f"{recorder} {options} >{label}.log 2>&1 &", "record_pid=$!",
                         "ready_waits=0", f"while ! grep -q '^RECORD ENABLE ' {label}.log; do",
                         f"  {fixture} sleep 10", "  ready_waits=$((ready_waits+1))",
                         f"  if [ \"$ready_waits\" -ge 500 ]; then cat {label}.log; exit 1; fi", "done",
                         f"{fixture} sleep {max(100, duration // 2)}", f'kill -{signal} "$record_pid"',
                         'wait "$record_pid"', "rc=$?", f"cat {label}.log", f'echo RECORD_CASE END name={label} rc="$rc"',
                         f"{fixture} dump {label}.pbcapture {label} || exit 1"])
            captures.append(label)
        rows.append('wait "$target" || exit 1')

    if suite in ("smoke", "full"):
        for mode in ("cpu", "sched", "fault"):
            record(mode, mode, mode)
    if suite == "existing":
        for mode in ("cpu", "sched", "fault"):
            label = "existing-" + mode
            command = (
                "command -v dd >/dev/null && command -v sleep >/dev/null || exit 1; "
                f"echo EXISTING_WORKLOAD READY mode={mode} pid=$$; "
                f"while [ ! -e {label}.stop ]; do "
                "dd if=/dev/zero of=/dev/null bs=1M count=2 2>/dev/null "
                "|| { echo EXISTING_WORKLOAD_FAIL; exit 1; }; sleep 0.01 || exit 1; done"
            )
            rows.extend([f"sh -c {shlex.quote(command)} >{label}-workload.log 2>&1 &", "target=$!",
                         f"{fixture} sleep 100", 'kill -0 "$target" || exit 1'])
            options = f"--events {mode} --cpus all --duration-ms {duration} --buffer-pages 16 --record-bytes 131072 --output {label}.pbcapture"
            if mode == "cpu":
                options += " --period-ns 10000000"
            # Kernel exec logging from the fork workload can interleave at byte
            # granularity on serial. Persist control text to a real file while
            # recording, then stop/reap the workload before replay or file dump.
            rows.extend([f"echo RECORD_CASE BEGIN name={label} >{label}-record.log",
                         f"{recorder} {options} >>{label}-record.log 2>&1", "rc=$?",
                         f'echo RECORD_CASE END name={label} rc="$rc" >>{label}-record.log',
                         'kill -0 "$target" || exit 1', f": > {label}.stop", 'wait "$target" || exit 1',
                         f"cat {label}-record.log", f"cat {label}-workload.log",
                         f"if grep -q EXISTING_WORKLOAD_FAIL {label}-workload.log; then exit 1; fi",
                         f"{fixture} dump {label}.pbcapture {label} || exit 1"])
            captures.append(label)
    if suite == "recovery":
        record("task", "task", "cpu", task=True)
        rows.extend(["rm -f exec-thread.tid exec-thread.go",
                     f"{fixture} exec-thread {duration} >exec-thread-workload.log 2>&1 &", "target=$!", "ready_waits=0",
                     "while [ ! -s exec-thread.tid ]; do", f"  {fixture} sleep 10", "  ready_waits=$((ready_waits+1))",
                     '  if [ "$ready_waits" -ge 500 ]; then cat exec-thread-workload.log; exit 1; fi', "done",
                     'initial_tid=$(cat exec-thread.tid)', "echo RECORD_CASE BEGIN name=nonleader-exec",
                     f'{recorder} --events task --tid "$initial_tid" --duration-ms 10000 --output nonleader-exec.pbcapture >nonleader-exec.log 2>&1 &',
                     "record_pid=$!", "ready_waits=0", "while ! grep -q '^RECORD ENABLE ' nonleader-exec.log; do",
                     f"  {fixture} sleep 10", "  ready_waits=$((ready_waits+1))",
                     '  if [ "$ready_waits" -ge 500 ]; then cat nonleader-exec.log; exit 1; fi', "done",
                     f"{fixture} sleep 300", ": > exec-thread.go", 'wait "$record_pid"', "rc=$?",
                     "cat nonleader-exec.log", 'echo RECORD_CASE END name=nonleader-exec rc="$rc"',
                     'wait "$target" || exit 1', "cat exec-thread-workload.log",
                     f"{fixture} dump nonleader-exec.pbcapture nonleader-exec || exit 1"])
        captures.append("nonleader-exec")
        rows.extend([f"{fixture} cpu {duration + 1500} stop-failure &", "target=$!", f"{fixture} sleep 100"])
        call("stop-failure", f"--events cpu --cpus all --duration-ms {duration} --output stop-failure.pbcapture --test-stop-failure", failure=True)
        captures.append("stop-failure")
        rows.extend([f"{fixture} dump stop-failure.pbcapture stop-failure || exit 1", 'wait "$target" || exit 1'])
    if suite in ("lifecycle", "full"):
        record("task", "task", "cpu", task=True)
        record("dup-close", "task", "cpu", task=True, extra="--test-dup-close")
        record("bounded-export", "cpu", "cpu", cpus="0,1", period=1_000_000,
               buffer_pages=1, extra="--record-bytes 4096")
        # An installed shell is an existing guest program, distinct from the
        # independent regression fixture and from the recorder itself.
        rows.extend(["sh -c 'i=0; while :; do i=$((i+1)); done' &", "target=$!", f"{fixture} sleep 100"])
        call("existing-shell", f'--events task --tid "$target" --duration-ms {duration} --frequency 99 --output existing-shell.pbcapture')
        rows.extend(['kill "$target"', 'wait "$target" || true'])
        record("sigint", "cpu", "cpu", signal=2)
        record("sigterm", "fault", "fault", signal=15)
        record("target-exit", "task", "cpu", task=True, target_exit=True)
    if suite in ("mixed", "lifecycle", "full"):
        record("mixed", "cpu,cpu,task,sched,fault", "mixed", task=True)
    if suite == "stacks":
        record("stack-task", "task", "cpu", task=True, extra="--callchain fp --stack-depth 32")
        record("mixed", "cpu,cpu,task,sched,fault", "mixed", task=True, extra="--callchain fp")
        rows.extend(["sh -c 'i=0; while :; do i=$((i+1)); done' &", "target=$!", f"{fixture} sleep 100"])
        call("existing-shell", f'--events task --tid "$target" --duration-ms {duration} --frequency 99 --callchain fp --output existing-shell.pbcapture')
        rows.extend(['kill "$target"', 'wait "$target" || true'])
        record("sigint", "cpu", "cpu", signal=2, extra="--callchain fp")
        record("target-exit", "task", "cpu", task=True, target_exit=True, extra="--callchain fp")
        record("bounded-export", "cpu", "cpu", cpus="0,1", period=1_000_000,
               buffer_pages=1, extra="--record-bytes 4096 --callchain fp")
        call("snapshot-failure", f"--events cpu --duration-ms {duration} --output rejected.pbcapture --test-fail-snapshot", failure=True)
        rows.extend([f"{fixture} cpu {duration + 1500} journal-failure &", "target=$!", f"{fixture} sleep 100"])
        call("journal-failure", f"--events cpu --duration-ms {duration} --output journal-failure.pbcapture --test-fail-journal", failure=True)
        captures.append("journal-failure")
        rows.extend([f"{fixture} dump journal-failure.pbcapture journal-failure || exit 1", 'wait "$target" || exit 1'])
    if suite == "mapping":
        rows.extend(["rm -f mapping.go", f"./mapping-fixture mapping >mapping-workload.log 2>&1 &", "target=$!",
                     "echo RECORD_CASE BEGIN name=mapping-lifecycle",
                     f'{recorder} --events cpu,task --tid "$target" --duration-ms 10000 --callchain fp --output mapping-lifecycle.pbcapture >mapping-record.log 2>&1 &',
                     "record_pid=$!", "ready_waits=0", "while ! grep -q '^RECORD ENABLE ' mapping-record.log; do",
                     f"  {fixture} sleep 10", "  ready_waits=$((ready_waits+1))",
                     '  if [ "$ready_waits" -ge 500 ]; then cat mapping-record.log; exit 1; fi', "done",
                     ": > mapping.go", 'wait "$record_pid"', "rc=$?", "cat mapping-record.log",
                     'echo RECORD_CASE END name=mapping-lifecycle rc="$rc"', 'wait "$target" || exit 1',
                     "cat mapping-workload.log", f"{fixture} dump mapping-lifecycle.pbcapture mapping-lifecycle || exit 1"])
        captures.append("mapping-lifecycle")
    if suite in ("negative", "full"):
        base = f"--events cpu --duration-ms {duration} --output rejected.pbcapture"
        for label, options in (
            ("no-args", ""), ("offline-cpu", base + " --cpus 4095"),
            ("duplicate-cpu", base + " --cpus 0,0"),
            ("zero-frequency", base + " --frequency 0"),
            ("conflicting-rate", base + " --frequency 99 --period-ns 10000000"),
            ("unsupported-scope", base + " --children"),
            ("bad-buffer", base + " --buffer-pages 3"),
            ("unsupported-callchain", base + " --callchain dwarf"),
            ("unsupported-stack-depth", base + " --callchain fp --stack-depth 31"),
            ("task-without-tid", f"--events task --duration-ms {duration} --output rejected.pbcapture"),
            ("load2", f"--events sched --cpus 0 --duration-ms {duration} --output rejected.pbcapture --test-fail-load 2"),
            ("attach2", f"--events sched --cpus 0 --duration-ms {duration} --output rejected.pbcapture --test-fail-attach 2"),
        ):
            call(label, options, failure=True)
        rows.extend([f"{fixture} cpu {duration + 1500} write-failure &", "target=$!", f"{fixture} sleep 100"])
        call("write-failure", f"--events cpu --cpus all --duration-ms {duration} --output write-failure.pbcapture --test-write-fail-after 1024", failure=True)
        rows.extend([f"{fixture} dump write-failure.pbcapture write-failure || exit 1", 'wait "$target" || exit 1'])
    if suite in ("benchmark", "full"):
        stats("baseline", "before")
        rows.append(f"{fixture} cpu {duration + 1500} baseline || exit 1")
        stats("baseline", "after")
        rows.extend([f"{fixture} cpu {duration + 1500} loaded_detached &", "target=$!", f"{fixture} sleep 100"])
        call("loaded-detached", f"--events cpu --cpus all --duration-ms {duration} --test-detached {duration} --output detached.pbcapture", capture=False)
        rows.append('wait "$target" || exit 1')
        stats("attached", "before")
        record("attached", "cpu", "cpu")
        stats("attached", "after")
    rows.append("exit 0")
    return "\n".join(rows) + "\n", captures, failures


def parse_cases(text: str) -> dict[str, dict]:
    cases: dict[str, dict] = {}
    current: str | None = None
    rows: list[str] = []
    for row in clean_console(text).splitlines():
        start = re.fullmatch(r"RECORD_CASE BEGIN name=([\w-]+)", row)
        end = re.fullmatch(r"RECORD_CASE END name=([\w-]+) rc=(\d+)", row)
        if start:
            if current or start[1] in cases:
                raise ValueError("overlapping or repeated CLI case")
            current, rows = start[1], []
        elif end:
            if end[1] != current:
                raise ValueError("CLI case end has no matching start")
            cases[current] = {"rc": int(end[2]), "log": "\n".join(rows)}
            current = None
        elif current:
            rows.append(row)
    if current:
        raise ValueError(f"unterminated CLI case: {current}")
    return cases


def validate_case(label: str, case: dict, expected_failure: bool) -> list[str]:
    errors = []
    text = case["log"]
    if expected_failure:
        if case["rc"] == 0:
            errors.append(f"{label}: invalid request succeeded")
        if label not in ("write-failure", "stop-failure", "journal-failure") and re.search(r"(?m)^RECORD ENABLE ", text):
            errors.append(f"{label}: rejected request enabled a source")
    elif case["rc"]:
        errors.append(f"{label}: recorder exited {case['rc']}")
    else:
        if "RECORD PREPARED " not in text:
            errors.append(f"{label}: missing attached-disabled preparation evidence")
        if label != "loaded-detached" and "RECORD STOP " not in text:
            errors.append(f"{label}: missing stop evidence")
    if label in ("load2", "attach2", "write-failure", "stop-failure", "snapshot-failure", "journal-failure") or not expected_failure:
        cleanup = re.search(r"(?m)^RECORD (?:CLEANUP|ROLLBACK) (.*)$", text)
        if not cleanup:
            errors.append(f"{label}: missing cleanup evidence")
        else:
            fields = dict(item.split("=", 1) for item in cleanup[1].split() if "=" in item)
            for resource in ("fds", "mapped", "events", "programs", "registered", "subscriptions"):
                before, after = fields.get(resource + "_before"), fields.get(resource + "_after")
                if before is None or before != after:
                    errors.append(f"{label}: missing or unequal {resource} before/after cleanup")
                if resource in ("registered", "subscriptions") and fields.get(resource + "_settled") != before:
                    errors.append(f"{label}: {resource} changed after cleanup settled")
    if label == "loaded-detached" and re.search(r"(?m)^RECORD ENABLE ", text):
        errors.append("loaded-detached: benchmark phase enabled a source")
    if label == "dup-close" and "RECORD DUP_CLOSE originals_closed=1 retained=1" not in text:
        errors.append("dup-close: missing original-FD close evidence")
    if label == "write-failure" and ("RECORD STOP " not in text or "RECORD SAVED " in text):
        errors.append("write-failure: did not stop sampling or claimed successful persistence")
    if (not expected_failure and label != "loaded-detached") or label in ("stop-failure", "journal-failure"):
        stable = re.search(r"(?m)^RECORD NO_GROWTH before=(\d+) after=(\d+)", text)
        if not stable or stable[1] != stable[2]:
            errors.append(f"{label}: continued output after disable/quiescence")
    if label == "stop-failure" and ("RECORD STOP " not in text or "RECORD SAVED " not in text):
        errors.append("stop-failure: failed to preserve stopped partial capture")
    reasons = {"sigint": "signal:2", "sigterm": "signal:15", "target-exit": "target-exit", "nonleader-exec": "target-exit"}
    if label in reasons and f"reason={reasons[label]}" not in text:
        errors.append(f"{label}: stop reason was not {reasons[label]}")
    return errors


def validate_report(label: str, report: dict) -> list[str]:
    """Require source-resolved actual samples, independently of success text."""
    errors = []
    if report.get("records_count", 0) <= 0:
        errors.append(f"{label}: no real records consumed by analyzer")
    recorder = report.get("recorder")
    if not recorder or not recorder.get("sources"):
        return errors + [f"{label}: missing explicit source metadata"]
    sources = recorder["sources"]
    ids = [source["logical_source"] for source in sources]
    bindings = recorder.get("record_sources", [])
    counts = Counter(bindings)
    if (len(ids) != len(set(ids)) or len(bindings) != report["records_count"]
            or set(counts) - set(ids)
            or any(counts[source["logical_source"]] != source["records_count"] for source in sources)):
        errors.append(f"{label}: source counts do not explain consumed records")
    observed = [source for source in sources if source["records_count"] > 0]
    if label == "mixed":
        software = Counter((source["cpu"], source["event_id"]) for source in observed
                           if source["kind"] in ("software-v2", "software-stack-v3") and source["cpu"] is not None)
        trace_ids = {source["event_id"] for source in observed if source["kind"] == "tracepoint"}
        if not software or max(software.values()) < 2 or not {6, 8} <= trace_ids:
            errors.append("mixed: missing repeated software sources or equal-length trace/fault contexts")
    elif label in ("fault", "sigterm", "existing-fault"):
        if not any(source["kind"] == "tracepoint" and source["event_id"] == 8 for source in observed):
            errors.append(f"{label}: no actual fault records")
    elif label in ("sched", "existing-sched"):
        if not {2, 3, 4, 6} <= {source["event_id"] for source in observed if source["kind"] == "tracepoint"}:
            errors.append("sched: missing switch/block/wake/enqueue records")
    elif not any(source["kind"] in ("software-v2", "software-stack-v3") for source in observed):
        errors.append(f"{label}: no actual software samples")
    if label == "bounded-export":
        counters = report.get("runtime_diagnostics", {}).get("counters", [])
        dropped = [counter for counter in counters if counter["name"] == "export_discarded"
                   and counter["kind"] == "loss" and (counter["value"] or 0) > 0]
        if not dropped or report.get("is_complete") is not False:
            errors.append("bounded-export: missing actual retained-budget loss or false completeness")
    if label == "existing-shell":
        if not sources or any(
            source.get("requested_frequency_hz") != 99
            or source.get("requested_sample_period") != 0
            or source.get("period") != 10101011
            or source.get("requested_config") != "task-clock"
            or source.get("config") != "task-clock"
            or source.get("unit") != "nanoseconds"
            or source.get("fallback") != "none"
            for source in sources
        ):
            errors.append("existing-shell: requested frequency/effective period/fallback were not preserved")
    if label in ("stop-failure", "journal-failure"):
        counters = report.get("runtime_diagnostics", {}).get("counters", [])
        if (report.get("is_complete") is not False
                or not any(counter["name"] == "control_errors" and counter["kind"] == "error"
                           and (counter["value"] or 0) > 0 for counter in counters)):
            errors.append(f"{label}: failed control operation was not recorded as partial/error")
    return errors


def verify_exec_identity(text: str, report: dict, timeline: dict) -> dict:
    text = clean_console(text)
    ready = re.search(r"(?m)^EXEC_THREAD READY parent_tid=(\d+) initial_tid=(\d+)$", text)
    exec_at = re.search(r"(?m)^EXEC_THREAD EXEC initial_tid=(\d+) at_ns=(\d+)$", text)
    after = re.search(r"(?m)^WORKLOAD RESULT label=exec-after mode=cpu pid=(\d+) start_ns=(\d+) stop_ns=(\d+) ", text)
    sources = report.get("recorder", {}).get("sources", [])
    if not ready or not exec_at or not after or len(sources) != 1:
        raise ValueError("nonleader exec lacks real fixture/source evidence")
    parent, initial = int(ready[1]), int(ready[2])
    source = sources[0]
    bound = source.get("bound_task_id")
    if (parent == initial or int(exec_at[1]) != initial or int(after[1]) != parent
            or source["tid"] != initial or not bound):
        raise ValueError("nonleader exec did not preserve a stable original task binding")
    events = timeline["events"]
    if any(event["task_id"] != bound for event in events):
        raise ValueError("nonleader exec source contains a different task identity")
    before_samples = [event for event in events if event["tid"] == initial and event["timestamp_ns"] < int(exec_at[2])]
    after_samples = [event for event in events if event["tid"] == parent and event["timestamp_ns"] >= int(after[2])]
    if not before_samples or not after_samples or source["disable_before_ns"] < int(after[3]):
        raise ValueError("recorder stopped at old numeric TID disappearance or lacks pre/post exec samples")
    return {"initial_tid": initial, "effective_tid_after_exec": parent, "bound_task_id": bound,
            "samples_before_exec": len(before_samples), "samples_after_exec": len(after_samples),
            "exec_ns": int(exec_at[2]), "post_exec_workload_stop_ns": int(after[3]),
            "source_disable_before_ns": source["disable_before_ns"]}


def verify_existing_workload(text: str, timeline: dict, label: str) -> dict:
    """Tie observed records to the installed workload's actual execution IDs."""
    mode = label.removeprefix("existing-")
    text = clean_console(text)
    ready = re.search(rf"(?m)^EXISTING_WORKLOAD READY mode={mode} pid=(\d+)$", text)
    # The enabled kernel logs each actual exec's current task ID. The installed
    # dd processes are single-threaded, so this is also their numeric TID.
    dd_tids = {int(match[1]) for match in re.finditer(
        r'\[\s*[\d.]+\s+\d+:(\d+)\s+[^\]]+\]\s+sys_execve: path="(?:/usr)?/bin/dd"', text)}
    if not ready or not dd_tids or "EXISTING_WORKLOAD_FAIL" in text:
        raise ValueError(f"{label}: missing actual installed shell/dd execution evidence")
    subjects = dd_tids | {int(ready[1])}
    ids = {0x1001, 0x1002} if mode == "cpu" else ({8} if mode == "fault" else {1, 2, 3, 4, 5, 6})
    observed = [event for event in timeline["events"] if event["event_id"] in ids and event["tid"] in subjects]
    if not observed:
        raise ValueError(f"{label}: capture has no events attributed to the actual shell/dd workload")
    return {"shell_tid": int(ready[1]), "dd_exec_tids": sorted(dd_tids),
            "attributed_records": len(observed), "observed_workload_tids": sorted({e["tid"] for e in observed})}


def benchmark_stats(text: str) -> dict:
    """Keep system counters separate from source loss; absent is never zero."""
    groups: dict[str, dict] = {}
    active = None
    expected_bytes = None
    body: list[str] = []
    for row in clean_console(text).splitlines():
        begin = re.fullmatch(r"(?:BENCH_STATS|RECORD_STATS) BEGIN phase=(\w+) point=(before|after)(?: bytes=(\d+))?", row)
        end = re.fullmatch(r"(?:BENCH_STATS|RECORD_STATS) END phase=(\w+) point=(before|after)", row)
        if begin:
            if active is not None:
                raise ValueError("overlapping benchmark snapshots")
            active, body = (begin[1], begin[2]), []
            expected_bytes = int(begin[3]) if begin[3] else None
        elif end:
            if active != (end[1], end[2]):
                raise ValueError("benchmark snapshot terminator mismatch")
            rows = [r for r in body if r.startswith(("PULSE_BPF_STATS ", "GLOBAL ", "EVENT ", "PROGRAM ", "END "))]
            if len(rows) < 3 or not rows[0].startswith("PULSE_BPF_STATS ") or not rows[-1].startswith("END "):
                raise ValueError("missing benchmark diagnostics header/trailer")
            raw = "\n".join(rows) + "\n"
            if expected_bytes is not None and len(raw.encode()) != expected_bytes:
                raise ValueError("benchmark snapshot byte length mismatch")
            def fields(line):
                result = {}
                for word in line.split()[1:]:
                    key, value = word.split("=", 1)
                    if key in result:
                        raise ValueError("duplicate benchmark diagnostic field")
                    result[key] = int(value) if value.isdigit() else value
                return result
            header = fields(rows[0])
            global_rows = [r for r in rows if r.startswith("GLOBAL ")]
            if len(global_rows) != 1 or header.get("available") != 1:
                raise ValueError("benchmark diagnostics unavailable")
            global_fields = fields(global_rows[0])
            required = {"timer_enqueued", "timer_dequeued", "timer_full", "timer_busy", "trace_enqueued",
                        "trace_full", "trace_recursive", "fault_started", "fault_completed", "fault_clock_errors"}
            if not required <= global_fields.keys() or not all(isinstance(v, int) for v in global_fields.values()):
                raise ValueError("missing benchmark global counter")
            if not all(isinstance(header.get(key), int) for key in ("registered_events", "trace_subscriptions")):
                raise ValueError("missing benchmark resource counter")
            events = [fields(r) for r in rows if r.startswith("EVENT ")]
            programs = [fields(r) for r in rows if r.startswith("PROGRAM ")]
            footer = fields(rows[-1])
            if footer.get("events") != len(events) or footer.get("programs") != len(programs):
                raise ValueError("benchmark diagnostics count mismatch")
            group = groups.setdefault(active[0], {})
            if active[1] in group:
                raise ValueError("duplicate benchmark snapshot")
            group[active[1]] = {"header": header, "global": global_fields, "events": events,
                                "programs": programs, "footer": footer, "raw": raw}
            active = None
        elif active is not None:
            body.append(row)
    if active is not None:
        raise ValueError("unfinished benchmark snapshot")
    for phase, group in groups.items():
        if set(group) != {"before", "after"}:
            raise ValueError(f"benchmark {phase} missing before/after snapshots")
        before, after = group["before"]["global"], group["after"]["global"]
        if before.keys() != after.keys() or any(after[key] < value for key, value in before.items()):
            raise ValueError("benchmark counters missing or regressed")
        group["global_counter_deltas"] = {key: after[key] - value for key, value in before.items()}
        group["scope"] = "system counters include all activity and overlapping source/worker layers; not additive loss"
        group["process_resource_scope"] = "EVENT/PROGRAM rows belong to the proc snapshot reader, not total guest memory"
    return groups


def benchmark(text: str, cases: dict, reports: dict, *, require_stats: bool = True) -> dict:
    rows = {}
    pattern = re.compile(r"(?m)^WORKLOAD RESULT label=(\S+) mode=(\S+) pid=(\d+) start_ns=(\d+) stop_ns=(\d+) wall_ns=(\d+) iterations=(\d+)$")
    for match in pattern.finditer(clean_console(text)):
        name, mode, pid, start, stop, wall, iterations = match.groups()
        if name not in ("baseline", "loaded_detached", "attached"):
            continue
        if name in rows or int(stop) - int(start) != int(wall) or int(wall) <= 0 or int(iterations) <= 0:
            raise ValueError("invalid benchmark measurement")
        rows[name] = {"mode": mode, "pid": int(pid), "start_ns": int(start), "stop_ns": int(stop),
                      "wall_ns": int(wall), "iterations": int(iterations),
                      "iterations_per_second": int(iterations) * 1e9 / int(wall)}
    if rows:
        if set(rows) != {"baseline", "loaded_detached", "attached"}:
            raise ValueError("three-stage benchmark is incomplete")
        baseline = rows["baseline"]["iterations_per_second"]
        snapshots = benchmark_stats(text)
        if require_stats and set(snapshots) != set(rows):
            raise ValueError("three-stage benchmark lacks actual system/resource/loss snapshots")
        for name, row in rows.items():
            row["system_diagnostics"] = snapshots.get(name)
            row["throughput_ratio_to_baseline"] = row["iterations_per_second"] / baseline
            row["throughput_delta_percent"] = 100 * (row["throughput_ratio_to_baseline"] - 1)
            label = "loaded-detached" if name == "loaded_detached" else name
            row["resource_evidence"] = [r for r in cases.get(label, {}).get("log", "").splitlines()
                                        if r.startswith(("RECORD PREPARED ", "RECORD RESOURCES ", "RECORD CLEANUP "))]
            row["runtime_diagnostics"] = reports.get(label, {}).get("runtime_diagnostics")
            row["measurement_scope"] = "whole external workload, including preparation/teardown margins; not steady-state overhead"
            if name == "attached":
                windows = []
                for source in reports.get(label, {}).get("recorder", {}).get("sources", []):
                    begin, end = source["enable_after_ns"], source["disable_before_ns"]
                    overlap = max(0, min(row["stop_ns"], end) - max(row["start_ns"], begin))
                    windows.append({"logical_source": source["logical_source"], "enabled_after_ns": begin,
                                    "disabled_before_ns": end, "overlap_ns": overlap,
                                    "workload_wall_fraction": overlap / row["wall_ns"]})
                row["source_window_overlap"] = windows
                if not windows or any(window["overlap_ns"] <= 0 for window in windows):
                    raise ValueError("attached benchmark has no measured overlap with a source")
            if name == "loaded_detached":
                phase_log = cases.get(label, {}).get("log", "")
                start = re.search(r"(?m)^RECORD DETACHED start_ns=(\d+) ", phase_log)
                end = re.search(r"(?m)^RECORD DETACHED_END stop_ns=(\d+)", phase_log)
                if not start or not end:
                    raise ValueError("loaded-detached benchmark lacks measured boundaries")
                overlap = max(0, min(row["stop_ns"], int(end[1])) - max(row["start_ns"], int(start[1])))
                row["detached_overlap_ns"] = overlap
                row["workload_wall_fraction"] = overlap / row["wall_ns"]
                if not overlap:
                    raise ValueError("loaded-detached benchmark did not overlap workload")
    return rows


def install(image: Path, source: Path, destination: str, run: Path) -> None:
    helpers.debugfs(image, f'write "{source}" {destination}', write=True)
    helpers.debugfs(image, f"set_inode_field {destination} mode 0100755", write=True)
    check = run / ("injected-" + Path(destination).name)
    helpers.debugfs(image, f'dump {destination} "{check}"')
    if helpers.digest(check) != helpers.digest(source):
        raise ValueError("injected artifact bytes differ")
    check.unlink()


def kernel_identity(kernel: Path, run: Path) -> Path:
    """For a raw RV boot image, require its matching build-provenance ELF."""
    if kernel.read_bytes()[:4] == b"\x7fELF":
        elf = kernel
    else:
        elf = kernel.with_suffix(".elf")
        provenance = elf.with_suffix(elf.suffix + ".provenance.json")
        facts = json.loads(provenance.read_text())["artifacts"]
        if (facts["binary"]["sha256"] != helpers.digest(kernel)
                or facts["elf"]["sha256"] != helpers.digest(elf)):
            raise ValueError("kernel ELF differs from boot binary provenance")
        shutil.copyfile(provenance, run / "kernel.provenance.json")
    output = run / "kernel.elf"
    shutil.copyfile(elf, output)
    return output


def verify_saved_hash(case: dict, raw: bytes) -> str:
    matches = re.findall(r"(?m)^RECORD SAVED .*\bsha256=([0-9a-f]{64})(?:\s|$)", case["log"])
    digest = collection.sha256(raw)
    if matches != [digest]:
        raise ValueError("host capture SHA differs from the synced guest file witness")
    return digest


def stack_proof(timeline: dict, report: dict, collection_report: dict, *, require_depth: bool) -> dict:
    events = [event for event in timeline["events"] if event.get("event_id") == 0x1002]
    depths = {mode: [event["semantic"]["chain_len"] for event in events if event["semantic"]["mode"] == mode]
              for mode in (1, 2)}
    if not events or any(event["semantic"]["chain_len"] != len(event["semantic"]["ips"]) for event in events):
        raise ValueError("missing real bounded stack payloads")
    if require_depth and max(depths[2], default=0) < 3:
        raise ValueError("external target has no observed user chain of at least three frames")
    manifest = collection_report["captured_manifest"]
    if not manifest["mapping_metadata"] or manifest["coverage"] is None:
        raise ValueError("original guest capture has no temporal mapping coverage")
    coverage = manifest["coverage"]
    if any(source["enable_before_ns"] < coverage["started_ns"] or source["disable_after_ns"] >= coverage["snapshot_ns"]
           for source in report["recorder"]["sources"]):
        raise ValueError("mapping journal does not cover every source enable/disable boundary")
    counters = {item["name"]: item["value"] for item in report["runtime_diagnostics"]["counters"]}
    initial = counters.get("mapping_initial_snapshot_ns")
    if initial is None or any(int(initial) > source["enable_before_ns"] for source in report["recorder"]["sources"]):
        raise ValueError("initial mapping snapshot was not established before enable")
    if manifest["kernel"] is None:
        raise ValueError("guest did not verify the deployed kernel ELF identity")
    kernel_sha = manifest["kernel"]["sha256"]
    if not any(item["sha256"] == kernel_sha and item["status"] == "verified" for item in collection_report["artifacts"]):
        raise ValueError("host did not collect the matching kernel ELF")
    return {"stack_samples": len(events), "max_user_depth": max(depths[2], default=0),
            "max_kernel_depth": max(depths[1], default=0), "initial_snapshot_ns": int(initial),
            "coverage": coverage, "termination_counts": dict(Counter(event["semantic"]["termination"] for event in events))}


def mapping_lifecycle_proof(text: str, manifest: dict) -> dict:
    """Match actual syscall markers to the original, analyzer-validated journal."""
    complete = re.search(r"(?m)^MAPPING COMPLETE pid=(\d+) child=(\d+) old=(\d+) moved=(\d+) at_ns=(\d+)$", clean_console(text))
    if complete is None:
        raise ValueError("mapping lifecycle workload did not complete")
    parent, child, old, moved, _ = map(int, complete.groups())
    entries, spaces = [], []
    lines = iter(manifest["journal"].splitlines()[1:-1])
    for line in lines:
        tag, *words = line.split()
        row = dict(word.split("=", 1) for word in words)
        row["kind_tag"] = tag
        if tag == "SPACE":
            row["maps"] = [dict(word.split("=", 1) for word in next(lines).split()[1:]) for _ in range(int(row["count"]))]
            if next(lines) != "ENDSPACE":
                raise ValueError("mapping journal snapshot boundary missing")
            spaces.append(row)
        entries.append(row)
    tasks = [row for row in entries if row["kind_tag"] == "TASK"]
    parent_rows = [row for row in tasks if int(row["pid"]) == parent]
    child_rows = [row for row in tasks if int(row["pid"]) == child]
    if not {"rename", "exit"} <= {row["kind"] for row in parent_rows} or not {"fork", "exec", "exit"} <= {row["kind"] for row in child_rows}:
        raise ValueError("original journal lacks actual fork/exec/rename/exit lifecycle")
    parent_tasks, child_tasks = {row["task"] for row in parent_rows}, {row["task"] for row in child_rows}
    if len(parent_tasks) != 1 or len(child_tasks) != 1 or parent_tasks == child_tasks:
        raise ValueError("parent and fork child did not retain distinct stable task identities")
    fork, executed = next(row for row in child_rows if row["kind"] == "fork"), next(row for row in child_rows if row["kind"] == "exec")
    if fork["space"] == executed["space"] or int(fork["exec"]) >= int(executed["exec"]):
        raise ValueError("real exec did not replace address space/generation")
    markers = {}
    for match in re.finditer(r"(?m)^MAPPING STEP (.*)$", clean_console(text)):
        row = dict(word.split("=", 1) for word in match[1].split())
        markers[row["phase"]] = row
    parent_space = parent_rows[0]["space"]

    def mappings(phase):
        time = int(markers[phase]["at_ns"])
        observed = [row for row in spaces if row["space"] == parent_space and int(row["ts"]) < time]
        if not observed:
            raise ValueError("mapping phase has no time-valid snapshot")
        return observed[-1]["maps"]

    def at(rows, address):
        return next((row for row in rows if int(row["start"]) <= address < int(row["start"]) + int(row["len"])), None)

    initial, renamed = at(mappings("mapped"), old), at(mappings("renamed"), old)
    remapped, reused = at(mappings("remapped"), moved), at(mappings("reused_address"), old)
    if not initial or not renamed or not remapped or not reused:
        raise ValueError("actual mapping transitions lack snapshots")
    if (int(initial["object"]) == 0 or {initial["object"], renamed["object"], remapped["object"]} != {initial["object"]}
            or int(initial["pgoff"]) != 4096 or int(remapped["pgoff"]) != 4096
            or int(reused["object"]) != 0 or at(mappings("remapped"), old) is not None):
        raise ValueError("rename/remap/address reuse borrowed stale object or file offset")
    return {"parent_pid": parent, "child_pid": child, "parent_task": next(iter(parent_tasks)),
            "child_task": next(iter(child_tasks)), "fork_space": fork["space"], "exec_space": executed["space"],
            "mapped_object": initial["object"], "byte_pgoff": 4096, "address_reused": old,
            "numeric_pid_reuse": "not observed; allocator reuse covered by adversarial analyzer tests"}


def guest(args: argparse.Namespace) -> int:
    fixture = build_fixture(args.arch)
    if args.recorder:
        recorder = args.recorder.resolve(strict=True)
    else:
        helpers.command([sys.executable, str(REPO / "tools/bpf-record/build.py"), "--arch", args.arch, "--acceptance"], cwd=REPO, timeout=180)
        recorder = REPO / "tools/bpf-record/build" / args.arch / "acceptance/bpf-record"
    helpers.check_elf(recorder, args.arch)
    kernel = (args.kernel or REPO / ARCHES[args.arch]["kernel"]).resolve(strict=True)
    image = helpers.check_image(args.image or REPO / ARCHES[args.arch]["primary"])
    run = helpers.new_run(f"{args.arch}-{args.suite}")
    for source, name in ((recorder, "bpf-record.elf"), (fixture, "record-fixture.elf"), (kernel, "kernel")):
        shutil.copyfile(source, run / name)
    kernel_elf = kernel_identity(kernel, run)
    # Freeze the host consumer alongside the guest producer. Development runs
    # can outlive source edits, so rebuilding only after QEMU exits could pair
    # a new unpublished wire layout with an older copied producer.
    helpers.command(["cargo", "build", "-p", "bpf-analyzer"], cwd=REPO, timeout=180)
    shutil.copyfile(REPO / "target/debug/bpf-analyzer", run / "bpf-analyzer")
    (run / "bpf-analyzer").chmod(0o755)
    for source, name in ((recorder.parent / "build.json", "recorder-build.json"),
                         (fixture.parent / "fixture-build.json", "fixture-build.json"),
                         (BASE / "fixture.rs", "fixture.rs")):
        if source.exists():
            shutil.copyfile(source, run / name)
    image_hash = helpers.digest(image)
    image_copy = helpers.copy_image(image, run, "disk.img")
    token = run.name.rsplit("-", 1)[-1]
    directory = "/bpf-record-" + token
    helpers.debugfs(image_copy, f"mkdir {directory}", write=True)
    helpers.debugfs(image_copy, f"set_inode_field {directory} mode 040755", write=True)
    script, expected, failures = cases_script(directory, args.suite, args.duration_ms)
    (run / "cases.sh").write_text(script)
    for source, name in ((run / "bpf-record.elf", "bpf-record"), (run / "record-fixture.elf", "record-fixture"), (run / "cases.sh", "cases.sh")):
        install(image_copy, source, directory + "/" + name, run)
    if args.suite == "mapping":
        install(image_copy, run / "record-fixture.elf", directory + "/mapping-fixture", run)
    try:
        helpers.debugfs(image_copy, "stat /boot")
    except ValueError as error:
        if "File not found" not in str(error):
            raise
        helpers.debugfs(image_copy, "mkdir /boot", write=True)
    try:
        helpers.debugfs(image_copy, "stat /boot/kernel.elf")
    except ValueError as error:
        if "File not found" not in str(error):
            raise
    else:
        helpers.debugfs(image_copy, "rm /boot/kernel.elf", write=True)
    install(image_copy, kernel_elf, "/boot/kernel.elf", run)
    helpers.debugfs(image_copy, f'dump /bin/busybox "{run / "busybox.elf"}"')
    candidates = [run / name for name in ("bpf-record.elf", "record-fixture.elf", "kernel.elf", "busybox.elf") if (run / name).exists()]
    command = qemu_command(args.arch, run / "kernel", image_copy)
    shell = f"sh {directory}/cases.sh; status=$?; printf '\\nBPF_HOST_EXIT {token} %s\\n' \"$status\""
    inputs = {"kind": "generic recorder with independently launched external workload", "arch": args.arch,
              "suite": args.suite, "duration_ms": args.duration_ms, "command": command, "guest_command": shell,
              "image_sha256": image_hash, "boot_image_sha256": helpers.digest(image_copy),
              "kernel_sha256": helpers.digest(run / "kernel"), "recorder_sha256": helpers.digest(run / "bpf-record.elf"),
              "kernel_elf_sha256": helpers.digest(kernel_elf), "guest_capture_sha_witness": True,
              "fixture_sha256": helpers.digest(run / "record-fixture.elf"), "script_sha256": helpers.digest(run / "cases.sh"),
              "analyzer_sha256": helpers.digest(run / "bpf-analyzer"),
              "workspace_commit": helpers.command(["git", "rev-parse", "HEAD"], cwd=REPO).strip()}
    (run / "inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")
    print(f"Logs: {run}", flush=True)
    print(shlex.join(command), flush=True)
    text, qemu_exit, reason = helpers.drive_guest(command, shell, token, run / "guest.log",
        r"(?:^|[\r\n])[^\r\n]*[#$] ?$", args.boot_timeout, args.timeout)
    errors = [reason] if reason else []
    if not re.search(rf"(?m)^BPF_HOST_EXIT {re.escape(token)} 0\s*$", text.replace("\r", "")):
        errors.append("missing successful harness exit")
    cases, reports, measurements = {}, {}, {}
    try:
        cases = parse_cases(text)
        for label in dict.fromkeys(expected + failures + (["loaded-detached"] if args.suite in ("benchmark", "full") else [])):
            if label not in cases:
                errors.append(f"missing case: {label}")
            else:
                errors += validate_case(label, cases[label], label in failures)
        for label in expected:
            raw = extract(text, label)
            path = run / f"{label}.pbcapture"
            path.write_bytes(raw)
            verify_saved_hash(cases[label], raw)
            collected = collection.collect(path, run, candidates, run / "bpf-analyzer")
            report = helpers.command([str(run / "bpf-analyzer"), str(path), "--json"], cwd=REPO, timeout=120)
            reports[label] = json.loads(report)
            (run / f"{label}-report.json").write_text(report)
            errors += validate_report(label, reports[label])
            if args.suite == "stacks" and label != "journal-failure":
                timeline_path = run / f"{label}-timeline.json"
                helpers.command([str(run / "bpf-analyzer"), str(path), "--timeline", str(timeline_path)], cwd=REPO)
                proof = stack_proof(json.loads(timeline_path.read_text()), reports[label], collected, require_depth=label == "stack-task")
                (run / f"{label}-stack-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
            if label == "mapping-lifecycle":
                proof = mapping_lifecycle_proof(text, collected["captured_manifest"])
                (run / f"{label}-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
            mapping = helpers.command([str(run / "bpf-analyzer"), str(path), "--mapping-report", "--bundle", str(run)], cwd=REPO)
            (run / f"{label}-mapping-report.json").write_text(mapping)
            if collection.sha256(path.read_bytes()) != verify_saved_hash(cases[label], raw):
                raise ValueError("analysis changed the original guest capture")
            if label == "nonleader-exec":
                timeline_path = run / "nonleader-exec-timeline.json"
                helpers.command([str(run / "bpf-analyzer"), str(path), "--timeline", str(timeline_path)], cwd=REPO)
                proof = verify_exec_identity(text, reports[label], json.loads(timeline_path.read_text()))
                (run / "nonleader-exec-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
            if label in ("existing-cpu", "existing-sched", "existing-fault"):
                timeline_path = run / f"{label}-timeline.json"
                helpers.command([str(run / "bpf-analyzer"), str(path), "--timeline", str(timeline_path)], cwd=REPO)
                proof = verify_existing_workload(text, json.loads(timeline_path.read_text()), label)
                (run / f"{label}-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
        if "write-failure" in failures:
            raw = extract(text, "write-failure")
            path = run / "write-failure.pbcapture"
            path.write_bytes(raw)
            if len(raw) != 1024:
                errors.append("write-failure: original truncated file bytes were not retained")
            try:
                helpers.command([str(run / "bpf-analyzer"), str(path), "--json"], cwd=REPO)
            except RuntimeError as error:
                (run / "write-failure-analyzer.txt").write_text(str(error) + "\n")
            else:
                errors.append("write-failure: missing-trailer capture was accepted")
        measurements = benchmark(text, cases, reports)
    except (ValueError, KeyError, RuntimeError) as error:
        errors.append(str(error))
    if helpers.digest(image) != image_hash:
        errors.append("source rootfs changed during snapshot run")
    result = {**inputs, "qemu_exit": qemu_exit, "errors": errors, "passed": not errors,
              "cases": cases, "benchmark": measurements,
              "captures": {name: {"sha256": helpers.digest(run / f"{name}.pbcapture"),
                                  "records_count": report["records_count"], "status": report["status"]}
                           for name, report in reports.items()}}
    (run / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    for row in text.replace("\r", "").splitlines():
        if row.startswith(("RECORD ", "RECORD_CASE ", "WORKLOAD ", "BPF_HOST_EXIT ")):
            print(row)
    for error in errors:
        print("FAIL: " + error, file=sys.stderr)
    print(f"Result: {'FAIL' if errors else 'PASS'}; {run}", flush=True)
    return int(bool(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build-fixture", "guest"))
    parser.add_argument("--arch", choices=tuple(ARCHES), required=True)
    parser.add_argument("--suite", choices=("smoke", "mixed", "stacks", "mapping", "lifecycle", "negative", "benchmark", "existing", "recovery", "full"), default="smoke")
    parser.add_argument("--duration-ms", type=int, default=1000)
    parser.add_argument("--recorder", type=Path)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--boot-timeout", type=float, default=120)
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    if not 100 <= args.duration_ms <= 30_000:
        parser.error("--duration-ms must be 100..30000")
    if args.action == "build-fixture":
        print(build_fixture(args.arch))
        return 0
    return guest(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
