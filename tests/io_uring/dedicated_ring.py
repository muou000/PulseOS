"""Validate the execution and syscall counts of one dedicated SQPOLL ring."""

import re
from collections import Counter

from worker_cpu import JOB


BEGIN = "DEDICATED_RING_BEGIN"
POLL_SQE = re.compile(r"SQPOLL consume ring=(\d+) user_data=1001 cpu=\d+\b")


class PendingPoll:
    """Release the pipe writer only after the target ring has polled the empty pipe."""

    def __init__(self):
        self.released = False

    def __call__(self, text, stdin):
        if self.released:
            return
        trace = text.partition(BEGIN)[2]
        sqe = POLL_SQE.search(trace)
        if sqe and re.search(rf"io_uring poll ring={sqe[1]} req=\d+ phase=first cpu=\d+ result=pending\b",
                             trace[sqe.end():]):
            stdin.write(b"pending\n")
            stdin.flush()
            self.released = True


def user_dispatch_counts(trace, ring):
    pattern = rf"SQPOLL observe ring={ring} phase=(setup|teardown) cpu=(\d+) user_dispatch=(\d+)"
    snapshots = {"setup": {}, "teardown": {}}
    for phase, cpu, count in re.findall(pattern, trace):
        counters = snapshots[phase]
        if int(cpu) in counters:
            raise ValueError(f"Repeated {phase} observation on CPU {cpu}")
        counters[int(cpu)] = int(count)
    cpus = set(range(8))
    before, after = snapshots["setup"], snapshots["teardown"]
    if before.keys() != cpus or after.keys() != cpus:
        raise ValueError(f"Missing per-CPU user dispatch counters on ring {ring}: {snapshots}")
    delta = {cpu: after[cpu] - before[cpu] for cpu in sorted(cpus)}
    if min(delta.values()) < 0 or sum(delta.values()) == 0 or delta[7] != 0:
        raise ValueError(f"Unexpected user dispatch counts during ring lifetime: {delta}")
    return {"setup": before, "teardown": after, "delta": delta}


def placement(cpus):
    counts = Counter(map(int, cpus))
    return {"per_cpu": dict(counts), "outside": counts.total() - counts[7]}


def check_dedicated_ring(log):
    boot_marker = "CPU reservation: reserved=0x80 user=0x7f sqpoll=0x80"
    if boot_marker not in log or log.count(BEGIN) != 1:
        raise ValueError("Expected one dedicated-ring workload with CPU 7 reserved in an eight-CPU guest")
    trace = log.partition(BEGIN)[2]
    for marker in ("DEDICATED_RING active unique=3 enters=0 producer0_cpu=0 producer1_cpu=1 wake_cpu=2",
                   "DEDICATED_RING close writer_eof=1 PASS"):
        if trace.count(marker) != 1:
            raise ValueError(f"Missing or repeated guest result: {marker}")
    times = re.findall(r"DEDICATED_RING active_start_ns=(\d+) active_end_ns=(\d+)", trace)
    if len(times) != 1 or not 0 < int(times[0][0]) < int(times[0][1]):
        raise ValueError(f"Invalid active interval: {times}")
    target_sqe = POLL_SQE.search(trace)
    if not target_sqe:
        raise ValueError("Missing target POLL_ADD SQ consumption")
    ring = target_sqe[1]
    idle = re.findall(r"DEDICATED_RING idle post_publish_need_wakeup=1 enters=1 unique=(\d+) "
                      r"witness=4001 witness_enters=([01])\b", trace)
    if len(idle) != 1 or not 1 <= int(idle[0][0]) <= 4:
        raise ValueError(f"Expected one post-publication wake and progress within four idle attempts: {idle}")
    idle_count, witness_enters = map(int, idle[0])
    sqes = list(re.finditer(rf"SQPOLL consume ring={ring} user_data=(\d+) cpu=(\d+)\b", trace))
    tags = [int(m[1]) for m in sqes]
    active_tags = [2001, 2002, 1001]
    if tags != [0, *active_tags, *range(3001, 3001 + idle_count), 4001] or any(m[2] != "7" for m in sqes):
        raise ValueError(f"Unexpected SQ observations: {[m.groups() for m in sqes]}")

    enters = list(re.finditer(rf"SQPOLL enter ring={ring} wakeup=(\w+) wait=(\w+)", trace))
    totals = re.findall(rf"SQPOLL (setup|teardown) ring={ring} enter_calls=(\d+)\b", trace)
    # The successful idle SQE can win the poller's final recheck and race the
    # wake syscall. The guest publishes 4001 only after that syscall returns.
    prev, last_idle, witness = sqes[-3:]
    lifetime = 2 + witness_enters
    if (totals != [("setup", "0"), ("teardown", str(lifetime))] or len(enters) != lifetime
            or any(m.groups() != ("true", "false") for m in enters)
            or enters[0].start() >= sqes[1].start()
            or not prev.end() < enters[1].start() < witness.start()
            or (witness_enters and enters[2].start() <= last_idle.end())):
        raise ValueError(f"Expected warmup, idle wake, and witness progress (kernel count {totals})")

    inline = [(tag, cpu, res) for tag, cpu, res in re.findall(
        rf"SQPOLL inline ring={ring} user_data=(\d+) cpu=(\d+) res=(-?\d+)", trace
    ) if int(tag) in active_tags]
    if inline != [("2001", "7", "2")]:
        raise ValueError(f"Expected the two-byte resident read to complete inline on CPU 7: {inline}")
    committed = re.findall(rf"SQPOLL committed ring={ring} req=(\d+) user_data=(\d+)", trace)
    reqs = {int(tag): req for req, tag in committed}
    if (set(reqs).intersection(active_tags) != {2002, 1001} or not set(reqs).issubset(tags)
            or len(reqs) != len(committed) or len(set(reqs.values())) != len(reqs)):
        raise ValueError(f"Incomplete or duplicate SQE to request mapping: {committed}")
    housekeeping = {req for tag, req in reqs.items() if tag not in active_tags}

    polls = re.findall(rf"io_uring poll ring={ring} req=(\d+) phase=(\w+) cpu=(\d+) "
                       r"result=(\w+) task=(\S+) seq=(\d+)", trace)
    polls = [poll for poll in polls if poll[0] not in housekeeping]
    if len(polls) < 2:
        raise ValueError(f"Missing native first or resumed poll: {polls}")
    for seq, (req, phase, cpu, result, task, number) in enumerate(polls, 1):
        expected = ("first" if seq == 1 else "resume", "ready" if seq == len(polls) else "pending")
        if (req != reqs[1001] or (phase, result) != expected or int(number) != seq
                or (cpu, task) != ("7", "async-exec-cpu-7")):
            raise ValueError(f"Unexpected, misplaced or lost native poll: {polls}")
    jobs = [m for m in JOB.finditer(trace) if m["ring"] == ring and m["req"] not in housekeeping]
    if ([m["phase"] for m in jobs] != ["start", "finish"]
            or any(m["req"] != reqs[2002] or m["cpu"] != "7" for m in jobs)
            or jobs[0]["task"] != jobs[1]["task"]):
        raise ValueError(f"Missing or misplaced worker read: {[m.groupdict() for m in jobs]}")

    return {
        "ring": int(ring), "reserved_cpu": 7, "user_mask": "0x7f",
        "submit_to_reap_ns": list(map(int, times[0])), "producer_cpus": [0, 1], "wake_cpu": 2,
        "sq_consumptions": [{"user_data": int(m[1]), "cpu": int(m[2])} for m in sqes],
        "inline_read": {"user_data": 2001, "cpu": 7, "bytes": 2},
        "polls": [{"req": int(req), "phase": phase, "cpu": int(cpu), "result": result,
                   "task": task, "seq": int(seq)} for req, phase, cpu, result, task, seq in polls],
        "committed": reqs, "worker": [m.groupdict() for m in jobs],
        "enter_calls": {"warmup": 1, "active": 0, "idle": 1, "witness": witness_enters,
                        "lifetime": int(totals[-1][1])},
        "active_request_placement": {
            "sq": placement(m[2] for m in sqes if int(m[1]) in active_tags),
            "inline": placement(cpu for _, cpu, _ in inline),
            "first_poll": placement(cpu for _, phase, cpu, *_ in polls if phase == "first"),
            "resumed_poll": placement(cpu for _, phase, cpu, *_ in polls if phase == "resume"),
            "worker_start": placement(m["cpu"] for m in jobs if m["phase"] == "start"),
            "worker_finish": placement(m["cpu"] for m in jobs if m["phase"] == "finish"),
        },
        "user_dispatch": user_dispatch_counts(trace, ring),
        "active_unique_cqes": 3, "idle_unique_cqes": idle_count, "witness_unique_cqes": 1, "passed": True,
    }
