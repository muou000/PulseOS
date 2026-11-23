"""Correlate Path 3 job lifetimes with worker stack switches in the SMP guest."""

import re


JOB = re.compile(r"io_uring worker ring=(?P<ring>\d+) req=(?P<req>\d+) "
                 r"phase=(?P<phase>start|finish) cpu=(?P<cpu>\d+) "
                 r"task=(?P<task>\d+) key=(?P<key>None|Some\(\d+\))")
WAIT = re.compile(r"io_uring worker wait task=(?P<task>\d+) "
                  r"phase=(?P<phase>block|resume) cpu=(?P<cpu>\d+)")
EXIT = re.compile(r"io_uring worker exit task=(?P<task>\d+) active=(?P<active>\d+)\b")


def consume(trace, user_data, cpu=7):
    return re.search(rf"SQPOLL consume ring=(?P<ring>\d+) user_data={user_data} cpu={cpu}\b", trace)


class WorkerGates:
    """Acknowledge only observations for the requested job in this guest run."""

    def __init__(self):
        self.sent = set()

    def __call__(self, text, stdin):
        _, begin, trace = text.partition("WORKER_CPU_BEGIN")
        if not begin:
            return
        for token, data, req in (("blocked", 1001, "1"), ("pipe", 2003, "3")):
            if token in self.sent:
                continue
            sqe = consume(trace, data)
            if sqe is None:
                continue
            start = next((m for m in JOB.finditer(trace, sqe.end())
                          if m.group("ring", "req", "phase") == (sqe["ring"], req, "start")), None)
            if start is None:
                continue
            if not any(
                w.group("task", "phase") == (start["task"], "block") for w in WAIT.finditer(trace, start.end())
            ):
                continue
            self.send(stdin, token)
        if "pipe" in self.sent and "idle" not in self.sent:
            previous = consume(trace, 2003)
            if previous and any(e["active"] == "0" for e in EXIT.finditer(trace, previous.end())):
                self.send(stdin, "idle")
        if "idle" in self.sent and "finished" not in self.sent:
            last = consume(trace, 2004)
            if last and any(
                m.group("ring", "req", "phase") == (last["ring"], "4", "finish")
                for m in JOB.finditer(trace, last.end())
            ):
                self.send(stdin, "finished")

    def send(self, stdin, token):
        stdin.write((token + "\n").encode())
        stdin.flush()
        self.sent.add(token)


def check_worker_cpu(trace):
    trace = trace.partition("WORKER_CPU_BEGIN")[2]
    if "WORKER_CPU_PASS" not in trace or "WORKER_CPU_CONNECT cpu=1" not in trace:
        raise ValueError("Guest did not verify the file reads, separate connector, cancellation and teardown")
    accept = consume(trace, 1001)
    read = consume(trace, 2001)
    if not accept or not read or accept["ring"] == read["ring"]:
        raise ValueError("Expected two distinct rings consuming SQEs on CPU 7")
    accept_ring, file_ring = accept["ring"], read["ring"]
    raw_read = consume(trace, 1002)
    if not raw_read or raw_read["ring"] != accept_ring:
        raise ValueError("Missing blocking device read on the ACCEPT ring")

    jobs = {}
    for event in JOB.finditer(trace):
        request = event.group("ring", "req")
        phases = jobs.setdefault(request, {})
        if event["phase"] in phases:
            raise ValueError(f"Duplicate {event['phase']} for {request}")
        phases[event["phase"]] = event
    ordinary = {ring for ring, _ in jobs} - {accept_ring, file_ring}
    if len(ordinary) != 1:
        raise ValueError(f"Expected one ordinary ring during the workload, saw {ordinary}")
    ordinary_ring = ordinary.pop()
    expected = {(accept_ring, "1"), (accept_ring, "2"), (ordinary_ring, "1"), (ordinary_ring, "2")}
    expected.update((file_ring, str(req)) for req in range(1, 5))
    if jobs.keys() != expected:
        raise ValueError(f"Unexpected or missing worker jobs: {jobs.keys() ^ expected}")

    observations = []
    outside = []
    for (ring, req), phases in jobs.items():
        if phases.keys() != {"start", "finish"}:
            raise ValueError(f"Incomplete worker lifetime: ring {ring} req {req}")
        start, finish = phases["start"], phases["finish"]
        if start.end() > finish.start() or start.group("task", "key") != finish.group("task", "key"):
            raise ValueError(f"Inconsistent worker lifetime: ring {ring} req {req}")
        waits = [w for w in WAIT.finditer(trace, start.end(), finish.start()) if w["task"] == start["task"]]
        if [w["phase"] for w in waits] != ["block", "resume"] * (len(waits) // 2):
            raise ValueError(f"Unpaired worker block/resume: ring {ring} req {req}")
        samples = [(event["phase"], int(event["cpu"])) for event in (start, *waits, finish)]
        observations.append(dict(ring=int(ring), req=int(req), task=int(start["task"]), samples=samples))
        if ring != ordinary_ring:
            outside.extend((ring, req, phase, cpu) for phase, cpu in samples if cpu != 7)

    accept_job = jobs[accept_ring, "1"]
    accept_task = accept_job["start"]["task"]
    blocks = [w for w in WAIT.finditer(trace, accept_job["start"].end(), read.start())
              if w.group("task", "phase") == (accept_task, "block")]
    resumes = [w for w in WAIT.finditer(trace, read.end(), accept_job["finish"].start())
               if w.group("task", "phase") == (accept_task, "resume")]
    if not blocks or not resumes:
        raise ValueError("ACCEPT did not block before B's submission and resume after connect")
    if not all(blocks[0].end() < jobs[r, "1"]["start"].start() < resumes[-1].start()
               for r in (ordinary_ring, file_ring)):
        raise ValueError("Both independent file reads must run while the ACCEPT is outstanding")
    if jobs[file_ring, "1"]["start"]["task"] == accept_task:
        raise ValueError("ACCEPT and B's independent read unexpectedly shared a worker stack")

    first, second = jobs[ordinary_ring, "2"], jobs[file_ring, "2"]
    if (first["start"]["key"] == "None" or first["start"]["key"] != second["start"]["key"]
            or first["finish"].end() > second["start"].start()):
        raise ValueError("Implicit-offset reads were not serialized on one cross-ring file key")
    if jobs[file_ring, "3"]["start"]["key"] == "None":
        raise ValueError("The pipe read held no serialization key during queued cancellation and close")

    last_read = consume(trace, 2004)
    if not last_read or last_read["ring"] != file_ring:
        raise ValueError("Missing final submission on the reserved file ring")
    recreated = jobs[file_ring, "4"]["start"]
    pipe_finish = jobs[file_ring, "3"]["finish"]
    exits = list(EXIT.finditer(trace, 0, last_read.start()))
    old_tasks = {phases["start"]["task"] for key, phases in jobs.items() if key != (file_ring, "4")}
    if (not any(m["active"] == "0" and m.start() > pipe_finish.end() for m in exits)
            or old_tasks - {m["task"] for m in exits} or recreated["task"] in old_tasks):
        raise ValueError("Final read did not run on a new worker after the previous workers timed out")
    if outside:
        raise ValueError(f"Reserved Path 3 samples outside CPU 7: {outside}")
    return dict(target=7, accept_ring=int(accept_ring), file_ring=int(file_ring), ordinary_ring=int(ordinary_ring),
                jobs=observations, outside=len(outside), idle_exits=[int(m["task"]) for m in exits],
                recreated_task=int(recreated["task"]), passed=True)


def check_worker_limits(log):
    trace = log.partition("WORKER_LIMITS_BEGIN")[2]
    full, release, _ = trace.partition("WORKER_LIMITS_RELEASE")
    if not release or "WORKER_LIMITS_PASS" not in trace:
        raise ValueError("Missing quota, round-robin or shared-position guest results")
    first = consume(trace, 5001)
    third = consume(full, 6001, cpu=6)
    if not first or not third:
        raise ValueError("Expected the two selected rings on CPUs 7 and 6")
    full_jobs = list(JOB.finditer(full))
    rings = {m["ring"] for m in full_jobs} - {first["ring"]}
    if len(rings) != 1 or third["ring"] in rings:
        raise ValueError("Expected only the first selected ring and the ordinary ring before release")
    ordinary = rings.pop()
    for ring in (first["ring"], ordinary):
        occupied = [(int(m["req"]), m["phase"]) for m in full_jobs if m["ring"] == ring]
        if sorted(occupied) != [(n, "start") for n in range(1, 9)]:
            raise ValueError(f"Expected eight occupied slots on ring {ring}, got {occupied}")

    starts = [m for m in JOB.finditer(trace) if m["phase"] == "start"]
    workers = {m["task"] for m in starts}
    if len(workers) != 16 or len(starts) != 23:
        raise ValueError(f"Expected 23 jobs on 16 worker threads, got {len(starts)} on {workers}")
    targets = {first["ring"]: "7", third["ring"]: "6"}
    if any(m["cpu"] != targets[m["ring"]] for m in JOB.finditer(trace) if m["ring"] in targets):
        raise ValueError("Selected jobs ran outside their respective service CPUs")
    expected = [(ordinary, "9"), (ordinary, "10"), (first["ring"], "12")]
    position = [m for m in starts if m.group("ring", "req") in expected]
    if ([m.group("ring", "req") for m in position] != expected
            or len({m["key"] for m in position}) != 1 or position[0]["key"] == "None"):
        raise ValueError("Shared offset requests did not start in position-ticket order")
    return dict(workers=len(workers), jobs=len(starts), per_ring=8, position_order=expected, passed=True)
