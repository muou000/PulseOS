# eevdf-scheduler

[![CI](https://github.com/muou000/eevdf-scheduler/actions/workflows/ci.yml/badge.svg)](https://github.com/muou000/eevdf-scheduler/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20GPL--3.0--or--later%20OR%20MulanPSL--2.0-blue)](#license)

A reusable `no_std` implementation of Earliest Eligible Virtual Deadline First
(EEVDF), extracted from [PulseOS](https://github.com/muou000/PulseOS).

For a Chinese explanation of the theory, formulas, queue invariants, lifecycle
API, PulseOS integration and Linux differences, see
[EEVDF 设计与实现指南](docs/algorithm-design.md).

## What it provides

- weighted virtual runtime, eligibility and virtual-deadline scheduling for
  ordinary tasks;
- intrusive eligible/ineligible red-black trees with cached aggregate state;
- lag preservation across wake-up and migration;
- strict real-time priorities `1..=99`, with FIFO and round-robin behavior;
- monotonic-time accounting, immediate-preemption queries and timer-deadline
  queries;
- a generic task wrapper and algorithm-level lifecycle API suitable for kernel
  adapters;
- no standard-library dependency outside tests.

The scheduler is designed as one run queue. SMP task placement, load balancing,
interrupt/timer programming and locking remain responsibilities of the host
kernel.

The real-time queues in this crate are priority FIFO/RR queues. They are **not**
Linux `SCHED_DEADLINE`, CBS or EDF admission control.

## Example

```rust
use std::sync::Arc;
use eevdf_scheduler::{
    EEVDFScheduler, EEVDFTask, EnqueueReason,
};

const BASE_SLICE_NS: u64 = 1_000_000;
let mut scheduler = EEVDFScheduler::<u32, BASE_SLICE_NS>::new();

let first = Arc::new(EEVDFTask::new(1));
let second = Arc::new(EEVDFTask::new(2));
scheduler.enqueue(first, EnqueueReason::Spawn, 0);
scheduler.enqueue(second, EnqueueReason::Spawn, 0);

let current = scheduler.pick_next_at(0).unwrap();
scheduler.on_task_start(&current, 0);
// Run `current`, then account the interval before re-enqueuing it.
scheduler.on_task_stop(&current, BASE_SLICE_NS);
scheduler.enqueue(current, EnqueueReason::Preempt, BASE_SLICE_NS);
```

Priority values `-120..=-81` encode ordinary nice levels `-20..=19`; values
`1..=99` select the real-time queues. Use `EEVDFScheduler::update_priority_at` for
an enqueued or running task so queue placement and elapsed time stay coherent.

## Verification

```bash
cargo test
cargo check --lib
```

Unit tests cover ordering, weighted fairness, lag preservation, lifecycle
transitions, timer deadlines, priority changes, FIFO/RR behavior and overflow
boundaries.

## Origin and contribution history

The implementation was developed in PulseOS and first landed in
[`42ac831d`](https://github.com/muou000/PulseOS/commit/42ac831d0ee955dda98e5bf6ad01085352ad04c0)
(`feat(sched): add EEVDF scheduler core`). Its intrusive-tree and RT-policy
optimization landed in
[`0e21c892`](https://github.com/muou000/PulseOS/commit/0e21c892a409dd3353643897963cfd199124de27)
(`feat(sched): optimize EEVDF queues and RT policies`). See [NOTICE](NOTICE) for
interface attribution.

The crate intentionally contains no `axsched::BaseScheduler` dependency.
PulseOS keeps that common scheduler contract and its EEVDF adapter in `axsched`,
so other kernels can integrate the algorithm through their own interfaces.

## License

Licensed under your choice of:

- Apache License, Version 2.0 ([LICENSE.Apache2](LICENSE.Apache2));
- GNU General Public License, Version 3 or later ([LICENSE.GPLv3](LICENSE.GPLv3));
- Mulan Permissive Software License, Version 2 ([LICENSE.MulanPSL2](LICENSE.MulanPSL2)).
