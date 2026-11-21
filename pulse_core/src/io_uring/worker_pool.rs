//! Path 3 globally bounded, lazily spawned kernel worker pool with Per-Ring Round-Robin.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet, VecDeque},
    format,
    vec::Vec,
};
use core::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use axtask::{WaitQueue, spawn_raw};
use kspin::SpinNoIrq;

const WORKER_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

struct WorkerJob {
    req_id: u64,
    serial_key: Option<u64>,
    task: Box<dyn FnOnce() + Send + 'static>,
}

struct RingWorkerQueue {
    jobs: VecDeque<WorkerJob>,
    in_flight: usize,
}

impl RingWorkerQueue {
    fn new() -> Self {
        Self {
            jobs: VecDeque::new(),
            in_flight: 0,
        }
    }
}

struct PoolInner {
    ring_order: VecDeque<u64>,
    rings: BTreeMap<u64, RingWorkerQueue>,
    in_flight_keys: BTreeSet<u64>,
    active_workers: usize,
    idle_workers: usize,
    queued_jobs: usize,
    next_worker_id: u64,
}

impl PoolInner {
    const fn new() -> Self {
        Self {
            ring_order: VecDeque::new(),
            rings: BTreeMap::new(),
            in_flight_keys: BTreeSet::new(),
            active_workers: 0,
            idle_workers: 0,
            queued_jobs: 0,
            next_worker_id: 1,
        }
    }

    #[inline]
    fn job_key_eligible(job: &WorkerJob, in_flight_keys: &BTreeSet<u64>) -> bool {
        job.serial_key.is_none_or(|k| !in_flight_keys.contains(&k))
    }

    fn has_runnable_job(&self, per_ring_limit: usize) -> bool {
        self.rings.values().any(|q| {
            q.in_flight < per_ring_limit
                && q.jobs
                    .iter()
                    .any(|job| Self::job_key_eligible(job, &self.in_flight_keys))
        })
    }

    /// Pops the next eligible job using Per-Ring Round-Robin fairness.
    fn pop_next_job(&mut self, per_ring_limit: usize) -> Option<(u64, WorkerJob)> {
        let len = self.ring_order.len();
        for _ in 0..len {
            let ring_id = self.ring_order.pop_front()?;
            let mut remove_ring = false;
            let mut picked = None;
            if let Some(entry) = self.rings.get_mut(&ring_id) {
                if !entry.jobs.is_empty() && entry.in_flight < per_ring_limit {
                    if let Some(idx) = entry
                        .jobs
                        .iter()
                        .position(|job| Self::job_key_eligible(job, &self.in_flight_keys))
                    {
                        picked = entry.jobs.remove(idx);
                        if let Some(ref job) = picked {
                            entry.in_flight += 1;
                            self.queued_jobs = self.queued_jobs.saturating_sub(1);
                            if let Some(key) = job.serial_key {
                                self.in_flight_keys.insert(key);
                            }
                        }
                    }
                }
                if entry.jobs.is_empty() && entry.in_flight == 0 {
                    remove_ring = true;
                }
            }
            if remove_ring {
                self.rings.remove(&ring_id);
            } else {
                // Rotate served (or deferred) ring to the tail for round-robin fairness.
                self.ring_order.push_back(ring_id);
            }
            if let Some(job) = picked {
                return Some((ring_id, job));
            }
        }
        None
    }
}

pub struct BoundedWorkerPool {
    inner: SpinNoIrq<PoolInner>,
    job_wq: WaitQueue,
}

static NEXT_RING_ID: AtomicU64 = AtomicU64::new(1);
static WORKER_POOL: BoundedWorkerPool = BoundedWorkerPool::new();

#[inline]
pub fn alloc_ring_pool_id() -> u64 {
    NEXT_RING_ID.fetch_add(1, Ordering::Relaxed)
}

#[inline]
pub fn global_worker_pool() -> &'static BoundedWorkerPool {
    &WORKER_POOL
}

impl BoundedWorkerPool {
    pub const fn new() -> Self {
        Self {
            inner: SpinNoIrq::new(PoolInner::new()),
            job_wq: WaitQueue::new(),
        }
    }

    #[inline]
    fn limits() -> (usize, usize) {
        let max_workers = axhal::cpu_num().saturating_mul(2).clamp(4, 16);
        let per_ring_limit = (max_workers / 2).max(2);
        (max_workers, per_ring_limit)
    }

    /// Submits one Path 3 blocking job associated with `(ring_id, req_id)`.
    pub fn submit(
        &'static self,
        ring_id: u64,
        req_id: u64,
        job: impl FnOnce() + Send + 'static,
    ) {
        self.submit_ordered(ring_id, req_id, None, job);
    }

    /// Submits one Path 3 blocking job with an optional ordering key (`serial_key`).
    /// At most one in-flight worker executes a given `Some(key)` at a time.
    pub fn submit_ordered(
        &'static self,
        ring_id: u64,
        req_id: u64,
        serial_key: Option<u64>,
        job: impl FnOnce() + Send + 'static,
    ) {
        let boxed: Box<dyn FnOnce() + Send + 'static> = Box::new(job);
        let (max_workers, _per_ring_limit) = Self::limits();

        let worker_to_spawn = {
            let mut inner = self.inner.lock();
            if !inner.rings.contains_key(&ring_id) {
                inner.rings.insert(ring_id, RingWorkerQueue::new());
                inner.ring_order.push_back(ring_id);
            }
            inner.rings.get_mut(&ring_id).unwrap().jobs.push_back(WorkerJob {
                req_id,
                serial_key,
                task: boxed,
            });
            inner.queued_jobs += 1;

            if inner.idle_workers == 0 && inner.active_workers < max_workers {
                inner.active_workers += 1;
                let wid = inner.next_worker_id;
                inner.next_worker_id = inner.next_worker_id.wrapping_add(1);
                Some(wid)
            } else {
                None
            }
        };

        self.job_wq.notify_one(false);

        if let Some(wid) = worker_to_spawn {
            spawn_raw(
                || self.worker_loop(),
                format!("io-uring-wk-{wid}"),
                axconfig::TASK_STACK_SIZE,
            );
        }
    }

    /// Cancels a queued (not yet started) Path 3 job for `(ring_id, req_id)`.
    ///
    /// Drops the removed closure outside `SpinNoIrq` to obey ADR-0007.
    pub fn cancel_queued_request(&self, ring_id: u64, req_id: u64) -> bool {
        let removed: Vec<WorkerJob> = {
            let mut inner = self.inner.lock();
            let mut found = Vec::new();
            if let Some(entry) = inner.rings.get_mut(&ring_id) {
                let mut i = 0;
                while i < entry.jobs.len() {
                    if entry.jobs[i].req_id == req_id {
                        if let Some(job) = entry.jobs.remove(i) {
                            found.push(job);
                            continue;
                        }
                    }
                    i += 1;
                }
            }
            inner.queued_jobs = inner.queued_jobs.saturating_sub(found.len());
            found
        };
        let cancelled = !removed.is_empty();
        drop(removed);
        cancelled
    }

    /// Cancels all queued Path 3 jobs belonging to `ring_id` (during teardown).
    pub fn cancel_ring_queued(&self, ring_id: u64) {
        let removed = {
            let mut inner = self.inner.lock();
            let mut should_remove = false;
            let drained = if let Some(entry) = inner.rings.get_mut(&ring_id) {
                let drained = entry.jobs.drain(..).collect::<Vec<_>>();
                should_remove = entry.in_flight == 0;
                drained
            } else {
                Vec::new()
            };
            inner.queued_jobs = inner.queued_jobs.saturating_sub(drained.len());
            if should_remove {
                inner.rings.remove(&ring_id);
                inner.ring_order.retain(|id| *id != ring_id);
            }
            drained
        };
        drop(removed);
    }

    fn finish_ring_job(&self, ring_id: u64, serial_key: Option<u64>) {
        let mut inner = self.inner.lock();
        if let Some(key) = serial_key {
            inner.in_flight_keys.remove(&key);
        }
        if let Some(entry) = inner.rings.get_mut(&ring_id) {
            entry.in_flight = entry.in_flight.saturating_sub(1);
            if entry.jobs.is_empty() && entry.in_flight == 0 {
                inner.rings.remove(&ring_id);
                inner.ring_order.retain(|id| *id != ring_id);
            }
        }
        drop(inner);
        self.job_wq.notify_one(false);
    }

    fn worker_loop(&'static self) {
        loop {
            let (_, per_ring_limit) = Self::limits();
            let next = {
                let mut inner = self.inner.lock();
                inner.pop_next_job(per_ring_limit)
            };

            if let Some((ring_id, job)) = next {
                let serial_key = job.serial_key;
                (job.task)();
                self.finish_ring_job(ring_id, serial_key);
                continue;
            }

            {
                let mut inner = self.inner.lock();
                inner.idle_workers += 1;
            }
            let timed_out = self.job_wq.wait_timeout_until(WORKER_IDLE_TIMEOUT, || {
                let (_, limit) = Self::limits();
                self.inner.lock().has_runnable_job(limit)
            });
            {
                let mut inner = self.inner.lock();
                inner.idle_workers = inner.idle_workers.saturating_sub(1);
                if timed_out && !inner.has_runnable_job(per_ring_limit) {
                    inner.active_workers = inner.active_workers.saturating_sub(1);
                    return;
                }
            }
        }
    }
}
