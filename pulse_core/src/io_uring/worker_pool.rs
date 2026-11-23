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

use axfs::FilePositionTicket;
use axtask::{AxCpuMask, WaitQueue, spawn_raw};
use kspin::SpinNoIrq;

use super::IoUringState;
use crate::fd_table::FileObject;

const WORKER_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

struct WorkerJob {
    req_id: u64,
    serial_key: Option<u64>,
    service_cpu: Option<usize>,
    position_ticket: Option<FilePositionTicket>,
    task: Box<dyn FnOnce(Option<FilePositionTicket>) + Send>,
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
    // Submission-time file-position tickets must enter execution in FIFO order,
    // even when the ring round-robin or its quota would pick a later ticket.
    position_jobs: BTreeMap<u64, VecDeque<(u64, u64)>>,
    active_workers: usize,
    // Includes newly spawned workers and workers between jobs.
    available_workers: usize,
    queued_jobs: usize,
    next_worker_id: u64,
}

impl PoolInner {
    const fn new() -> Self {
        Self {
            ring_order: VecDeque::new(),
            rings: BTreeMap::new(),
            in_flight_keys: BTreeSet::new(),
            position_jobs: BTreeMap::new(),
            active_workers: 0,
            available_workers: 0,
            queued_jobs: 0,
            next_worker_id: 1,
        }
    }

    fn job_eligible(&self, ring_id: u64, job: &WorkerJob) -> bool {
        let Some(key) = job.serial_key else {
            return true;
        };
        !self.in_flight_keys.contains(&key)
            && (job.position_ticket.is_none()
                || self.position_jobs[&key].front() == Some(&(ring_id, job.req_id)))
    }

    fn remove_position_job(&mut self, ring_id: u64, job: &WorkerJob) {
        if job.position_ticket.is_some() {
            let key = job.serial_key.expect("file-position ordering key");
            let fifo = self
                .position_jobs
                .get_mut(&key)
                .expect("queued position ticket");
            if fifo.front() == Some(&(ring_id, job.req_id)) {
                fifo.pop_front();
            } else {
                // A queued cancellation can remove an entry in the middle.
                fifo.retain(|&id| id != (ring_id, job.req_id));
            }
            if fifo.is_empty() {
                self.position_jobs.remove(&key);
            }
        }
    }

    fn remove_empty_ring(&mut self, ring_id: u64) {
        if self
            .rings
            .get(&ring_id)
            .is_some_and(|q| q.in_flight == 0 && q.jobs.is_empty())
        {
            self.rings.remove(&ring_id);
            self.ring_order.retain(|id| *id != ring_id);
        }
    }

    fn has_runnable_job(&self, per_ring_limit: usize) -> bool {
        self.rings.iter().any(|(&ring_id, q)| {
            q.in_flight < per_ring_limit && q.jobs.iter().any(|job| self.job_eligible(ring_id, job))
        })
    }

    /// Pops the next eligible job using Per-Ring Round-Robin fairness.
    fn pop_next_job(&mut self, per_ring_limit: usize) -> Option<(u64, WorkerJob)> {
        let len = self.ring_order.len();
        for _ in 0..len {
            let ring_id = self.ring_order.pop_front()?;
            self.ring_order.push_back(ring_id);
            let entry = &self.rings[&ring_id];
            if entry.in_flight >= per_ring_limit {
                continue;
            }
            if let Some(index) = entry
                .jobs
                .iter()
                .position(|job| self.job_eligible(ring_id, job))
            {
                let entry = self.rings.get_mut(&ring_id).unwrap();
                let job = entry.jobs.remove(index).unwrap();
                entry.in_flight += 1;
                self.queued_jobs -= 1;
                self.available_workers -= 1;
                self.remove_position_job(ring_id, &job);
                if let Some(key) = job.serial_key {
                    self.in_flight_keys.insert(key);
                }
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

    /// Submits one Path 3 blocking job for this ring.
    pub(super) fn submit(
        &'static self,
        ring: &IoUringState,
        req_id: u64,
        job: impl FnOnce() + Send + 'static,
    ) {
        self.submit_ordered(ring, req_id, None, job);
    }

    /// At most one in-flight worker executes a given ordering key at a time.
    pub(super) fn submit_ordered(
        &'static self,
        ring: &IoUringState,
        req_id: u64,
        serial_key: Option<u64>,
        job: impl FnOnce() + Send + 'static,
    ) {
        self.submit_with_position(ring, req_id, serial_key, None, move |_| job());
    }

    /// Reserve the file position and publish the job in the same critical
    /// section. A later ticket must never hold the serial key while its
    /// predecessor is still queued in this pool.
    pub(super) fn submit_with_position(
        &'static self,
        ring: &IoUringState,
        req_id: u64,
        serial_key: Option<u64>,
        position_file: Option<&FileObject>,
        job: impl FnOnce(Option<FilePositionTicket>) + Send + 'static,
    ) {
        let task = Box::new(job);
        let ring_id = ring.ring_id();
        let service_cpu = ring.sqpoll_service_cpu();

        {
            let mut inner = self.inner.lock();
            let position_ticket = position_file.and_then(FileObject::reserve_position_ticket);
            if position_ticket.is_some() {
                let key = serial_key.expect("file-position ordering key");
                inner
                    .position_jobs
                    .entry(key)
                    .or_default()
                    .push_back((ring_id, req_id));
            }
            if !inner.rings.contains_key(&ring_id) {
                inner.rings.insert(ring_id, RingWorkerQueue::new());
                inner.ring_order.push_back(ring_id);
            }
            inner
                .rings
                .get_mut(&ring_id)
                .unwrap()
                .jobs
                .push_back(WorkerJob {
                    req_id,
                    serial_key,
                    service_cpu,
                    position_ticket,
                    task,
                });
            inner.queued_jobs += 1;
        }
        self.service_backlog();
    }

    /// Supply a worker for runnable jobs. A claim can leave further runnable
    /// jobs behind just before its worker blocks; a cancellation can expose the
    /// head of one or more position FIFOs after earlier idle workers retired.
    fn service_backlog(&'static self) {
        let (max_workers, per_ring_limit) = Self::limits();
        let worker_to_spawn = {
            let mut inner = self.inner.lock();
            if inner.queued_jobs == 0
                || (inner.available_workers == 0 && inner.active_workers == max_workers)
                || !inner.has_runnable_job(per_ring_limit)
            {
                return;
            }
            if inner.queued_jobs > inner.available_workers && inner.active_workers < max_workers {
                inner.available_workers += 1;
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
    pub fn cancel_queued_request(&'static self, ring_id: u64, req_id: u64) -> bool {
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
            for job in &found {
                inner.remove_position_job(ring_id, job);
            }
            inner.remove_empty_ring(ring_id);
            inner.queued_jobs = inner.queued_jobs.saturating_sub(found.len());
            found
        };
        let cancelled = !removed.is_empty();
        drop(removed);
        if cancelled {
            self.service_backlog();
        }
        cancelled
    }

    /// Cancels all queued Path 3 jobs belonging to `ring_id` (during teardown).
    pub fn cancel_ring_queued(&'static self, ring_id: u64) {
        let removed = {
            let mut inner = self.inner.lock();
            let drained = if let Some(entry) = inner.rings.get_mut(&ring_id) {
                entry.jobs.drain(..).collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            for job in &drained {
                inner.remove_position_job(ring_id, job);
            }
            inner.queued_jobs = inner.queued_jobs.saturating_sub(drained.len());
            inner.remove_empty_ring(ring_id);
            drained
        };
        if !removed.is_empty() {
            drop(removed);
            self.service_backlog();
        }
    }

    fn finish_ring_job(&'static self, ring_id: u64, serial_key: Option<u64>) {
        let mut inner = self.inner.lock();
        if let Some(key) = serial_key {
            inner.in_flight_keys.remove(&key);
        }
        inner
            .rings
            .get_mut(&ring_id)
            .expect("running ring")
            .in_flight -= 1;
        inner.available_workers += 1;
        inner.remove_empty_ring(ring_id);
        drop(inner);
        self.service_backlog();
    }

    fn worker_loop(&'static self) {
        let default_mask = axtask::current().cpumask();
        loop {
            let (_, per_ring_limit) = Self::limits();
            let next = {
                let mut inner = self.inner.lock();
                inner.pop_next_job(per_ring_limit)
            };

            if let Some((ring_id, job)) = next {
                self.service_backlog();
                let serial_key = job.serial_key;
                if let Some(cpu) = job.service_cpu {
                    // The ring validated this online CPU at setup. Migration
                    // completes before the closure runs; wakes use the same mask.
                    assert!(axtask::set_current_affinity(AxCpuMask::one_shot(cpu)));
                }
                #[cfg(feature = "guest-checks")]
                trace_job(ring_id, job.req_id, "start", serial_key);
                (job.task)(job.position_ticket);
                #[cfg(feature = "guest-checks")]
                trace_job(ring_id, job.req_id, "finish", serial_key);
                if job.service_cpu.is_some() {
                    assert!(axtask::set_current_affinity(default_mask));
                }
                self.finish_ring_job(ring_id, serial_key);
                continue;
            }

            let timed_out = self.job_wq.wait_timeout_until(WORKER_IDLE_TIMEOUT, || {
                let (_, limit) = Self::limits();
                self.inner.lock().has_runnable_job(limit)
            });
            {
                let mut inner = self.inner.lock();
                if timed_out && !inner.has_runnable_job(per_ring_limit) {
                    inner.available_workers -= 1;
                    inner.active_workers -= 1;
                    #[cfg(feature = "guest-checks")]
                    {
                        let active = inner.active_workers;
                        drop(inner);
                        axlog::info!(
                            "io_uring worker exit task={} active={}",
                            axtask::current().id().as_u64(),
                            active
                        );
                    }
                    return;
                }
            }
        }
    }
}

#[cfg(feature = "guest-checks")]
fn trace_job(ring_id: u64, req_id: u64, phase: &str, serial_key: Option<u64>) {
    axlog::info!(
        "io_uring worker ring={} req={} phase={} cpu={} task={} key={:?}",
        ring_id,
        req_id,
        phase,
        axhal::percpu::this_cpu_id(),
        axtask::current().id().as_u64(),
        serial_key
    );
}
