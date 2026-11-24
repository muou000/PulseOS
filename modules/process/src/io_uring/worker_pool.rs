//! Path 3 globally bounded, lazily spawned kernel worker pool with Per-Ring Round-Robin.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet, VecDeque},
    format,
};
use core::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use axfs::FilePositionTicket;
use axtask::{AxCpuMask, WaitQueue, spawn_raw};
use kspin::SpinNoIrq;

use super::IoUringState;
use crate::fd::FileObject;

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

/// Work to perform after releasing the file-position and pool locks.
struct WorkerDispatch {
    wake: usize,
    spawn: usize,
    first_worker_id: u64,
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

    fn remove_position_job(&mut self, ring_id: u64, job: &WorkerJob) -> bool {
        if job.position_ticket.is_none() {
            return false;
        }
        let key = job.serial_key.expect("file-position ordering key");
        let fifo = self
            .position_jobs
            .get_mut(&key)
            .expect("queued position ticket");
        let first = fifo.front() == Some(&(ring_id, job.req_id));
        if first {
            fifo.pop_front();
        } else {
            fifo.retain(|&id| id != (ring_id, job.req_id));
        }
        if fifo.is_empty() {
            self.position_jobs.remove(&key);
            return false;
        }
        first
    }

    /// One newly eligible submission or FIFO head creates at most one more
    /// execution opportunity. Reserve stack-backed workers under the pool lock.
    fn plan_dispatch(&mut self, opportunities: usize, max_workers: usize) -> WorkerDispatch {
        let spawn = opportunities
            .min(self.queued_jobs.saturating_sub(self.available_workers))
            .min(max_workers - self.active_workers);
        let wake = (opportunities - spawn).min(self.available_workers);
        let first_worker_id = self.next_worker_id;
        self.next_worker_id = self.next_worker_id.wrapping_add(spawn as u64);
        self.active_workers += spawn;
        self.available_workers += spawn;
        WorkerDispatch {
            wake,
            spawn,
            first_worker_id,
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

    fn enqueue(
        &mut self,
        ring_id: u64,
        job: WorkerJob,
        max_workers: usize,
        per_ring_limit: usize,
    ) -> WorkerDispatch {
        if job.position_ticket.is_some() {
            let key = job.serial_key.expect("file-position ordering key");
            self.position_jobs
                .entry(key)
                .or_default()
                .push_back((ring_id, job.req_id));
        }
        let eligible = self.job_eligible(ring_id, &job);
        if !self.rings.contains_key(&ring_id) {
            self.rings.insert(ring_id, RingWorkerQueue::new());
            self.ring_order.push_back(ring_id);
        }
        let entry = self.rings.get_mut(&ring_id).unwrap();
        let runnable = eligible && entry.in_flight < per_ring_limit;
        entry.jobs.push_back(job);
        self.queued_jobs += 1;
        self.plan_dispatch(usize::from(runnable), max_workers)
    }

    fn finish_job(
        &mut self,
        ring_id: u64,
        serial_key: Option<u64>,
        max_workers: usize,
    ) -> WorkerDispatch {
        if let Some(key) = serial_key {
            self.in_flight_keys.remove(&key);
        }
        let entry = self.rings.get_mut(&ring_id).expect("running ring");
        let ring_has_backlog = !entry.jobs.is_empty();
        entry.in_flight -= 1;
        self.available_workers += 1;
        self.remove_empty_ring(ring_id);
        // This worker can cover one job. Each additional ring slot can
        // overlap a job released by the key on another ring, even when
        // earlier finishers haven't claimed their replacement jobs yet.
        let extra = ring_has_backlog && serial_key.is_some() && self.queued_jobs > 1;
        self.plan_dispatch(usize::from(extra), max_workers)
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

        let (max_workers, per_ring_limit) = Self::limits();
        let enqueue = move |position_ticket: Option<FilePositionTicket>| {
            let job = WorkerJob {
                req_id,
                serial_key,
                service_cpu,
                position_ticket,
                task,
            };
            self.inner
                .lock()
                .enqueue(ring_id, job, max_workers, per_ring_limit)
        };
        // The file-position lock precedes the pool lock. Enqueue only
        // transfers the ticket and the pre-boxed job into the bounded pool.
        let dispatch = match position_file {
            Some(file) => file.publish_position_ticket(enqueue),
            None => enqueue(None),
        };
        self.dispatch(dispatch);
    }

    fn dispatch(&'static self, dispatch: WorkerDispatch) {
        for _ in 0..dispatch.wake {
            self.job_wq.notify_one(false);
        }
        for index in 0..dispatch.spawn {
            let id = dispatch.first_worker_id.wrapping_add(index as u64);
            spawn_raw(
                || self.worker_loop(),
                format!("io-uring-wk-{id}"),
                axconfig::TASK_STACK_SIZE,
            );
        }
    }

    /// Cancels a queued (not yet started) Path 3 job for `(ring_id, req_id)`.
    ///
    /// Drops the removed closure outside `SpinNoIrq` to obey ADR-0007.
    pub fn cancel_queued_request(&'static self, ring_id: u64, req_id: u64) -> bool {
        let (max_workers, _) = Self::limits();
        let (removed, dispatch) = {
            let mut inner = self.inner.lock();
            let Some(entry) = inner.rings.get_mut(&ring_id) else {
                return false;
            };
            let Some(index) = entry.jobs.iter().position(|job| job.req_id == req_id) else {
                return false;
            };
            let job = entry.jobs.remove(index).unwrap();
            let exposed = inner.remove_position_job(ring_id, &job);
            inner.remove_empty_ring(ring_id);
            inner.queued_jobs -= 1;
            (job, inner.plan_dispatch(usize::from(exposed), max_workers))
        };
        drop(removed);
        self.dispatch(dispatch);
        true
    }

    /// Cancels all queued Path 3 jobs belonging to `ring_id` (during teardown).
    pub fn cancel_ring_queued(&'static self, ring_id: u64) {
        let (max_workers, _) = Self::limits();
        let (removed, dispatch) = {
            let mut inner = self.inner.lock();
            let Some(entry) = inner.rings.get_mut(&ring_id) else {
                return;
            };
            let drained = core::mem::take(&mut entry.jobs);
            let position_keys: BTreeSet<_> = drained
                .iter()
                .filter(|job| job.position_ticket.is_some())
                .filter_map(|job| job.serial_key)
                .collect();
            let mut exposed = 0;
            for key in position_keys {
                let fifo = inner
                    .position_jobs
                    .get_mut(&key)
                    .expect("queued position ticket");
                let was_head = fifo.front().is_some_and(|&(ring, _)| ring == ring_id);
                fifo.retain(|&(ring, _)| ring != ring_id);
                if fifo.is_empty() {
                    inner.position_jobs.remove(&key);
                } else if was_head {
                    exposed += 1;
                }
            }
            inner.queued_jobs -= drained.len();
            inner.remove_empty_ring(ring_id);
            (drained, inner.plan_dispatch(exposed, max_workers))
        };
        drop(removed);
        self.dispatch(dispatch);
    }

    fn finish_ring_job(&'static self, ring_id: u64, serial_key: Option<u64>) {
        let (max_workers, _) = Self::limits();
        let dispatch = self
            .inner
            .lock()
            .finish_job(ring_id, serial_key, max_workers);
        self.dispatch(dispatch);
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
                let serial_key = job.serial_key;
                if let Some(cpu) = job.service_cpu {
                    // The ring validated this online CPU at setup. Migration
                    // completes before the closure runs; wakes use the same mask.
                    assert!(axtask::set_current_affinity(AxCpuMask::one_shot(cpu)));
                }
                #[cfg(feature = "guest-checks")]
                {
                    let expected = job.service_cpu.map_or(default_mask, AxCpuMask::one_shot);
                    assert_eq!(axtask::current().cpumask(), expected);
                    trace_job(ring_id, job.req_id, "start", serial_key);
                }
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

/// Two workers from a saturated ring finish before either claims its next job.
#[cfg(feature = "guest-checks")]
pub(super) fn check_overlapping_worker_finishes() {
    const MAX: usize = 4;
    const LIMIT: usize = 2;
    let mut pool = PoolInner::new();
    let submit = |pool: &mut PoolInner, ring, req_id, serial_key| {
        let job = WorkerJob {
            req_id,
            serial_key,
            service_cpu: None,
            position_ticket: None,
            task: Box::new(|_| {}),
        };
        pool.enqueue(ring, job, MAX, LIMIT)
    };

    let ring_a = 1;
    let ring_b = 2;
    let ring_c = 3;
    let first_key = Some(10);
    let second_key = Some(20);
    assert_eq!(submit(&mut pool, ring_a, 1, first_key).spawn, 1);
    assert_eq!(submit(&mut pool, ring_a, 2, second_key).spawn, 1);
    let (first_ring, first) = pool.pop_next_job(LIMIT).unwrap();
    let (second_ring, second) = pool.pop_next_job(LIMIT).unwrap();
    let waiting = [
        (ring_a, 3, None),
        (ring_a, 4, None),
        (ring_b, 5, first_key),
        (ring_c, 6, second_key),
    ];
    for (ring, req_id, key) in waiting {
        let dispatch = submit(&mut pool, ring, req_id, key);
        assert_eq!(dispatch.spawn + dispatch.wake, 0);
    }
    assert!(pool.pop_next_job(LIMIT).is_none());

    let first = pool.finish_job(first_ring, first.serial_key, MAX);
    let second = pool.finish_job(second_ring, second.serial_key, MAX);
    assert_eq!(
        first.spawn + second.spawn,
        2,
        "overlapping completions must supply two more workers"
    );
    assert_eq!(pool.available_workers, 4);
    let mut claimed = BTreeSet::new();
    for _ in waiting {
        let (ring, job) = pool.pop_next_job(LIMIT).expect("eligible successor");
        claimed.insert((ring, job.req_id, job.serial_key));
    }
    assert_eq!(claimed, BTreeSet::from(waiting));
    assert_eq!(pool.available_workers, 0);
    axlog::ax_println!("WORKER_OVERLAPPING_FINISH_PASS");
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
