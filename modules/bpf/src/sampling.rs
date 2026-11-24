//! Bounded handoff of frozen samples from IRQ observers to deferred BPF execution.
//!
//! A single FIFO preserves the order in which a thread publishes samples across
//! CPU migration. The IRQ adapter supplies synchronization and counts drops.

use crate::perf_event::RuntimeSample;

/// Fixed-capacity FIFO for frozen samples from all CPUs.
pub struct SampleQueue {
    slots: [Option<RuntimeSample>; Self::CAPACITY],
    head: usize,
    len: usize,
}

impl SampleQueue {
    /// Maximum number of snapshots kept until the worker drains them.
    pub const CAPACITY: usize = 128;

    /// Creates an empty queue without allocating.
    pub const fn new() -> Self {
        Self {
            slots: [None; Self::CAPACITY],
            head: 0,
            len: 0,
        }
    }

    /// Appends a snapshot, returning false if the queue is full.
    pub fn push(&mut self, sample: RuntimeSample) -> bool {
        if self.len == Self::CAPACITY {
            return false;
        }
        let tail = (self.head + self.len) % Self::CAPACITY;
        self.slots[tail] = Some(sample);
        self.len += 1;
        true
    }

    /// Removes the oldest snapshot.
    pub fn pop(&mut self) -> Option<RuntimeSample> {
        if self.len == 0 {
            return None;
        }
        let sample = self.slots[self.head].take();
        self.head = (self.head + 1) % Self::CAPACITY;
        self.len -= 1;
        sample
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ip: u64) -> RuntimeSample {
        RuntimeSample {
            timestamp_ns: 10,
            cpu: 2,
            pid: 100,
            tid: 101,
            task_id: 200,
            ip,
            stack: pulse_bpf_schema::FrozenStack::unavailable(
                pulse_bpf_schema::StackRegisters {
                    ip,
                    sp: 0,
                    fp: 0,
                    ra: 0,
                },
                pulse_bpf_schema::StackStatus::Unavailable,
            ),
            user_mode: true,
            task_clock_ns: 9,
            generation: 4,
        }
    }

    #[test]
    fn snapshot_queue_preserves_task_clock_order_across_cpu_migration() {
        let mut queue = SampleQueue::new();
        // This thread first runs on CPU 1, then migrates to CPU 0. Draining
        // per-CPU batches in CPU-number order would deliver these backwards.
        let mut before = sample(0x1000);
        before.cpu = 1;
        before.task_clock_ns = 100;
        let mut after = sample(0x2000);
        after.cpu = 0;
        after.timestamp_ns = 20;
        after.task_clock_ns = 200;
        assert!(queue.push(before));
        assert!(queue.push(after));
        let first = queue.pop().unwrap();
        let second = queue.pop().unwrap();
        assert_eq!((first.cpu, first.task_clock_ns, first.ip), (1, 100, 0x1000));
        assert_eq!(
            (second.cpu, second.task_clock_ns, second.ip),
            (0, 200, 0x2000)
        );
        assert_eq!(first.task_id, second.task_id);
        assert!(queue.pop().is_none());
    }

    #[test]
    fn snapshot_queue_preserves_origin_and_fifo_across_wrap() {
        let mut queue = SampleQueue::new();
        for ip in 0..SampleQueue::CAPACITY as u64 {
            assert!(queue.push(sample(ip)));
        }
        assert!(!queue.push(sample(999)));
        for ip in 0..64 {
            assert_eq!(queue.pop().unwrap().ip, ip);
        }
        for ip in 128..192 {
            assert!(queue.push(sample(ip)));
        }
        for ip in 64..192 {
            let observed = queue.pop().unwrap();
            assert_eq!(observed.ip, ip);
            assert_eq!(observed.timestamp_ns, 10);
            assert_eq!(observed.cpu, 2);
            assert_eq!(observed.pid, 100);
            assert_eq!(observed.tid, 101);
            assert_eq!(observed.task_id, 200);
            assert!(observed.user_mode);
            assert_eq!(observed.task_clock_ns, 9);
            assert_eq!(observed.generation, 4);
        }
        assert!(queue.pop().is_none());
    }
}
