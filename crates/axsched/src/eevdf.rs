use alloc::sync::Arc;

use eevdf_scheduler::{EEVDFScheduler, EEVDFTask, EnqueueReason};

use crate::{BaseScheduler, SchedEnqueueReason};

const fn map_enqueue_reason(reason: SchedEnqueueReason) -> EnqueueReason {
    match reason {
        SchedEnqueueReason::Spawn => EnqueueReason::Spawn,
        SchedEnqueueReason::Wake => EnqueueReason::Wake,
        SchedEnqueueReason::Yield => EnqueueReason::Yield,
        SchedEnqueueReason::Preempt => EnqueueReason::Preempt,
        SchedEnqueueReason::Migration => EnqueueReason::Migration,
    }
}

impl<T, const S: u64> BaseScheduler for EEVDFScheduler<T, S> {
    type SchedItem = Arc<EEVDFTask<T>>;

    fn init(&mut self) {}

    fn add_task(&mut self, task: Self::SchedItem) {
        EEVDFScheduler::enqueue_new(self, task);
    }

    fn enqueue_task(&mut self, task: Self::SchedItem, reason: SchedEnqueueReason, now_ns: u64) {
        EEVDFScheduler::enqueue(self, task, map_enqueue_reason(reason), now_ns);
    }

    fn remove_task(&mut self, task: &Self::SchedItem) -> Option<Self::SchedItem> {
        EEVDFScheduler::remove(self, task)
    }

    fn pick_next_task(&mut self) -> Option<Self::SchedItem> {
        EEVDFScheduler::pick_next(self)
    }

    fn pick_next_task_at(&mut self, now_ns: u64) -> Option<Self::SchedItem> {
        EEVDFScheduler::pick_next_at(self, now_ns)
    }

    fn put_prev_task(&mut self, prev: Self::SchedItem, preempt: bool) {
        EEVDFScheduler::requeue_previous(self, prev, preempt);
    }

    fn task_started(&mut self, task: &Self::SchedItem, now_ns: u64) {
        EEVDFScheduler::on_task_start(self, task, now_ns);
    }

    fn task_stopped(&mut self, task: &Self::SchedItem, now_ns: u64) {
        EEVDFScheduler::on_task_stop(self, task, now_ns);
    }

    fn task_tick(&mut self, current: &Self::SchedItem) -> bool {
        EEVDFScheduler::tick(self, current)
    }

    fn task_tick_at(&mut self, current: &Self::SchedItem, now_ns: u64) -> bool {
        EEVDFScheduler::tick_at(self, current, now_ns)
    }

    fn should_preempt(
        &mut self,
        current: &Self::SchedItem,
        candidate: &Self::SchedItem,
        now_ns: u64,
    ) -> bool {
        EEVDFScheduler::candidate_preempts(self, current, candidate, now_ns)
    }

    fn next_preemption_deadline(&self, current: &Self::SchedItem, now_ns: u64) -> Option<u64> {
        EEVDFScheduler::preemption_deadline(self, current, now_ns)
    }

    fn set_priority(&mut self, task: &Self::SchedItem, priority: isize) -> bool {
        EEVDFScheduler::update_priority(self, task, priority)
    }

    fn set_priority_at(&mut self, task: &Self::SchedItem, priority: isize, now_ns: u64) -> bool {
        EEVDFScheduler::update_priority_at(self, task, priority, now_ns)
    }

    fn is_empty(&self) -> bool {
        EEVDFScheduler::queued_is_empty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_enqueue_reason() {
        assert_eq!(
            map_enqueue_reason(SchedEnqueueReason::Spawn),
            EnqueueReason::Spawn
        );
        assert_eq!(
            map_enqueue_reason(SchedEnqueueReason::Wake),
            EnqueueReason::Wake
        );
        assert_eq!(
            map_enqueue_reason(SchedEnqueueReason::Yield),
            EnqueueReason::Yield
        );
        assert_eq!(
            map_enqueue_reason(SchedEnqueueReason::Preempt),
            EnqueueReason::Preempt
        );
        assert_eq!(
            map_enqueue_reason(SchedEnqueueReason::Migration),
            EnqueueReason::Migration
        );
    }

    #[test]
    fn base_scheduler_adapter_forwards_to_the_algorithm() {
        let mut scheduler = EEVDFScheduler::<usize, 1_000>::new();
        let task = Arc::new(EEVDFTask::new(7));

        BaseScheduler::enqueue_task(&mut scheduler, task, SchedEnqueueReason::Spawn, 0);
        assert!(!BaseScheduler::is_empty(&scheduler));

        let selected = BaseScheduler::pick_next_task_at(&mut scheduler, 0).unwrap();
        assert_eq!(*selected.inner(), 7);
    }
}
