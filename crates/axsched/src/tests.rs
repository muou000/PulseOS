macro_rules! def_test_sched {
    ($name:ident, $scheduler:ty, $task:ty) => {
        mod $name {
            use alloc::sync::Arc;

            use crate::*;

            #[test]
            fn test_sched() {
                const NUM_TASKS: usize = 11;

                let mut scheduler = <$scheduler>::new();
                for i in 0..NUM_TASKS {
                    scheduler.add_task(Arc::new(<$task>::new(i)));
                }

                for i in 0..NUM_TASKS * 10 - 1 {
                    let next = scheduler.pick_next_task().unwrap();
                    assert_eq!(*next.inner(), i % NUM_TASKS);
                    // pass a tick to ensure the order of tasks
                    scheduler.task_tick(&next);
                    scheduler.put_prev_task(next, false);
                }

                let mut n = 0;
                while scheduler.pick_next_task().is_some() {
                    n += 1;
                }
                assert_eq!(n, NUM_TASKS);
            }

            #[test]
            fn bench_yield() {
                const NUM_TASKS: usize = 1_000_000;
                const COUNT: usize = NUM_TASKS * 3;

                let mut scheduler = <$scheduler>::new();
                for i in 0..NUM_TASKS {
                    scheduler.add_task(Arc::new(<$task>::new(i)));
                }

                let t0 = std::time::Instant::now();
                for _ in 0..COUNT {
                    let next = scheduler.pick_next_task().unwrap();
                    scheduler.put_prev_task(next, false);
                }
                let t1 = std::time::Instant::now();
                println!(
                    "  {}: task yield speed: {:?}/task",
                    stringify!($scheduler),
                    (t1 - t0) / (COUNT as u32)
                );
            }

            #[test]
            fn bench_remove() {
                const NUM_TASKS: usize = 10_000;

                let mut scheduler = <$scheduler>::new();
                let mut tasks = Vec::new();
                for i in 0..NUM_TASKS {
                    let t = Arc::new(<$task>::new(i));
                    tasks.push(t.clone());
                    scheduler.add_task(t);
                }

                let t0 = std::time::Instant::now();
                for i in (0..NUM_TASKS).rev() {
                    let t = scheduler.remove_task(&tasks[i]).unwrap();
                    assert_eq!(*t.inner(), i);
                }
                let t1 = std::time::Instant::now();
                println!(
                    "  {}: task remove speed: {:?}/task",
                    stringify!($scheduler),
                    (t1 - t0) / (NUM_TASKS as u32)
                );
            }
        }
    };
}

def_test_sched!(fifo, FifoScheduler::<usize>, FifoTask::<usize>);
def_test_sched!(rr, RRScheduler::<usize, 5>, RRTask::<usize, 5>);
def_test_sched!(cfs, CFScheduler::<usize>, CFSTask::<usize>);

mod rr_load_balance {
    use alloc::sync::Arc;

    use crate::{BaseScheduler, RRScheduler, RRTask};

    type TestTask = RRTask<usize, 5>;
    type TestScheduler = RRScheduler<usize, 5>;

    fn task(id: usize) -> Arc<TestTask> {
        Arc::new(TestTask::new(id))
    }

    #[test]
    fn detach_normal_task_preserves_order_and_rt_priority() {
        let mut scheduler = TestScheduler::new();
        let rt = task(99);
        rt.set_priority(99);

        scheduler.add_task(task(0));
        scheduler.add_task(task(1));
        scheduler.add_task(rt.clone());
        scheduler.add_task(task(2));
        scheduler.add_task(task(3));

        assert_eq!(scheduler.normal_task_count(), 4);
        let detached = scheduler
            .detach_normal_task(|candidate| *candidate.inner() == 2)
            .expect("normal task should be detachable");
        assert_eq!(*detached.inner(), 2);
        assert_eq!(scheduler.normal_task_count(), 3);

        assert!(Arc::ptr_eq(&scheduler.pick_next_task().unwrap(), &rt));
        for expected in [0, 1, 3] {
            assert_eq!(*scheduler.pick_next_task().unwrap().inner(), expected);
        }
        assert!(scheduler.pick_next_task().is_none());
    }

    #[test]
    fn detach_normal_task_respects_predicate_and_never_takes_rt() {
        let mut scheduler = TestScheduler::new();
        let rt = task(10);
        rt.set_priority(10);
        scheduler.add_task(rt.clone());
        scheduler.add_task(task(20));

        assert!(scheduler.detach_normal_task(|_| false).is_none());
        assert!(
            scheduler
                .detach_normal_task(|candidate| candidate.priority() == 10)
                .is_none()
        );
        assert_eq!(scheduler.normal_task_count(), 1);
        assert!(Arc::ptr_eq(&scheduler.pick_next_task().unwrap(), &rt));
        assert_eq!(*scheduler.pick_next_task().unwrap().inner(), 20);
    }
}
