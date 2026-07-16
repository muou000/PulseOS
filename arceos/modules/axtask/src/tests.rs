use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, Once};

use axerrno::{AxError, AxResult};
use axpoll::{IoEvents, Pollable};

use crate::{WaitQueue, api as axtask, current};

static INIT: Once = Once::new();
static SERIAL: Mutex<()> = Mutex::new(());

#[test]
fn test_sched_fifo() {
    let _lock = SERIAL.lock();
    INIT.call_once(axtask::init_scheduler);

    const NUM_TASKS: usize = 10;
    static FINISHED_TASKS: AtomicUsize = AtomicUsize::new(0);

    for i in 0..NUM_TASKS {
        axtask::spawn_raw(
            move || {
                println!("sched-fifo: Hello, task {}! ({})", i, current().id_name());
                axtask::yield_now();
                let order = FINISHED_TASKS.fetch_add(1, Ordering::Release);
                assert_eq!(order, i); // FIFO scheduler
            },
            format!("T{}", i),
            0x1000,
        );
    }

    while FINISHED_TASKS.load(Ordering::Acquire) < NUM_TASKS {
        axtask::yield_now();
    }
}

#[test]
fn test_fp_state_switch() {
    let _lock = SERIAL.lock();
    INIT.call_once(axtask::init_scheduler);

    const NUM_TASKS: usize = 5;
    const FLOATS: [f64; NUM_TASKS] = [
        3.141592653589793,
        2.718281828459045,
        -1.4142135623730951,
        0.0,
        0.618033988749895,
    ];
    static FINISHED_TASKS: AtomicUsize = AtomicUsize::new(0);

    for (i, float) in FLOATS.iter().enumerate() {
        axtask::spawn(move || {
            let mut value = float + i as f64;
            axtask::yield_now();
            value -= i as f64;

            println!("fp_state_switch: Float {} = {}", i, value);
            assert!((value - float).abs() < 1e-9);
            FINISHED_TASKS.fetch_add(1, Ordering::Release);
        });
    }
    while FINISHED_TASKS.load(Ordering::Acquire) < NUM_TASKS {
        axtask::yield_now();
    }
}

#[test]
fn test_wait_queue() {
    let _lock = SERIAL.lock();
    INIT.call_once(axtask::init_scheduler);

    const NUM_TASKS: usize = 10;

    static WQ1: WaitQueue = WaitQueue::new();
    static WQ2: WaitQueue = WaitQueue::new();
    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    for _ in 0..NUM_TASKS {
        axtask::spawn(move || {
            COUNTER.fetch_add(1, Ordering::Release);
            println!("wait_queue: task {:?} started", current().id());
            WQ1.notify_one(true); // WQ1.wait_until()
            WQ2.wait();

            assert!(!current().in_wait_queue());

            COUNTER.fetch_sub(1, Ordering::Release);
            println!("wait_queue: task {:?} finished", current().id());
            WQ1.notify_one(true); // WQ1.wait_until()
        });
    }

    println!("task {:?} is waiting for tasks to start...", current().id());
    WQ1.wait_until(|| COUNTER.load(Ordering::Acquire) == NUM_TASKS);
    assert_eq!(COUNTER.load(Ordering::Acquire), NUM_TASKS);
    assert!(!current().in_wait_queue());
    WQ2.notify_all(true); // WQ2.wait()

    println!(
        "task {:?} is waiting for tasks to finish...",
        current().id()
    );
    WQ1.wait_until(|| COUNTER.load(Ordering::Acquire) == 0);
    assert_eq!(COUNTER.load(Ordering::Acquire), 0);
    assert!(!current().in_wait_queue());
}

#[test]
fn test_task_join() {
    let _lock = SERIAL.lock();
    INIT.call_once(axtask::init_scheduler);

    const NUM_TASKS: usize = 10;
    let mut tasks = Vec::with_capacity(NUM_TASKS);

    for i in 0..NUM_TASKS {
        tasks.push(axtask::spawn_raw(
            move || {
                println!("task_join: task {}! ({})", i, current().id_name());
                axtask::yield_now();
                axtask::exit(i as _);
            },
            format!("T{}", i),
            0x1000,
        ));
    }

    for i in 0..NUM_TASKS {
        assert_eq!(tasks[i].join(), Some(i as _));
    }
}

#[test]
fn test_async_task() {
    use core::sync::atomic::AtomicU64;
    let _lock = SERIAL.lock();
    INIT.call_once(axtask::init_scheduler);

    static HAS_KERNEL_STACK: AtomicBool = AtomicBool::new(false);
    static TASK_ID_BEFORE_YIELD: AtomicU64 = AtomicU64::new(0);
    static TASK_ID_AFTER_YIELD: AtomicU64 = AtomicU64::new(0);

    HAS_KERNEL_STACK.store(false, Ordering::Release);
    TASK_ID_BEFORE_YIELD.store(0, Ordering::Release);
    TASK_ID_AFTER_YIELD.store(0, Ordering::Release);

    let task = axtask::spawn_async(async {
        println!("async task: Hello, world!");
        let curr = current();
        HAS_KERNEL_STACK.store(curr.kernel_stack_top().is_some(), Ordering::Release);
        TASK_ID_BEFORE_YIELD.store(curr.id().as_u64(), Ordering::Release);

        // Waking and returning Ready in the same poll is legal. The stack-backed
        // block_on model must not leave a stale scheduler entry in this case.
        core::future::poll_fn(|cx| {
            cx.waker().wake_by_ref();
            core::task::Poll::Ready(())
        })
        .await;

        crate::future::yield_now().await;
        println!("async task: Resumed!");
        TASK_ID_AFTER_YIELD.store(current().id().as_u64(), Ordering::Release);
    });

    assert_eq!(task.join(), Some(0));
    assert!(HAS_KERNEL_STACK.load(Ordering::Acquire));
    assert_eq!(
        TASK_ID_BEFORE_YIELD.load(Ordering::Acquire),
        task.id().as_u64()
    );
    assert_eq!(
        TASK_ID_AFTER_YIELD.load(Ordering::Acquire),
        task.id().as_u64()
    );
}

#[test]
fn test_poll_io_registers_before_recheck() {
    struct RegisterMakesReady {
        ready: AtomicBool,
        registrations: AtomicUsize,
    }

    impl Pollable for RegisterMakesReady {
        fn poll(&self) -> IoEvents {
            if self.ready.load(Ordering::Acquire) {
                IoEvents::IN
            } else {
                IoEvents::empty()
            }
        }

        fn register(&self, _context: &mut core::task::Context<'_>, _events: IoEvents) {
            self.registrations.fetch_add(1, Ordering::Relaxed);
            self.ready.store(true, Ordering::Release);
        }
    }

    let _lock = SERIAL.lock();
    INIT.call_once(axtask::init_scheduler);

    let pollable = RegisterMakesReady {
        ready: AtomicBool::new(false),
        registrations: AtomicUsize::new(0),
    };
    let result = crate::future::block_on(crate::future::poll_io(
        &pollable,
        IoEvents::IN,
        false,
        || -> AxResult<usize> {
            if pollable.ready.load(Ordering::Acquire) {
                Ok(7)
            } else {
                Err(AxError::WouldBlock)
            }
        },
    ));

    assert_eq!(result, Ok(7));
    assert_eq!(pollable.registrations.load(Ordering::Relaxed), 1);
}
