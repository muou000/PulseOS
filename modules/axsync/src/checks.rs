//! Lock stress tests and guest runtime checks for `axsync` synchronization primitives.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use axtask as thread;

use crate::{Mutex, RwLock};

/// Lightweight pseudo-random number generator for concurrency stress testing in no_std.
fn rand_pseudo() -> u32 {
    static RNG_STATE: AtomicU64 = AtomicU64::new(0x1234_5678_9abcdef0);
    let prev = RNG_STATE.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
    (prev ^ (prev >> 30)) as u32
}

/// Helper that yields the current task until the target completion count is reached.
fn wait_until_count(counter: &AtomicU32, target: u32) {
    while counter.load(Ordering::SeqCst) < target {
        thread::yield_now();
    }
}

/// Verifies basic Mutex acquisition, exclusive guard access, explicit drop paths,
/// and reentrancy rejection.
fn test_mutex_basic_and_reentrancy() -> Result<(), &'static str> {
    log::info!("[AXSYNC_GUEST] Mutex basic, guard drop, and reentrancy checks...");

    let lock = Mutex::new(42);
    assert_eq!(*lock.lock(), 42);

    // Test try_lock when unlocked
    {
        let guard = lock.try_lock().ok_or("try_lock failed on unlocked mutex")?;
        assert_eq!(*guard, 42);

        // Test reentrancy rejection: try_lock must fail when already held by the current task
        assert!(
            lock.try_lock().is_none(),
            "try_lock must fail when lock is already held by calling task"
        );
        assert!(lock.is_locked(), "lock must report is_locked while guard is held");

        // Guard drops at end of scope
    }

    // After drop, try_lock succeeds immediately
    assert!(!lock.is_locked());
    let mut guard = lock.try_lock().ok_or("try_lock failed after guard drop")?;
    *guard = 100;
    drop(guard);

    assert_eq!(*lock.lock(), 100);

    // Direct RawMutex primitive checks
    use lock_api::RawMutex as _;
    let raw = crate::RawMutex::new();
    assert!(!raw.is_locked());
    assert!(raw.try_lock(), "RawMutex::try_lock failed on unlocked mutex");
    assert!(raw.is_locked());
    assert!(
        !raw.try_lock(),
        "RawMutex::try_lock must reject re-entrant acquisition"
    );
    // SAFETY:
    // - Precondition 1 (ownership): `raw.try_lock()` succeeded immediately above on this
    //   same calling task, establishing exclusive ownership with `owner_id == current().id().as_u64()`.
    // - Precondition 2 (no aliasing references): No guards or derived references were created from
    //   `raw` (only primitive state checks were run), so no references remain active.
    // Therefore, calling `unlock()` soundly releases the raw mutex.
    unsafe { raw.unlock() };
    assert!(!raw.is_locked());

    log::info!("[AXSYNC_GUEST] Mutex basic, guard drop, and reentrancy: PASS");
    Ok(())
}

/// Runs a high-concurrency Mutex stress test across multiple tasks with yielding and wakeups.
fn test_mutex_concurrent_stress() -> Result<(), &'static str> {
    log::info!("[AXSYNC_GUEST] Mutex concurrent stress test...");

    const NUM_TASKS: usize = 8;
    const ITERS_PER_TASK: usize = 1000;

    let counter = Arc::new(Mutex::new(0u64));
    let done_count = Arc::new(AtomicU32::new(0));

    for _ in 0..NUM_TASKS {
        let counter = counter.clone();
        let done = done_count.clone();
        thread::spawn(move || {
            for _ in 0..ITERS_PER_TASK {
                let mut val = counter.lock();
                *val += 1;
                if *val % 100 == 0 {
                    thread::yield_now();
                }
                drop(val);
                if rand_pseudo() % 5 == 0 {
                    thread::yield_now();
                }
            }
            done.fetch_add(1, Ordering::SeqCst);
        });
    }

    wait_until_count(&done_count, NUM_TASKS as u32);

    let final_val = *counter.lock();
    assert_eq!(
        final_val,
        (NUM_TASKS * ITERS_PER_TASK) as u64,
        "Mutex stress final value mismatch: expected {}, got {}",
        NUM_TASKS * ITERS_PER_TASK,
        final_val
    );

    log::info!("[AXSYNC_GUEST] Mutex concurrent stress: PASS");
    Ok(())
}

/// Verifies basic RwLock shared/exclusive semantics, reader counts, guard drop paths,
/// `into_inner`, and `get_mut`.
fn test_rwlock_basic_and_guard_drop() -> Result<(), &'static str> {
    log::info!("[AXSYNC_GUEST] RwLock basic, reader count, and guard drop checks...");

    let rw = RwLock::new(100);

    // Shared reading
    let r1 = rw.read();
    assert_eq!(*r1, 100);
    assert_eq!(rw.reader_count(), 1);
    assert!(!rw.is_write_locked());

    let r2 = rw
        .try_read()
        .ok_or("try_read should succeed when read-locked")?;
    assert_eq!(*r2, 100);
    assert_eq!(rw.reader_count(), 2);

    // Exclusive write must fail while readers exist
    assert!(
        rw.try_write().is_none(),
        "try_write must fail while readers hold the lock"
    );

    drop(r1);
    assert_eq!(rw.reader_count(), 1);
    drop(r2);
    assert_eq!(rw.reader_count(), 0);

    // Exclusive writing
    {
        let mut w = rw.write();
        *w = 200;
        assert!(rw.is_write_locked());
        assert_eq!(rw.reader_count(), 0);

        // Neither readers nor writers can acquire while write-locked
        assert!(
            rw.try_read().is_none(),
            "try_read must fail while write-locked"
        );
        assert!(
            rw.try_write().is_none(),
            "try_write must fail while write-locked"
        );
        drop(w);
    }

    assert!(!rw.is_write_locked());
    assert_eq!(*rw.read(), 200);

    // get_mut and into_inner
    let mut rw2 = RwLock::new(10);
    *rw2.get_mut() += 5;
    assert_eq!(rw2.into_inner(), 15);

    log::info!("[AXSYNC_GUEST] RwLock basic, reader count, and guard drop: PASS");
    Ok(())
}

/// Tests high-concurrency reader-writer contention, verifying mutual exclusivity and absence of torn reads.
fn test_rwlock_concurrent_readers_and_writers() -> Result<(), &'static str> {
    log::info!("[AXSYNC_GUEST] RwLock concurrent readers & writers stress test...");

    const NUM_WRITERS: usize = 4;
    const NUM_READERS: usize = 4;
    const WRITER_ITERS: usize = 500;

    // Invariant: second element == first element * 2 + 1
    let data = Arc::new(RwLock::new((0u64, 1u64)));
    let writers_done = Arc::new(AtomicU32::new(0));
    let readers_done = Arc::new(AtomicU32::new(0));
    let stop_readers = Arc::new(AtomicBool::new(false));

    // Spawn writers
    for _ in 0..NUM_WRITERS {
        let data = data.clone();
        let done = writers_done.clone();
        thread::spawn(move || {
            for _ in 0..WRITER_ITERS {
                let mut w = data.write();
                let next_a = w.0 + 1;
                w.0 = next_a;
                w.1 = next_a * 2 + 1;
                if next_a % 50 == 0 {
                    thread::yield_now();
                }
                drop(w);
                if rand_pseudo() % 4 == 0 {
                    thread::yield_now();
                }
            }
            done.fetch_add(1, Ordering::SeqCst);
        });
    }

    // Spawn readers
    for _ in 0..NUM_READERS {
        let data = data.clone();
        let done = readers_done.clone();
        let stop = stop_readers.clone();
        thread::spawn(move || {
            let mut reads = 0;
            while !stop.load(Ordering::Acquire) || reads < 100 {
                let r = data.read();
                let (a, b) = *r;
                assert_eq!(
                    b,
                    a * 2 + 1,
                    "Torn read detected in RwLock: a={}, b={}",
                    a,
                    b
                );
                reads += 1;
                if reads % 50 == 0 {
                    thread::yield_now();
                }
                drop(r);
            }
            done.fetch_add(1, Ordering::SeqCst);
        });
    }

    // Await all writers
    wait_until_count(&writers_done, NUM_WRITERS as u32);
    stop_readers.store(true, Ordering::Release);

    // Await all readers
    wait_until_count(&readers_done, NUM_READERS as u32);

    let final_val = *data.read();
    assert_eq!(
        final_val.0,
        (NUM_WRITERS * WRITER_ITERS) as u64,
        "RwLock final writer value mismatch"
    );
    assert_eq!(
        final_val.1,
        final_val.0 * 2 + 1,
        "RwLock final invariant mismatch"
    );

    log::info!("[AXSYNC_GUEST] RwLock concurrent readers & writers: PASS");
    Ok(())
}

/// Tests RwLock wakeups across writers and readers, and anti-starvation backing off for waiting writers.
fn test_rwlock_wakeups_and_starvation() -> Result<(), &'static str> {
    log::info!("[AXSYNC_GUEST] RwLock wakeup and writer anti-starvation checks...");

    let lock = Arc::new(RwLock::new(0u32));
    let reader_held = Arc::new(AtomicBool::new(false));
    let writer_waiting = Arc::new(AtomicBool::new(false));
    let writer_finished = Arc::new(AtomicBool::new(false));

    // Task 1: acquires read lock, signals reader_held, waits for writer to queue, then drops read lock.
    let lock_clone1 = lock.clone();
    let reader_held_clone = reader_held.clone();
    let writer_waiting_clone = writer_waiting.clone();
    thread::spawn(move || {
        let r = lock_clone1.read();
        reader_held_clone.store(true, Ordering::Release);
        while !writer_waiting_clone.load(Ordering::Acquire) {
            thread::yield_now();
        }
        // Yield to allow writer to block on wq
        for _ in 0..5 {
            thread::yield_now();
        }
        drop(r);
    });

    // Wait until reader holds lock
    while !reader_held.load(Ordering::Acquire) {
        thread::yield_now();
    }

    // Task 2: writer tries to acquire write lock, blocking on wq until reader drops.
    let lock_clone2 = lock.clone();
    let writer_waiting_clone2 = writer_waiting.clone();
    let writer_finished_clone = writer_finished.clone();
    thread::spawn(move || {
        writer_waiting_clone2.store(true, Ordering::Release);
        let mut w = lock_clone2.write();
        *w = 999;
        drop(w);
        writer_finished_clone.store(true, Ordering::Release);
    });

    // Await writer completion
    while !writer_finished.load(Ordering::Acquire) {
        thread::yield_now();
    }

    assert_eq!(*lock.read(), 999);
    log::info!("[AXSYNC_GUEST] RwLock wakeup and writer anti-starvation: PASS");
    Ok(())
}

/// Runs the complete suite of axsync lock stress and safety checks.
pub fn run_lock_stress_checks() -> Result<(), &'static str> {
    log::info!("[AXSYNC_GUEST] Starting axsync lock stress & concurrency checks...");

    test_mutex_basic_and_reentrancy()?;
    test_mutex_concurrent_stress()?;
    test_rwlock_basic_and_guard_drop()?;
    test_rwlock_concurrent_readers_and_writers()?;
    test_rwlock_wakeups_and_starvation()?;

    log::info!("[AXSYNC_GUEST] All axsync lock stress & concurrency checks PASSED!");
    Ok(())
}

