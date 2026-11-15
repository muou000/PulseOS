//! Diagnostic only: actual axsync mutex source with a task-ID boundary adapter.
//! No scheduler or wait-queue behavior is simulated or verified here.
extern crate self as axtask;

use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
};

use lock_api::RawMutex as _;

thread_local! { static TASK_ID: Cell<u64> = const { Cell::new(1) }; }

pub struct TaskId(u64);
impl TaskId {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}
pub struct Current;
impl Current {
    pub fn id(&self) -> TaskId {
        TaskId(TASK_ID.get())
    }
    pub fn id_name(&self) -> String {
        format!("host-task-{}", TASK_ID.get())
    }
}
pub fn current() -> Current {
    Current
}

pub enum WaitReason {
    Mutex,
}
pub struct WaitContext;
impl WaitContext {
    pub fn new<F: Fn() -> (WaitReason, u64, u64)>(_: F) -> Self {
        Self
    }
}
pub struct WakeContext;
impl WakeContext {
    pub fn task() -> Self {
        Self
    }
}
pub struct WaitQueue;
impl WaitQueue {
    pub const fn new() -> Self {
        Self
    }
    pub fn wait_until_with_context<F: Fn() -> bool>(&self, _: WaitContext, _: F) {
        panic!("scheduler wait reached outside diagnostic scope")
    }
    pub fn notify_one_with_context(&self, _: bool, _: WakeContext) -> bool {
        false
    }
}

#[path = "../../../modules/axsync/src/mutex.rs"]
mod actual_mutex;
use actual_mutex::{Mutex, RawMutex};

fn zero_id_is_rejected(blocking: bool) -> bool {
    TASK_ID.set(0);
    let raw = RawMutex::new();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if blocking {
            raw.lock();
        } else {
            let _ = raw.try_lock();
        }
    }));
    let ok = result.is_err() && !raw.is_locked();
    println!(
        "zero-ID {} rejection and unchanged state: {}",
        if blocking { "lock" } else { "try_lock" },
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let zero_lock_ok = zero_id_is_rejected(true);
    let zero_try_ok = zero_id_is_rejected(false);
    TASK_ID.set(7);
    let mutex = Mutex::new(41);
    let mut guard: actual_mutex::MutexGuard<'_, i32> = mutex.lock();
    *guard += 1;
    assert!(mutex.try_lock().is_none());
    let panic = catch_unwind(AssertUnwindSafe(|| {
        drop(mutex.lock());
    }))
    .expect_err("recursive acquisition must be rejected");
    let message = panic
        .downcast_ref::<String>()
        .expect("formatted recursion panic");
    assert!(message.contains("tried to acquire mutex it already owns"));
    // The rejected nested acquisition must leave the original permission intact.
    assert_eq!(*guard, 42);
    assert!(mutex.try_lock().is_none());
    drop(guard);
    assert_eq!(*mutex.lock(), 42);
    println!("nonzero-ID exclusivity, reentrancy, guard drop: PASS");

    // Scoped threads keep the mutex alive without leaking any allocation.
    std::thread::scope(|scope| {
        let guard = mutex.lock();
        scope
            .spawn(move || {
                TASK_ID.set(8);
                assert_eq!(*guard, 42);
                drop(guard);
            })
            .join()
            .unwrap();
    });
    assert!(mutex.try_lock().is_some());
    println!("guard transfer/drop on another task ID: PASS");
    if !(zero_lock_ok && zero_try_ok) {
        std::process::exit(1);
    }
}
