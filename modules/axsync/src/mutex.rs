//! A naïve sleeping mutex.

use core::sync::atomic::{AtomicU64, Ordering};

use axtask::{WaitContext, WaitQueue, WaitReason, WakeContext, current};

/// A [`lock_api::RawMutex`] implementation.
///
/// When the mutex is locked, the current task will block and be put into the
/// wait queue. When the mutex is unlocked, tasks waiting on the queue
/// will be woken up.
pub struct RawMutex {
    // Safety invariant: `wq` coordinates task blocking and wakeups. Tasks sleeping on `wq`
    // are guaranteed to be woken via `notify_one_with_context` when the lock owner releases
    // the mutex in `unlock()`.
    wq: WaitQueue,

    // Safety invariant:
    // - `owner_id == 0`: the mutex is unlocked; no task holds exclusive access to the
    //   protected data.
    // - `owner_id != 0`: the mutex is held exclusively by the task whose `TaskId::as_u64()`
    //   matches `owner_id`.
    // Valid task IDs in `axtask` are strictly positive integers (>= 1). Therefore, 0
    // unambiguously designates the unlocked state.
    owner_id: AtomicU64,
}

impl RawMutex {
    /// Creates a [`RawMutex`].
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            wq: WaitQueue::new(),
            owner_id: AtomicU64::new(0),
        }
    }
}

// SAFETY:
// Implementation of `lock_api::RawMutex` for `RawMutex`.
//
// Proof obligations:
// 1. Mutual Exclusivity: Only one task can hold the lock at any given time.
// 2. Memory Synchronization: Lock acquisition establishes `Acquire` ordering and release
//    establishes `Release` ordering, forming a happens-before relationship that prevents
//    data races on the protected data across task transitions.
// 3. Exclusivity Permission for Guards: A successful `lock` or `try_lock` grants the caller
//    exclusive permission to access the protected `T` via `lock_api::MutexGuard`.
// 4. Sound Release Contract: `unlock` releases the lock and allows subsequent tasks to acquire it.
//
// Evidence:
// - Atomic State Invariant: `owner_id` represents the current owner state. 0 represents unlocked;
//   non-zero `N` represents exclusive ownership initially acquired by the task with `TaskId` `N`.
// - In `axtask`, `TaskId` values are generated sequentially starting from 1 (`AtomicU64::new(1)`),
//   guaranteeing `TaskId != 0` for all live tasks and uniqueness across distinct tasks.
// - Exclusive acquisition:
//   - In `try_lock`, `owner_id.compare_exchange(0, current_id, Ordering::Acquire, Ordering::Relaxed)`
//     atomically transitions `owner_id` from 0 to `current_id`. By hardware atomic guarantees,
//     at most one task can succeed in transitioning `0 -> current_id`.
//   - In `lock`, `compare_exchange_weak` atomically attempts the same transition in a loop, sleeping
//     on `self.wq` between attempts when `owner_id != 0`.
//   - Both acquisition paths use `Ordering::Acquire`, which synchronizes with the `Ordering::Release`
//     transition in `unlock`. By the Rust memory model, all writes to the protected data performed
//     by prior owners happen-before the current task reads or writes the protected data.
// - Reentrancy Rejection:
//   - If the current task attempts to re-acquire the lock it already owns, `lock()` asserts
//     `owner_id != current_id`, preventing recursive deadlocks and aliasing mutable references.
//     `try_lock()` fails and returns `false` because `owner_id` is already non-zero.
// - Release and Wakeups:
//   - `unlock` atomically transitions `owner_id` from non-zero to 0 with `Ordering::Release`.
//   - Only the holder of the unique `MutexGuard` (or legitimate caller satisfying `# Safety`)
//     may call `unlock`.
//   - Once `owner_id` becomes 0, `wq.notify_one_with_context` wakes one sleeping waiter.
// - Guard Transfer:
//   - `GuardMarker = lock_api::GuardSend` permits sending the `MutexGuard` across tasks (e.g.,
//     in asynchronous execution across await points). Ownership of the unique guard token transfers
//     exclusivity permission, and `unlock` soundly releases the lock upon drop.
//
// Therefore, `RawMutex` satisfies all safety requirements of `lock_api::RawMutex`.
unsafe impl lock_api::RawMutex for RawMutex {
    /// Initial value for an unlocked mutex.
    ///
    /// A “non-constant” const item is a legacy way to supply an initialized value to downstream
    /// static items. Can hopefully be replaced with `const fn new() -> Self` at some point.
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT: Self = RawMutex::new();

    type GuardMarker = lock_api::GuardSend;

    #[inline(always)]
    fn lock(&self) {
        let current_id = current().id().as_u64();
        loop {
            // Can fail to lock even if the spinlock is not locked. May be more efficient than `try_lock`
            // when called in a loop.
            match self.owner_id.compare_exchange_weak(
                0,
                current_id,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(owner_id) => {
                    if owner_id == 0 {
                        // Spurious CAS failure; lock is free, retry immediately.
                        continue;
                    }
                    assert_ne!(
                        owner_id,
                        current_id,
                        "{} tried to acquire mutex it already owns.",
                        current().id_name()
                    );
                    // Wait until the lock looks unlocked before retrying
                    self.wq.wait_until_with_context(
                        WaitContext::new(|| {
                            (
                                WaitReason::Mutex,
                                self as *const Self as usize as u64,
                                owner_id,
                            )
                        }),
                        || !self.is_locked(),
                    );
                }
            }
        }
    }

    #[inline(always)]
    fn try_lock(&self) -> bool {
        let current_id = current().id().as_u64();
        // The reason for using a strong compare_exchange is explained here:
        // https://github.com/Amanieu/parking_lot/pull/207#issuecomment-575869107
        self.owner_id
            .compare_exchange(0, current_id, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Releases the mutex.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// 1. The lock is currently held by the caller (ownership was acquired via `lock` or
    ///    `try_lock`, and the corresponding guard has not yet been unlocked).
    /// 2. No active references (`&T` or `&mut T`) derived from the guard associated with this
    ///    lock remain in use across or after this call.
    #[inline(always)]
    unsafe fn unlock(&self) {
        // Synchronization / State transition:
        // Transition `owner_id` from non-zero to 0 with `Release` ordering.
        // - Precondition 1 guarantees the lock is held.
        // - `swap(0)` atomically clears ownership and publishes all writes performed in the
        //   critical section to any subsequent locker acquiring with `Ordering::Acquire`.
        // - The assertion verifies that the lock was in fact locked prior to unlock.
        // - `self.wq.notify_one_with_context` wakes up one waiting task.
        let prev = self.owner_id.swap(0, Ordering::Release);
        assert_ne!(
            prev,
            0,
            "{} tried to release mutex that was not locked",
            current().id_name()
        );
        self.wq.notify_one_with_context(true, WakeContext::task());
    }

    #[inline(always)]
    fn is_locked(&self) -> bool {
        self.owner_id.load(Ordering::Relaxed) != 0
    }
}

/// A mutual exclusion primitive based on [`RawMutex`] and [`lock_api::Mutex`].
///
/// # Safety and Concurrency Guarantees
///
/// - **Interior Mutability**: Wraps protected data `T` inside an `UnsafeCell<T>`.
/// - **Guard Exclusivity**: `Mutex::lock()` and `Mutex::try_lock()` return a [`MutexGuard`]
///   which implements [`core::ops::Deref`] and [`core::ops::DerefMut`]. Because `RawMutex`
///   guarantees mutual exclusion, at most one task can hold a `MutexGuard` at any time,
///   guaranteeing exclusive, race-free `&mut T` reference access.
/// - **Thread Safety (`Send` / `Sync`)**:
///   - `Mutex<T>` implements `Send` when `T: Send`, because transferring ownership of the
///     mutex moves the underlying `T`.
///   - `Mutex<T>` implements `Sync` when `T: Send`, because a task with a shared reference
///     `&Mutex<T>` can acquire exclusive `&mut T` access via `lock()`, allowing values of type
///     `T` to be mutated or moved out across task boundaries.
///   - `MutexGuard` is `Send` (`GuardSend`) when `T: Send`, allowing guards to be transferred
///     across execution contexts (such as across `.await` points in asynchronous tasks).
pub type Mutex<T> = lock_api::Mutex<RawMutex, T>;

/// An RAII implementation of a “scoped lock” of a mutex.
///
/// When this structure is dropped (falls out of scope), the lock will be
/// released.
pub type MutexGuard<'a, T> = lock_api::MutexGuard<'a, RawMutex, T>;

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use axtask as thread;

    use crate::Mutex;

    static INIT: Once = Once::new();

    fn may_interrupt() {
        // simulate interrupts
        if rand::random::<u32>() % 3 == 0 {
            thread::yield_now();
        }
    }

    #[test]
    fn lots_and_lots() {
        INIT.call_once(thread::init_scheduler);

        const NUM_TASKS: u32 = 10;
        const NUM_ITERS: u32 = 10_000;
        static M: Mutex<u32> = Mutex::new(0);

        fn inc(delta: u32) {
            for _ in 0..NUM_ITERS {
                let mut val = M.lock();
                *val += delta;
                may_interrupt();
                drop(val);
                may_interrupt();
            }
        }

        for _ in 0..NUM_TASKS {
            thread::spawn(|| inc(1));
            thread::spawn(|| inc(2));
        }

        println!("spawn OK");
        loop {
            let val = M.lock();
            if *val == NUM_ITERS * NUM_TASKS * 3 {
                break;
            }
            may_interrupt();
            drop(val);
            may_interrupt();
        }

        assert_eq!(*M.lock(), NUM_ITERS * NUM_TASKS * 3);
        println!("Mutex test OK");
    }
}
