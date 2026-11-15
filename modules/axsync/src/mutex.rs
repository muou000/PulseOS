//! A naïve sleeping mutex.

use core::sync::atomic::{AtomicU64, Ordering};

use axtask::{WaitContext, WaitQueue, WaitReason, WakeContext, current};

/// A [`lock_api::RawMutex`] implementation.
///
/// Contenders sleep on a wait queue; unlocking notifies one waiter to retry.
/// There is no FIFO or starvation-freedom guarantee.
///
/// Both acquisition methods panic for task ID zero (the unlocked sentinel).
/// `lock` also panics when the recorded acquirer ID matches the current task.
/// This detects ordinary recursive acquisition, but can also reject the original
/// task after it sends its guard elsewhere; the recorded ID does not follow the
/// guard. `try_lock` simply fails while any acquisition is outstanding.
pub struct RawMutex {
    // Waiting affects progress only: notification never grants data access.
    wq: WaitQueue,

    // M-TOKEN: 0 means no outstanding raw acquisition; nonzero means exactly
    // one. The value records its original task ID for recursion diagnostics,
    // not the present guard owner. Both acquisition paths reject ID zero before
    // CAS, so exclusion does not assume the task ID allocator never wraps.
    // A token exists between successful CAS and unlock, including guard
    // construction/drop windows. Forgetting a guard leaves the token reserved.
    // This concerns access through locking; lock_api's get_mut/into_inner may
    // instead use an exclusive borrow/ownership even after a forgotten guard.
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

// SAFETY: lock_api 0.4.14's RawMutex requires that a held lock cannot be acquired
// again. M-TOKEN starts at zero (new/INIT); only a successful atomic 0 -> nonzero
// CAS grants one token. Failed/spurious CAS, diagnostic panic, and wakeup grant
// none. The sole release is unsafe unlock, whose caller must consume that token
// exactly once. Thus no second acquisition succeeds until release, independently
// of ID uniqueness. This supplies lock_api::Mutex's exclusive guard permission.
//
// Each successful Acquire CAS reads either the initial zero or the zero written
// by a prior Release unlock. In the latter case all prior critical-section
// accesses happen-before subsequent guard access (core::sync::atomic::Ordering).
// A preliminary relaxed is_locked load grants no permission and is never used
// instead of the CAS. See records/axsync-154/README.md for exact authority/TCB.
//
// GuardSend transfers the one token, not another acquisition. unlock has no
// thread-affine operation or owner-ID equality requirement; its atomic release
// and WaitQueue notification may run on the destination task. lock_api supplies
// the guard's T bounds, reference lifetimes, and exactly-once Drop contract.
// Leaking a guard does not unlock. WaitQueue/axtask and lock_api are the explicit
// dependency boundary, not an assertion that their internals are proved here.
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
        assert_ne!(current_id, 0, "RawMutex cannot acquire with task ID zero");
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
                    // WaitQueue checks the predicate while holding its queue
                    // lock and enrolls the task before releasing that lock.
                    // unlock publishes zero before taking the same queue lock
                    // to notify: either the check sees release, or notification
                    // sees the enrolled waiter. A competing acquisition may
                    // make us wait again; only our successful CAS grants access.
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
        assert_ne!(current_id, 0, "RawMutex cannot acquire with task ID zero");
        // Strong CAS does not spuriously reject an unlocked mutex.
        self.owner_id
            .compare_exchange(0, current_id, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Releases the mutex.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// 1. The caller holds the one outstanding acquisition from `lock` or a
    ///    successful `try_lock`, possibly transferred with a `Send` guard. Release
    ///    it exactly once; the current task need not match the recorded ID.
    /// 2. No active references (`&T` or `&mut T`) derived from the guard associated with this
    ///    lock remain in use across or after this call.
    #[inline(always)]
    unsafe fn unlock(&self) {
        // The caller's token and ended data borrows permit the Release transition
        // to zero (M-TOKEN). This publishes critical-section accesses before a
        // later Acquire CAS. The assertion is diagnostic, not what authorizes
        // release: an invalid unsafe caller may already have corrupted the state.
        // Publish before notification so a waiter cannot miss the unlock between
        // its condition check and queue enrollment (see lock's wait proof).
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
