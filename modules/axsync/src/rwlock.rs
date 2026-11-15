// Proof premises, dependency boundaries and validation: records/axsync-154/README.md.

use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicI32, Ordering},
};

use axtask::{WaitContext, WaitQueue, WaitReason, WakeContext};

/// A reader-writer lock based on sleeping/yielding tasks.
///
/// Readers back off when they observe a waiting writer. Admission is not FIFO:
/// a reader racing writer registration or another writer may acquire first.
/// Recursive read acquisition can deadlock behind a waiting writer; recursive
/// writes and read-to-write upgrades are not supported. Use the `try_*` methods
/// to reject unavailable access without blocking.
pub struct RwLock<T: ?Sized> {
    // Waiting grants no access to `value`: every wakeup retries the state CAS.
    // WaitQueue checks the condition and enrolls the task under its queue lock;
    // releases publish state before taking that same queue lock to notify. Thus
    // a waiter either observes availability or is enrolled for the notification.
    // This relies on axtask's wait/enqueue/unblock contract, not on fairness.
    wq: WaitQueue,

    // STATE invariant (all fields and guard constructors are private here):
    // - 0: no outstanding acquisition token.
    // - n in 1..=i32::MAX: exactly n outstanding reader tokens, no writer token.
    // - -1: exactly one outstanding writer token, no reader tokens.
    // A successful CAS creates a token before constructing its guard; Drop
    // consumes it before notifying. Moving a guard transfers its token, and
    // forgetting a guard leaves its token reserved. Counts therefore need not
    // equal the number of live Rust guard values. Values below -1 are excluded
    // by checked increments and one decrement per non-Clone reader guard.
    //
    // ORDER invariant: each successful acquisition and reader release is a
    // SeqCst RMW (hence both Acquire and Release). It reads the preceding state
    // modification and republishes its happens-before history. Chaining these
    // RMWs carries the last writer's Release swap to every subsequent reader,
    // and every reader's accesses through the final decrement to the next
    // writer's acquiring CAS. Failed CAS/diagnostic loads grant no permission.
    // This uses core::sync::atomic::Ordering's Acquire/Release/SeqCst contracts;
    // the individual transitions below preserve both STATE and ORDER.
    state: AtomicI32,

    // Outstanding slow-path writer reservations, in 0..=i32::MAX. A bounded
    // increment creates one reservation; that writer removes it after acquiring
    // STATE's writer token. A panic while waiting can strand a reservation and
    // obstruct readers, but cannot grant access or invalidate STATE/ORDER.
    // The separate, relaxed reader check is only an admission preference.
    waiting_writers: AtomicI32,

    // Initialized by new(T). Guard references require the corresponding STATE
    // token and are bounded by a borrow of that guard. get_mut/into_inner instead
    // use an exclusive borrow/ownership of the entire lock; they remain safe
    // after forgotten guards, even when the stored state is nonzero.
    value: UnsafeCell<T>,
}

// SAFETY: Moving the lock transfers its owned T, so T: Send is sufficient.
// Any usable guard/reference borrows the lock and prevents this move. Forgotten
// guards provide no usable references and require no cleanup for memory safety.
// AtomicI32 and the selected axtask WaitQueue implementation are Send, and
// UnsafeCell<T> is Send for T: Send; no task-affine state is added here.
unsafe impl<T: ?Sized + Send> Send for RwLock<T> {}

// SAFETY: STATE permits either shared reader tokens or a single writer token;
// ORDER publishes earlier accesses before conflicting later accesses. Only the
// private guard implementations expose `value`: readers yield &T (T: Sync),
// while a writer can replace/move T through &mut T on another task (T: Send).
// Guard borrows exclude conflicting references through the same token, and
// get_mut/into_inner require exclusive access to the entire lock. Metadata uses
// atomics and axtask's synchronized WaitQueue. Thus sharing &RwLock<T> exposes
// no unsynchronized access beyond what T: Send + Sync already permits.
unsafe impl<T: ?Sized + Send + Sync> Sync for RwLock<T> {}

impl<T> RwLock<T> {
    /// Creates a new RwLock.
    pub const fn new(value: T) -> Self {
        Self {
            wq: WaitQueue::new(),
            state: AtomicI32::new(0),
            waiting_writers: AtomicI32::new(0),
            value: UnsafeCell::new(value),
        }
    }

    /// Consumes the lock, returning the underlying data.
    ///
    /// Ownership excludes usable guards, including references derived from them.
    /// Forgotten guards may leave a reservation but cannot access the moved value.
    pub fn into_inner(self) -> T {
        self.value.into_inner()
    }
}

impl<T: ?Sized> RwLock<T> {
    /// Returns a mutable reference to the underlying data.
    ///
    /// The exclusive borrow prevents concurrent guard access without locking.
    /// This also works after a guard was forgotten; it does not clear the
    /// forgotten guard's reservation.
    pub fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }

    /// Returns `true` if the lock is currently held in write mode.
    ///
    /// Primarily intended for diagnostics and lock state assertions in tests.
    #[doc(hidden)]
    pub fn is_write_locked(&self) -> bool {
        self.state.load(Ordering::Relaxed) == -1
    }

    /// Returns a snapshot of the number of outstanding reader acquisitions.
    ///
    /// This includes forgotten guards. Primarily intended for diagnostics;
    /// the snapshot grants no permission to access the value.
    #[doc(hidden)]
    pub fn reader_count(&self) -> usize {
        let s = self.state.load(Ordering::Relaxed);
        if s > 0 { s as usize } else { 0 }
    }

    /// Acquires a shared read lock, waiting while a writer is active or observed
    /// waiting. Panics if the reader count is exhausted.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            let current_state = self.state.load(Ordering::Acquire);
            let waiting = self.waiting_writers.load(Ordering::Relaxed);
            if current_state >= 0 && waiting == 0 {
                // STATE: only nonnegative counts below MAX can increment, so
                // no wrap can fabricate a writer token or an unlocked state.
                // Success creates exactly one reader token and preserves ORDER.
                assert!(current_state < i32::MAX, "RwLock reader count overflow");
                if self
                    .state
                    .compare_exchange_weak(
                        current_state,
                        current_state + 1,
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    break;
                }
            } else {
                self.wq.wait_until_with_context(
                    WaitContext::new(|| {
                        (
                            WaitReason::RwLockRead,
                            self as *const Self as *const () as usize as u64,
                            current_state as i64 as u64,
                        )
                    }),
                    || {
                        self.state.load(Ordering::Relaxed) >= 0
                            && self.waiting_writers.load(Ordering::Relaxed) == 0
                    },
                );
            }
        }
        RwLockReadGuard { lock: self }
    }

    /// Acquires an exclusive write lock, blocking the current task until unlocked.
    /// Panics if the waiting-writer count is exhausted.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        // STATE: 0 has no reader/writer token; only one CAS can consume it.
        // ORDER: the acquiring half imports preceding releases before access.
        if self
            .state
            .compare_exchange(0, -1, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            return RwLockWriteGuard { lock: self };
        }
        // Atomic arithmetic wraps even in debug builds. Refuse overflow before
        // publication so reader admission never mistakes wrapped reservations
        // for zero. Failure creates no reservation and changes no lock state.
        let mut waiting = self.waiting_writers.load(Ordering::Relaxed);
        loop {
            let next = waiting
                .checked_add(1)
                .expect("RwLock waiting writer count overflow");
            match self.waiting_writers.compare_exchange_weak(
                waiting,
                next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => waiting = actual,
            }
        }
        loop {
            if self
                .state
                .compare_exchange_weak(0, -1, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
            self.wq.wait_until_with_context(
                WaitContext::new(|| {
                    (
                        WaitReason::RwLockWrite,
                        self as *const Self as *const () as usize as u64,
                        self.state.load(Ordering::Relaxed) as i64 as u64,
                    )
                }),
                || self.state.load(Ordering::Relaxed) == 0,
            );
        }
        // This path owns one reservation and now the unique writer token.
        // Removing the reservation cannot underflow, nor admit readers while
        // state == -1. No fallible operation occurs before the guard is returned.
        self.waiting_writers.fetch_sub(1, Ordering::SeqCst);
        RwLockWriteGuard { lock: self }
    }

    /// Attempts to acquire this lock with shared read access.
    ///
    /// Returns `Some(RwLockReadGuard)` if the lock was acquired, or `None` if
    /// a writer is observed active/waiting or the reader count is exhausted.
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        let mut current_state = self.state.load(Ordering::Acquire);
        while current_state >= 0 && self.waiting_writers.load(Ordering::Relaxed) == 0 {
            if current_state == i32::MAX {
                return None;
            }
            // As in read(), success adds one bounded reader token and is the
            // acquiring event. Failure grants no access and retries actual state.
            match self.state.compare_exchange_weak(
                current_state,
                current_state + 1,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(RwLockReadGuard { lock: self }),
                Err(actual) => current_state = actual,
            }
        }
        None
    }

    /// Attempts to acquire this lock with exclusive write access.
    ///
    /// Returns `Some(RwLockWriteGuard)` if the lock was acquired, or `None` if
    /// the lock is currently held by readers or another writer.
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        // The same 0 -> -1 transition as write(): unique token plus ORDER.
        if self
            .state
            .compare_exchange(0, -1, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            Some(RwLockWriteGuard { lock: self })
        } else {
            None
        }
    }
}

impl<T: Default> Default for RwLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// A guard that provides shared read access to the data inside the `RwLock`.
pub struct RwLockReadGuard<'a, T: ?Sized> {
    lock: &'a RwLock<T>,
}

// SAFETY: A shared guard exposes only &T through Deref, requiring T: Sync.
// Its private lock field is never returned, so sharing a guard does not expose
// RwLock's write methods (which would additionally require T: Send). &guard
// cannot consume/drop the token. Its borrow keeps the token and allocation
// alive; STATE excludes a writer throughout all these shared accesses.
unsafe impl<'a, T: ?Sized + Sync> Sync for RwLockReadGuard<'a, T> {}

// SAFETY: A move transfers one reader token without duplicating it. The retained
// bounds make &RwLock<T> Send (RwLock<T>: Sync), and T: Sync permits the &T
// exposed at the destination. Drop consumes only that token by atomic RMW and
// uses axtask's task-independent WaitQueue notification; it needs no original
// task identity. The stored borrow preserves the lock's lifetime across the move.
unsafe impl<'a, T: ?Sized + Send + Sync> Send for RwLockReadGuard<'a, T> {}

impl<'a, T: ?Sized> Deref for RwLockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: UnsafeCell::get returns a pointer to this initialized inline T,
        // preserving its alignment, provenance and (for ?Sized T) metadata. The
        // stored &'a RwLock keeps that allocation live; the returned &T is bound
        // to &self, so it cannot outlive this guard or be used across its Drop.
        // Only read/try_read construct this private-field guard, after adding
        // one STATE token. While it is usable that token keeps state > 0 and
        // excludes every writer token. get_mut/into_inner cannot coexist with
        // the guard's borrow of the lock. ORDER imports the last writer's writes.
        // Other readers expose only &T; any mutation within T's own UnsafeCells
        // must obey T's safe API, with T: Sync required for cross-task sharing.
        // These facts establish UnsafeCell's shared-reference aliasing contract.
        unsafe { &*self.lock.value.get() }
    }
}

impl<'a, T: ?Sized> Drop for RwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        // &mut self excludes any still-used reference returned by Deref. This
        // non-Clone guard owns one STATE token, so prev >= 1 and consuming it
        // cannot underflow. The SeqCst RMW releases this reader's accesses and
        // acquires/republishes earlier readers' releases (ORDER); the eventual
        // final decrement therefore carries every finished reader to a writer.
        // Forgetting a guard skips this transition, conservatively retaining it.
        let prev = self.lock.state.fetch_sub(1, Ordering::SeqCst);
        assert!(
            prev > 0,
            "RwLockReadGuard::drop: reader count underflow (corrupted state: {})",
            prev
        );
        // If `prev == 1`, this was the last active reader, and `state` has transitioned to 0
        // (unlocked). Wake up all waiting tasks (including any waiting writers) to contest for the lock.
        if prev == 1 {
            self.lock
                .wq
                .notify_all_with_context(true, WakeContext::task());
        }
    }
}

/// A guard that provides exclusive write access to the data inside the `RwLock`.
pub struct RwLockWriteGuard<'a, T: ?Sized> {
    lock: &'a RwLock<T>,
}

// SAFETY: &guard exposes &T through Deref, requiring T: Sync. It cannot call
// DerefMut, move/drop the guard, or reach the private &RwLock field. Its borrow
// keeps the unique writer token alive and precludes mutable borrows of that
// guard, so simultaneous shared access cannot overlap any &mut T.
unsafe impl<'a, T: ?Sized + Sync> Sync for RwLockWriteGuard<'a, T> {}

// SAFETY: Moving this non-Clone guard transfers the unique STATE writer token.
// T: Send permits exclusive access/moving T at the destination; the retained
// T: Sync bound additionally makes its borrowed &RwLock<T> Send. Existing guard
// borrows prevent a move until their uses end. Neither the release RMW nor the
// selected WaitQueue notification depends on which task acquired the token.
unsafe impl<'a, T: ?Sized + Send + Sync> Send for RwLockWriteGuard<'a, T> {}

impl<'a, T: ?Sized> Deref for RwLockWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: value.get() addresses the initialized inline T, with its
        // alignment/provenance and any DST metadata preserved. The stored lock
        // borrow keeps it live. Only write/try_write construct this guard,
        // after the acquiring 0 -> -1 CAS: STATE excludes every other token,
        // and ORDER imports prior accesses. Borrowing &self permits other &T
        // from this guard but precludes DerefMut and Drop until those uses end.
        // The lock borrow also excludes get_mut/into_inner. The result is tied
        // to &self, satisfying UnsafeCell's shared-reference aliasing contract
        // (while still allowing interior mutation through T's own safe API).
        unsafe { &*self.lock.value.get() }
    }
}

impl<'a, T: ?Sized> DerefMut for RwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: UnsafeCell::get points to the initialized inline T and
        // preserves its alignment, provenance and DST metadata. The stored
        // lock borrow keeps it allocated. This private-field, non-Clone guard
        // owns the sole writer token from write/try_write's acquiring 0 -> -1
        // CAS; STATE excludes all other guards, and ORDER imports prior accesses.
        // &mut self excludes still-used references from this same guard and
        // prevents another Deref/DerefMut/Drop while the result is usable. The
        // borrowed lock excludes get_mut/into_inner. Thus the returned &mut T
        // is exclusive for its lifetime, bounded by this borrow of the guard,
        // as required by UnsafeCell even when T itself contains UnsafeCells.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<'a, T: ?Sized> Drop for RwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        // &mut self excludes still-used references derived from this guard.
        // Its unique writer token means state == -1; the Release swap consumes
        // that token and publishes all accesses before the next acquiring CAS.
        // Readers propagate that history through ORDER's SeqCst RMW chain.
        // A forgotten guard never executes this release and prevents new tokens.
        let prev = self.lock.state.swap(0, Ordering::Release);
        assert_eq!(
            prev, -1,
            "RwLockWriteGuard::drop: lock was not in write-locked state (corrupted state: {})",
            prev
        );
        // Wake up all waiting tasks (readers and writers) to contest for the lock.
        self.lock
            .wq
            .notify_all_with_context(true, WakeContext::task());
    }
}
