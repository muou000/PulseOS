use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicI32, Ordering},
};

use axtask::{WaitContext, WaitQueue, WaitReason, WakeContext};

/// A reader-writer lock based on sleeping/yielding tasks.
pub struct RwLock<T: ?Sized> {
    // Safety invariant: `wq` coordinates blocking and wakeup of tasks waiting for read
    // or write access. Tasks sleeping on `wq` are woken when the last active reader drops
    // or when the active writer drops.
    wq: WaitQueue,

    // Safety invariant:
    // - `0`: Unlocked. No active readers or writers.
    // - `> 0`: Shared read mode. The value is the exact count of active `RwLockReadGuard`s.
    //   Writers cannot acquire the lock while `state > 0`.
    // - `-1`: Exclusive write mode. Exactly one `RwLockWriteGuard` exists.
    //   No readers or other writers can acquire the lock while `state == -1`.
    // - `state < -1`: Invalid state, prohibited by synchronization invariants.
    state: AtomicI32,

    // Safety invariant:
    // - `>= 0`: Count of writers currently waiting in `write()`.
    // - When `waiting_writers > 0`, incoming readers in `read()` and `try_read()` back off
    //   and wait to prevent writer starvation.
    waiting_writers: AtomicI32,

    // Safety invariant: `value` stores the protected data.
    // - Shared references `&T` are exposed only when `state > 0`.
    // - Exclusive reference `&mut T` is exposed only when `state == -1`.
    value: UnsafeCell<T>,
}

// SAFETY:
// `RwLock<T>` owns `value: UnsafeCell<T>`, `wq: WaitQueue`, `state: AtomicI32`, and
// `waiting_writers: AtomicI32`.
// - Moving `RwLock<T>` to another execution context transfers ownership of `T`.
// - `WaitQueue`, `AtomicI32`, and `UnsafeCell<T>` are safe to send across threads/tasks
//   provided `T: Send`.
// - Therefore, `RwLock<T>` is soundly `Send` whenever `T: Send`.
unsafe impl<T: ?Sized + Send> Send for RwLock<T> {}

// SAFETY:
// `RwLock<T>` provides synchronized access to `T` through shared references `&RwLock<T>`.
// - Concurrent read guards (`RwLockReadGuard`) provide concurrent `&T` references to multiple
//   tasks. For multiple tasks to hold `&T` concurrently, `T` must implement `Sync`.
// - Exclusive write guards (`RwLockWriteGuard`) provide exclusive `&mut T` reference to a single
//   task. An exclusive `&mut T` on another task allows mutating `T`, replacing values in `T`,
//   or moving values out of `T` across thread boundaries. Therefore, `T` must implement `Send`.
// - Synchronization invariants ensure that `&mut T` and `&T` never exist simultaneously, and
//   `Acquire`/`Release`/`SeqCst` memory ordering ensures that all writes to `T` happen-before
//   any subsequent reads or writes on another task.
// - Therefore, `RwLock<T>` is soundly `Sync` whenever `T: Send + Sync`.
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
    pub fn into_inner(self) -> T {
        self.value.into_inner()
    }
}

impl<T: ?Sized> RwLock<T> {
    /// Returns a mutable reference to the underlying data.
    ///
    /// Since this call borrows `RwLock` mutably, no other references to `self`
    /// exist, guaranteeing exclusive access statically without runtime locking.
    pub fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }

    /// Returns `true` if the lock is currently held in write mode.
    pub fn is_write_locked(&self) -> bool {
        self.state.load(Ordering::Relaxed) == -1
    }

    /// Returns the number of active readers currently holding the lock.
    pub fn reader_count(&self) -> usize {
        let s = self.state.load(Ordering::Relaxed);
        if s > 0 {
            s as usize
        } else {
            0
        }
    }

    /// Acquires a shared read lock, blocking the current task if a writer is active
    /// or if writers are waiting.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            let current_state = self.state.load(Ordering::Acquire);
            let waiting = self.waiting_writers.load(Ordering::Relaxed);
            if current_state >= 0 && waiting == 0 {
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
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        if self
            .state
            .compare_exchange(0, -1, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            return RwLockWriteGuard { lock: self };
        }
        self.waiting_writers.fetch_add(1, Ordering::SeqCst);
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
        self.waiting_writers.fetch_sub(1, Ordering::SeqCst);
        RwLockWriteGuard { lock: self }
    }

    /// Attempts to acquire this lock with shared read access.
    ///
    /// Returns `Some(RwLockReadGuard)` if the lock was acquired, or `None` if
    /// a writer is active or waiting.
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        let mut current_state = self.state.load(Ordering::Acquire);
        while current_state >= 0 && self.waiting_writers.load(Ordering::Relaxed) == 0 {
            if current_state == i32::MAX {
                return None;
            }
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

// SAFETY:
// `RwLockReadGuard` grants shared access `&T` to the protected value.
// - For multiple tasks to hold `&RwLockReadGuard<T>` concurrently, `&T` must be safe to share
//   concurrently across threads, which requires `T: Sync`.
// - Dropping or referencing `&RwLockReadGuard` performs only read-only dereferences or atomic
//   decrement on `state`.
unsafe impl<'a, T: ?Sized + Sync> Sync for RwLockReadGuard<'a, T> {}

// SAFETY:
// Moving `RwLockReadGuard` to another task transfers one active reader token.
// - The guard provides shared access `&T` in the destination task, which requires `T: Sync`.
// - Additionally, `RwLock<T>` must be `Sync` so that the borrowed reference `&'a RwLock<T>`
//   is `Send`, which requires `T: Send`.
// - Dropping the guard on another task atomically decrements `state` and notifies `wq`, which
//   is thread-safe.
unsafe impl<'a, T: ?Sized + Send + Sync> Send for RwLockReadGuard<'a, T> {}

impl<'a, T: ?Sized> Deref for RwLockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY:
        // Operation: Creating shared reference `&T` from raw pointer `self.lock.value.get()`.
        // Contract:
        // 1. Pointer must be non-null, aligned for `T`, and point to valid, initialized memory
        //    for the duration of the borrow.
        // 2. No mutable reference (`&mut T`) to the pointee may exist for the duration of the borrow.
        // 3. No concurrent writes to `*value.get()` may occur while `&T` is active.
        //
        // Evidence:
        // - Validity and alignment: `self.lock.value` is an inline `UnsafeCell<T>` within `RwLock<T>`.
        //   Since `self.lock` is a valid reference `&'a RwLock<T>`, `value.get()` produces a non-null,
        //   properly aligned pointer to initialized memory that remains live for at least `'a`.
        // - Atomic state invariant: The creation of `RwLockReadGuard` in `read()` or `try_read()`
        //   successfully incremented `self.lock.state` to a value > 0 using `SeqCst` ordering.
        // - Guard exclusivity: A writer can only acquire write access when `state == 0`. Since `state > 0`
        //   for the lifetime of this guard (and is only decremented on drop), no `RwLockWriteGuard`
        //   exists or can be created while this guard is alive.
        // - Absence of mutable references: Only `RwLockWriteGuard` can create `&mut T`. Since no write
        //   guard exists, no `&mut T` exists.
        // - Lifetime bound: The returned reference is bound to `&self`, so it cannot outlive the
        //   `RwLockReadGuard`, which in turn cannot outlive `'a`.
        // - Concurrency: Concurrent readers may also obtain `&T`. Since `T: Sync` is required for
        //   sharing `RwLock<T>` across tasks, concurrent read-only access does not cause data races.
        //
        // Therefore, dereferencing `self.lock.value.get()` to `&T` is sound.
        unsafe { &*self.lock.value.get() }
    }
}

impl<'a, T: ?Sized> Drop for RwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        // SAFETY / State transition:
        // Atomically decrement the reader count with `SeqCst` ordering.
        // `SeqCst` ordering ensures that all reads performed through this guard happen-before
        // any subsequent writer acquires exclusive access.
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

// SAFETY:
// `RwLockWriteGuard` provides `&T` access via `Deref`.
// - Sharing `&RwLockWriteGuard` across tasks allows concurrent `&T` reads, which requires `T: Sync`.
unsafe impl<'a, T: ?Sized + Sync> Sync for RwLockWriteGuard<'a, T> {}

// SAFETY:
// Moving `RwLockWriteGuard` to another task transfers exclusive `&mut T` access.
// - In Rust, transferring exclusive access to `T` across tasks requires `T: Send`.
// - Dropping the guard on another task atomically clears `state` to 0 with `Release` ordering
//   and notifies `wq`, which is thread-safe.
unsafe impl<'a, T: ?Sized + Send> Send for RwLockWriteGuard<'a, T> {}

impl<'a, T: ?Sized> Deref for RwLockWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY:
        // Operation: Creating shared reference `&T` from raw pointer `self.lock.value.get()`.
        // Contract:
        // 1. Pointer must be non-null, aligned for `T`, and valid for reads of `T`.
        // 2. No other active reference to `*value.get()` (neither `&T` nor `&mut T`) may exist
        //    that conflicts with this shared borrow.
        //
        // Evidence:
        // - Validity: `value` is an inline `UnsafeCell<T>` in `RwLock<T>`, so `value.get()` is non-null,
        //   properly aligned, and valid for `size_of::<T>()` bytes.
        // - Atomic state invariant: The creation of `RwLockWriteGuard` in `write()` or `try_write()`
        //   atomically transitioned `state` from 0 to -1 via `SeqCst` compare-exchange.
        // - Guard exclusivity: While `state == -1`, no readers can acquire the lock (readers require
        //   `state >= 0`), and no other writer can acquire the lock (writers require `state == 0`).
        // - Single owner: `RwLockWriteGuard` uniquely owns the lock token for `state == -1`.
        // - Lifetime bound: The returned reference is bound to `&self`, ensuring it cannot outlive
        //   this guard.
        //
        // Therefore, creating `&T` is sound.
        unsafe { &*self.lock.value.get() }
    }
}

impl<'a, T: ?Sized> DerefMut for RwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY:
        // Operation: Creating mutable reference `&mut T` from raw pointer `self.lock.value.get()`.
        // Contract:
        // 1. Pointer must be non-null, properly aligned, and valid for writes of `T`.
        // 2. No other references (`&T` or `&mut T`) to the pointee may exist for the duration
        //    of the mutable borrow (exclusivity guarantee of `&mut`).
        //
        // Evidence:
        // - Validity and alignment: `self.lock.value` is an inline `UnsafeCell<T>` within `RwLock<T>`,
        //   guaranteeing a non-null, properly aligned pointer to initialized memory for `'a`.
        // - Atomic state invariant: `self.lock.state` is -1, established atomically by CAS from 0
        //   with `SeqCst` ordering.
        // - Mutual exclusivity: While `state == -1`, no `RwLockReadGuard` exists (readers require
        //   `state > 0`) and no other `RwLockWriteGuard` exists (only one CAS from 0 to -1 can succeed).
        // - Borrow exclusivity: `deref_mut` takes `&mut self`. By Rust's borrow checker rules, while
        //   the returned `&mut Self::Target` is active, no other borrow of `self` (including `deref`)
        //   can be called.
        // - Memory ordering: The transition to `state = -1` used `SeqCst` ordering, synchronizing
        //   with all prior reader releases (`SeqCst` `fetch_sub`) and writer releases (`Release` store/swap).
        //   All prior operations on `T` happen-before this mutable access.
        // - Lifetime: The returned `&mut Self::Target` is bound to the lifetime of `&mut self`, ensuring
        //   it cannot outlive the guard.
        //
        // Therefore, constructing `&mut T` satisfies Rust's aliasing rules and is sound.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<'a, T: ?Sized> Drop for RwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        // SAFETY / State transition:
        // Atomically release the exclusive write lock by storing 0 with `Release` ordering.
        // `Release` ordering ensures that all mutations performed through `&mut T` happen-before
        // subsequent readers or writers observe `state == 0` with `Acquire`/`SeqCst`.
        let prev = self.lock.state.swap(0, Ordering::Release);
        assert_eq!(
            prev,
            -1,
            "RwLockWriteGuard::drop: lock was not in write-locked state (corrupted state: {})",
            prev
        );
        // Wake up all waiting tasks (readers and writers) to contest for the lock.
        self.lock
            .wq
            .notify_all_with_context(true, WakeContext::task());
    }
}
