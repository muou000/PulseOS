use axtask::WaitQueue;
use core::sync::atomic::{AtomicI32, Ordering};
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};

/// A reader-writer lock based on sleeping/yielding tasks.
pub struct RwLock<T: ?Sized> {
    wq: WaitQueue,
    state: AtomicI32, // 0: unlocked, >0: readers, -1: writer
    waiting_writers: AtomicI32,
    value: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Send for RwLock<T> {}
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
}

impl<T: ?Sized> RwLock<T> {
    /// Acquires a shared read lock, blocking the current task if a writer is active.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            let current_state = self.state.load(Ordering::Acquire);
            let waiting = self.waiting_writers.load(Ordering::Relaxed);
            if current_state >= 0 && waiting == 0 {
                if self.state.compare_exchange_weak(
                    current_state,
                    current_state + 1,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                ).is_ok() {
                    break;
                }
            } else {
                self.wq.wait_until(|| {
                    self.state.load(Ordering::Relaxed) >= 0 &&
                    self.waiting_writers.load(Ordering::Relaxed) == 0
                });
            }
        }
        RwLockReadGuard { lock: self }
    }

    /// Acquires an exclusive write lock, blocking the current task until unlocked.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        if self.state.compare_exchange(
            0,
            -1,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ).is_ok() {
            return RwLockWriteGuard { lock: self };
        }
        self.waiting_writers.fetch_add(1, Ordering::SeqCst);
        loop {
            if self.state.compare_exchange_weak(
                0,
                -1,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ).is_ok() {
                break;
            }
            self.wq.wait_until(|| self.state.load(Ordering::Relaxed) == 0);
        }
        self.waiting_writers.fetch_sub(1, Ordering::SeqCst);
        RwLockWriteGuard { lock: self }
    }

    /// Attempts to acquire this lock with shared read access.
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        let current_state = self.state.load(Ordering::Acquire);
        let waiting = self.waiting_writers.load(Ordering::Relaxed);
        if current_state >= 0 && waiting == 0 {
            if self.state.compare_exchange(
                current_state,
                current_state + 1,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ).is_ok() {
                return Some(RwLockReadGuard { lock: self });
            }
        }
        None
    }

    /// Attempts to acquire this lock with exclusive write access.
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        if self.state.compare_exchange(
            0,
            -1,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ).is_ok() {
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

/// A guard that provides read access to the data inside the `RwLock`.
pub struct RwLockReadGuard<'a, T: ?Sized> {
    lock: &'a RwLock<T>,
}

impl<'a, T: ?Sized> Deref for RwLockReadGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.value.get() }
    }
}

impl<'a, T: ?Sized> Drop for RwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        let prev = self.lock.state.fetch_sub(1, Ordering::SeqCst);
        if prev == 1 {
            self.lock.wq.notify_all(true);
        }
    }
}

/// A guard that provides write access to the data inside the `RwLock`.
pub struct RwLockWriteGuard<'a, T: ?Sized> {
    lock: &'a RwLock<T>,
}

impl<'a, T: ?Sized> Deref for RwLockWriteGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.value.get() }
    }
}

impl<'a, T: ?Sized> DerefMut for RwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<'a, T: ?Sized> Drop for RwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.state.store(0, Ordering::Release);
        self.lock.wq.notify_all(true);
    }
}
