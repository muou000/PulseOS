use spin::{Mutex as SpinMutex, RwLock as SpinRwLock};
use spin::{MutexGuard as SpinMutexGuard, RwLockReadGuard as SpinRwLockReadGuard, RwLockWriteGuard as SpinRwLockWriteGuard};
use kernel_guard::NoPreempt;

pub struct Mutex<T> {
    inner: SpinMutex<T>,
}

impl<T: core::fmt::Debug> core::fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.inner, f)
    }
}

impl<T> Mutex<T> {
    pub const fn new(t: T) -> Self {
        Self {
            inner: SpinMutex::new(t),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        let guard = NoPreempt::new();
        MutexGuard {
            inner: self.inner.lock(),
            _guard: guard,
        }
    }
}

pub struct MutexGuard<'a, T> {
    inner: SpinMutexGuard<'a, T>,
    _guard: NoPreempt,
}

impl<'a, T> core::ops::Deref for MutexGuard<'a, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &*self.inner
    }
}

impl<'a, T> core::ops::DerefMut for MutexGuard<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut *self.inner
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

pub struct RwLock<T> {
    inner: SpinRwLock<T>,
}

impl<T: core::fmt::Debug> core::fmt::Debug for RwLock<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.inner, f)
    }
}

impl<T> RwLock<T> {
    pub const fn new(t: T) -> Self {
        Self {
            inner: SpinRwLock::new(t),
        }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        let guard = NoPreempt::new();
        RwLockReadGuard {
            inner: self.inner.read(),
            _guard: guard,
        }
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        let guard = NoPreempt::new();
        RwLockWriteGuard {
            inner: self.inner.write(),
            _guard: guard,
        }
    }
}

pub struct RwLockReadGuard<'a, T> {
    inner: SpinRwLockReadGuard<'a, T>,
    _guard: NoPreempt,
}

impl<'a, T> core::ops::Deref for RwLockReadGuard<'a, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &*self.inner
    }
}

pub struct RwLockWriteGuard<'a, T> {
    inner: SpinRwLockWriteGuard<'a, T>,
    _guard: NoPreempt,
}

impl<'a, T> core::ops::Deref for RwLockWriteGuard<'a, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &*self.inner
    }
}

impl<'a, T> core::ops::DerefMut for RwLockWriteGuard<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut *self.inner
    }
}

impl<T: Default> Default for RwLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}
