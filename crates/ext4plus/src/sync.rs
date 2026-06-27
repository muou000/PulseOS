//! Sync primitives

#[cfg(not(feature = "sync"))]
mod async_inner {
    /// A mutual exclusion primitive useful for protecting shared data.
    pub struct Mutex<T> {
        inner: async_lock::Mutex<T>,
    }

    /// Alias for MutexGuard under async.
    pub type MutexGuardRaw<'a, T> = async_lock::MutexGuard<'a, T>;

    impl<T> Mutex<T> {
        /// Create a new mutex in an unlocked state ready for use.
        pub fn new(t: T) -> Self {
            Self {
                inner: async_lock::Mutex::new(t),
            }
        }

        /// Acquires a lock, blocking the current task until it is able to do so.
        pub async fn lock(&self) -> async_lock::MutexGuard<'_, T> {
            self.inner.lock().await
        }

        /// Lock helper for maybe_async context.
        pub async fn lock_maybe(&self) -> MutexGuardRaw<'_, T> {
            self.inner.lock().await
        }
    }

    /// A reader-writer lock.
    pub struct RwLock<T> {
        inner: async_lock::RwLock<T>,
    }

    impl<T> RwLock<T> {
        /// Create a new RwLock in an unlocked state ready for use.
        pub fn new(t: T) -> Self {
            Self {
                inner: async_lock::RwLock::new(t),
            }
        }

        /// Acquires a shared read lock, blocking the current task until it is able to do so.
        pub async fn read(&self) -> async_lock::RwLockReadGuard<'_, T> {
            self.inner.read().await
        }

        /// Acquires an exclusive write lock, blocking the current task until it is able to do so.
        pub async fn write(&self) -> async_lock::RwLockWriteGuard<'_, T> {
            self.inner.write().await
        }
    }
}

#[cfg(feature = "sync")]
mod sync_inner {
    /// A mutual exclusion primitive useful for protecting shared data.
    pub struct Mutex<T> {
        inner: axsync::Mutex<T>,
    }

    /// Alias for MutexGuard under sync.
    pub type MutexGuardRaw<'a, T> = MutexGuard<'a, T>;

    impl<T> Mutex<T> {
        /// Create a new mutex in an unlocked state ready for use.
        pub fn new(t: T) -> Self {
            Self {
                inner: axsync::Mutex::new(t),
            }
        }

        /// Acquires a lock, blocking the current thread until it is able to do so.
        pub fn lock(&self) -> MutexGuard<'_, T> {
            MutexGuard {
                inner: self.inner.lock(),
            }
        }

        /// Lock helper for maybe_async context.
        pub fn lock_maybe(&self) -> MutexGuardRaw<'_, T> {
            self.lock()
        }
    }

    /// A guard that provides mutable data access for [`Mutex`].
    pub struct MutexGuard<'a, T> {
        inner: axsync::MutexGuard<'a, T>,
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

    /// A reader-writer lock.
    pub struct RwLock<T> {
        inner: axsync::RwLock<T>,
    }

    impl<T> RwLock<T> {
        /// Create a new RwLock in an unlocked state ready for use.
        pub fn new(t: T) -> Self {
            Self {
                inner: axsync::RwLock::new(t),
            }
        }

        /// Acquires a shared read lock, blocking the current thread until it is able to do so.
        pub fn read(&self) -> RwLockReadGuard<'_, T> {
            RwLockReadGuard {
                inner: self.inner.read(),
            }
        }

        /// Acquires an exclusive write lock, blocking the current thread until it is able to do so.
        pub fn write(&self) -> RwLockWriteGuard<'_, T> {
            RwLockWriteGuard {
                inner: self.inner.write(),
            }
        }
    }

    /// A guard that provides read access for [`RwLock`].
    pub struct RwLockReadGuard<'a, T> {
        inner: axsync::RwLockReadGuard<'a, T>,
    }

    impl<'a, T> core::ops::Deref for RwLockReadGuard<'a, T> {
        type Target = T;
        #[inline]
        fn deref(&self) -> &T {
            &*self.inner
        }
    }

    /// A guard that provides write access for [`RwLock`].
    pub struct RwLockWriteGuard<'a, T> {
        inner: axsync::RwLockWriteGuard<'a, T>,
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
}

#[cfg(not(feature = "sync"))]
pub use self::async_inner::*;
#[cfg(feature = "sync")]
pub use self::sync_inner::*;

#[cfg(not(feature = "multi-threaded"))]
pub(crate) type PtrPrimitive<T> = alloc::rc::Rc<T>;

#[cfg(feature = "multi-threaded")]
pub(crate) type PtrPrimitive<T> = alloc::sync::Arc<T>;

#[cfg(all(test, feature = "sync"))]
mod tests {
    use super::*;

    #[test]
    fn test_mutex_lock() {
        let mutex = Mutex::new(41);
        *mutex.lock() += 1;
        assert_eq!(*mutex.lock(), 42);
    }

    #[test]
    fn test_rwlock_read_write() {
        let lock = RwLock::new(String::from("a"));
        assert_eq!(&*lock.read(), "a");

        {
            let mut guard = lock.write();
            guard.push('b');
        }

        assert_eq!(&*lock.read(), "ab");
    }

    #[test]
    fn test_ptr_primitive_alias() {
        let ptr = PtrPrimitive::new(7u8);
        assert_eq!(*ptr, 7);
    }
}
