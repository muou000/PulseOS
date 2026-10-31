//! [ArceOS](https://github.com/arceos-org/arceos) synchronization primitives.
//!
//! Currently supported primitives:
//!
//! - [`Mutex`]: A mutual exclusion primitive.
//! - mod [`spin`]: spinlocks imported from the [`kspin`] crate.
//!
//! # Cargo Features
//!
//! - `multitask`: For use in the multi-threaded environments. If the feature is
//!   not enabled, [`Mutex`] will be an alias of [`spin::SpinNoIrq`]. This
//!   feature is enabled by default.

#![cfg_attr(not(test), no_std)]
#![feature(doc_cfg)]

extern crate alloc;

pub use kspin as spin;

#[cfg(feature = "multitask")]
mod mutex;
#[cfg(feature = "multitask")]
mod rwlock;
#[cfg(feature = "multitask")]
mod checks;

#[cfg(feature = "multitask")]
#[doc(cfg(feature = "multitask"))]
pub use self::{
    checks::run_lock_stress_checks,
    mutex::{Mutex, MutexGuard, RawMutex},
    rwlock::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

#[cfg(not(feature = "multitask"))]
#[doc(cfg(not(feature = "multitask")))]
pub use kspin::{SpinNoIrq as Mutex, SpinNoIrqGuard as MutexGuard};

#[cfg(not(feature = "multitask"))]
#[doc(cfg(not(feature = "multitask")))]
pub use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(not(feature = "multitask"))]
pub fn run_lock_stress_checks() -> Result<(), &'static str> {
    Ok(())
}
