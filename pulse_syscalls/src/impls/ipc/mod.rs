//! System V shared memory and semaphore syscall implementations.

mod sem;
mod shm;

pub(crate) use sem::*;
pub(crate) use shm::*;

