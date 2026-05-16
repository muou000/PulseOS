//! System V IPC (inter-process communication) support.

pub mod shm;

pub use shm::{ShmManager, SHM_MANAGER};
