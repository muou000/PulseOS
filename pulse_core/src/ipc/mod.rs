//! System V IPC (inter-process communication) support.

pub mod shm;

pub use shm::{SHM_MANAGER, ShmManager};
