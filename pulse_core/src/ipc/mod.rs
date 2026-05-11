//! System V IPC (inter-process communication) support.

pub mod shm;

pub use shm::{clear_proc_shm, ShmManager, SHM_MANAGER};
