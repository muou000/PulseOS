//! System V IPC (inter-process communication) support.

pub mod sem;
pub mod shm;

pub use sem::{SEM_MANAGER, SemManager, SemUndoEntry, SemBuf, exit_sem_undos};
pub use shm::{SHM_MANAGER, ShmManager};

