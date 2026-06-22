#![no_std]

extern crate alloc;

mod fs;
mod mount;
mod node;
pub mod path;
mod types;
pub mod inmem;

pub use fs::*;
pub use mount::*;
pub use node::*;
pub use types::*;
pub use inmem::*;

pub type VfsError = axerrno::AxError;
pub type VfsResult<T> = Result<T, VfsError>;

use spin::{Mutex, MutexGuard};
