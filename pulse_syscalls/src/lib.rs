#![no_std]

extern crate alloc;

use axerrno::LinuxError;
use syscalls::Sysno;

mod handler;
mod impls;
mod net;

pub use handler::syscall_handler;
