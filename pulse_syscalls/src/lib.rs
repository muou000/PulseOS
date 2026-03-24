#![no_std]

extern crate alloc;

use axerrno::LinuxError;
use syscalls::Sysno;

mod handler;
mod impls;

pub use handler::syscall_handler;

/// 系统调用结果类型
pub type SyscallResult = isize;
