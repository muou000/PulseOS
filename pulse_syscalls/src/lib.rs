#![no_std]

#[cfg(target_os = "none")]
extern crate alloc;

#[cfg(target_os = "none")]
use axerrno::LinuxError;
#[cfg(target_os = "none")]
use syscalls::Sysno;

#[cfg_attr(not(target_os = "none"), allow(dead_code))]
mod validation;

#[cfg(target_os = "none")]
mod handler;
#[cfg(target_os = "none")]
mod impls;

#[cfg(target_os = "none")]
pub use handler::syscall_handler;
#[cfg(target_os = "none")]
pub use impls::sys_sync;
