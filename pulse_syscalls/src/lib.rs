#![no_std]

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
#[cfg(not(target_os = "none"))]
#[allow(dead_code)]
pub(crate) mod impls {
    #[path = "bpf/mod.rs"]
    pub mod bpf;
}

#[cfg(target_os = "none")]
pub use handler::syscall_handler;
#[cfg(target_os = "none")]
pub use impls::{run_bpf_guest_checks, sys_sync};
