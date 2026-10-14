pub mod abi;
pub mod elem;
pub mod info;
pub mod perf_event;

#[cfg(target_os = "none")]
pub mod prog;

#[cfg(target_os = "none")]
mod sys;
#[cfg(target_os = "none")]
pub use perf_event::sys_perf_event_open;
#[cfg(target_os = "none")]
pub use sys::{run_bpf_guest_checks, sys_bpf};


