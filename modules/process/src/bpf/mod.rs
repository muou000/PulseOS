//! BPF object model.
//!
//! BPF objects are exposed to user space only through BPF object FDs: each
//! descriptor holds an `Arc` reference, so `dup`, fork, exec CLOEXEC removal
//! and `close` follow the generic [`crate::fd`] lifecycle and the object
//! is destroyed when its last reference goes away.

mod object;

pub use object::{BpfLinkObject, BpfMapObject, BpfProgramObject, PerfEventObject};

#[cfg(feature = "bpf-trace")]
pub mod mappings;
#[cfg(feature = "bpf-trace")]
pub mod sampling;

#[cfg(all(
    feature = "bpf-trace",
    target_os = "none",
    any(target_arch = "riscv64", target_arch = "loongarch64")
))]
mod stack_capture;
