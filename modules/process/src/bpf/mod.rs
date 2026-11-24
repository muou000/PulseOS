//! BPF object model.
//!
//! BPF objects are exposed to user space only through BPF object FDs: each
//! descriptor holds an `Arc` reference, so `dup`, fork, exec CLOEXEC removal
//! and `close` follow the generic [`crate::fd`] lifecycle and the object
//! is destroyed when its last reference goes away.

mod object;

// Compatibility exports for callers of the original pulse_core::bpf API.
pub use bpf::{
    insn::*,
    interpreter,
    interpreter::{
        BPF_MAX_RECURSION_DEPTH, BPF_MAX_STEPS, BpfEnv, BpfVmError, DefaultBpfEnv, execute,
    },
    link,
    link::*,
    map::*,
    perf_event,
    perf_event::*,
    program,
    program::*,
    ring_buffer,
    ring_buffer::*,
    verifier,
};
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
