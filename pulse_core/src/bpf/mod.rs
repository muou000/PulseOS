//! BPF object model.
//!
//! BPF objects are exposed to user space only through BPF object FDs: each
//! descriptor holds an `Arc` reference, so `dup`, fork, exec CLOEXEC removal
//! and `close` follow the generic [`crate::fd_table`] lifecycle and the object
//! is destroyed when its last reference goes away.

mod insn;
mod map;
mod object;
pub mod perf_event;
mod program;
pub mod interpreter;
pub mod verifier;

pub use insn::*;
pub use interpreter::{execute, BpfEnv, BpfVmError, DefaultBpfEnv, BPF_MAX_RECURSION_DEPTH, BPF_MAX_STEPS};
pub use map::*;
pub use object::{BpfMapObject, BpfProgramObject, PerfEventObject};
pub use perf_event::*;
pub use program::*;

