//! Validated, resource-bounded plans for the guest recorder.
#![no_std]
extern crate alloc;

pub mod arena;
mod plan;
pub mod observation;
pub use plan::{Callchain, Capabilities, Event, Options, SessionPlan, SourcePlan};
