//! Validated, resource-bounded plans for the guest recorder.
#![no_std]
extern crate alloc;

mod plan;
pub use plan::{Capabilities, Event, Options, SessionPlan, SourcePlan};
