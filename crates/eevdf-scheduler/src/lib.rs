#![cfg_attr(not(test), no_std)]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod eevdf;

pub use eevdf::{EEVDFScheduler, EEVDFTask, EnqueueReason, RtPolicy};
