//! Independent host capture analyzer for PulseOS BPF captures.

pub mod analyzer;
pub mod emission;
pub mod error;
pub mod event;
pub mod stats;

pub use analyzer::CaptureAnalyzer;
pub use emission::FoldedOutput;
pub use error::AnalyzerError;
pub use event::{EventPayload, NormalizedEvent};
pub use stats::{
    CpuStatistics, OffCpuInterval, OnCpuInterval, SessionStatistics, TaskStatistics,
};
