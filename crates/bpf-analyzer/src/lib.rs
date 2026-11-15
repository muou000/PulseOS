//! Independent host capture analyzer for PulseOS BPF captures.

pub mod analyzer;
pub mod mapping;
pub mod artifact;
pub mod perf;
pub mod emission;
pub mod error;
pub mod event;
pub mod stats;
pub mod scheduler;
pub mod query;
pub mod fault;

pub use analyzer::CaptureAnalyzer;
pub use emission::FoldedOutput;
pub use error::AnalyzerError;
pub use event::{EventPayload, NormalizedEvent};
pub use stats::{
    CpuStatistics, OffCpuInterval, OnCpuInterval, SessionStatistics, TaskStatistics,
};

pub use scheduler::{SchedulerReport, SchedulerDiagnostics, WakeLatency, BlockedWait, UnfinishedEpisode, UnfinishedReason, LatencySummary, HistogramBucket, TaskIdentity};

pub use fault::FaultReport;
