use bpf_capture::framing::{CaptureArch, CaptureHeader, SessionStatusCode};
use bpf_capture::reader::{CaptureData, CaptureReader};
use bpf_capture::record::NormalizedRecord;
use bpf_capture::session::{LayeredLossCounters, SessionMetadata};
use std::fs;
use std::path::Path;

use crate::error::AnalyzerError;

/// Independent host analyzer for PulseOS BPF captures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureAnalyzer {
    data: CaptureData,
}

impl CaptureAnalyzer {
    /// Load and validate a capture directly from binary bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AnalyzerError> {
        let data = CaptureReader::from_bytes(bytes)?;
        Ok(Self { data })
    }

    /// Load and validate a capture from a file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, AnalyzerError> {
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Internal access to raw CaptureData.
    pub fn data(&self) -> &CaptureData {
        &self.data
    }

    /// Fixed capture header.
    pub fn header(&self) -> &CaptureHeader {
        &self.data.header
    }

    /// Session metadata recorded at start/stop.
    pub fn metadata(&self) -> &SessionMetadata {
        &self.data.metadata
    }

    /// Layered loss and error counters.
    pub fn loss_counters(&self) -> &LayeredLossCounters {
        &self.data.metadata.counters
    }

    /// Target architecture of the guest OS that produced the capture.
    pub fn target_arch(&self) -> CaptureArch {
        self.data.header.target_arch
    }

    /// Raw normalized records as delivered in capture.
    pub fn records(&self) -> &[NormalizedRecord] {
        &self.data.records
    }

    /// Effective session status code, reflecting trailer status, metadata status,
    /// or non-zero loss/error counters.
    pub fn status_code(&self) -> SessionStatusCode {
        if !self.data.trailer.status_code.is_complete() {
            return self.data.trailer.status_code;
        }
        if !self.data.metadata.status.is_complete() {
            return self.data.metadata.status;
        }
        if self.data.metadata.counters.has_error() {
            return SessionStatusCode::IncompleteError;
        }
        if self.data.metadata.counters.has_loss() {
            return SessionStatusCode::IncompleteLoss;
        }
        SessionStatusCode::Complete
    }

    /// Check whether the capture is fully complete without any loss, corruption, or error.
    pub fn is_complete(&self) -> bool {
        self.status_code().is_complete()
    }

    /// Capture integrity does not certify complete CPU/off-CPU attribution.
    /// Full scheduler and IRQ residency evidence is not available.
    pub fn attribution_claim_allowed(&self) -> bool {
        false
    }

    /// Globally order all events across all CPUs by timestamp_ns ascending (Anchor A2).
    pub fn ordered_events(&self) -> Vec<crate::event::NormalizedEvent> {
        crate::event::parse_records(&self.data.records)
    }

    /// Apply one fallible query after whole-capture association. All CLI
    /// renderers share this result and its explicit effective window.
    pub fn query(&self, query: &crate::query::Query) -> Result<crate::query::AnalysisResult, String> {
        query.apply(self)
    }

    /// Compute aggregated semantic statistics for all events in the capture.
    pub fn aggregate_statistics(&self) -> crate::stats::SessionStatistics {
        let events = self.ordered_events();
        crate::stats::SessionStatistics::compute(&events, self.loss_counters())
    }

    /// Reconstruct scheduler intervals from the complete observed event stream,
    /// before any display filter discards cross-CPU wake or switch history.
    pub fn scheduler_report(&self) -> crate::scheduler::SchedulerReport {
        crate::scheduler::SchedulerReport::compute(&self.ordered_events(), !self.is_complete())
    }

    /// Analyze observed fault completion records without promoting unknown
    /// capture coverage into complete attribution.
    pub fn fault_report(&self) -> crate::fault::FaultReport {
        crate::fault::FaultReport::compute(&self.ordered_events(), self.attribution_claim_allowed())
    }

    /// Render a human-readable table of normalized events.
    pub fn render_event_table(&self) -> String {
        crate::emission::render_event_table(self, &self.ordered_events())
    }

    /// Render a human-readable loss and integrity report.
    pub fn render_loss_report(&self) -> String {
        crate::emission::render_loss_report(self)
    }

    /// Render a machine-readable JSON document.
    pub fn render_json(&self) -> String {
        let stats = self.aggregate_statistics();
        crate::emission::render_json(self, &stats)
    }

    /// Render FlameGraph-compatible on-CPU folded stack frames.
    pub fn render_on_cpu_folded(&self) -> crate::emission::FoldedOutput {
        let events = self.ordered_events();
        let stats = crate::stats::SessionStatistics::compute(&events, self.loss_counters());
        crate::emission::render_on_cpu_folded(self, &events, &stats)
    }

    /// Render FlameGraph-compatible off-CPU folded stack frames.
    pub fn render_off_cpu_folded(&self) -> crate::emission::FoldedOutput {
        let stats = self.aggregate_statistics();
        crate::emission::render_off_cpu_folded(self, &stats)
    }
}
