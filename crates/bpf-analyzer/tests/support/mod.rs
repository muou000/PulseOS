//! Synthetic declarations for analyzer semantic tests, never runtime provenance.
#![allow(dead_code)]
use bpf_capture::{
    CaptureError, CaptureScope, CaptureWriter, NormalizedRecord, RecorderKind, RecorderSource,
    RuntimeDiagnostics, SchemaRegistry, SessionConfig, SourceClock, SourceConfig, SourceFallback,
    SourceUnit,
};

pub fn source(id: u32, kind: RecorderKind, event_id: u32, schema_version: u32, cpu: u32,
              period: u64, kernel_event_id: u64, start: u64, stop: u64) -> RecorderSource {
    let (config, unit) = match kind {
        RecorderKind::SoftwareV2 | RecorderKind::SoftwareStackV3 => (SourceConfig::CpuClock, SourceUnit::Nanoseconds),
        RecorderKind::Tracepoint => (SourceConfig::Tracepoint, SourceUnit::Events),
        RecorderKind::Normalized => (SourceConfig::Custom, SourceUnit::Events),
    };
    RecorderSource {
        id, kind, event_id, schema_version, scope: CaptureScope::PerCpu(cpu), bound_task_id: 0,
        sample_period: period, kernel_event_id, program_id: id, link_id: id,
        enable_before_ns: start, enable_after_ns: start, disable_before_ns: stop, disable_after_ns: stop,
        clock: SourceClock::Monotonic, requested_config: config, config,
        requested_sample_period: period, requested_frequency_hz: 0, effective_frequency_hz: 0,
        requested_buffer_pages: 4, effective_buffer_pages: 4, unit, fallback: SourceFallback::None,
    }
}

/// Stages synthetic records, declaring one independent test source for each.
/// Tests concerned with source identity use CaptureWriter directly instead.
pub struct SemanticFixture {
    config: SessionConfig,
    registry: SchemaRegistry,
    diagnostics: Option<RuntimeDiagnostics>,
    records: Vec<NormalizedRecord>,
    start_ns: u64,
}
impl SemanticFixture {
    pub fn new(config: SessionConfig, registry: SchemaRegistry) -> Self {
        Self { config, registry, diagnostics: None, records: Vec::new(), start_ns: 0 }
    }
    pub fn start(&mut self, time: u64) -> Result<(), CaptureError> {
        self.start_ns = time;
        Ok(())
    }
    pub fn set_diagnostics(&mut self, diagnostics: RuntimeDiagnostics) -> Result<(), CaptureError> {
        self.diagnostics = Some(diagnostics);
        Ok(())
    }
    pub fn write_record(&mut self, record: NormalizedRecord) -> Result<(), CaptureError> {
        self.records.push(record);
        Ok(())
    }
    pub fn finish(self, stop_ns: u64) -> Result<Vec<u8>, CaptureError> {
        let mut sources = Vec::new();
        for (index, record) in self.records.iter().enumerate() {
            let id = index as u32 + 1;
            let kind = match record.event_id {
                0x1001 => RecorderKind::SoftwareV2,
                0x1002 => RecorderKind::SoftwareStackV3,
                id if pulse_bpf_schema::lookup_by_id(id).is_ok() => RecorderKind::Tracepoint,
                _ => RecorderKind::Normalized,
            };
            let period = if matches!(kind, RecorderKind::SoftwareV2 | RecorderKind::SoftwareStackV3) {
                u64::from_le_bytes(record.payload[..8].try_into().unwrap())
            } else { 1 };
            sources.push(source(id, kind, record.event_id, record.schema_version, record.cpu_id,
                                period, u64::from(id), self.start_ns, stop_ns));
        }
        if sources.is_empty() {
            sources.push(source(1, RecorderKind::SoftwareV2, 0x1001, 2, 0, 1, 1, self.start_ns, stop_ns));
        }
        let mut writer = CaptureWriter::new(self.config, self.registry);
        writer.configure_recorder(sources, bpf_capture::recorder::MAX_RECORDER_RECORD_BYTES)?;
        if let Some(diagnostics) = self.diagnostics { writer.set_diagnostics(diagnostics)?; }
        writer.start(self.start_ns)?;
        for (index, record) in self.records.into_iter().enumerate() {
            assert!(writer.write_record_from(index as u32 + 1, record)?);
        }
        writer.finish(stop_ns)
    }
}
