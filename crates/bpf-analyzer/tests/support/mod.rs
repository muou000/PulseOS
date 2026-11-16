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

/// A RISC-V PIE with named functions and a nonzero PT_LOAD file offset.
pub fn perf_test_image() -> Vec<u8> {
    fn put16(b: &mut [u8], at: usize, n: u16) { b[at..at + 2].copy_from_slice(&n.to_le_bytes()); }
    fn put32(b: &mut [u8], at: usize, n: u32) { b[at..at + 4].copy_from_slice(&n.to_le_bytes()); }
    fn put64(b: &mut [u8], at: usize, n: u64) { b[at..at + 8].copy_from_slice(&n.to_le_bytes()); }
    let mut b = vec![0; 0x3300];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut b, 16, 3);
    put16(&mut b, 18, 243);
    put32(&mut b, 20, 1);
    put64(&mut b, 32, 64);
    put64(&mut b, 40, 0x3000);
    put16(&mut b, 52, 64);
    put16(&mut b, 54, 56);
    put16(&mut b, 56, 1);
    put16(&mut b, 58, 64);
    put16(&mut b, 60, 5);
    put16(&mut b, 62, 4);
    put32(&mut b, 64, 1);
    put32(&mut b, 68, 5);
    put64(&mut b, 72, 0x1000);
    put64(&mut b, 80, 0x2000);
    put64(&mut b, 96, 0x1000);
    put64(&mut b, 104, 0x1000);
    put64(&mut b, 112, 0x1000);
    let names = b"\0leaf\0parent\0outer\0";
    b[0x2900..0x2900 + names.len()].copy_from_slice(names);
    let sections = b"\0.text\0.symtab\0.strtab\0.shstrtab\0";
    b[0x2980..0x2980 + sections.len()].copy_from_slice(sections);
    for (i, name, address) in [(1, 1, 0x2100), (2, 6, 0x2200), (3, 13, 0x2300)] {
        let at = 0x2800 + i * 24;
        put32(&mut b, at, name);
        b[at + 4] = 0x12;
        put16(&mut b, at + 6, 1);
        put64(&mut b, at + 8, address);
        put64(&mut b, at + 16, 0x80);
    }
    for (i, name, kind, flags, addr, off, size, link, align, entsize) in [
        (1, 1, 1, 6, 0x2000, 0x1000, 0x1000, 0, 16, 0),
        (2, 7, 2, 0, 0, 0x2800, 96, 3, 8, 24),
        (3, 15, 3, 0, 0, 0x2900, names.len() as u64, 0, 1, 0),
        (4, 23, 3, 0, 0, 0x2980, sections.len() as u64, 0, 1, 0),
    ] {
        let at = 0x3000 + i * 64;
        put32(&mut b, at, name);
        put32(&mut b, at + 4, kind);
        put64(&mut b, at + 8, flags);
        put64(&mut b, at + 16, addr);
        put64(&mut b, at + 24, off);
        put64(&mut b, at + 32, size);
        put32(&mut b, at + 40, link);
        put64(&mut b, at + 48, align);
        put64(&mut b, at + 56, entsize);
    }
    b
}
