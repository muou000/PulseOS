#![allow(dead_code)]
use bpf_capture::{CaptureScope, RecorderKind, RecorderSource};
use bpf_capture::recorder::{SourceClock, SourceConfig, SourceFallback, SourceUnit};

/// Explicit synthetic declaration used by transport tests. IDs are chosen by
/// the test, independently of the records passed through the public writer.
pub fn trace(id: u32, event_id: u32, cpu: u32, start: u64, stop: u64) -> RecorderSource {
    RecorderSource {
        id, kind: RecorderKind::Tracepoint, event_id, schema_version: 1,
        scope: CaptureScope::PerCpu(cpu), bound_task_id: 0, sample_period: 1,
        kernel_event_id: 1000 + id as u64, program_id: 2000 + id, link_id: 3000 + id,
        enable_before_ns: start, enable_after_ns: start,
        disable_before_ns: stop, disable_after_ns: stop,
        clock: SourceClock::Monotonic, config: SourceConfig::Tracepoint,
        requested_config: SourceConfig::Tracepoint,
        requested_sample_period: 1, requested_frequency_hz: 0,
        effective_frequency_hz: 0, requested_buffer_pages: 1, effective_buffer_pages: 1,
        unit: SourceUnit::Events, fallback: SourceFallback::None,
    }
}

pub fn software(id: u32, cpu: u32, period: u64, start: u64, stop: u64) -> RecorderSource {
    RecorderSource {
        kind: RecorderKind::SoftwareV2, event_id: 0x1001, schema_version: 2,
        sample_period: period, requested_sample_period: period,
        config: SourceConfig::CpuClock, requested_config: SourceConfig::CpuClock,
        unit: SourceUnit::Nanoseconds,
        ..trace(id, 1, cpu, start, stop)
    }
}
