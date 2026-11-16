//! Source-bound recorder transport and required current capture metadata.
//!
//! The BPF program stamps each RAW payload with a 24-byte little-endian header:
//! magic u32, version u16, kind u16, context length u32, logical source u32,
//! reserved u64. Context kind is never inferred from its length or period.
//! The capture preserves the declaration table and one source ID per record.

use alloc::{collections::BTreeSet, vec::Vec};

use crate::{CaptureError, CaptureScope, NormalizedRecord};

pub const RECORDER_ENVELOPE_MAGIC: u32 = 0x3152_4250;
pub const RECORDER_ENVELOPE_VERSION: u16 = 1;
pub const RECORDER_ENVELOPE_SIZE: usize = 24;
pub const MAX_RECORDER_SOURCES: usize = 512;
/// Maximum retained normalized bytes plus their four-byte source bindings.
pub const MAX_RECORDER_RECORD_BYTES: usize = 64 * 1024 * 1024;
const METADATA_MAGIC: &[u8; 8] = b"PBSRC003";
pub const SOURCE_SCHEMA_VERSION: u32 = 3;
const SOURCE_BYTES: usize = 160;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum RecorderKind {
    SoftwareV2 = 1,
    Tracepoint = 2,
    SoftwareStackV3 = 3,
    /// Explicit normalized records validated against the declared registry.
    Normalized = 4,
}

impl RecorderKind {
    pub const fn as_str(self) -> &'static str {
        match self { Self::SoftwareV2 => "software-v2", Self::Tracepoint => "tracepoint", Self::SoftwareStackV3 => "software-stack-v3", Self::Normalized => "normalized" }
    }
    fn from_raw(value: u32) -> Result<Self, CaptureError> {
        match value {
            1 => Ok(Self::SoftwareV2),
            2 => Ok(Self::Tracepoint),
            3 => Ok(Self::SoftwareStackV3),
            4 => Ok(Self::Normalized),
            _ => Err(invalid("unknown recorder context kind")),
        }
    }
}

/// Timestamp clock for source windows and normalized records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SourceClock { Monotonic = 1 }
impl SourceClock { pub const fn as_str(self) -> &'static str { "monotonic" } }
/// Event configuration, independent of its native payload representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SourceConfig { CpuClock = 1, TaskClock = 2, Tracepoint = 3, HardwareCycles = 4, Custom = 5 }
impl SourceConfig {
    fn from_raw(value: u32) -> Result<Self, CaptureError> {
        match value { 1 => Ok(Self::CpuClock), 2 => Ok(Self::TaskClock), 3 => Ok(Self::Tracepoint), 4 => Ok(Self::HardwareCycles), 5 => Ok(Self::Custom), _ => Err(invalid("unknown source configuration")) }
    }
    pub const fn as_str(self) -> &'static str {
        match self { Self::CpuClock => "cpu-clock", Self::TaskClock => "task-clock", Self::Tracepoint => "tracepoint", Self::HardwareCycles => "hardware-cycles", Self::Custom => "custom" }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SourceUnit { Nanoseconds = 1, Events = 2 }
impl SourceUnit { pub const fn as_str(self) -> &'static str { match self { Self::Nanoseconds => "nanoseconds", Self::Events => "events" } } }
/// Why the effective event differs from the requested event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SourceFallback { None = 0, HardwareUnavailable = 1 }
impl SourceFallback { pub const fn as_str(self) -> &'static str { match self { Self::None => "none", Self::HardwareUnavailable => "hardware-unavailable" } } }

/// One independently prepared source. The logical ID is stamped by its BPF
/// program; kernel object IDs and control windows come from the live session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecorderSource {
    pub id: u32,
    pub kind: RecorderKind,
    pub event_id: u32,
    pub schema_version: u32,
    pub scope: CaptureScope,
    /// Stable kernel task identity retained by a task-scoped source. A task's
    /// numeric TID may change during exec. Zero is required for CPU sources.
    pub bound_task_id: u64,
    /// Effective period, in `unit`.
    pub sample_period: u64,
    pub clock: SourceClock,
    pub requested_config: SourceConfig,
    pub config: SourceConfig,
    /// Exactly one of requested period and frequency is nonzero.
    pub requested_sample_period: u64,
    pub requested_frequency_hz: u64,
    /// Zero for effective period mode.
    pub effective_frequency_hz: u64,
    pub requested_buffer_pages: u64,
    pub effective_buffer_pages: u64,
    pub unit: SourceUnit,
    pub fallback: SourceFallback,
    pub kernel_event_id: u64,
    pub program_id: u32,
    pub link_id: u32,
    pub enable_before_ns: u64,
    pub enable_after_ns: u64,
    pub disable_before_ns: u64,
    pub disable_after_ns: u64,
}

fn invalid(reason: &'static str) -> CaptureError {
    CaptureError::InvalidRecord(reason)
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

impl RecorderSource {
    pub(crate) fn validate_declaration(&self) -> Result<(), CaptureError> {
        if self.id == 0 || self.kernel_event_id == 0 || self.program_id == 0
            || self.link_id == 0 || self.sample_period == 0
            || matches!(self.scope, CaptureScope::AllCpus | CaptureScope::Task(0))
            || matches!(self.scope, CaptureScope::Task(tid) if tid > u32::MAX as u64)
            || matches!(self.scope, CaptureScope::PerCpu(_) if self.bound_task_id != 0)
            || matches!(self.scope, CaptureScope::Task(_) if self.bound_task_id == 0)
        {
            return Err(invalid("invalid recorder source identity or scope"));
        }
        if (self.requested_sample_period == 0) == (self.requested_frequency_hz == 0)
            || self.requested_buffer_pages == 0 || self.effective_buffer_pages == 0
            || !self.requested_buffer_pages.is_power_of_two() || !self.effective_buffer_pages.is_power_of_two()
        { return Err(invalid("invalid requested or effective source parameters")); }
        let software = matches!(self.kind, RecorderKind::SoftwareV2 | RecorderKind::SoftwareStackV3);
        if (software && (!matches!(self.config, SourceConfig::CpuClock | SourceConfig::TaskClock) || self.unit != SourceUnit::Nanoseconds))
            || (self.kind == RecorderKind::Tracepoint && (self.config != SourceConfig::Tracepoint || self.unit != SourceUnit::Events))
            || (self.kind == RecorderKind::Normalized && (self.config != SourceConfig::Custom || self.unit != SourceUnit::Events))
        { return Err(invalid("source configuration and payload kind disagree")); }
        if !software && (self.requested_frequency_hz != 0 || self.effective_frequency_hz != 0) {
            return Err(invalid("frequency mode requires a software clock source"));
        }
        match self.fallback {
            SourceFallback::None if self.requested_config == self.config => {},
            SourceFallback::HardwareUnavailable if self.requested_config == SourceConfig::HardwareCycles && software => {},
            _ => return Err(invalid("invalid source fallback declaration")),
        }
        match self.kind {
            RecorderKind::SoftwareV2 if self.event_id == crate::schema::PERF_EVENT_SOFTWARE_V2_ID
                && self.schema_version == 2 => Ok(()),
            RecorderKind::SoftwareStackV3 if self.event_id == crate::schema::PERF_EVENT_SOFTWARE_STACK_V3_ID
                && self.schema_version == 3 => Ok(()),
            RecorderKind::Normalized if self.event_id != 0 && self.schema_version != 0
                && !matches!(self.event_id, 0x1000..=0x1002)
                && pulse_bpf_schema::lookup_by_id(self.event_id).is_err() => Ok(()),
            RecorderKind::Tracepoint => {
                let native = pulse_bpf_schema::lookup_by_id(self.event_id)
                    .map_err(|_| invalid("unknown recorder tracepoint"))?;
                if self.schema_version != native.version {
                    return Err(invalid("recorder tracepoint schema mismatch"));
                }
                Ok(())
            }
            _ => Err(invalid("recorder kind and schema disagree")),
        }
    }

    pub(crate) fn same_binding(&self, other: &Self) -> bool {
        self.id == other.id && self.kind == other.kind && self.event_id == other.event_id
            && self.schema_version == other.schema_version && self.scope == other.scope
            && self.bound_task_id == other.bound_task_id
            && self.sample_period == other.sample_period && self.clock == other.clock
            && self.requested_config == other.requested_config && self.config == other.config
            && self.requested_sample_period == other.requested_sample_period
            && self.requested_frequency_hz == other.requested_frequency_hz
            && self.effective_frequency_hz == other.effective_frequency_hz
            && self.requested_buffer_pages == other.requested_buffer_pages
            && self.effective_buffer_pages == other.effective_buffer_pages
            && self.unit == other.unit && self.fallback == other.fallback
            && self.kernel_event_id == other.kernel_event_id
            && self.program_id == other.program_id && self.link_id == other.link_id
    }

    pub(crate) fn validate_window(&self, start: u64, stop: u64) -> Result<(), CaptureError> {
        if start == 0 || start > self.enable_before_ns
            || self.enable_before_ns > self.enable_after_ns
            || self.enable_after_ns > self.disable_before_ns
            || self.disable_before_ns > self.disable_after_ns
            || self.disable_after_ns > stop
        {
            return Err(invalid("invalid recorder source control window"));
        }
        Ok(())
    }

    pub(crate) fn validate_record(&self, record: &NormalizedRecord, final_window: bool) -> Result<(), CaptureError> {
        if record.event_id != self.event_id || record.schema_version != self.schema_version
            || record.timestamp_ns == 0
            || matches!(self.scope, CaptureScope::PerCpu(cpu) if cpu != record.cpu_id)
            || matches!(self.scope, CaptureScope::Task(_) if self.bound_task_id != record.task_id)
        {
            return Err(invalid("recorder record differs from source binding"));
        }
        if self.kind == RecorderKind::SoftwareV2
            && (record.payload.len() != 32 || u64_at(&record.payload, 0) != self.sample_period)
        {
            return Err(invalid("recorder sample period differs from source"));
        }
        if self.kind == RecorderKind::SoftwareStackV3 {
            let stack = record.software_stack_v3()?;
            if stack.source_id != self.kernel_event_id || u64_at(&record.payload, 0) != self.sample_period {
                return Err(invalid("stack kernel identity or period differs from source"));
            }
        }
        if final_window && (record.timestamp_ns < self.enable_before_ns || record.timestamp_ns > self.disable_after_ns) {
            return Err(invalid("recorder record lies outside source control window"));
        }
        Ok(())
    }
}

/// Required source attribution for the current capture, independent of event layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecorderMetadata {
    /// Must be SOURCE_SCHEMA_VERSION: typed configuration and stable task IDs.
    pub source_schema_version: u32,
    pub sources: Vec<RecorderSource>,
    /// One logical source ID for every normalized record, in transport order.
    pub record_sources: Vec<u32>,
}

impl RecorderMetadata {
    pub(crate) fn validate_sources(&self) -> Result<(), CaptureError> {
        if self.source_schema_version != SOURCE_SCHEMA_VERSION {
            return Err(invalid("unknown recorder source schema"));
        }
        if self.sources.is_empty() || self.sources.len() > MAX_RECORDER_SOURCES {
            return Err(invalid("invalid recorder source count"));
        }
        let mut ids = BTreeSet::new();
        let mut events = BTreeSet::new();
        let mut links = BTreeSet::new();
        for source in &self.sources {
            source.validate_declaration()?;
            if !ids.insert(source.id) || !events.insert(source.kernel_event_id) || !links.insert(source.link_id) {
                return Err(invalid("duplicate recorder source identity"));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_registry(&self, registry: &crate::SchemaRegistry) -> Result<(), CaptureError> {
        for source in &self.sources {
            let schema = registry.lookup(source.event_id).ok_or_else(|| invalid("source schema is not registered"))?;
            if schema.version != source.schema_version {
                return Err(invalid("source schema differs from registry"));
            }
            let expected = match source.kind {
                RecorderKind::SoftwareV2 => 32,
                RecorderKind::SoftwareStackV3 => 608,
                RecorderKind::Tracepoint => pulse_bpf_schema::lookup_by_id(source.event_id)
                    .map_err(|_| invalid("unknown recorder tracepoint"))?.context_size - 40,
                RecorderKind::Normalized => schema.payload_size as usize,
            };
            if schema.payload_size as usize != expected {
                return Err(invalid("source payload size differs from registry"));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_records(&self, records: &[NormalizedRecord], start: u64, stop: u64) -> Result<(), CaptureError> {
        self.validate_sources()?;
        if records.len() != self.record_sources.len() {
            return Err(invalid("recorder source binding count differs from record count"));
        }
        for source in &self.sources { source.validate_window(start, stop)?; }
        for (record, id) in records.iter().zip(&self.record_sources) {
            self.source(*id)?.validate_record(record, true)?;
        }
        Ok(())
    }

    pub fn source(&self, id: u32) -> Result<&RecorderSource, CaptureError> {
        self.sources.iter().find(|source| source.id == id)
            .ok_or_else(|| invalid("undeclared recorder source"))
    }

    pub(crate) fn decode_sample(&self, cpu: u32, bytes: &[u8]) -> Result<(u32, NormalizedRecord), CaptureError> {
        if bytes.len() < RECORDER_ENVELOPE_SIZE {
            return Err(CaptureError::TruncatedRecord);
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        let kind = RecorderKind::from_raw(u16::from_le_bytes(bytes[6..8].try_into().unwrap()) as u32)?;
        let length = u32_at(bytes, 8) as usize;
        let id = u32_at(bytes, 12);
        if u32_at(bytes, 0) != RECORDER_ENVELOPE_MAGIC || version != RECORDER_ENVELOPE_VERSION
            || bytes[16..24] != [0; 8] || length != bytes.len() - RECORDER_ENVELOPE_SIZE
        {
            return Err(invalid("invalid recorder envelope header"));
        }
        let source = self.source(id)?;
        if source.kind != kind { return Err(invalid("recorder envelope kind differs from source")); }
        let raw = &bytes[RECORDER_ENVELOPE_SIZE..];
        let record = match kind {
            RecorderKind::SoftwareV2 => NormalizedRecord::from_perf_event_v2_slice(raw)?,
            RecorderKind::SoftwareStackV3 => NormalizedRecord::from_software_stack_v3_slice(raw)?,
            RecorderKind::Normalized => return Err(invalid("normalized source has no native context")),
            RecorderKind::Tracepoint => {
                let native = pulse_bpf_schema::lookup_by_id(source.event_id)
                    .map_err(|_| invalid("unknown recorder tracepoint"))?;
                if raw.len() != native.context_size || u32_at(raw, 0) != source.event_id || raw[28..32] != [0; 4] {
                    return Err(invalid("recorder tracepoint context differs from source"));
                }
                NormalizedRecord::from_tracepoint_slice(source.event_id, raw)?
            }
        };
        if record.cpu_id != cpu { return Err(invalid("recorder source CPU differs from ring CPU")); }
        source.validate_record(&record, false)?;
        Ok((id, record))
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24 + self.sources.len() * SOURCE_BYTES + self.record_sources.len() * 4);
        bytes.extend_from_slice(METADATA_MAGIC);
        bytes.extend_from_slice(&(self.sources.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(self.record_sources.len() as u64).to_le_bytes());
        for source in &self.sources {
            let (scope, target) = source.scope.to_bytes();
            for value in [source.id, source.kind as u32, source.event_id, source.schema_version, scope, 0] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            for value in [target, source.sample_period, source.kernel_event_id] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            bytes.extend_from_slice(&source.program_id.to_le_bytes());
            bytes.extend_from_slice(&source.link_id.to_le_bytes());
            for value in [source.enable_before_ns, source.enable_after_ns, source.disable_before_ns, source.disable_after_ns] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            bytes.extend_from_slice(&source.bound_task_id.to_le_bytes());
            for value in [source.clock as u32, source.requested_config as u32, source.config as u32, source.unit as u32, source.fallback as u32, 0] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            for value in [source.requested_sample_period, source.requested_frequency_hz, source.effective_frequency_hz, source.requested_buffer_pages, source.effective_buffer_pages] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        for id in &self.record_sources { bytes.extend_from_slice(&id.to_le_bytes()); }
        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CaptureError> {
        if bytes.len() < 24 || u32_at(bytes, 12) != 0 {
            return Err(invalid("invalid recorder metadata header"));
        }
        if &bytes[..8] != METADATA_MAGIC {
            return Err(invalid("unknown recorder source schema"));
        }
        let source_count = u32_at(bytes, 8) as usize;
        let binding_count = usize::try_from(u64_at(bytes, 16)).map_err(|_| invalid("recorder binding count overflow"))?;
        if source_count == 0 || source_count > MAX_RECORDER_SOURCES {
            return Err(invalid("invalid recorder source count"));
        }
        let source_end = 24 + source_count * SOURCE_BYTES;
        let end = binding_count.checked_mul(4).and_then(|n| n.checked_add(source_end))
            .ok_or_else(|| invalid("recorder binding count overflow"))?;
        if end != bytes.len() || binding_count > MAX_RECORDER_RECORD_BYTES / (crate::record::RECORD_HEADER_SIZE + 4) {
            return Err(invalid("invalid recorder metadata length"));
        }
        let mut sources = Vec::with_capacity(source_count);
        for raw in bytes[24..source_end].chunks_exact(SOURCE_BYTES) {
            let scope = match u32_at(raw, 16) {
                1 => CaptureScope::PerCpu(u32::try_from(u64_at(raw, 24)).map_err(|_| invalid("recorder CPU overflow"))?),
                2 => CaptureScope::Task(u64_at(raw, 24)),
                _ => return Err(invalid("unknown recorder source scope")),
            };
            if u32_at(raw, 20) != 0 { return Err(invalid("nonzero recorder reserved field")); }
            if u32_at(raw, 116) != 0 { return Err(invalid("nonzero source configuration reserved field")); }
            sources.push(RecorderSource {
                id: u32_at(raw, 0), kind: RecorderKind::from_raw(u32_at(raw, 4))?,
                event_id: u32_at(raw, 8), schema_version: u32_at(raw, 12), scope,
                bound_task_id: u64_at(raw, 88),
                clock: match u32_at(raw, 96) { 1 => SourceClock::Monotonic, _ => return Err(invalid("unknown source clock")) },
                requested_config: SourceConfig::from_raw(u32_at(raw, 100))?,
                config: SourceConfig::from_raw(u32_at(raw, 104))?,
                unit: match u32_at(raw, 108) { 1 => SourceUnit::Nanoseconds, 2 => SourceUnit::Events, _ => return Err(invalid("unknown source unit")) },
                fallback: match u32_at(raw, 112) { 0 => SourceFallback::None, 1 => SourceFallback::HardwareUnavailable, _ => return Err(invalid("unknown source fallback")) },
                requested_sample_period: u64_at(raw, 120), requested_frequency_hz: u64_at(raw, 128),
                effective_frequency_hz: u64_at(raw, 136), requested_buffer_pages: u64_at(raw, 144), effective_buffer_pages: u64_at(raw, 152),
                sample_period: u64_at(raw, 32), kernel_event_id: u64_at(raw, 40),
                program_id: u32_at(raw, 48), link_id: u32_at(raw, 52),
                enable_before_ns: u64_at(raw, 56), enable_after_ns: u64_at(raw, 64),
                disable_before_ns: u64_at(raw, 72), disable_after_ns: u64_at(raw, 80),
            });
        }
        let record_sources = bytes[source_end..].chunks_exact(4)
            .map(|raw| u32_at(raw, 0)).collect();
        let metadata = Self { source_schema_version: SOURCE_SCHEMA_VERSION, sources, record_sources };
        metadata.validate_sources()?;
        Ok(metadata)
    }
}
