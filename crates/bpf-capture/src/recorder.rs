//! Source-bound recorder transport and required capture v5 metadata.
//!
//! The BPF program stamps each RAW payload with a 24-byte little-endian header:
//! magic u32, version u16, kind u16, context length u32, logical source u32,
//! reserved u64. Context kind is never inferred from its length or period.
//! Capture v5 preserves the declaration table and one source ID per record.

use alloc::{collections::BTreeSet, vec::Vec};

use crate::{CaptureError, CaptureScope, NormalizedRecord};

pub const RECORDER_ENVELOPE_MAGIC: u32 = 0x3152_4250;
pub const RECORDER_ENVELOPE_VERSION: u16 = 1;
pub const RECORDER_ENVELOPE_SIZE: usize = 24;
pub const MAX_RECORDER_SOURCES: usize = 512;
/// Maximum retained normalized bytes plus their four-byte source bindings.
pub const MAX_RECORDER_RECORD_BYTES: usize = 64 * 1024 * 1024;
const LEGACY_METADATA_MAGIC: &[u8; 8] = b"PBSRC001";
const METADATA_MAGIC: &[u8; 8] = b"PBSRC002";
const LEGACY_SOURCE_BYTES: usize = 88;
const SOURCE_BYTES: usize = 96;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum RecorderKind {
    SoftwareV2 = 1,
    Tracepoint = 2,
}

impl RecorderKind {
    fn from_raw(value: u32) -> Result<Self, CaptureError> {
        match value {
            1 => Ok(Self::SoftwareV2),
            2 => Ok(Self::Tracepoint),
            _ => Err(invalid("unknown recorder context kind")),
        }
    }
}

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
    /// numeric TID may change during exec. Zero is required for CPU sources;
    /// older PBSRC001 task declarations decode as unknown (zero) as well.
    pub bound_task_id: u64,
    pub sample_period: u64,
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
    pub(crate) fn validate_declaration(&self, legacy: bool) -> Result<(), CaptureError> {
        if self.id == 0 || self.kernel_event_id == 0 || self.program_id == 0
            || self.link_id == 0 || self.sample_period == 0
            || matches!(self.scope, CaptureScope::AllCpus | CaptureScope::Task(0))
            || matches!(self.scope, CaptureScope::Task(tid) if tid > u32::MAX as u64)
            || matches!(self.scope, CaptureScope::PerCpu(_) if self.bound_task_id != 0)
            || matches!(self.scope, CaptureScope::Task(_) if self.bound_task_id == 0 && !legacy)
        {
            return Err(invalid("invalid recorder source identity or scope"));
        }
        match self.kind {
            RecorderKind::SoftwareV2 if self.event_id == crate::schema::PERF_EVENT_SOFTWARE_V2_ID
                && self.schema_version == 2 => Ok(()),
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
            && self.sample_period == other.sample_period && self.kernel_event_id == other.kernel_event_id
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
            || matches!(self.scope, CaptureScope::Task(tid) if
                if self.bound_task_id == 0 { tid != record.tid as u64 }
                else { self.bound_task_id != record.task_id })
        {
            return Err(invalid("recorder record differs from source binding"));
        }
        if self.kind == RecorderKind::SoftwareV2
            && (record.payload.len() != 32 || u64_at(&record.payload, 0) != self.sample_period)
        {
            return Err(invalid("recorder sample period differs from source"));
        }
        if final_window && (record.timestamp_ns < self.enable_before_ns || record.timestamp_ns > self.disable_after_ns) {
            return Err(invalid("recorder record lies outside source control window"));
        }
        Ok(())
    }
}

/// Required source attribution for capture v5, independent of event layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecorderMetadata {
    /// 1 preserves legacy numeric-TID bindings; 2 binds stable kernel task IDs.
    pub source_schema_version: u32,
    pub sources: Vec<RecorderSource>,
    /// One logical source ID for every normalized record, in transport order.
    pub record_sources: Vec<u32>,
}

impl RecorderMetadata {
    pub(crate) fn validate_sources(&self) -> Result<(), CaptureError> {
        if !matches!(self.source_schema_version, 1 | 2)
            || self.sources.is_empty() || self.sources.len() > MAX_RECORDER_SOURCES {
            return Err(invalid("invalid recorder source count"));
        }
        let mut ids = BTreeSet::new();
        let mut events = BTreeSet::new();
        let mut links = BTreeSet::new();
        for source in &self.sources {
            source.validate_declaration(self.source_schema_version == 1)?;
            if !ids.insert(source.id) || !events.insert(source.kernel_event_id) || !links.insert(source.link_id) {
                return Err(invalid("duplicate recorder source identity"));
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

    pub(crate) fn source(&self, id: u32) -> Result<&RecorderSource, CaptureError> {
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
        let source_bytes = if self.source_schema_version == 1 { LEGACY_SOURCE_BYTES } else { SOURCE_BYTES };
        let mut bytes = Vec::with_capacity(24 + self.sources.len() * source_bytes + self.record_sources.len() * 4);
        bytes.extend_from_slice(if self.source_schema_version == 1 { LEGACY_METADATA_MAGIC } else { METADATA_MAGIC });
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
            if self.source_schema_version >= 2 {
                bytes.extend_from_slice(&source.bound_task_id.to_le_bytes());
            }
        }
        for id in &self.record_sources { bytes.extend_from_slice(&id.to_le_bytes()); }
        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CaptureError> {
        if bytes.len() < 24 || u32_at(bytes, 12) != 0 {
            return Err(invalid("invalid recorder metadata header"));
        }
        let (source_schema_version, source_bytes) = match &bytes[..8] {
            magic if magic == LEGACY_METADATA_MAGIC => (1, LEGACY_SOURCE_BYTES),
            magic if magic == METADATA_MAGIC => (2, SOURCE_BYTES),
            _ => return Err(invalid("unknown recorder source schema")),
        };
        let source_count = u32_at(bytes, 8) as usize;
        let binding_count = usize::try_from(u64_at(bytes, 16)).map_err(|_| invalid("recorder binding count overflow"))?;
        if source_count == 0 || source_count > MAX_RECORDER_SOURCES {
            return Err(invalid("invalid recorder source count"));
        }
        let source_end = 24 + source_count * source_bytes;
        let end = binding_count.checked_mul(4).and_then(|n| n.checked_add(source_end))
            .ok_or_else(|| invalid("recorder binding count overflow"))?;
        if end != bytes.len() || binding_count > MAX_RECORDER_RECORD_BYTES / (crate::record::RECORD_HEADER_SIZE + 4) {
            return Err(invalid("invalid recorder metadata length"));
        }
        let mut sources = Vec::with_capacity(source_count);
        for raw in bytes[24..source_end].chunks_exact(source_bytes) {
            let scope = match u32_at(raw, 16) {
                1 => CaptureScope::PerCpu(u32::try_from(u64_at(raw, 24)).map_err(|_| invalid("recorder CPU overflow"))?),
                2 => CaptureScope::Task(u64_at(raw, 24)),
                _ => return Err(invalid("unknown recorder source scope")),
            };
            if u32_at(raw, 20) != 0 { return Err(invalid("nonzero recorder reserved field")); }
            sources.push(RecorderSource {
                id: u32_at(raw, 0), kind: RecorderKind::from_raw(u32_at(raw, 4))?,
                event_id: u32_at(raw, 8), schema_version: u32_at(raw, 12), scope,
                bound_task_id: if source_schema_version >= 2 { u64_at(raw, 88) } else { 0 },
                sample_period: u64_at(raw, 32), kernel_event_id: u64_at(raw, 40),
                program_id: u32_at(raw, 48), link_id: u32_at(raw, 52),
                enable_before_ns: u64_at(raw, 56), enable_after_ns: u64_at(raw, 64),
                disable_before_ns: u64_at(raw, 72), disable_after_ns: u64_at(raw, 80),
            });
        }
        let record_sources = bytes[source_end..].chunks_exact(4)
            .map(|raw| u32_at(raw, 0)).collect();
        let metadata = Self { source_schema_version, sources, record_sources };
        metadata.validate_sources()?;
        Ok(metadata)
    }
}
