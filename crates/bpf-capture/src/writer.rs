//! Binary BPF capture writer with streaming record persistence and integrity trailer.

use alloc::vec::Vec;
use crate::diagnostics::RuntimeDiagnostics;
use crate::framing::{
    compute_checksum, compute_checksum_ieee, CaptureError, CaptureHeader, CaptureTrailer,
    FORMAT_VERSION_V2, FORMAT_VERSION_V3, FORMAT_VERSION_V4, FORMAT_VERSION_V5,
    REQUIRED_SOFTWARE_STACK_V3, REQUIRED_MAPPINGS_V4, REQUIRED_RECORDER_V5, SessionStatusCode,
    CAPTURE_HEADER_SIZE, CAPTURE_TRAILER_SIZE,
};
use crate::record::NormalizedRecord;
use crate::schema::{SchemaRegistry, PERF_EVENT_SOFTWARE_ID};
use crate::session::{SamplingSession, SessionConfig, SessionMetadata};

pub const PERF_RECORD_LOST: u32 = 2;
pub const PERF_RECORD_SAMPLE: u32 = 9;

pub const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;
pub const BPF_RINGBUF_DISCARD_BIT: u32 = 1 << 30;
pub const BPF_RINGBUF_HDR_MASK: u32 = BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT;

/// Format selected from the attached program/configuration, never guessed
/// from a 64-byte payload (which also matches a legacy TaskEnqueue context).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeContextFormat {
    PerfEventV1,
    PerfEventV2,
    SoftwareStackV3,
    Tracepoint,
}

/// Backwards-compatible name for explicitly declared native context formats.
pub type SampleFormat = NativeContextFormat;

/// Session capture writer producing independent versioned capture files.
#[derive(Clone, Debug)]
pub struct CaptureWriter {
    config: SessionConfig,
    registry: SchemaRegistry,
    session: SamplingSession,
    records_buf: Vec<u8>,
    records_count: u64,
    diagnostics: Option<RuntimeDiagnostics>,
    requires_stack_v3: bool,
    mappings: Option<crate::mapping::MappingMetadata>,
    recorder: Option<crate::recorder::RecorderMetadata>,
    recorder_record_budget: usize,
    start_ns: u64,
}

impl CaptureWriter {
    pub fn new(config: SessionConfig, registry: SchemaRegistry) -> Self {
        let session = SamplingSession::new(config.clone());
        Self {
            config,
            registry,
            session,
            records_buf: Vec::new(),
            records_count: 0,
            diagnostics: None,
            requires_stack_v3: false,
            mappings: None,
            recorder: None,
            recorder_record_budget: 0,
            start_ns: 0,
        }
    }

    /// Attach runtime evidence and select capture format v2. Values may be
    /// updated until finish; diagnostic loss/unknown values can only reduce status.
    pub fn set_diagnostics(&mut self, diagnostics: RuntimeDiagnostics) -> Result<(), CaptureError> {
        if self.session.is_finished() { return Err(CaptureError::IoError("session already finished")); }
        diagnostics.validate()?;
        self.diagnostics = Some(diagnostics);
        Ok(())
    }

    /// Attach original temporal mapping evidence and verified artifact identities.
    pub fn set_mappings(&mut self, mappings: crate::mapping::MappingMetadata) -> Result<(), CaptureError> {
        if self.session.is_finished() { return Err(CaptureError::IoError("session already finished")); }
        if self.recorder.is_some() { return Err(CaptureError::InvalidRecord("recorder mappings are unsupported")); }
        mappings.validate()?;
        self.mappings = Some(mappings);
        Ok(())
    }

    pub fn start(&mut self, now_ns: u64) -> Result<(), CaptureError> {
        self.session.start(now_ns)?;
        self.start_ns = now_ns;
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.session.is_running()
    }

    pub fn write_record(&mut self, record: NormalizedRecord) -> Result<(), CaptureError> {
        if self.recorder.is_some() {
            return Err(CaptureError::InvalidRecord("recorder requires a source-bound envelope"));
        }
        self.write_record_inner(record)
    }

    fn write_record_inner(&mut self, record: NormalizedRecord) -> Result<(), CaptureError> {
        if !self.session.is_running() {
            return Err(CaptureError::IoError("session is not running"));
        }

        self.registry.validate_record(&record)?;
        if record.event_id == crate::schema::PERF_EVENT_SOFTWARE_STACK_V3_ID {
            self.requires_stack_v3 = true;
        }
        let bytes = record.to_bytes();
        self.records_buf.extend_from_slice(&bytes);
        self.records_count += 1;
        self.session.record_sample_delivered();
        Ok(())
    }

    /// Select source-bound capture v5 before accepting any records. Control
    /// windows may initially be zero; fill them with update_recorder_source
    /// before finish. The budget bounds retained normalized bytes plus source
    /// bindings; exhausted capacity is explicit consumer loss, never silent.
    pub fn configure_recorder(&mut self, sources: Vec<crate::recorder::RecorderSource>, record_budget: usize) -> Result<(), CaptureError> {
        if self.session.is_finished() || self.records_count != 0 || self.recorder.is_some()
            || self.mappings.is_some() || record_budget == 0
            || record_budget > crate::recorder::MAX_RECORDER_RECORD_BYTES
        {
            return Err(CaptureError::InvalidRecord("invalid recorder configuration or budget"));
        }
        let metadata = crate::recorder::RecorderMetadata { source_schema_version: 2, sources, record_sources: Vec::new() };
        metadata.validate_sources()?;
        self.recorder = Some(metadata);
        self.recorder_record_budget = record_budget;
        Ok(())
    }

    /// Publish measured enable/disable windows without changing source identity.
    pub fn update_recorder_source(&mut self, source: crate::recorder::RecorderSource) -> Result<(), CaptureError> {
        if self.session.is_finished() { return Err(CaptureError::IoError("session already finished")); }
        let metadata = self.recorder.as_mut().ok_or(CaptureError::InvalidRecord("recorder is not configured"))?;
        let old = metadata.sources.iter_mut().find(|old| old.id == source.id)
            .ok_or(CaptureError::InvalidRecord("undeclared recorder source"))?;
        if !old.same_binding(&source) {
            return Err(CaptureError::InvalidRecord("recorder source binding cannot change"));
        }
        *old = source;
        Ok(())
    }

    /// Consume a program-stamped RAW payload. Returns false only when a valid
    /// sample is discarded because the configured retention budget is full.
    pub fn ingest_recorder_sample(&mut self, cpu: u32, envelope: &[u8]) -> Result<bool, CaptureError> {
        if !self.session.is_running() { return Err(CaptureError::IoError("session is not running")); }
        let decoded = (|| {
            let metadata = self.recorder.as_ref().ok_or(CaptureError::InvalidRecord("recorder is not configured"))?;
            let (source, record) = metadata.decode_sample(cpu, envelope)?;
            self.registry.validate_record(&record)?;
            Ok((source, record))
        })();
        let (source, record) = match decoded {
            Ok(value) => value,
            Err(error) => { self.session.record_consumer_corruption(); return Err(error); }
        };
        let retained = self.records_buf.len() + self.recorder.as_ref().unwrap().record_sources.len() * 4;
        let required = crate::record::RECORD_HEADER_SIZE + record.payload.len() + 4;
        if required > self.recorder_record_budget - retained {
            self.session.record_discarded_record();
            return Ok(false);
        }
        self.write_record_inner(record)?;
        self.recorder.as_mut().unwrap().record_sources.push(source);
        Ok(true)
    }

    /// Consume an unchanged aligned PERF_RECORD_SAMPLE/LOST frame from a ring.
    /// A true return also covers an accounted LOST notice; it is not a sample
    /// count. Unknown or malformed frames increment consumer corruption.
    pub fn ingest_recorder_frame(&mut self, cpu: u32, frame: &[u8]) -> Result<bool, CaptureError> {
        if !self.session.is_running() || self.recorder.is_none() {
            return Err(CaptureError::IoError("recorder session is not running"));
        }
        let parsed = (|| {
            if frame.len() < 8 { return Err(CaptureError::TruncatedRecord); }
            let kind = u32::from_le_bytes(frame[..4].try_into().unwrap());
            let size = u16::from_le_bytes(frame[6..8].try_into().unwrap()) as usize;
            if size != frame.len() || size % 8 != 0 {
                return Err(CaptureError::InvalidRecord("invalid recorder perf frame boundary"));
            }
            match kind {
                PERF_RECORD_SAMPLE if size >= 12 => {
                    let length = u32::from_le_bytes(frame[8..12].try_into().unwrap()) as usize;
                    let end = length.checked_add(12).ok_or(CaptureError::TruncatedRecord)?;
                    if end > size || size - end > 7 { return Err(CaptureError::InvalidRecord("invalid recorder RAW length")); }
                    Ok(Some(&frame[12..end]))
                }
                PERF_RECORD_LOST if size == 24 => Ok(None),
                _ => Err(CaptureError::InvalidRecord("unknown recorder perf frame")),
            }
        })();
        match parsed {
            Ok(Some(raw)) => self.ingest_recorder_sample(cpu, raw),
            Ok(None) => {
                self.ingest_perf_lost(cpu, u64::from_le_bytes(frame[16..24].try_into().unwrap()));
                Ok(true)
            }
            Err(error) => { self.session.record_consumer_corruption(); Err(error) }
        }
    }

    /// Backwards-compatible v1 ingestion. Native samplers must supply their
    /// declared source format through ingest_perf_sample_as for v2/v3 contexts.
    pub fn ingest_perf_sample(&mut self, cpu: u32, raw_sample: &[u8]) -> Result<(), CaptureError> {
        let format = if raw_sample.len() == 48 { SampleFormat::PerfEventV1 } else { SampleFormat::Tracepoint };
        self.ingest_perf_sample_as(cpu, raw_sample, format)
    }

    pub fn ingest_perf_sample_as(&mut self, cpu: u32, raw_sample: &[u8], format: SampleFormat) -> Result<(), CaptureError> {
        if !self.session.is_running() {
            return Err(CaptureError::IoError("session is not running"));
        }
        let result = (|| {
            let record = match format {
                SampleFormat::PerfEventV1 => {
                    if raw_sample.len() != 48 { return Err(CaptureError::TruncatedRecord); }
                    NormalizedRecord::from_perf_event_slice(PERF_EVENT_SOFTWARE_ID, raw_sample)?
                }
                SampleFormat::PerfEventV2 => NormalizedRecord::from_perf_event_v2_slice(raw_sample)?,
                SampleFormat::SoftwareStackV3 => NormalizedRecord::from_software_stack_v3_slice(raw_sample)?,
                SampleFormat::Tracepoint => {
                    if raw_sample.len() < 40 { return Err(CaptureError::TruncatedRecord); }
                    let id = u32::from_le_bytes(raw_sample[..4].try_into().unwrap());
                    let metadata = pulse_bpf_schema::lookup_by_id(id)
                        .map_err(|_| CaptureError::InvalidRecord("unknown tracepoint"))?;
                    if raw_sample.len() != metadata.context_size || raw_sample[28..32] != [0; 4] {
                        return Err(CaptureError::InvalidRecord("tracepoint context length/reserved"));
                    }
                    NormalizedRecord::from_tracepoint_slice(id, raw_sample)?
                }
            };
            if record.cpu_id != cpu {
                return Err(CaptureError::InvalidRecord("source CPU differs from transport CPU"));
            }
            self.write_record(record)
        })();
        if result.is_err() { self.session.record_consumer_corruption(); }
        result
    }

    /// Ingest a PERF_RECORD_LOST notification with lost event count.
    pub fn ingest_perf_lost(&mut self, cpu: u32, count: u64) {
        self.session.record_perf_lost(cpu, count);
    }

    /// Ingest one complete legacy raw frame, including its alignment padding.
    pub fn ingest_raw_perf_frame(&mut self, cpu: u32, raw_frame: &[u8]) -> Result<(), CaptureError> {
        self.ingest_perf_frame_inner(cpu, raw_frame, None)
    }

    pub fn ingest_raw_perf_frame_as(&mut self, cpu: u32, raw_frame: &[u8], format: SampleFormat) -> Result<(), CaptureError> {
        self.ingest_perf_frame_inner(cpu, raw_frame, Some(format))
    }

    fn ingest_perf_frame_inner(&mut self, cpu: u32, raw_frame: &[u8], format: Option<SampleFormat>) -> Result<(), CaptureError> {
        if !self.session.is_running() {
            return Err(CaptureError::IoError("session is not running"));
        }
        let frame = (|| {
            if raw_frame.len() < 8 { return Err(CaptureError::TruncatedRecord); }
            let kind = u32::from_le_bytes(raw_frame[..4].try_into().unwrap());
            let size = u16::from_le_bytes(raw_frame[6..8].try_into().unwrap()) as usize;
            if size != raw_frame.len() || size % 8 != 0 {
                return Err(CaptureError::InvalidRecord("invalid frame boundary"));
            }
            match kind {
                PERF_RECORD_SAMPLE => {
                    if size < 12 { return Err(CaptureError::TruncatedRecord); }
                    let len = u32::from_le_bytes(raw_frame[8..12].try_into().unwrap()) as usize;
                    let end = 12usize.checked_add(len).ok_or(CaptureError::TruncatedRecord)?;
                    if end > size || size - end > 7 {
                        return Err(CaptureError::InvalidRecord("invalid RAW length or padding"));
                    }
                    Ok(Some(&raw_frame[12..end]))
                }
                PERF_RECORD_LOST if size == 24 => Ok(None),
                _ => Err(CaptureError::InvalidRecord("unknown or malformed perf frame")),
            }
        })();
        match frame {
            Err(e) => { self.session.record_consumer_corruption(); Err(e) }
            Ok(None) => {
                let lost = u64::from_le_bytes(raw_frame[16..24].try_into().unwrap());
                self.ingest_perf_lost(cpu, lost);
                Ok(())
            }
            Ok(Some(raw)) => match format {
                Some(format) => self.ingest_perf_sample_as(cpu, raw, format),
                None => self.ingest_perf_sample(cpu, raw),
            }
        }
    }

    /// Ingest a ring buffer loss counter increment.
    pub fn ingest_ringbuf_lost(&mut self, count: u64) {
        self.session.record_ringbuf_lost(count);
    }

    /// Ingest a normalized raw sample payload originating from Ring Buffer (`bpf_ringbuf_output`).
    ///
    /// The payload has the same normalized format (`pulse_bpf_schema`) as Perf Buffer samples.
    pub fn ingest_ringbuf_sample(&mut self, cpu: u32, raw_sample: &[u8]) -> Result<(), CaptureError> {
        self.ingest_perf_sample(cpu, raw_sample)
    }

    /// Ingest a raw Linux Ring Buffer record frame (8-byte header + payload).
    pub fn ingest_raw_ringbuf_frame(&mut self, cpu: u32, raw_frame: &[u8]) -> Result<(), CaptureError> {
        if raw_frame.len() < 8 {
            self.session.record_consumer_corruption();
            return Err(CaptureError::TruncatedRecord);
        }

        let raw_hdr = u32::from_ne_bytes(raw_frame[0..4].try_into().unwrap());
        if (raw_hdr & BPF_RINGBUF_BUSY_BIT) != 0 {
            // Busy bit set: producer has not finished committing
            return Err(CaptureError::TruncatedRecord);
        }

        let is_discard = (raw_hdr & BPF_RINGBUF_DISCARD_BIT) != 0;
        let data_len = (raw_hdr & !BPF_RINGBUF_HDR_MASK) as usize;
        if raw_frame.len() < 8 + data_len {
            self.session.record_consumer_corruption();
            return Err(CaptureError::TruncatedRecord);
        }

        if is_discard {
            self.session.record_discarded_record();
            return Ok(());
        }

        let payload = &raw_frame[8..8 + data_len];
        self.ingest_ringbuf_sample(cpu, payload)
    }

    /// Preserve an interrupted recorder's observed data when a final clock or
    /// quiescence observation is unavailable. Consumes the writer so recording
    /// cannot resume. Known source windows and diagnostic rows are unchanged;
    /// stop_ns=0 is explicitly unknown. The absent integrity trailer makes this
    /// artifact unconditionally truncated to CaptureReader, never complete.
    /// This also works after a failed finish, even if it advanced session state.
    pub fn abort_partial_bytes(self) -> Result<Vec<u8>, CaptureError> {
        let recorder = self.recorder.as_ref()
            .ok_or(CaptureError::InvalidRecord("abort requires a recorder capture"))?;
        recorder.validate_sources()?;
        if recorder.record_sources.len() as u64 != self.records_count {
            return Err(CaptureError::InvalidRecord("recorder source binding count differs from record count"));
        }
        let metadata = SessionMetadata {
            config: self.config.clone(), start_ns: self.start_ns, stop_ns: 0,
            status: SessionStatusCode::IncompleteTruncated,
            counters: self.session.counters().clone(),
        };
        let diagnostics = self.diagnostics.as_ref().cloned().unwrap_or_default().to_bytes()?;
        let mut metadata_buf = self.registry.to_bytes();
        metadata_buf.extend_from_slice(&metadata.to_bytes());
        metadata_buf.extend_from_slice(&(diagnostics.len() as u32).to_le_bytes());
        metadata_buf.extend_from_slice(&diagnostics);
        metadata_buf.extend_from_slice(&recorder.to_bytes());
        metadata_buf.extend_from_slice(&REQUIRED_RECORDER_V5.to_le_bytes());
        Ok(self.frame_capture(&metadata_buf, FORMAT_VERSION_V5, None))
    }

    /// Finalize capture, compute checksums, and emit the complete binary capture file.
    pub fn finish(&mut self, stop_ns: u64) -> Result<Vec<u8>, CaptureError> {
        // A required stack extension always has the diagnostics section defined
        // by v2. Missing runtime evidence stays explicitly unknown.
        if (self.requires_stack_v3 || self.mappings.is_some() || self.recorder.is_some()) && self.diagnostics.is_none() {
            self.diagnostics = Some(RuntimeDiagnostics::default());
        }
        let recorder_bytes = if let Some(recorder) = &self.recorder {
            recorder.validate_sources()?;
            if recorder.record_sources.len() as u64 != self.records_count {
                return Err(CaptureError::InvalidRecord("recorder source binding count differs from record count"));
            }
            // Validate final windows before consuming the session. Decode one
            // record at a time so validation does not duplicate the retained file.
            let start = self.start_ns;
            for source in &recorder.sources { source.validate_window(start, stop_ns)?; }
            let mut offset = 0;
            for id in &recorder.record_sources {
                let (record, size) = NormalizedRecord::from_bytes(&self.records_buf[offset..])?;
                recorder.source(*id)?.validate_record(&record, true)?;
                offset += size;
            }
            Some(recorder.to_bytes())
        } else { None };
        // Serialize before stopping, so invalid evidence does not consume the session.
        let diagnostics_bytes = self.diagnostics.as_ref().map(RuntimeDiagnostics::to_bytes).transpose()?;
        let mappings_bytes = self.mappings.as_ref().map(crate::mapping::MappingMetadata::to_bytes).transpose()?;
        let mut metadata = self.session.stop(stop_ns)?;
        if self.diagnostics.is_some() && (metadata.start_ns == 0 || stop_ns <= metadata.start_ns) {
            return Err(CaptureError::InvalidRecord("invalid runtime session window"));
        }
        if let Some(diagnostics) = &self.diagnostics {
            let status = diagnostics.status();
            if self.records_count == 0 || status == SessionStatusCode::IncompleteError {
                metadata.status = SessionStatusCode::IncompleteError;
            } else if metadata.status.is_complete() && !status.is_complete() {
                metadata.status = status;
            }
        }
        // v5 certifies record/source binding, not exhaustive producer and
        // pending-fault coverage. Generic diagnostic rows cannot serve as a
        // completeness certificate by merely containing unrelated known zeros.
        if self.recorder.is_some() && metadata.status.is_complete() {
            metadata.status = SessionStatusCode::IncompleteError;
        }

        if let Some(mappings) = &self.mappings {
            let journal = crate::mapping::MappingJournal::parse(&mappings.journal)?;
            if journal.dropped > 0 && metadata.status.is_complete() {
                metadata.status = SessionStatusCode::IncompleteLoss;
            }
        }
        let mut metadata_buf = Vec::new();
        metadata_buf.extend_from_slice(&self.registry.to_bytes());
        metadata_buf.extend_from_slice(&metadata.to_bytes());
        if let Some(bytes) = diagnostics_bytes {
            // v4 delimits diagnostics before the independently bounded journal.
            if self.mappings.is_some() || self.recorder.is_some() { metadata_buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes()); }
            metadata_buf.extend_from_slice(&bytes);
        }
        if let Some(bytes) = mappings_bytes { metadata_buf.extend_from_slice(&bytes); }
        if let Some(bytes) = recorder_bytes { metadata_buf.extend_from_slice(&bytes); }
        if self.requires_stack_v3 || self.mappings.is_some() || self.recorder.is_some() {
            let required = if self.requires_stack_v3 { REQUIRED_SOFTWARE_STACK_V3 } else { 0 }
                | if self.mappings.is_some() { REQUIRED_MAPPINGS_V4 } else { 0 }
                | if self.recorder.is_some() { REQUIRED_RECORDER_V5 } else { 0 };
            metadata_buf.extend_from_slice(&required.to_le_bytes());
        }

        let mut version = crate::framing::FORMAT_VERSION_V1;
        if self.diagnostics.is_some() { version = FORMAT_VERSION_V2; }
        if self.requires_stack_v3 { version = FORMAT_VERSION_V3; }
        if self.mappings.is_some() { version = FORMAT_VERSION_V4; }
        if self.recorder.is_some() { version = FORMAT_VERSION_V5; }
        Ok(self.frame_capture(&metadata_buf, version, Some(metadata.status)))
    }

    fn frame_capture(&self, metadata_buf: &[u8], version: u32, status: Option<SessionStatusCode>) -> Vec<u8> {
        let metadata_offset = CAPTURE_HEADER_SIZE as u64;
        let metadata_size = metadata_buf.len() as u64;
        let records_offset = metadata_offset + metadata_size;
        let records_size = self.records_buf.len() as u64;
        let trailer_offset = records_offset + records_size;
        let trailer_size = CAPTURE_TRAILER_SIZE as u64;

        let mut header = CaptureHeader::new(self.config.target_arch);
        header.format_version = version;
        header.metadata_offset = metadata_offset;
        header.metadata_size = metadata_size;
        header.records_offset = records_offset;
        header.records_count = self.records_count;
        header.records_size = records_size;
        header.trailer_offset = trailer_offset;
        header.trailer_size = trailer_size;

        let mut output = Vec::with_capacity((trailer_offset + if status.is_some() { trailer_size } else { 0 }) as usize);
        output.extend_from_slice(&header.to_bytes());
        output.extend_from_slice(metadata_buf);
        output.extend_from_slice(&self.records_buf);

        if let Some(status) = status {
            let checksum = if version >= FORMAT_VERSION_V2 { compute_checksum_ieee(&output) } else { compute_checksum(&output) };
            let trailer = CaptureTrailer::new(self.records_count, records_size, checksum, status);
            output.extend_from_slice(&trailer.to_bytes());
        }
        output
    }
}
