//! Binary BPF capture writer with streaming record persistence and integrity trailer.

use alloc::vec::Vec;
use crate::diagnostics::RuntimeDiagnostics;
use crate::framing::{
    compute_checksum, compute_checksum_ieee, CaptureError, CaptureHeader, CaptureTrailer,
    FORMAT_VERSION_V2, SessionStatusCode,
    CAPTURE_HEADER_SIZE, CAPTURE_TRAILER_SIZE,
};
use crate::record::NormalizedRecord;
use crate::schema::{SchemaRegistry, PERF_EVENT_SOFTWARE_ID};
use crate::session::{SamplingSession, SessionConfig};

pub const PERF_RECORD_LOST: u32 = 2;
pub const PERF_RECORD_SAMPLE: u32 = 9;

pub const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;
pub const BPF_RINGBUF_DISCARD_BIT: u32 = 1 << 30;
pub const BPF_RINGBUF_HDR_MASK: u32 = BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT;

/// Format selected from the attached program/configuration, never guessed
/// from a 64-byte payload (which also matches a legacy TaskEnqueue context).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleFormat {
    PerfEventV1,
    PerfEventV2,
    Tracepoint,
}

/// Session capture writer producing independent versioned capture files.
#[derive(Clone, Debug)]
pub struct CaptureWriter {
    config: SessionConfig,
    registry: SchemaRegistry,
    session: SamplingSession,
    records_buf: Vec<u8>,
    records_count: u64,
    diagnostics: Option<RuntimeDiagnostics>,
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

    pub fn start(&mut self, now_ns: u64) -> Result<(), CaptureError> {
        self.session.start(now_ns)
    }

    pub fn is_running(&self) -> bool {
        self.session.is_running()
    }

    pub fn write_record(&mut self, record: NormalizedRecord) -> Result<(), CaptureError> {
        if !self.session.is_running() {
            return Err(CaptureError::IoError("session is not running"));
        }

        self.registry.validate_record(&record)?;
        let bytes = record.to_bytes();
        self.records_buf.extend_from_slice(&bytes);
        self.records_count += 1;
        self.session.record_sample_delivered();
        Ok(())
    }

    /// Backwards-compatible v1 ingestion. Native samplers must supply their
    /// declared source format through ingest_perf_sample_as for v2 contexts.
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

    /// Finalize capture, compute checksums, and emit the complete binary capture file.
    pub fn finish(&mut self, stop_ns: u64) -> Result<Vec<u8>, CaptureError> {
        // Serialize before stopping, so invalid evidence does not consume the session.
        let diagnostics_bytes = self.diagnostics.as_ref().map(RuntimeDiagnostics::to_bytes).transpose()?;
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

        let mut metadata_buf = Vec::new();
        metadata_buf.extend_from_slice(&self.registry.to_bytes());
        metadata_buf.extend_from_slice(&metadata.to_bytes());
        if let Some(bytes) = diagnostics_bytes { metadata_buf.extend_from_slice(&bytes); }

        let metadata_offset = CAPTURE_HEADER_SIZE as u64;
        let metadata_size = metadata_buf.len() as u64;
        let records_offset = metadata_offset + metadata_size;
        let records_size = self.records_buf.len() as u64;
        let trailer_offset = records_offset + records_size;
        let trailer_size = CAPTURE_TRAILER_SIZE as u64;

        let mut header = CaptureHeader::new(self.config.target_arch);
        if self.diagnostics.is_some() { header.format_version = FORMAT_VERSION_V2; }
        header.metadata_offset = metadata_offset;
        header.metadata_size = metadata_size;
        header.records_offset = records_offset;
        header.records_count = self.records_count;
        header.records_size = records_size;
        header.trailer_offset = trailer_offset;
        header.trailer_size = trailer_size;

        let mut output = Vec::with_capacity((trailer_offset + trailer_size) as usize);
        output.extend_from_slice(&header.to_bytes());
        output.extend_from_slice(&metadata_buf);
        output.extend_from_slice(&self.records_buf);

        let checksum = if self.diagnostics.is_some() { compute_checksum_ieee(&output) } else { compute_checksum(&output) };
        let trailer = CaptureTrailer::new(self.records_count, records_size, checksum, metadata.status);
        output.extend_from_slice(&trailer.to_bytes());

        Ok(output)
    }
}
