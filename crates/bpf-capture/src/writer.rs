//! Binary BPF capture writer with streaming record persistence and integrity trailer.

use alloc::vec::Vec;
use crate::framing::{
    compute_checksum, CaptureError, CaptureHeader, CaptureTrailer,
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

/// Session capture writer producing independent versioned capture files.
#[derive(Clone, Debug)]
pub struct CaptureWriter {
    config: SessionConfig,
    registry: SchemaRegistry,
    session: SamplingSession,
    records_buf: Vec<u8>,
    records_count: u64,
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
        }
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

    /// Ingest a sample payload from a Linux Perf Buffer or software event context.
    pub fn ingest_perf_sample(&mut self, cpu: u32, raw_sample: &[u8]) -> Result<(), CaptureError> {
        if !self.session.is_running() {
            return Err(CaptureError::IoError("session is not running"));
        }

        // Software perf_event sample context (fixed 48 bytes)
        if raw_sample.len() == 48 && self.registry.lookup(PERF_EVENT_SOFTWARE_ID).is_some() {
            let mut rec = NormalizedRecord::from_perf_event_slice(PERF_EVENT_SOFTWARE_ID, raw_sample)?;
            rec.cpu_id = cpu;
            return self.write_record(rec);
        }

        // Tracepoint contexts: size >= 40, version == 1, event_id 1..=7
        if raw_sample.len() >= 40 {
            let event_id = u32::from_ne_bytes(raw_sample[0..4].try_into().unwrap());
            let version = u32::from_ne_bytes(raw_sample[4..8].try_into().unwrap());
            if version == 1 && (1..=7).contains(&event_id) && self.registry.lookup(event_id).is_some() {
                let mut rec = NormalizedRecord::from_tracepoint_slice(event_id, raw_sample)?;
                rec.cpu_id = cpu;
                return self.write_record(rec);
            }
        }

        // Fallback: unparseable/corrupt sample format
        self.session.record_consumer_corruption();
        Err(CaptureError::TruncatedRecord)
    }

    /// Ingest a PERF_RECORD_LOST notification with lost event count.
    pub fn ingest_perf_lost(&mut self, cpu: u32, count: u64) {
        self.session.record_perf_lost(cpu, count);
    }

    /// Ingest a raw ring buffer frame (PERF_RECORD_SAMPLE or PERF_RECORD_LOST) from Linux Perf Buffer.
    pub fn ingest_raw_perf_frame(&mut self, cpu: u32, raw_frame: &[u8]) -> Result<(), CaptureError> {
        if raw_frame.len() < 8 {
            self.session.record_consumer_corruption();
            return Err(CaptureError::TruncatedRecord);
        }

        let event_type = u32::from_ne_bytes(raw_frame[0..4].try_into().unwrap());
        let rec_size = u16::from_ne_bytes(raw_frame[6..8].try_into().unwrap()) as usize;
        if raw_frame.len() < rec_size {
            self.session.record_consumer_corruption();
            return Err(CaptureError::TruncatedRecord);
        }

        if event_type == PERF_RECORD_SAMPLE {
            if rec_size < 12 {
                self.session.record_consumer_corruption();
                return Err(CaptureError::TruncatedRecord);
            }
            let raw_len = u32::from_ne_bytes(raw_frame[8..12].try_into().unwrap()) as usize;
            if rec_size < 12 + raw_len {
                self.session.record_consumer_corruption();
                return Err(CaptureError::TruncatedRecord);
            }
            let payload = &raw_frame[12..12 + raw_len];
            self.ingest_perf_sample(cpu, payload)
        } else if event_type == PERF_RECORD_LOST {
            if rec_size < 24 {
                self.session.record_consumer_corruption();
                return Err(CaptureError::TruncatedRecord);
            }
            let lost_count = u64::from_ne_bytes(raw_frame[16..24].try_into().unwrap());
            self.ingest_perf_lost(cpu, lost_count);
            Ok(())
        } else {
            self.session.record_consumer_corruption();
            Err(CaptureError::TruncatedRecord)
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
        let metadata = self.session.stop(stop_ns)?;

        let mut metadata_buf = Vec::new();
        metadata_buf.extend_from_slice(&self.registry.to_bytes());
        metadata_buf.extend_from_slice(&metadata.to_bytes());

        let metadata_offset = CAPTURE_HEADER_SIZE as u64;
        let metadata_size = metadata_buf.len() as u64;
        let records_offset = metadata_offset + metadata_size;
        let records_size = self.records_buf.len() as u64;
        let trailer_offset = records_offset + records_size;
        let trailer_size = CAPTURE_TRAILER_SIZE as u64;

        let mut header = CaptureHeader::new(self.config.target_arch);
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

        let checksum = compute_checksum(&output);
        let trailer = CaptureTrailer::new(self.records_count, records_size, checksum, metadata.status);
        output.extend_from_slice(&trailer.to_bytes());

        Ok(output)
    }
}
