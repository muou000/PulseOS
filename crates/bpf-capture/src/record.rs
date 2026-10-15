//! Normalized transport-neutral BPF event records.

use alloc::vec;
use alloc::vec::Vec;
use crate::framing::CaptureError;

pub const RECORD_HEADER_SIZE: usize = 48;

/// Transport-neutral normalized BPF event record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedRecord {
    pub event_id: u32,
    pub schema_version: u32,
    pub timestamp_ns: u64,
    pub cpu_id: u32,
    pub pid: u32,
    pub tid: u32,
    pub task_id: u64,
    pub payload: Vec<u8>,
}

impl NormalizedRecord {
    pub fn new(
        event_id: u32,
        schema_version: u32,
        timestamp_ns: u64,
        cpu_id: u32,
        pid: u32,
        tid: u32,
        task_id: u64,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            event_id,
            schema_version,
            timestamp_ns,
            cpu_id,
            pid,
            tid,
            task_id,
            payload,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let mut buf = vec![0u8; RECORD_HEADER_SIZE + self.payload.len()];
        buf[0..4].copy_from_slice(&self.event_id.to_le_bytes());
        buf[4..8].copy_from_slice(&self.schema_version.to_le_bytes());
        buf[8..16].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        buf[16..20].copy_from_slice(&self.cpu_id.to_le_bytes());
        buf[20..24].copy_from_slice(&self.pid.to_le_bytes());
        buf[24..28].copy_from_slice(&self.tid.to_le_bytes());
        buf[28..32].copy_from_slice(&0u32.to_le_bytes()); // _reserved
        buf[32..40].copy_from_slice(&self.task_id.to_le_bytes());
        buf[40..44].copy_from_slice(&payload_len.to_le_bytes());
        buf[44..48].copy_from_slice(&0u32.to_le_bytes()); // _pad
        buf[RECORD_HEADER_SIZE..].copy_from_slice(&self.payload);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), CaptureError> {
        if bytes.len() < RECORD_HEADER_SIZE {
            return Err(CaptureError::TruncatedRecord);
        }

        let event_id = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let schema_version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let timestamp_ns = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let cpu_id = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let pid = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        let tid = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        let task_id = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let payload_len = u32::from_le_bytes(bytes[40..44].try_into().unwrap()) as usize;

        let total_size = RECORD_HEADER_SIZE + payload_len;
        if bytes.len() < total_size {
            return Err(CaptureError::TruncatedRecord);
        }

        let payload = bytes[RECORD_HEADER_SIZE..total_size].to_vec();

        Ok((
            Self {
                event_id,
                schema_version,
                timestamp_ns,
                cpu_id,
                pid,
                tid,
                task_id,
                payload,
            },
            total_size,
        ))
    }

    /// Extract a normalized record from a raw tracepoint context matching pulse_bpf_schema layout.
    pub fn from_tracepoint_slice(event_id: u32, slice: &[u8]) -> Result<Self, CaptureError> {
        const COMMON_SIZE: usize = 40;
        if slice.len() < COMMON_SIZE {
            return Err(CaptureError::TruncatedRecord);
        }

        let _raw_event_id = u32::from_ne_bytes(slice[0..4].try_into().unwrap());
        let version = u32::from_ne_bytes(slice[4..8].try_into().unwrap());
        let timestamp_ns = u64::from_ne_bytes(slice[8..16].try_into().unwrap());
        let cpu_id = u32::from_ne_bytes(slice[16..20].try_into().unwrap());
        let pid = u32::from_ne_bytes(slice[20..24].try_into().unwrap());
        let tid = u32::from_ne_bytes(slice[24..28].try_into().unwrap());
        let task_id = u64::from_ne_bytes(slice[32..40].try_into().unwrap());

        let payload = slice[COMMON_SIZE..].to_vec();

        Ok(Self {
            event_id,
            schema_version: version,
            timestamp_ns,
            cpu_id,
            pid,
            tid,
            task_id,
            payload,
        })
    }

    /// Extract a normalized record from a software perf_event sample context.
    pub fn from_perf_event_slice(event_id: u32, slice: &[u8]) -> Result<Self, CaptureError> {
        const PERF_CTX_SIZE: usize = 48;
        if slice.len() < PERF_CTX_SIZE {
            return Err(CaptureError::TruncatedRecord);
        }

        let sample_period = u64::from_ne_bytes(slice[0..8].try_into().unwrap());
        let addr = u64::from_ne_bytes(slice[8..16].try_into().unwrap());
        let timestamp_ns = u64::from_ne_bytes(slice[16..24].try_into().unwrap());
        let cpu_id = u32::from_ne_bytes(slice[24..28].try_into().unwrap());
        let pid = u32::from_ne_bytes(slice[28..32].try_into().unwrap());
        let tid = u32::from_ne_bytes(slice[32..36].try_into().unwrap());
        let task_id = u64::from_ne_bytes(slice[40..48].try_into().unwrap());

        let mut payload = vec![0u8; 16];
        payload[0..8].copy_from_slice(&sample_period.to_le_bytes());
        payload[8..16].copy_from_slice(&addr.to_le_bytes());

        Ok(Self {
            event_id,
            schema_version: 1,
            timestamp_ns,
            cpu_id,
            pid,
            tid,
            task_id,
            payload,
        })
    }
}

