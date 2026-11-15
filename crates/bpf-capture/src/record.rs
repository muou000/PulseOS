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

        let total_size = RECORD_HEADER_SIZE.checked_add(payload_len).ok_or(CaptureError::TruncatedRecord)?;
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

        let _raw_event_id = u32::from_le_bytes(slice[0..4].try_into().unwrap());
        let version = u32::from_le_bytes(slice[4..8].try_into().unwrap());
        let timestamp_ns = u64::from_le_bytes(slice[8..16].try_into().unwrap());
        let cpu_id = u32::from_le_bytes(slice[16..20].try_into().unwrap());
        let pid = u32::from_le_bytes(slice[20..24].try_into().unwrap());
        let tid = u32::from_le_bytes(slice[24..28].try_into().unwrap());
        let task_id = u64::from_le_bytes(slice[32..40].try_into().unwrap());

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

    /// Decode an explicitly identified PulseOS software-sample v2 context.
    /// A 64-byte length alone is insufficient: TaskEnqueue also uses 64 bytes.
    pub fn from_perf_event_v2_slice(slice: &[u8]) -> Result<Self, CaptureError> {
        if slice.len() != 64 {
            return Err(CaptureError::TruncatedRecord);
        }
        let version = u32::from_le_bytes(slice[60..64].try_into().unwrap());
        let mode = u32::from_le_bytes(slice[56..60].try_into().unwrap());
        let period = u64::from_le_bytes(slice[0..8].try_into().unwrap());
        let timestamp_ns = u64::from_le_bytes(slice[16..24].try_into().unwrap());
        let cpu_id = u32::from_le_bytes(slice[24..28].try_into().unwrap());
        let pid = u32::from_le_bytes(slice[28..32].try_into().unwrap());
        let tid = u32::from_le_bytes(slice[32..36].try_into().unwrap());
        let task_id = u64::from_le_bytes(slice[40..48].try_into().unwrap());
        let ip = u64::from_le_bytes(slice[48..56].try_into().unwrap());
        if version != 2 || !matches!(mode, 1 | 2) || slice[36..40] != [0; 4]
            || period == 0 || timestamp_ns == 0 || task_id == 0 || ip == 0
            || (mode == 2 && (pid == 0 || tid == 0))
        {
            return Err(CaptureError::InvalidRecord("invalid software sample v2 context"));
        }
        let mut payload = vec![0; 32];
        payload[..16].copy_from_slice(&slice[..16]); // period and data address
        payload[16..24].copy_from_slice(&slice[48..56]);
        payload[24..28].copy_from_slice(&slice[56..60]);
        Ok(Self {
            event_id: crate::schema::PERF_EVENT_SOFTWARE_V2_ID, schema_version: 2,
            timestamp_ns, cpu_id, pid, tid, task_id, payload,
        })
    }

    /// Decode the declared 640-byte native software stack context. The legacy
    /// 64-byte prefix keeps version 2; the extension itself declares version 3.
    pub fn from_software_stack_v3_slice(slice: &[u8]) -> Result<Self, CaptureError> {
        pulse_bpf_schema::PerfStackSampleContext::from_bytes(slice)
            .map_err(|_| CaptureError::InvalidRecord("invalid software stack v3 context"))?;
        let mut record = Self::from_perf_event_v2_slice(&slice[..64])?;
        record.event_id = crate::schema::PERF_EVENT_SOFTWARE_STACK_V3_ID;
        record.schema_version = 3;
        record.payload.extend_from_slice(&slice[64..]);
        Ok(record)
    }

    /// Restore the native context from the normalized common header and payload.
    /// Decoding applies the same validation used at the raw ingestion seam.
    pub fn software_stack_v3(&self) -> Result<pulse_bpf_schema::PerfStackSampleContext, CaptureError> {
        if self.event_id != crate::schema::PERF_EVENT_SOFTWARE_STACK_V3_ID
            || self.schema_version != 3 || self.payload.len() != 608 {
            return Err(CaptureError::InvalidRecord("invalid normalized software stack v3 schema"));
        }
        let mut raw = [0u8; 640];
        raw[..16].copy_from_slice(&self.payload[..16]);
        raw[16..24].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        raw[24..28].copy_from_slice(&self.cpu_id.to_le_bytes());
        raw[28..32].copy_from_slice(&self.pid.to_le_bytes());
        raw[32..36].copy_from_slice(&self.tid.to_le_bytes());
        raw[40..48].copy_from_slice(&self.task_id.to_le_bytes());
        raw[48..60].copy_from_slice(&self.payload[16..28]);
        raw[60..64].copy_from_slice(&2u32.to_le_bytes());
        raw[64..].copy_from_slice(&self.payload[32..]);
        if self.payload[28..32] != [0; 4] {
            return Err(CaptureError::InvalidRecord("nonzero software stack reserved field"));
        }
        pulse_bpf_schema::PerfStackSampleContext::from_bytes(&raw)
            .map_err(|_| CaptureError::InvalidRecord("invalid normalized software stack v3 context"))
    }

}

