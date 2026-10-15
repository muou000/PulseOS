//! Explicit sampling session lifecycle, session metadata, and layered loss/error accounting.

use alloc::string::String;
use alloc::vec::Vec;
use crate::codec::{decode_string, encode_string};
use crate::framing::{CaptureArch, CaptureError, SessionStatusCode};

/// Scope of BPF sampling event collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureScope {
    AllCpus,
    PerCpu(u32),
    Task(u64),
}

impl CaptureScope {
    pub fn to_bytes(&self) -> (u32, u64) {
        match self {
            Self::AllCpus => (0, 0),
            Self::PerCpu(cpu) => (1, *cpu as u64),
            Self::Task(tid) => (2, *tid),
        }
    }

    pub fn from_raw(scope_type: u32, target: u64) -> Self {
        match scope_type {
            1 => Self::PerCpu(target as u32),
            2 => Self::Task(target),
            _ => Self::AllCpus,
        }
    }
}

/// Layered loss and failure counters across kernel, helper, verifier, and consumer boundaries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LayeredLossCounters {
    pub attempted: u64,
    pub delivered: u64,
    pub lost_records_total: u64,
    pub per_cpu_lost: Vec<(u32, u64)>,
    pub ringbuf_lost: u64,
    pub discarded_records: u64,
    pub re_entry_drops: u64,
    pub helper_failures: u64,
    pub budget_failures: u64,
    pub verifier_failures: u64,
    pub load_failures: u64,
    pub attach_failures: u64,
    pub consumer_corrupt_records: u64,
    pub consumer_out_of_bounds: u64,
}

impl LayeredLossCounters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_per_cpu_lost(&mut self, cpu: u32, count: u64) {
        if let Some(entry) = self.per_cpu_lost.iter_mut().find(|(c, _)| *c == cpu) {
            entry.1 = entry.1.saturating_add(count);
        } else {
            self.per_cpu_lost.push((cpu, count));
        }
        self.lost_records_total = self.lost_records_total.saturating_add(count);
    }

    pub fn get_cpu_lost(&self, cpu: u32) -> u64 {
        self.per_cpu_lost
            .iter()
            .find(|(c, _)| *c == cpu)
            .map(|(_, cnt)| *cnt)
            .unwrap_or(0)
    }

    pub fn has_loss(&self) -> bool {
        self.lost_records_total > 0 || self.ringbuf_lost > 0 || self.discarded_records > 0
    }

    pub fn has_error(&self) -> bool {
        self.re_entry_drops > 0
            || self.helper_failures > 0
            || self.budget_failures > 0
            || self.verifier_failures > 0
            || self.load_failures > 0
            || self.attach_failures > 0
            || self.consumer_corrupt_records > 0
            || self.consumer_out_of_bounds > 0
    }

    pub fn has_loss_or_error(&self) -> bool {
        self.has_loss() || self.has_error()
    }

    pub fn total_loss_and_error(&self) -> u64 {
        self.lost_records_total
            + self.ringbuf_lost
            + self.discarded_records
            + self.re_entry_drops
            + self.helper_failures
            + self.budget_failures
            + self.verifier_failures
            + self.load_failures
            + self.attach_failures
            + self.consumer_corrupt_records
            + self.consumer_out_of_bounds
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.attempted.to_le_bytes());
        buf.extend_from_slice(&self.delivered.to_le_bytes());
        buf.extend_from_slice(&self.lost_records_total.to_le_bytes());
        buf.extend_from_slice(&self.ringbuf_lost.to_le_bytes());
        buf.extend_from_slice(&self.discarded_records.to_le_bytes());
        buf.extend_from_slice(&self.re_entry_drops.to_le_bytes());
        buf.extend_from_slice(&self.helper_failures.to_le_bytes());
        buf.extend_from_slice(&self.budget_failures.to_le_bytes());
        buf.extend_from_slice(&self.verifier_failures.to_le_bytes());
        buf.extend_from_slice(&self.load_failures.to_le_bytes());
        buf.extend_from_slice(&self.attach_failures.to_le_bytes());
        buf.extend_from_slice(&self.consumer_corrupt_records.to_le_bytes());
        buf.extend_from_slice(&self.consumer_out_of_bounds.to_le_bytes());

        let cpu_count = self.per_cpu_lost.len() as u32;
        buf.extend_from_slice(&cpu_count.to_le_bytes());
        for (cpu, count) in &self.per_cpu_lost {
            buf.extend_from_slice(&cpu.to_le_bytes());
            buf.extend_from_slice(&count.to_le_bytes());
        }

        buf
    }

    pub fn from_bytes(slice: &[u8]) -> Result<(Self, usize), CaptureError> {
        const FIXED_LEN: usize = 13 * 8 + 4;
        if slice.len() < FIXED_LEN {
            return Err(CaptureError::TruncatedMetadata);
        }

        let mut offset = 0;
        let attempted = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let delivered = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let lost_records_total = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let ringbuf_lost = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let discarded_records = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let re_entry_drops = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let helper_failures = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let budget_failures = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let verifier_failures = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let load_failures = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let attach_failures = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let consumer_corrupt_records = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let consumer_out_of_bounds = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let cpu_count = u32::from_le_bytes(slice[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if slice.len() < offset + cpu_count * 12 {
            return Err(CaptureError::TruncatedMetadata);
        }

        let mut per_cpu_lost = Vec::with_capacity(cpu_count);
        for _ in 0..cpu_count {
            let cpu = u32::from_le_bytes(slice[offset..offset + 4].try_into().unwrap());
            let count = u64::from_le_bytes(slice[offset + 4..offset + 12].try_into().unwrap());
            offset += 12;
            per_cpu_lost.push((cpu, count));
        }

        Ok((
            Self {
                attempted,
                delivered,
                lost_records_total,
                per_cpu_lost,
                ringbuf_lost,
                discarded_records,
                re_entry_drops,
                helper_failures,
                budget_failures,
                verifier_failures,
                load_failures,
                attach_failures,
                consumer_corrupt_records,
                consumer_out_of_bounds,
            },
            offset,
        ))
    }
}

/// Initial configuration and build identity for a sampling session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionConfig {
    pub pulse_commit: String,
    pub target_arch: CaptureArch,
    pub kernel_elf_path: String,
    pub kernel_elf_hash: String,
    pub image_path: String,
    pub image_hash: String,
    pub libbpf_fixture_version: String,
    pub prog_id: u32,
    pub map_id: u32,
    pub link_id: u32,
    pub perf_event_id: u32,
    pub output_path: String,
    pub scope: CaptureScope,
    pub sample_period: u64,
    pub buffer_pages: u64,
    pub clock_name: String,
    pub clock_res_ns: u64,
}

impl SessionConfig {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_string(&mut buf, &self.pulse_commit);
        buf.extend_from_slice(&self.target_arch.as_u32().to_le_bytes());
        encode_string(&mut buf, &self.kernel_elf_path);
        encode_string(&mut buf, &self.kernel_elf_hash);
        encode_string(&mut buf, &self.image_path);
        encode_string(&mut buf, &self.image_hash);
        encode_string(&mut buf, &self.libbpf_fixture_version);

        buf.extend_from_slice(&self.prog_id.to_le_bytes());
        buf.extend_from_slice(&self.map_id.to_le_bytes());
        buf.extend_from_slice(&self.link_id.to_le_bytes());
        buf.extend_from_slice(&self.perf_event_id.to_le_bytes());

        encode_string(&mut buf, &self.output_path);

        let (scope_type, scope_target) = self.scope.to_bytes();
        buf.extend_from_slice(&scope_type.to_le_bytes());
        buf.extend_from_slice(&scope_target.to_le_bytes());

        buf.extend_from_slice(&self.sample_period.to_le_bytes());
        buf.extend_from_slice(&self.buffer_pages.to_le_bytes());

        encode_string(&mut buf, &self.clock_name);
        buf.extend_from_slice(&self.clock_res_ns.to_le_bytes());

        buf
    }

    pub fn from_bytes(slice: &[u8], offset: &mut usize) -> Result<Self, CaptureError> {
        let pulse_commit = decode_string(slice, offset)?;
        if slice.len() < *offset + 4 {
            return Err(CaptureError::TruncatedMetadata);
        }
        let target_arch = CaptureArch::from_u32(u32::from_le_bytes(
            slice[*offset..*offset + 4].try_into().unwrap(),
        ));
        *offset += 4;

        let kernel_elf_path = decode_string(slice, offset)?;
        let kernel_elf_hash = decode_string(slice, offset)?;
        let image_path = decode_string(slice, offset)?;
        let image_hash = decode_string(slice, offset)?;
        let libbpf_fixture_version = decode_string(slice, offset)?;

        if slice.len() < *offset + 16 {
            return Err(CaptureError::TruncatedMetadata);
        }
        let prog_id = u32::from_le_bytes(slice[*offset..*offset + 4].try_into().unwrap());
        let map_id = u32::from_le_bytes(slice[*offset + 4..*offset + 8].try_into().unwrap());
        let link_id = u32::from_le_bytes(slice[*offset + 8..*offset + 12].try_into().unwrap());
        let perf_event_id = u32::from_le_bytes(slice[*offset + 12..*offset + 16].try_into().unwrap());
        *offset += 16;

        let output_path = decode_string(slice, offset)?;

        if slice.len() < *offset + 12 {
            return Err(CaptureError::TruncatedMetadata);
        }
        let scope_type = u32::from_le_bytes(slice[*offset..*offset + 4].try_into().unwrap());
        let scope_target = u64::from_le_bytes(slice[*offset + 4..*offset + 12].try_into().unwrap());
        *offset += 12;
        let scope = CaptureScope::from_raw(scope_type, scope_target);

        if slice.len() < *offset + 16 {
            return Err(CaptureError::TruncatedMetadata);
        }
        let sample_period = u64::from_le_bytes(slice[*offset..*offset + 8].try_into().unwrap());
        let buffer_pages = u64::from_le_bytes(slice[*offset + 8..*offset + 16].try_into().unwrap());
        *offset += 16;

        let clock_name = decode_string(slice, offset)?;
        if slice.len() < *offset + 8 {
            return Err(CaptureError::TruncatedMetadata);
        }
        let clock_res_ns = u64::from_le_bytes(slice[*offset..*offset + 8].try_into().unwrap());
        *offset += 8;

        Ok(Self {
            pulse_commit,
            target_arch,
            kernel_elf_path,
            kernel_elf_hash,
            image_path,
            image_hash,
            libbpf_fixture_version,
            prog_id,
            map_id,
            link_id,
            perf_event_id,
            output_path,
            scope,
            sample_period,
            buffer_pages,
            clock_name,
            clock_res_ns,
        })
    }
}

/// Metadata describing a capture session and all its build/environment identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionMetadata {
    pub config: SessionConfig,
    pub start_ns: u64,
    pub stop_ns: u64,
    pub status: SessionStatusCode,
    pub counters: LayeredLossCounters,
}

impl SessionMetadata {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.config.to_bytes();
        buf.extend_from_slice(&self.start_ns.to_le_bytes());
        buf.extend_from_slice(&self.stop_ns.to_le_bytes());
        buf.extend_from_slice(&self.status.as_u32().to_le_bytes());

        let counters_bytes = self.counters.to_bytes();
        buf.extend_from_slice(counters_bytes.as_slice());
        buf
    }

    pub fn from_bytes(slice: &[u8]) -> Result<(Self, usize), CaptureError> {
        let mut offset = 0;
        let config = SessionConfig::from_bytes(slice, &mut offset)?;

        if slice.len() < offset + 20 {
            return Err(CaptureError::TruncatedMetadata);
        }
        let start_ns = u64::from_le_bytes(slice[offset..offset + 8].try_into().unwrap());
        let stop_ns = u64::from_le_bytes(slice[offset + 8..offset + 16].try_into().unwrap());
        let status = SessionStatusCode::from_u32(u32::from_le_bytes(
            slice[offset + 16..offset + 20].try_into().unwrap(),
        ));
        offset += 20;

        let (counters, counters_consumed) = LayeredLossCounters::from_bytes(&slice[offset..])?;
        offset += counters_consumed;

        Ok((
            Self {
                config,
                start_ns,
                stop_ns,
                status,
                counters,
            },
            offset,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionState {
    Created,
    Running { start_ns: u64 },
    Stopped { start_ns: u64, stop_ns: u64 },
}

/// Explicit lifecycle manager for a BPF sampling session.
#[derive(Clone, Debug)]
pub struct SamplingSession {
    config: SessionConfig,
    state: SessionState,
    counters: LayeredLossCounters,
}

impl SamplingSession {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            state: SessionState::Created,
            counters: LayeredLossCounters::new(),
        }
    }

    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    pub fn is_running(&self) -> bool {
        matches!(self.state, SessionState::Running { .. })
    }

    pub fn is_finished(&self) -> bool {
        matches!(self.state, SessionState::Stopped { .. })
    }

    pub fn start(&mut self, now_ns: u64) -> Result<(), CaptureError> {
        match self.state {
            SessionState::Created => {
                self.state = SessionState::Running { start_ns: now_ns };
                Ok(())
            }
            _ => Err(CaptureError::IoError("session already started or finished")),
        }
    }

    pub fn record_sample_delivered(&mut self) {
        self.counters.attempted += 1;
        self.counters.delivered += 1;
    }

    pub fn record_perf_lost(&mut self, cpu: u32, count: u64) {
        self.counters.attempted += count;
        self.counters.record_per_cpu_lost(cpu, count);
    }

    pub fn record_consumer_corruption(&mut self) {
        self.counters.consumer_corrupt_records += 1;
    }

    pub fn record_consumer_out_of_bounds(&mut self) {
        self.counters.consumer_out_of_bounds += 1;
    }

    pub fn record_helper_failure(&mut self) {
        self.counters.helper_failures += 1;
    }

    pub fn record_re_entry_drop(&mut self) {
        self.counters.re_entry_drops += 1;
    }

    pub fn record_budget_failure(&mut self) {
        self.counters.budget_failures += 1;
    }

    pub fn counters(&self) -> &LayeredLossCounters {
        &self.counters
    }

    pub fn counters_mut(&mut self) -> &mut LayeredLossCounters {
        &mut self.counters
    }

    pub fn stop(&mut self, now_ns: u64) -> Result<SessionMetadata, CaptureError> {
        let start_ns = match self.state {
            SessionState::Running { start_ns } => start_ns,
            _ => return Err(CaptureError::IoError("cannot stop session that is not running")),
        };

        self.state = SessionState::Stopped {
            start_ns,
            stop_ns: now_ns,
        };

        let status = if self.counters.has_error() {
            SessionStatusCode::IncompleteError
        } else if self.counters.has_loss() {
            SessionStatusCode::IncompleteLoss
        } else {
            SessionStatusCode::Complete
        };

        Ok(SessionMetadata {
            config: self.config.clone(),
            start_ns,
            stop_ns: now_ns,
            status,
            counters: self.counters.clone(),
        })
    }
}
