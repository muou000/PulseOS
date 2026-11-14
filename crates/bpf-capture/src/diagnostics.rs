//! Versioned, scoped runtime evidence. Unknown values stay unknown and counters
//! from overlapping producer/VM/transport scopes are never added together.
//!
//! Capture format v2 appends this block after the existing registry and session
//! metadata: `PBDIAG01`, u32 counter count and entries, u32 identity count and
//! entries, u32 phase count and entries, then optional evidence text. All integer
//! fields are little-endian. Strings use a u32 byte length and UTF-8; options use
//! a 0/1 byte followed by a value only for 1. Counter entries contain name, scope,
//! kind byte, optional u64. Identities contain name and optional string. Phases
//! contain name, start/stop/iterations u64 values, optional mapped bytes u64.
//! Limits are checked before allocating decoded entries or serializing a block.

use alloc::{collections::BTreeSet, string::String, vec::Vec};

use crate::{
    codec::{decode_string, encode_string},
    framing::{CaptureError, SessionStatusCode},
};

const MAGIC: &[u8; 8] = b"PBDIAG01";
const MAX_BYTES: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_TEXT: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CounterKind {
    Activity = 0,
    Loss     = 1,
    Error    = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticCounter {
    pub name: String,
    /// For example `system`, `source:42`, `sink:7`, or `consumer`.
    pub scope: String,
    pub value: Option<u64>,
    pub kind: CounterKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticIdentity {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhaseMeasurement {
    pub name: String,
    pub start_ns: u64,
    pub stop_ns: u64,
    pub iterations: u64,
    /// Sampler-owned virtual mappings, not RSS or total kernel memory.
    pub mapped_bytes: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeDiagnostics {
    pub counters: Vec<DiagnosticCounter>,
    pub identities: Vec<DiagnosticIdentity>,
    pub phases: Vec<PhaseMeasurement>,
    /// Supplementary source material. Quality decisions use typed fields above.
    pub evidence_json: Option<String>,
}

fn invalid() -> CaptureError {
    CaptureError::InvalidRecord("invalid runtime diagnostics")
}
fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|v| v.is_ascii_graphic())
}
fn put_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    out.push(u8::from(value.is_some()));
    if let Some(value) = value {
        out.extend_from_slice(&value.to_le_bytes());
    }
}
fn put_optional_string(out: &mut Vec<u8>, value: &Option<String>) {
    out.push(u8::from(value.is_some()));
    if let Some(value) = value {
        encode_string(out, value);
    }
}

impl RuntimeDiagnostics {
    pub fn validate(&self) -> Result<(), CaptureError> {
        if self.counters.len() > MAX_ENTRIES
            || self.identities.len() > MAX_ENTRIES
            || self.phases.len() > MAX_ENTRIES
        {
            return Err(invalid());
        }
        let mut bytes = 8usize + 3 * 4 + 1;
        let mut account = |size: usize| -> Result<(), CaptureError> {
            bytes = bytes.checked_add(size).ok_or_else(invalid)?;
            if bytes > MAX_BYTES {
                return Err(invalid());
            }
            Ok(())
        };
        let mut keys = BTreeSet::new();
        for counter in &self.counters {
            account(
                10 + counter.name.len()
                    + counter.scope.len()
                    + if counter.value.is_some() { 8 } else { 0 },
            )?;
            if !valid_name(&counter.name)
                || !valid_name(&counter.scope)
                || !keys.insert((&counter.scope, &counter.name))
            {
                return Err(invalid());
            }
        }
        let mut names = BTreeSet::new();
        for identity in &self.identities {
            account(5 + identity.name.len() + identity.value.as_ref().map_or(0, |s| 4 + s.len()))?;
            if !valid_name(&identity.name)
                || !names.insert(&identity.name)
                || identity
                    .value
                    .as_ref()
                    .is_some_and(|value| value.is_empty() || value.len() > MAX_TEXT)
            {
                return Err(invalid());
            }
        }
        let mut names = BTreeSet::new();
        for phase in &self.phases {
            account(29 + phase.name.len() + if phase.mapped_bytes.is_some() { 8 } else { 0 })?;
            if !valid_name(&phase.name)
                || !names.insert(&phase.name)
                || phase.start_ns == 0
                || phase.stop_ns <= phase.start_ns
                || phase.iterations == 0
            {
                return Err(invalid());
            }
        }
        account(self.evidence_json.as_ref().map_or(0, |s| 4 + s.len()))?;
        if self
            .evidence_json
            .as_ref()
            .is_some_and(|s| s.len() > MAX_TEXT)
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// This is only a report about recorded evidence. It does not prove that
    /// every event source needed for complete CPU/off-CPU attribution exists.
    pub fn status(&self) -> SessionStatusCode {
        let unknown = self.counters.is_empty()
            || self.identities.is_empty()
            || self.phases.is_empty()
            || self.counters.iter().any(|c| c.value.is_none())
            || self.identities.iter().any(|i| i.value.is_none())
            || self.phases.iter().any(|p| p.mapped_bytes.is_none());
        if unknown
            || self
                .counters
                .iter()
                .any(|c| c.kind == CounterKind::Error && c.value.is_some_and(|v| v != 0))
        {
            SessionStatusCode::IncompleteError
        } else if self
            .counters
            .iter()
            .any(|c| c.kind == CounterKind::Loss && c.value.is_some_and(|v| v != 0))
        {
            SessionStatusCode::IncompleteLoss
        } else {
            SessionStatusCode::Complete
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CaptureError> {
        self.validate()?;
        let mut out = Vec::from(MAGIC.as_slice());
        out.extend_from_slice(&(self.counters.len() as u32).to_le_bytes());
        for counter in &self.counters {
            encode_string(&mut out, &counter.name);
            encode_string(&mut out, &counter.scope);
            out.push(counter.kind as u8);
            put_optional_u64(&mut out, counter.value);
        }
        out.extend_from_slice(&(self.identities.len() as u32).to_le_bytes());
        for identity in &self.identities {
            encode_string(&mut out, &identity.name);
            put_optional_string(&mut out, &identity.value);
        }
        out.extend_from_slice(&(self.phases.len() as u32).to_le_bytes());
        for phase in &self.phases {
            encode_string(&mut out, &phase.name);
            out.extend_from_slice(&phase.start_ns.to_le_bytes());
            out.extend_from_slice(&phase.stop_ns.to_le_bytes());
            out.extend_from_slice(&phase.iterations.to_le_bytes());
            put_optional_u64(&mut out, phase.mapped_bytes);
        }
        put_optional_string(&mut out, &self.evidence_json);
        if out.len() > MAX_BYTES {
            return Err(invalid());
        }
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), CaptureError> {
        if bytes.len() > MAX_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(invalid());
        }
        let mut input = Decoder { bytes, pos: 8 };
        let mut counters = Vec::new();
        for _ in 0..input.count(10)? {
            let name = input.string()?;
            let scope = input.string()?;
            let kind = match input.byte()? {
                0 => CounterKind::Activity,
                1 => CounterKind::Loss,
                2 => CounterKind::Error,
                _ => return Err(invalid()),
            };
            counters.push(DiagnosticCounter {
                name,
                scope,
                kind,
                value: input.optional_u64()?,
            });
        }
        let mut identities = Vec::new();
        for _ in 0..input.count(5)? {
            identities.push(DiagnosticIdentity {
                name: input.string()?,
                value: input.optional_string()?,
            });
        }
        let mut phases = Vec::new();
        for _ in 0..input.count(29)? {
            phases.push(PhaseMeasurement {
                name: input.string()?,
                start_ns: input.u64()?,
                stop_ns: input.u64()?,
                iterations: input.u64()?,
                mapped_bytes: input.optional_u64()?,
            });
        }
        let result = Self {
            counters,
            identities,
            phases,
            evidence_json: input.optional_string()?,
        };
        result.validate()?;
        Ok((result, input.pos))
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl Decoder<'_> {
    fn take(&mut self, len: usize) -> Result<&[u8], CaptureError> {
        let end = self.pos.checked_add(len).ok_or_else(invalid)?;
        let result = self
            .bytes
            .get(self.pos..end)
            .ok_or(CaptureError::TruncatedMetadata)?;
        self.pos = end;
        Ok(result)
    }
    fn byte(&mut self) -> Result<u8, CaptureError> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64, CaptureError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn count(&mut self, minimum: usize) -> Result<usize, CaptureError> {
        let count = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        if count > MAX_ENTRIES || count > (self.bytes.len() - self.pos) / minimum {
            return Err(invalid());
        }
        Ok(count)
    }
    fn string(&mut self) -> Result<String, CaptureError> {
        // Check length before decode_string allocates the value.
        let prefix = self
            .bytes
            .get(self.pos..self.pos.checked_add(4).ok_or_else(invalid)?)
            .ok_or(CaptureError::TruncatedMetadata)?;
        if u32::from_le_bytes(prefix.try_into().unwrap()) as usize > MAX_TEXT {
            return Err(invalid());
        }
        decode_string(self.bytes, &mut self.pos)
    }
    fn optional_u64(&mut self) -> Result<Option<u64>, CaptureError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(invalid()),
        }
    }
    fn optional_string(&mut self) -> Result<Option<String>, CaptureError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.string()?)),
            _ => Err(invalid()),
        }
    }
}
