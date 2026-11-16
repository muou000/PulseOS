//! Current capture mapping evidence. The original producer journal is retained verbatim;
//! paths are labels, never object identities or implicit host lookup instructions.
use alloc::{string::String, vec::Vec};

use crate::{
    CaptureError,
    codec::{decode_string, encode_string},
};
const MAGIC: &[u8; 8] = b"PBMAP001";
const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 262144;
fn invalid() -> CaptureError {
    CaptureError::InvalidRecord("invalid mapping evidence")
}
pub fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_build_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.len() % 2 == 0
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    pub sha256: String,
    /// None means the actual ELF has no GNU build-id; never a truncated SHA.
    pub gnu_build_id: Option<String>,
    pub path: String,
    pub debug_sha256: Option<String>,
    pub debug_build_id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelArtifact {
    pub sha256: String,
    pub reference_symbol: String,
    pub reference_address: u64,
    pub text_start: u64,
    pub text_end: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingMetadata {
    pub journal: String,
    pub artifacts: Vec<Artifact>,
    pub kernel: Option<KernelArtifact>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskClass {
    Unknown,
    User,
    Kernel,
    Idle,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationTarget {
    Space,
    Task,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub start: u64,
    pub len: u64,
    pub pgoff: u64,
    pub permissions: u32,
    pub object: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MappingEvent {
    Mutation {
        target: MutationTarget,
        id: u64,
        token: u64,
        complete: bool,
    },
    Space {
        space: u64,
        revision: u64,
        begin_ns: u64,
        maps: Vec<Mapping>,
    },
    Task {
        task: u64,
        pid: u32,
        tid: u32,
        space: u64,
        exec: u64,
        kind: String,
        begin_ns: u64,
        parent: u64,
        class: TaskClass,
        comm: String,
    },
    Object {
        object: u64,
        sha256: Option<String>,
        path: String,
    },
    Tlb {
        space: u64,
        token: u64,
        complete: bool,
    },
    Kernel {
        start: u64,
        len: u64,
        reference: u64,
        symbol: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingEntry {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub event: MappingEvent,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingJournal {
    pub started_ns: u64,
    pub snapshot_ns: u64,
    pub dropped: u64,
    pub entries: Vec<MappingEntry>,
}
/// Validated temporal bounds of an original journal, without materializing rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingCoverage {
    pub started_ns: u64,
    pub snapshot_ns: u64,
    pub dropped: u64,
    pub records: u64,
}

// Current rows contain at most fourteen fields. Keep parsing bounded and on
// the stack; guest allocators can turn each heap allocation into journal work.
struct Fields<'a> {
    pairs: [(&'a str, &'a str); 32],
    len: usize,
}
impl<'a> Fields<'a> {
    fn get(&self, key: &str) -> Option<&&'a str> {
        self.pairs[..self.len]
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value)
    }
    fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }
}
fn fields(line: &str) -> Result<(&str, Fields<'_>), CaptureError> {
    let mut words = line.split_ascii_whitespace();
    let kind = words.next().ok_or_else(invalid)?;
    let mut result = Fields {
        pairs: [("", ""); 32],
        len: 0,
    };
    for word in words {
        let (key, value) = word.split_once('=').ok_or_else(invalid)?;
        if key.is_empty()
            || value.is_empty()
            || result.contains_key(key)
            || result.len == result.pairs.len()
        {
            return Err(invalid());
        }
        result.pairs[result.len] = (key, value);
        result.len += 1;
    }
    Ok((kind, result))
}
fn num(f: &Fields<'_>, key: &str) -> Result<u64, CaptureError> {
    let s = f.get(key).ok_or_else(invalid)?;
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    s.parse().map_err(|_| invalid())
}
fn narrow(f: &Fields<'_>, key: &str) -> Result<u32, CaptureError> {
    u32::try_from(num(f, key)?).map_err(|_| invalid())
}
fn txt<const RETAIN: bool>(f: &Fields<'_>, key: &str) -> Result<String, CaptureError> {
    let value = *f.get(key).ok_or_else(invalid)?;
    if value == "-" {
        return Ok(String::new());
    }
    if value.len() > 8192 || value.len() % 2 != 0 {
        return Err(invalid());
    }
    let mut bytes = [0u8; 4096];
    for (byte, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let hex = core::str::from_utf8(pair).map_err(|_| invalid())?;
        *byte = u8::from_str_radix(hex, 16).map_err(|_| invalid())?;
    }
    let decoded = core::str::from_utf8(&bytes[..value.len() / 2]).map_err(|_| invalid())?;
    Ok(if RETAIN {
        decoded.into()
    } else {
        String::new()
    })
}
impl MappingJournal {
    /// Materialize validated rows for host temporal analysis.
    pub fn parse(text: &str) -> Result<Self, CaptureError> {
        Self::scan::<true>(text).map(|(journal, _)| journal)
    }

    /// Apply exactly the same full semantic validation as `parse`, without
    /// allocating journal entries, maps, strings or field tables.
    pub fn validate(text: &str) -> Result<MappingCoverage, CaptureError> {
        let (journal, records) = Self::scan::<false>(text)?;
        Ok(MappingCoverage {
            started_ns: journal.started_ns,
            snapshot_ns: journal.snapshot_ns,
            dropped: journal.dropped,
            records,
        })
    }

    fn scan<const RETAIN: bool>(text: &str) -> Result<(Self, u64), CaptureError> {
        if text.len() > MAX_BYTES {
            return Err(invalid());
        }
        let mut lines = text.lines();
        let (tag, head) = fields(lines.next().ok_or_else(invalid)?)?;
        if tag != "PULSE_BPF_MAPPINGS"
            || num(&head, "version")? != 2
            || num(&head, "available")? != 1
        {
            return Err(invalid());
        }
        let mut out = Self {
            started_ns: num(&head, "started_ns")?,
            snapshot_ns: num(&head, "snapshot_ns")?,
            dropped: num(&head, "dropped")?,
            entries: Vec::new(),
        };
        let count = num(&head, "records")?;
        if count > MAX_ENTRIES as u64 || out.snapshot_ns < out.started_ns {
            return Err(invalid());
        }
        let mut previous = 0;
        let mut previous_time = out.started_ns;
        let mut ended = false;
        let mut records = 0;
        while let Some(line) = lines.next() {
            let (tag, f) = fields(line)?;
            if tag == "END" {
                if num(&f, "records")? != count
                    || num(&f, "dropped")? != out.dropped
                    || num(&f, "snapshot_ns")? != out.snapshot_ns
                    || lines.next().is_some()
                {
                    return Err(invalid());
                }
                ended = true;
                break;
            }
            let sequence = num(&f, "seq")?;
            let timestamp_ns = num(&f, "ts")?;
            if sequence <= previous
                || timestamp_ns < previous_time
                || timestamp_ns > out.snapshot_ns
            {
                return Err(invalid());
            }
            if sequence != previous + 1 && out.dropped == 0 {
                return Err(invalid());
            }
            previous = sequence;
            previous_time = timestamp_ns;
            let event = match tag {
                "SPACE" => {
                    let space = num(&f, "space")?;
                    let begin_ns = num(&f, "begin_ns")?;
                    let n = num(&f, "count")?;
                    if space == 0 || begin_ns > timestamp_ns || n > MAX_ENTRIES as u64 {
                        return Err(invalid());
                    }
                    let mut maps = Vec::new();
                    let mut end = 0;
                    for _ in 0..n {
                        let (tag, m) = fields(lines.next().ok_or_else(invalid)?)?;
                        if tag != "MAP" {
                            return Err(invalid());
                        }
                        let map = Mapping {
                            start: num(&m, "start")?,
                            len: num(&m, "len")?,
                            pgoff: num(&m, "pgoff")?,
                            permissions: narrow(&m, "perms")?,
                            object: num(&m, "object")?,
                        };
                        if map.len == 0 || map.start < end || map.permissions & !15 != 0 {
                            return Err(invalid());
                        }
                        end = map.start.checked_add(map.len).ok_or_else(invalid)?;
                        map.pgoff.checked_add(map.len).ok_or_else(invalid)?;
                        if RETAIN {
                            maps.push(map);
                        }
                    }
                    if lines.next() != Some("ENDSPACE") {
                        return Err(invalid());
                    }
                    MappingEvent::Space {
                        space,
                        revision: num(&f, "revision")?,
                        begin_ns,
                        maps,
                    }
                }
                "TASK" => {
                    let kind = *f.get("kind").ok_or_else(invalid)?;
                    if !matches!(kind, "bind" | "fork" | "exec" | "rename" | "exit")
                        || num(&f, "task")? == 0
                    {
                        return Err(invalid());
                    }
                    if f.contains_key("begin_ns") && num(&f, "begin_ns")? > timestamp_ns {
                        return Err(invalid());
                    }
                    let class = match *f.get("class").ok_or_else(invalid)? {
                        "user" => TaskClass::User,
                        "kernel" => TaskClass::Kernel,
                        "idle" => TaskClass::Idle,
                        "unknown" => TaskClass::Unknown,
                        _ => return Err(invalid()),
                    };
                    MappingEvent::Task {
                        task: num(&f, "task")?,
                        pid: narrow(&f, "pid")?,
                        tid: narrow(&f, "tid")?,
                        space: num(&f, "space")?,
                        exec: num(&f, "exec")?,
                        kind: if RETAIN { kind.into() } else { String::new() },
                        begin_ns: if f.contains_key("begin_ns") {
                            num(&f, "begin_ns")?
                        } else {
                            timestamp_ns
                        },
                        parent: num(&f, "parent")?,
                        class,
                        comm: txt::<RETAIN>(&f, "comm_hex")?,
                    }
                }
                "OBJECT" => {
                    let sha = *f.get("sha256").ok_or_else(invalid)?;
                    if sha != "unknown" && !valid_sha(sha) || num(&f, "object")? == 0 {
                        return Err(invalid());
                    }
                    MappingEvent::Object {
                        object: num(&f, "object")?,
                        sha256: if sha == "unknown" || !RETAIN {
                            None
                        } else {
                            Some(sha.into())
                        },
                        path: txt::<RETAIN>(&f, "path_hex")?,
                    }
                }
                "MUTATION" => {
                    let target = match *f.get("target").ok_or_else(invalid)? {
                        "space" => MutationTarget::Space,
                        "task" => MutationTarget::Task,
                        _ => return Err(invalid()),
                    };
                    let complete = num(&f, "complete")?;
                    let id = num(&f, "id")?;
                    let token = num(&f, "token")?;
                    if complete > 1 || id == 0 || token == 0 {
                        return Err(invalid());
                    }
                    MappingEvent::Mutation {
                        target,
                        id,
                        token,
                        complete: complete == 1,
                    }
                }
                "TLB" => {
                    let complete = num(&f, "complete")?;
                    if complete > 1 || num(&f, "space")? == 0 || num(&f, "token")? == 0 {
                        return Err(invalid());
                    }
                    MappingEvent::Tlb {
                        space: num(&f, "space")?,
                        token: num(&f, "token")?,
                        complete: complete == 1,
                    }
                }
                "KERNEL" => {
                    let start = num(&f, "start")?;
                    let len = num(&f, "len")?;
                    let reference = num(&f, "reference")?;
                    let end = start.checked_add(len).ok_or_else(invalid)?;
                    if len == 0 || !(start..end).contains(&reference) {
                        return Err(invalid());
                    }
                    MappingEvent::Kernel {
                        start,
                        len,
                        reference,
                        symbol: txt::<RETAIN>(&f, "symbol_hex")?,
                    }
                }
                _ => return Err(invalid()),
            };
            if RETAIN {
                out.entries.push(MappingEntry {
                    sequence,
                    timestamp_ns,
                    event,
                });
            }
            records += 1;
            if records > MAX_ENTRIES as u64 {
                return Err(invalid());
            }
        }
        if !ended || records != count {
            return Err(invalid());
        }
        Ok((out, records))
    }
}
impl MappingMetadata {
    pub fn validate(&self) -> Result<(), CaptureError> {
        MappingJournal::validate(&self.journal)?;
        if self.artifacts.len() > 4096 {
            return Err(invalid());
        }
        for (index, a) in self.artifacts.iter().enumerate() {
            if !valid_sha(&a.sha256)
                || a.path
                    .strip_prefix("artifacts/")
                    .and_then(|path| path.strip_suffix(".elf"))
                    != Some(a.sha256.as_str())
                || a.gnu_build_id
                    .as_deref()
                    .is_some_and(|id| !valid_build_id(id))
                || a.debug_sha256.as_deref().is_some_and(|sha| !valid_sha(sha))
                || a.debug_build_id
                    .as_deref()
                    .is_some_and(|id| !valid_build_id(id))
                || a.debug_build_id.is_some() && a.debug_sha256.is_none()
                || self.artifacts[..index]
                    .iter()
                    .any(|previous| previous.sha256 == a.sha256)
            {
                return Err(invalid());
            }
        }
        if let Some(k) = &self.kernel {
            if !valid_sha(&k.sha256)
                || !self
                    .artifacts
                    .iter()
                    .any(|artifact| artifact.sha256 == k.sha256)
                || k.reference_symbol.is_empty()
                || k.reference_symbol.len() > 4096
                || k.text_end <= k.text_start
                || !(k.text_start..k.text_end).contains(&k.reference_address)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, CaptureError> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        encode_string(&mut out, &self.journal);
        out.extend_from_slice(&(self.artifacts.len() as u32).to_le_bytes());
        for a in &self.artifacts {
            for s in [
                a.sha256.as_str(),
                a.gnu_build_id.as_deref().unwrap_or(""),
                a.path.as_str(),
                a.debug_sha256.as_deref().unwrap_or(""),
                a.debug_build_id.as_deref().unwrap_or(""),
            ] {
                encode_string(&mut out, s);
            }
        }
        out.push(u8::from(self.kernel.is_some()));
        if let Some(k) = &self.kernel {
            encode_string(&mut out, &k.sha256);
            encode_string(&mut out, &k.reference_symbol);
            for n in [k.reference_address, k.text_start, k.text_end] {
                out.extend_from_slice(&n.to_le_bytes());
            }
        }
        if out.len() > MAX_BYTES {
            return Err(invalid());
        }
        Ok(out)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), CaptureError> {
        if bytes.len() > MAX_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(invalid());
        }
        let mut pos = 8;
        let journal = decode_string(bytes, &mut pos)?;
        let count = u32::from_le_bytes(
            bytes
                .get(pos..pos + 4)
                .ok_or_else(invalid)?
                .try_into()
                .unwrap(),
        );
        pos += 4;
        if count > 4096 {
            return Err(invalid());
        }
        let mut artifacts = Vec::new();
        fn optional(s: String) -> Option<String> {
            if s.is_empty() { None } else { Some(s) }
        }
        for _ in 0..count {
            artifacts.push(Artifact {
                sha256: decode_string(bytes, &mut pos)?,
                gnu_build_id: optional(decode_string(bytes, &mut pos)?),
                path: decode_string(bytes, &mut pos)?,
                debug_sha256: optional(decode_string(bytes, &mut pos)?),
                debug_build_id: optional(decode_string(bytes, &mut pos)?),
            });
        }
        let flag = *bytes.get(pos).ok_or_else(invalid)?;
        pos += 1;
        let kernel = match flag {
            0 => None,
            1 => {
                let sha256 = decode_string(bytes, &mut pos)?;
                let reference_symbol = decode_string(bytes, &mut pos)?;
                let b = bytes.get(pos..pos + 24).ok_or_else(invalid)?;
                pos += 24;
                Some(KernelArtifact {
                    sha256,
                    reference_symbol,
                    reference_address: u64::from_le_bytes(b[..8].try_into().unwrap()),
                    text_start: u64::from_le_bytes(b[8..16].try_into().unwrap()),
                    text_end: u64::from_le_bytes(b[16..].try_into().unwrap()),
                })
            }
            _ => return Err(invalid()),
        };
        let result = Self {
            journal,
            artifacts,
            kernel,
        };
        result.validate()?;
        Ok((result, pos))
    }
}
