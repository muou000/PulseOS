//! Pre-enable and post-disable mapping and artifact observation.
//!
//! Paths never establish identity. The immutable producer journal is copied
//! verbatim, and a failed final snapshot retains only the actual initial cut.

use alloc::{format, string::String, vec::Vec};

use bpf_capture::{
    CounterKind, DiagnosticCounter, DiagnosticIdentity, RuntimeDiagnostics,
    mapping::{
        Artifact, KernelArtifact, MappingCoverage, MappingJournal, MappingMetadata, valid_sha,
    },
};
use sha2::{Digest, Sha256};

pub const JOURNAL_READ_LIMIT: usize = 9 * 1024 * 1024;
pub const KERNEL_ELF_READ_LIMIT: usize = 128 * 1024 * 1024;

pub struct Observation {
    initial: String,
    initial_coverage: MappingCoverage,
    initial_hash: String,
    kernel_id: Option<String>,
    kernel: Option<KernelArtifact>,
    kernel_artifact: Option<Artifact>,
}

pub struct ObservationResult {
    pub mappings: MappingMetadata,
    pub diagnostics: RuntimeDiagnostics,
    pub errors: Vec<String>,
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let mut values = line
        .split_ascii_whitespace()
        .skip(1)
        .filter_map(|word| word.split_once('='))
        .filter(|(name, _)| *name == key);
    let value = values.next()?.1;
    if values.next().is_some() {
        None
    } else {
        Some(value)
    }
}
fn number(line: &str, key: &str) -> Result<u64, String> {
    let value = field(line, key).ok_or("missing mapping field")?;
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid mapping number".into());
    }
    value.parse().map_err(|_| "mapping number overflow".into())
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(DIGITS[(byte >> 4) as usize] as char);
        text.push(DIGITS[(byte & 15) as usize] as char);
    }
    text
}
fn build_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.len() % 2 == 0
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn add_artifacts(journal: &str, artifacts: &mut Vec<Artifact>) -> Result<u64, String> {
    let mut unknown = 0;
    for line in journal
        .lines()
        .filter(|line| line.split_ascii_whitespace().next() == Some("OBJECT"))
    {
        let sha = field(line, "sha256").ok_or("missing object SHA identity")?;
        let id = field(line, "build_id").unwrap_or("unknown");
        if sha == "unknown" || id == "unknown" {
            unknown += 1;
            continue;
        }
        if !valid_sha(sha) || id != "none" && !build_id(id) {
            return Err("invalid object artifact identity".into());
        }
        let id = if id == "none" { None } else { Some(id) };
        if let Some(previous) = artifacts.iter().find(|artifact| artifact.sha256 == sha) {
            if previous.gnu_build_id.as_deref() != id {
                return Err("conflicting object GNU build-id".into());
            }
            continue;
        }
        if artifacts.len() == 4096 {
            return Err("artifact identity budget exceeded".into());
        }
        artifacts.push(Artifact {
            path: format!("artifacts/{sha}.elf"),
            sha256: sha.into(),
            gnu_build_id: id.map(String::from),
            debug_sha256: None,
            debug_build_id: None,
        });
    }
    Ok(unknown)
}

fn journal_body(text: &str) -> Result<&str, String> {
    // Use the actual first/last line extents, preserving original record bytes
    // and line endings. The shared parser allows tabs and CRLF as whitespace,
    // and does not require a newline after the footer.
    let mut lines = text.split_inclusive('\n');
    let header = lines.next().ok_or("missing mapping header line")?;
    let footer = lines.next_back().ok_or("missing mapping footer line")?;
    if header.split_ascii_whitespace().next() != Some("PULSE_BPF_MAPPINGS")
        || footer.split_ascii_whitespace().next() != Some("END")
    {
        return Err("invalid mapping boundary lines".into());
    }
    let end = text
        .len()
        .checked_sub(footer.len())
        .ok_or("invalid mapping footer extent")?;
    text.get(header.len()..end)
        .ok_or("invalid mapping body extent".into())
}

impl Observation {
    /// Freeze mapping facts before enabling any source. An explicitly supplied
    /// kernel candidate is accepted only after matching the running GNU note.
    pub fn begin(initial: String, kernel_elf: Option<&[u8]>) -> Result<Self, String> {
        if initial.len() > JOURNAL_READ_LIMIT {
            return Err("mapping journal exceeds read limit".into());
        }
        let initial_coverage = MappingJournal::validate(&initial)
            .map_err(|error| format!("invalid initial mapping journal: {error:?}"))?;
        let mut result = Self {
            initial_hash: hex(&Sha256::digest(initial.as_bytes())),
            initial,
            initial_coverage,
            kernel_id: None,
            kernel: None,
            kernel_artifact: None,
        };
        let mut kernels = result
            .initial
            .lines()
            .filter(|line| line.split_ascii_whitespace().next() == Some("KERNEL"));
        let kernel = kernels.next();
        if kernels.next().is_some() {
            return Err("duplicate kernel mapping identity".into());
        }
        result.kernel_id = kernel
            .and_then(|line| field(line, "build_id"))
            .filter(|id| build_id(id))
            .map(String::from);
        if let Some(bytes) = kernel_elf {
            if bytes.len() > KERNEL_ELF_READ_LIMIT {
                return Err("kernel ELF exceeds read limit".into());
            }
            let actual = pulse_bpf_schema::elf::elf_build_id(bytes.len() as u64, |offset, out| {
                let Ok(offset) = usize::try_from(offset) else {
                    return false;
                };
                let Some(end) = offset.checked_add(out.len()) else {
                    return false;
                };
                let Some(input) = bytes.get(offset..end) else {
                    return false;
                };
                out.copy_from_slice(input);
                true
            })
            .map_err(|_| "kernel ELF identity unreadable")?
            .ok_or("kernel ELF has no GNU build-id")?;
            if result.kernel_id.as_deref() != Some(hex(actual.as_bytes()).as_str()) {
                return Err("kernel ELF differs from running build-id".into());
            }
            let row = kernel.ok_or("kernel mapping unavailable")?;
            let sha256 = hex(&Sha256::digest(bytes));
            let text_start = number(row, "start")?;
            let text_end = text_start
                .checked_add(number(row, "len")?)
                .ok_or("kernel range overflow")?;
            let reference_address = number(row, "reference")?;
            if !(text_start..text_end).contains(&reference_address)
                || field(row, "symbol_hex") != Some("5f7374657874")
            {
                return Err("invalid kernel reference mapping".into());
            }
            result.kernel_artifact = Some(Artifact {
                path: format!("artifacts/{sha256}.elf"),
                sha256: sha256.clone(),
                gnu_build_id: result.kernel_id.clone(),
                debug_sha256: None,
                debug_build_id: None,
            });
            result.kernel = Some(KernelArtifact {
                sha256,
                reference_symbol: "_stext".into(),
                reference_address,
                text_start,
                text_end,
            });
        }
        Ok(result)
    }

    pub fn initial_snapshot_ns(&self) -> u64 {
        self.initial_coverage.snapshot_ns
    }
    pub fn kernel_sha256(&self) -> Option<&str> {
        self.kernel.as_ref().map(|kernel| kernel.sha256.as_str())
    }
    pub fn kernel_build_id(&self) -> Option<&str> {
        self.kernel_id.as_deref()
    }

    pub fn finish(self, final_journal: Result<String, String>) -> ObservationResult {
        let mut errors = Vec::new();
        let final_journal = final_journal.and_then(|text| {
            if text.len() > JOURNAL_READ_LIMIT {
                return Err("mapping journal exceeds read limit".into());
            }
            let last = MappingJournal::validate(&text)
                .map_err(|error| format!("invalid final mapping journal: {error:?}"))?;
            if last.started_ns != self.initial_coverage.started_ns
                || last.snapshot_ns < self.initial_coverage.snapshot_ns
                || last.dropped < self.initial_coverage.dropped
                || !journal_body(&text)?.starts_with(journal_body(&self.initial)?)
            {
                return Err("mapping final journal changed initial facts".into());
            }
            Ok((text, last))
        });
        let (journal, final_cut, dropped) = match final_journal {
            Ok((text, coverage)) => (text, Some(coverage.snapshot_ns), coverage.dropped),
            Err(error) => {
                errors.push(error);
                (self.initial, None, self.initial_coverage.dropped)
            }
        };
        let mut artifacts = Vec::new();
        if let Some(artifact) = self.kernel_artifact {
            artifacts.push(artifact);
        }
        let unknown_artifacts = match add_artifacts(&journal, &mut artifacts) {
            Ok(unknown) => Some(unknown),
            Err(error) => {
                errors.push(error);
                None
            }
        };
        let mut diagnostics = RuntimeDiagnostics::default();
        for (name, value) in [
            ("mapping_initial_sha256", Some(self.initial_hash)),
            ("kernel_build_identity", self.kernel_id),
        ] {
            diagnostics.identities.push(DiagnosticIdentity {
                name: name.into(),
                value,
            });
        }
        for (name, value, kind) in [
            (
                "mapping_initial_snapshot_ns",
                Some(self.initial_coverage.snapshot_ns),
                CounterKind::Activity,
            ),
            (
                "mapping_final_snapshot_ns",
                final_cut,
                CounterKind::Activity,
            ),
            ("mapping_journal_dropped", Some(dropped), CounterKind::Loss),
            (
                "mapping_artifact_identity_unknown",
                unknown_artifacts,
                CounterKind::Activity,
            ),
            (
                "mapping_observation_errors",
                Some(errors.len() as u64),
                CounterKind::Error,
            ),
        ] {
            diagnostics.counters.push(DiagnosticCounter {
                name: name.into(),
                scope: "session".into(),
                value,
                kind,
            });
        }
        ObservationResult {
            mappings: MappingMetadata {
                journal,
                artifacts,
                kernel: self.kernel,
            },
            diagnostics,
            errors,
        }
    }
}
