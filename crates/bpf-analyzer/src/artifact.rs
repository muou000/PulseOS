//! Explicit content-addressed ELF verification; no host basename fallback.
use std::{fs, io::Read, path::Path};

use bpf_capture::{
    CaptureArch,
    mapping::{Artifact, KernelArtifact},
};
use sha2::{Digest, Sha256};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadSegment {
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
}
#[derive(Clone, Debug)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub function: bool,
}
#[derive(Clone, Debug)]
pub struct VerifiedElf {
    pub sha256: String,
    pub gnu_build_id: Option<String>,
    pub machine: u16,
    pub elf_type: u16,
    pub segments: Vec<LoadSegment>,
    pub symbols: Vec<Symbol>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElfAddress {
    pub sha256: String,
    pub virtual_address: u64,
    pub symbol: Option<String>,
    pub symbol_offset: Option<u64>,
}
pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn slice(bytes: &[u8], offset: u64, len: u64) -> Result<&[u8], String> {
    let end = offset.checked_add(len).ok_or("ELF range overflow")?;
    let start = usize::try_from(offset).map_err(|_| "ELF offset out of range")?;
    let end = usize::try_from(end).map_err(|_| "ELF end out of range")?;
    bytes.get(start..end).ok_or("truncated ELF range".into())
}
fn u16at(b: &[u8], n: usize) -> u16 {
    u16::from_le_bytes(b[n..n + 2].try_into().unwrap())
}
fn u32at(b: &[u8], n: usize) -> u32 {
    u32::from_le_bytes(b[n..n + 4].try_into().unwrap())
}
fn u64at(b: &[u8], n: usize) -> u64 {
    u64::from_le_bytes(b[n..n + 8].try_into().unwrap())
}
/// Inspect the actual GNU note using the same bounded decoder as the guest.
/// An unreadable, malformed or over-budget identity is an error, never absence.
pub fn elf_build_id(bytes: &[u8], arch: CaptureArch) -> Result<Option<String>, String> {
    let h = slice(bytes, 0, 64)?;
    let expected = match arch {
        CaptureArch::Riscv64 => 243,
        CaptureArch::LoongArch64 => 258,
        CaptureArch::Unknown => return Err("unknown ELF target architecture".into()),
    };
    if u16at(h, 18) != expected || !matches!(u16at(h, 16), 2 | 3) {
        return Err("ELF architecture/type mismatch".into());
    }
    pulse_bpf_schema::elf::elf_build_id(bytes.len() as u64, |offset, out| {
        let Ok(input) = slice(bytes, offset, out.len() as u64) else {
            return false;
        };
        out.copy_from_slice(input);
        true
    })
    .map(|id| {
        id.map(|id| {
            id.as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        })
    })
    .map_err(|_| "ELF identity unreadable: malformed or over-budget table/note".into())
}
impl VerifiedElf {
    pub fn from_bytes(
        bytes: &[u8],
        artifact: &Artifact,
        arch: CaptureArch,
    ) -> Result<Self, String> {
        if sha256(bytes) != artifact.sha256 {
            return Err("ELF SHA256 mismatch".into());
        }
        let gnu_build_id = elf_build_id(bytes, arch)?;
        if gnu_build_id != artifact.gnu_build_id {
            return Err("ELF GNU build-id/absence mismatch".into());
        }
        let h = slice(bytes, 0, 64)?;
        let machine = u16at(h, 18);
        let elf_type = u16at(h, 16);
        let phoff = u64at(h, 32);
        let shoff = u64at(h, 40);
        let phsize = u16at(h, 54) as u64;
        let phnum = u16at(h, 56) as u64;
        let shsize = u16at(h, 58) as u64;
        let shnum = u16at(h, 60) as u64;
        if phnum == 0 {
            return Err("unsupported ELF table shape".into());
        }
        let mut segments = Vec::new();
        for i in 0..phnum {
            let p = slice(
                bytes,
                phoff.checked_add(i * phsize).ok_or("ELF table overflow")?,
                phsize,
            )?;
            let kind = u32at(p, 0);
            let offset = u64at(p, 8);
            let vaddr = u64at(p, 16);
            let filesz = u64at(p, 32);
            let memsz = u64at(p, 40);
            if kind == 1 {
                let align = u64at(p, 48);
                if align > 1 && (!align.is_power_of_two() || vaddr % align != offset % align) {
                    return Err("invalid ELF load alignment".into());
                }
                if memsz < filesz {
                    return Err("invalid ELF load sizes".into());
                }
                slice(bytes, offset, filesz)?;
                vaddr
                    .checked_add(memsz)
                    .ok_or("ELF virtual range overflow")?;
                segments.push(LoadSegment {
                    offset,
                    vaddr,
                    filesz,
                    memsz,
                    flags: u32at(p, 4),
                });
            }
        }
        let mut sections = Vec::new();
        for i in 0..shnum {
            let s = slice(
                bytes,
                shoff
                    .checked_add(i * shsize)
                    .ok_or("ELF section overflow")?,
                shsize,
            )?;
            sections.push(s);
        }
        let mut symbols = Vec::new();
        for s in &sections {
            if !matches!(u32at(s, 4), 2 | 11) {
                continue;
            }
            let entsize = u64at(s, 56);
            let size = u64at(s, 32);
            if entsize != 24 || size % 24 != 0 || size / 24 > 4_000_000 {
                return Err("invalid ELF symbol table".into());
            }
            let strings = sections
                .get(u32at(s, 40) as usize)
                .ok_or("invalid ELF string table link")?;
            if u32at(strings, 4) != 3 {
                return Err("invalid ELF string table type".into());
            }
            let strings = slice(bytes, u64at(strings, 24), u64at(strings, 32))?;
            let entries = slice(bytes, u64at(s, 24), size)?;
            for item in entries.chunks_exact(24) {
                if u16at(item, 6) == 0 {
                    continue;
                }
                let name = strings
                    .get(u32at(item, 0) as usize..)
                    .ok_or("invalid ELF symbol name")?;
                let end = name
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or("unterminated ELF symbol name")?;
                let name = std::str::from_utf8(&name[..end]).map_err(|_| "non-UTF8 ELF symbol")?;
                let address = u64at(item, 8);
                let size = u64at(item, 16);
                address.checked_add(size).ok_or("ELF symbol overflow")?;
                if !name.is_empty() {
                    symbols.push(Symbol {
                        name: name.into(),
                        address,
                        size,
                        function: item[4] & 15 == 2,
                    });
                }
            }
        }
        Ok(Self {
            sha256: artifact.sha256.clone(),
            gnu_build_id,
            machine,
            elf_type,
            segments,
            symbols,
        })
    }
    pub fn from_bundle(
        root: &Path,
        artifact: &Artifact,
        arch: CaptureArch,
    ) -> Result<Self, String> {
        if !bpf_capture::mapping::valid_sha(&artifact.sha256)
            || artifact.path != format!("artifacts/{}.elf", artifact.sha256)
        {
            return Err("invalid bundle object path".into());
        }
        let mut bytes = Vec::new();
        let limit = 256 * 1024 * 1024u64;
        fs::File::open(root.join(&artifact.path))
            .map_err(|e| format!("ELF unavailable: {e}"))?
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("ELF read: {e}"))?;
        if bytes.len() as u64 > limit {
            return Err("ELF exceeds bound".into());
        }
        let mut image = Self::from_bytes(&bytes, artifact, arch)?;
        if let Some(sha) = &artifact.debug_sha256 {
            if sha == &artifact.sha256 {
                if artifact.debug_build_id != artifact.gnu_build_id {
                    return Err("embedded debug identity mismatch".into());
                }
                return Ok(image);
            }
            if artifact.gnu_build_id.is_none() || artifact.debug_build_id != artifact.gnu_build_id {
                return Err("debug ELF binding unavailable".into());
            }
            let debug = Artifact {
                sha256: sha.clone(),
                gnu_build_id: artifact.debug_build_id.clone(),
                path: format!("artifacts/{sha}.elf"),
                debug_sha256: None,
                debug_build_id: None,
            };
            image.symbols = Self::from_bundle(root, &debug, arch)?.symbols;
        }
        Ok(image)
    }
    pub fn address_for_file_offset(&self, offset: u64) -> Result<ElfAddress, String> {
        let mut found = None;
        for p in &self.segments {
            if p.flags & 1 != 0 && offset >= p.offset && offset - p.offset < p.filesz {
                let address = p
                    .vaddr
                    .checked_add(offset - p.offset)
                    .ok_or("ELF address overflow")?;
                if found.is_some_and(|old| old != address) {
                    return Err("ambiguous ELF file offset".into());
                }
                found = Some(address);
            }
        }
        self.address(found.ok_or("offset outside executable file-backed PT_LOAD")?)
    }
    pub fn address(&self, address: u64) -> Result<ElfAddress, String> {
        let symbol = self
            .symbols
            .iter()
            .filter(|s| {
                s.function
                    && address >= s.address
                    && (address - s.address < s.size || s.size == 0 && address == s.address)
            })
            .max_by_key(|s| s.address);
        Ok(ElfAddress {
            sha256: self.sha256.clone(),
            virtual_address: address,
            symbol: symbol.map(|s| s.name.clone()),
            symbol_offset: symbol.map(|s| address - s.address),
        })
    }
    pub fn kernel_address(
        &self,
        link: &KernelArtifact,
        start: u64,
        len: u64,
        reference: u64,
        symbol: &str,
        ip: u64,
    ) -> Result<ElfAddress, String> {
        if link.sha256 != self.sha256
            || symbol != link.reference_symbol
            || self
                .symbols
                .iter()
                .all(|s| s.name != link.reference_symbol || s.address != link.reference_address)
        {
            return Err("kernel reference symbol mismatch".into());
        }
        if link.text_end.checked_sub(link.text_start) != Some(len)
            || link
                .reference_address
                .checked_sub(link.text_start)
                .and_then(|o| start.checked_add(o))
                != Some(reference)
        {
            return Err("kernel relocation/range mismatch".into());
        }
        let relative = ip
            .checked_sub(start)
            .filter(|v| *v < len)
            .ok_or("outside runtime kernel text")?;
        let address = link
            .text_start
            .checked_add(relative)
            .ok_or("kernel relocation overflow")?;
        if !self
            .segments
            .iter()
            .any(|p| p.flags & 1 != 0 && address >= p.vaddr && address - p.vaddr < p.filesz)
        {
            return Err("kernel reference outside executable ELF".into());
        }
        self.address(address)
    }
}
