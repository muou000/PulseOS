//! Bounded ELF identity decoding shared by the mapping producer and recorder.
//! A missing GNU note is distinct from an unreadable or malformed artifact.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildId {
    bytes: [u8; 128],
    len: usize,
}
impl BuildId {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn range(size: u64, offset: u64, length: u64) -> Result<(), ()> {
    if offset <= size && length <= size - offset {
        Ok(())
    } else {
        Err(())
    }
}

/// Decode actual GNU build-id notes from a little-endian ELF64 artifact.
/// `read` must fill the whole requested span or return false. Tables are bounded
/// to 4096 entries and note bytes to 1 MiB; exceeding bounds is unknown, not an
/// assertion that the object has no build-id. Both PT_NOTE and SHT_NOTE count.
pub fn elf_build_id(
    size: u64,
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
) -> Result<Option<BuildId>, ()> {
    let mut header = [0; 64];
    if size < 64
        || !read(0, &mut header)
        || &header[..7] != b"\x7fELF\x02\x01\x01"
        || u16_at(&header, 52) != 64
        || u32_at(&header, 20) != 1
    {
        return Err(());
    }
    let mut result = None;
    let mut budget = 1024 * 1024u64;
    for (table, stride, count, expected, note_kind) in [
        (
            u64_at(&header, 32),
            u16_at(&header, 54),
            u16_at(&header, 56),
            56u16,
            4u32,
        ),
        (
            u64_at(&header, 40),
            u16_at(&header, 58),
            u16_at(&header, 60),
            64u16,
            7u32,
        ),
    ] {
        if count == 0 {
            // Extended section numbering needs section zero to recover counts.
            // It is outside this bounded reader; never report a missing ID.
            if table != 0 {
                return Err(());
            }
            continue;
        }
        if count > 4096 || stride != expected {
            return Err(());
        }
        range(size, table, u64::from(stride) * u64::from(count))?;
        for index in 0..count {
            let mut entry = [0; 64];
            if !read(
                table + u64::from(index) * u64::from(stride),
                &mut entry[..stride as usize],
            ) {
                return Err(());
            }
            let (kind, offset, length) = if stride == 56 {
                (u32_at(&entry, 0), u64_at(&entry, 8), u64_at(&entry, 32))
            } else {
                (u32_at(&entry, 4), u64_at(&entry, 24), u64_at(&entry, 32))
            };
            if kind != note_kind {
                continue;
            }
            range(size, offset, length)?;
            budget = budget.checked_sub(length).ok_or(())?;
            notes(offset, length, &mut read, &mut result)?;
        }
    }
    Ok(result)
}

fn notes(
    offset: u64,
    length: u64,
    read: &mut impl FnMut(u64, &mut [u8]) -> bool,
    result: &mut Option<BuildId>,
) -> Result<(), ()> {
    let mut cursor = 0;
    while cursor < length {
        let mut header = [0; 12];
        if length - cursor < 12 {
            let padding = &mut header[..(length - cursor) as usize];
            return if read(offset + cursor, padding) && padding.iter().all(|b| *b == 0) {
                Ok(())
            } else {
                Err(())
            };
        }
        if !read(offset + cursor, &mut header) {
            return Err(());
        }
        let namesz = u64::from(u32_at(&header, 0));
        let descsz = u64::from(u32_at(&header, 4));
        let name = cursor + 12;
        let desc = name + (namesz + 3) / 4 * 4;
        let end = desc + (descsz + 3) / 4 * 4;
        if end > length {
            return Err(());
        }
        if u32_at(&header, 8) == 3 && namesz == 4 {
            let mut owner = [0; 4];
            if !read(offset + name, &mut owner) {
                return Err(());
            }
            if &owner == b"GNU\0" {
                if descsz == 0 || descsz > 128 {
                    return Err(());
                }
                let mut id = BuildId {
                    bytes: [0; 128],
                    len: descsz as usize,
                };
                if !read(offset + desc, &mut id.bytes[..id.len]) {
                    return Err(());
                }
                if result.as_ref().is_some_and(|previous| previous != &id) {
                    return Err(());
                }
                *result = Some(id);
            }
        }
        cursor = end;
    }
    Ok(())
}
