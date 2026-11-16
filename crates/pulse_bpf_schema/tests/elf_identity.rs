use pulse_bpf_schema::elf::elf_build_id;

fn elf(note: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = vec![0; 512];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    if let Some(id) = note {
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&4u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&256u64.to_le_bytes());
        let size = 16 + (id.len() + 3) / 4 * 4;
        bytes[96..104].copy_from_slice(&(size as u64).to_le_bytes());
        bytes[256..260].copy_from_slice(&4u32.to_le_bytes());
        bytes[260..264].copy_from_slice(&(id.len() as u32).to_le_bytes());
        bytes[264..268].copy_from_slice(&3u32.to_le_bytes());
        bytes[268..272].copy_from_slice(b"GNU\0");
        bytes[272..272 + id.len()].copy_from_slice(id);
    }
    bytes
}

fn inspect(bytes: &[u8]) -> Result<Option<Vec<u8>>, ()> {
    elf_build_id(bytes.len() as u64, |offset, out| {
        let Some(input) = bytes.get(offset as usize..offset as usize + out.len()) else {
            return false;
        };
        out.copy_from_slice(input);
        true
    })
    .map(|id| id.map(|id| id.as_bytes().to_vec()))
}

#[test]
fn artifact_identity_uses_actual_gnu_note_and_distinguishes_absence() {
    assert_eq!(inspect(&elf(None)), Ok(None));
    assert_eq!(
        inspect(&elf(Some(b"actual-id"))),
        Ok(Some(b"actual-id".to_vec()))
    );
}

#[test]
fn unreadable_or_truncated_notes_are_unknown_not_absent() {
    let mut bytes = elf(Some(b"actual-id"));
    bytes[96..104].copy_from_slice(&17u64.to_le_bytes());
    assert_eq!(inspect(&bytes), Err(()));
    assert!(elf_build_id(512, |_, _| false).is_err());
}

#[test]
fn section_only_build_id_is_detected_without_program_headers() {
    let mut bytes = elf(Some(b"section-id"));
    bytes[56..58].copy_from_slice(&0u16.to_le_bytes());
    bytes[32..40].copy_from_slice(&0u64.to_le_bytes());
    bytes[40..48].copy_from_slice(&128u64.to_le_bytes());
    bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&1u16.to_le_bytes());
    bytes[132..136].copy_from_slice(&7u32.to_le_bytes());
    bytes[152..160].copy_from_slice(&256u64.to_le_bytes());
    bytes[160..168].copy_from_slice(&28u64.to_le_bytes());
    assert_eq!(inspect(&bytes), Ok(Some(b"section-id".to_vec())));
}

#[test]
fn unsupported_extended_numbering_and_elf_versions_are_unknown() {
    let mut bytes = elf(None);
    bytes[40..48].copy_from_slice(&128u64.to_le_bytes());
    assert_eq!(inspect(&bytes), Err(()));
    let mut bytes = elf(None);
    bytes[20..24].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(inspect(&bytes), Err(()));
}
