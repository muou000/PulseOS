use bpf_analyzer::artifact::{LoadSegment, Symbol, VerifiedElf, sha256};
use bpf_capture::{
    CaptureArch,
    mapping::{Artifact, KernelArtifact},
};
fn put16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn elf(kind: u16, build: Option<&[u8]>) -> Vec<u8> {
    let mut b = vec![0; 0x3000];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut b, 16, kind);
    put16(&mut b, 18, 243);
    put32(&mut b, 20, 1);
    put64(&mut b, 32, 64);
    put16(&mut b, 52, 64);
    put16(&mut b, 54, 56);
    put16(&mut b, 56, if build.is_some() { 2 } else { 1 });
    put32(&mut b, 64, 1);
    put32(&mut b, 68, 5);
    put64(&mut b, 72, 0x1000);
    put64(&mut b, 80, 0x2000);
    put64(&mut b, 96, 0x1000);
    put64(&mut b, 104, 0x2000);
    put64(&mut b, 112, 0x1000);
    if let Some(id) = build {
        put32(&mut b, 120, 4);
        put64(&mut b, 128, 0x200);
        put64(&mut b, 152, (16 + id.len().next_multiple_of(4)) as u64);
        put32(&mut b, 0x200, 4);
        put32(&mut b, 0x204, id.len() as u32);
        put32(&mut b, 0x208, 3);
        b[0x20c..0x210].copy_from_slice(b"GNU\0");
        b[0x210..0x210 + id.len()].copy_from_slice(id);
    }
    b
}
fn artifact(bytes: &[u8], id: Option<&str>) -> Artifact {
    let hash = sha256(bytes);
    Artifact {
        path: format!("artifacts/{hash}.elf"),
        sha256: hash,
        gnu_build_id: id.map(str::to_owned),
        debug_sha256: None,
        debug_build_id: None,
    }
}
#[test]
fn pie_and_executable_use_pt_load_file_offset_not_runtime_base() {
    for kind in [2, 3] {
        let b = elf(kind, None);
        let image = VerifiedElf::from_bytes(&b, &artifact(&b, None), CaptureArch::Riscv64).unwrap();
        assert_eq!(
            image
                .address_for_file_offset(0x1234)
                .unwrap()
                .virtual_address,
            0x2234
        );
        assert!(
            image.address_for_file_offset(0x2000).is_err(),
            "BSS has no ELF file bytes"
        );
        assert!(image.address_for_file_offset(0x999).is_err());
    }
}
#[test]
fn actual_gnu_build_id_and_explicit_absence_are_verified() {
    let b = elf(3, Some(&[1, 2, 3, 4, 5]));
    assert_eq!(
        VerifiedElf::from_bytes(&b, &artifact(&b, Some("0102030405")), CaptureArch::Riscv64)
            .unwrap()
            .gnu_build_id,
        Some("0102030405".into())
    );
    assert!(VerifiedElf::from_bytes(&b, &artifact(&b, None), CaptureArch::Riscv64).is_err());
    let b = elf(3, None);
    assert!(
        VerifiedElf::from_bytes(
            &b,
            &artifact(&b, Some(&sha256(&b)[..40])),
            CaptureArch::Riscv64
        )
        .is_err()
    );
}
#[test]
fn same_name_wrong_elf_and_missing_elf_fail_closed() {
    let b = elf(3, None);
    let a = artifact(&b, None);
    let root = std::env::temp_dir().join(format!("pulse-artifacts-{}", std::process::id()));
    std::fs::create_dir_all(root.join("artifacts")).unwrap();
    assert!(VerifiedElf::from_bundle(&root, &a, CaptureArch::Riscv64).is_err());
    let mut wrong = b.clone();
    wrong[0x1000] = 1;
    std::fs::write(root.join(&a.path), &wrong).unwrap();
    assert!(
        VerifiedElf::from_bundle(&root, &a, CaptureArch::Riscv64)
            .unwrap_err()
            .contains("SHA")
    );
    std::fs::write(root.join(&a.path), &b).unwrap();
    let mut embedded = a.clone();
    embedded.debug_sha256 = Some(a.sha256.clone());
    assert!(VerifiedElf::from_bundle(&root, &embedded, CaptureArch::Riscv64).is_ok());
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn machine_and_load_alignment_and_overflow_are_validated() {
    let b = elf(3, None);
    assert!(VerifiedElf::from_bytes(&b, &artifact(&b, None), CaptureArch::LoongArch64).is_err());
    let mut b = elf(3, None);
    put64(&mut b, 112, 3);
    assert!(VerifiedElf::from_bytes(&b, &artifact(&b, None), CaptureArch::Riscv64).is_err());
    let mut b = elf(3, None);
    put64(&mut b, 80, u64::MAX - 4095);
    assert!(VerifiedElf::from_bytes(&b, &artifact(&b, None), CaptureArch::Riscv64).is_err());
}
#[test]
fn runtime_kernel_range_and_reference_must_match_actual_symbol() {
    let sha = "a".repeat(64);
    let elf = VerifiedElf {
        sha256: sha.clone(),
        gnu_build_id: None,
        machine: 243,
        elf_type: 2,
        segments: vec![LoadSegment {
            offset: 0,
            vaddr: 0x1000,
            filesz: 0x1000,
            memsz: 0x1000,
            flags: 5,
        }],
        symbols: vec![Symbol {
            name: "_stext".into(),
            address: 0x1000,
            size: 16,
            function: true,
        }],
    };
    let k = KernelArtifact {
        sha256: sha,
        reference_symbol: "_stext".into(),
        reference_address: 0x1000,
        text_start: 0x1000,
        text_end: 0x2000,
    };
    assert_eq!(
        elf.kernel_address(&k, 0x10000, 0x1000, 0x10000, "_stext", 0x10004)
            .unwrap()
            .virtual_address,
        0x1004
    );
    assert!(
        elf.kernel_address(&k, 0x10000, 0x1001, 0x10000, "_stext", 0x10004)
            .is_err()
    );
    assert!(
        elf.kernel_address(&k, 0x10000, 0x1000, 0x10001, "_stext", 0x10004)
            .is_err()
    );
    assert!(
        elf.kernel_address(&k, 0x10000, 0x1000, 0x10000, "_other", 0x10004)
            .is_err()
    );
}
