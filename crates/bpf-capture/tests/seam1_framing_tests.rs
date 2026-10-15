use bpf_capture::framing::{
    compute_checksum, CaptureArch, CaptureError, CaptureHeader, CaptureTrailer, SessionStatusCode,
    CAPTURE_HEADER_MAGIC, CAPTURE_HEADER_SIZE, CAPTURE_TRAILER_MAGIC, CAPTURE_TRAILER_SIZE,
    FORMAT_VERSION_V1, SCHEMA_VERSION_V1,
};

#[test]
fn test_header_round_trip() {
    let header = CaptureHeader {
        magic: CAPTURE_HEADER_MAGIC,
        format_version: FORMAT_VERSION_V1,
        schema_version: SCHEMA_VERSION_V1,
        header_size: CAPTURE_HEADER_SIZE as u32,
        target_arch: CaptureArch::Riscv64,
        metadata_offset: 64,
        metadata_size: 128,
        records_offset: 192,
        records_count: 10,
        records_size: 880,
        trailer_offset: 1072,
        trailer_size: CAPTURE_TRAILER_SIZE as u64,
    };

    let bytes = header.to_bytes();
    assert_eq!(bytes.len(), CAPTURE_HEADER_SIZE);

    let parsed = CaptureHeader::from_bytes(&bytes).expect("header parse should succeed");
    assert_eq!(parsed, header);
}

#[test]
fn test_header_rejects_bad_magic() {
    let mut header = CaptureHeader::new(CaptureArch::LoongArch64);
    header.magic = *b"BADMAGIC";
    let bytes = header.to_bytes();

    let err = CaptureHeader::from_bytes(&bytes).expect_err("should reject bad magic");
    assert_eq!(err, CaptureError::BadMagic);
}

#[test]
fn test_header_rejects_unsupported_version() {
    let mut header = CaptureHeader::new(CaptureArch::Riscv64);
    header.format_version = 42;
    let bytes = header.to_bytes();

    let err = CaptureHeader::from_bytes(&bytes).expect_err("should reject unsupported version");
    assert_eq!(err, CaptureError::UnsupportedFormatVersion(42));
}

#[test]
fn test_header_rejects_truncated_input() {
    let bytes = vec![0u8; CAPTURE_HEADER_SIZE - 1];
    let err = CaptureHeader::from_bytes(&bytes).expect_err("should reject truncated header");
    assert_eq!(err, CaptureError::TruncatedHeader);
}

#[test]
fn test_trailer_round_trip() {
    let trailer = CaptureTrailer {
        magic: CAPTURE_TRAILER_MAGIC,
        records_count: 42,
        records_bytes: 3696,
        checksum: 0x12345678,
        status_code: SessionStatusCode::Complete,
        trailer_size: CAPTURE_TRAILER_SIZE as u32,
        _reserved: 0,
    };

    let bytes = trailer.to_bytes();
    assert_eq!(bytes.len(), CAPTURE_TRAILER_SIZE);

    let parsed = CaptureTrailer::from_bytes(&bytes).expect("trailer parse should succeed");
    assert_eq!(parsed, trailer);
}

#[test]
fn test_trailer_rejects_bad_magic() {
    let mut trailer = CaptureTrailer::new(10, 880, 0xABCDEF01, SessionStatusCode::Complete);
    trailer.magic = *b"NOTTRAIL";
    let bytes = trailer.to_bytes();

    let err = CaptureTrailer::from_bytes(&bytes).expect_err("should reject bad trailer magic");
    assert_eq!(err, CaptureError::BadTrailerMagic);
}

#[test]
fn test_trailer_rejects_truncated_input() {
    let bytes = vec![0u8; CAPTURE_TRAILER_SIZE - 1];
    let err = CaptureTrailer::from_bytes(&bytes).expect_err("should reject truncated trailer");
    assert_eq!(err, CaptureError::TruncatedTrailer);
}

#[test]
fn test_checksum_computation_and_mismatch() {
    let data = b"PulseOS BPF deterministic sample payload 2026";
    let crc = compute_checksum(data);
    assert_ne!(crc, 0);

    // Same data gives same checksum
    assert_eq!(compute_checksum(data), crc);

    // Corrupted byte produces different checksum
    let mut corrupted = data.to_vec();
    corrupted[0] ^= 0xFF;
    let corrupted_crc = compute_checksum(&corrupted);
    assert_ne!(corrupted_crc, crc);
}

#[test]
fn test_trailer_integrity_validation() {
    let data = b"some capture body payload";
    let crc = compute_checksum(data);
    let trailer = CaptureTrailer::new(5, data.len() as u64, crc, SessionStatusCode::Complete);

    assert!(trailer.validate_integrity(5, data.len() as u64, crc).is_ok());

    // Record count mismatch
    let err = trailer.validate_integrity(4, data.len() as u64, crc).unwrap_err();
    assert_eq!(err, CaptureError::RecordCountMismatch { expected: 5, actual: 4 });

    // Byte count mismatch
    let err = trailer.validate_integrity(5, data.len() as u64 + 1, crc).unwrap_err();
    assert_eq!(err, CaptureError::ByteCountMismatch { expected: data.len() as u64, actual: data.len() as u64 + 1 });

    // Checksum mismatch
    let err = trailer.validate_integrity(5, data.len() as u64, crc ^ 0x1111).unwrap_err();
    assert_eq!(err, CaptureError::ChecksumMismatch { expected: crc, actual: crc ^ 0x1111 });
}
