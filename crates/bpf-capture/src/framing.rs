//! Binary framing, header, trailer, and integrity validation for BPF captures.

pub const CAPTURE_HEADER_MAGIC: [u8; 8] = *b"PBCAP001";
pub const CAPTURE_TRAILER_MAGIC: [u8; 8] = *b"PBCAPTRL";
pub const FORMAT_VERSION_V1: u32 = 1;
pub const SCHEMA_VERSION_V1: u32 = 1;

pub const CAPTURE_HEADER_SIZE: usize = 80;
pub const CAPTURE_TRAILER_SIZE: usize = 40;

/// Architecture identity recorded in capture header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum CaptureArch {
    Unknown = 0,
    Riscv64 = 1,
    LoongArch64 = 2,
}

impl CaptureArch {
    pub const fn from_u32(raw: u32) -> Self {
        match raw {
            1 => Self::Riscv64,
            2 => Self::LoongArch64,
            _ => Self::Unknown,
        }
    }

    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Riscv64 => "riscv64",
            Self::LoongArch64 => "loongarch64",
            Self::Unknown => "unknown",
        }
    }
}

/// Completion or loss/error status code in capture trailer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SessionStatusCode {
    Complete = 0,
    IncompleteLoss = 1,
    IncompleteTruncated = 2,
    IncompleteError = 3,
}

impl SessionStatusCode {
    pub const fn from_u32(raw: u32) -> Self {
        match raw {
            0 => Self::Complete,
            1 => Self::IncompleteLoss,
            2 => Self::IncompleteTruncated,
            _ => Self::IncompleteError,
        }
    }

    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Capture validation and decoding errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureError {
    BadMagic,
    UnsupportedFormatVersion(u32),
    UnsupportedSchemaVersion(u32),
    TruncatedHeader,
    BadTrailerMagic,
    TruncatedTrailer,
    TruncatedMetadata,
    TruncatedRecord,
    SchemaMismatch { expected: u32, actual: u32 },
    RecordCountMismatch { expected: u64, actual: u64 },
    ByteCountMismatch { expected: u64, actual: u64 },
    ChecksumMismatch { expected: u32, actual: u32 },
    IncompleteStatus(SessionStatusCode),
    InvalidRecordOffset,
    InvalidTrailerOffset,
    IoError(&'static str),
}

/// Fixed 80-byte header at the start of every BPF capture artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureHeader {
    pub magic: [u8; 8],
    pub format_version: u32,
    pub schema_version: u32,
    pub header_size: u32,
    pub target_arch: CaptureArch,
    pub metadata_offset: u64,
    pub metadata_size: u64,
    pub records_offset: u64,
    pub records_count: u64,
    pub records_size: u64,
    pub trailer_offset: u64,
    pub trailer_size: u64,
}

impl CaptureHeader {
    pub const fn new(arch: CaptureArch) -> Self {
        Self {
            magic: CAPTURE_HEADER_MAGIC,
            format_version: FORMAT_VERSION_V1,
            schema_version: SCHEMA_VERSION_V1,
            header_size: CAPTURE_HEADER_SIZE as u32,
            target_arch: arch,
            metadata_offset: 0,
            metadata_size: 0,
            records_offset: 0,
            records_count: 0,
            records_size: 0,
            trailer_offset: 0,
            trailer_size: CAPTURE_TRAILER_SIZE as u64,
        }
    }

    pub fn to_bytes(&self) -> [u8; CAPTURE_HEADER_SIZE] {
        let mut buf = [0u8; CAPTURE_HEADER_SIZE];
        buf[0..8].copy_from_slice(&self.magic);
        buf[8..12].copy_from_slice(&self.format_version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.schema_version.to_le_bytes());
        buf[16..20].copy_from_slice(&self.header_size.to_le_bytes());
        buf[20..24].copy_from_slice(&self.target_arch.as_u32().to_le_bytes());
        buf[24..32].copy_from_slice(&self.metadata_offset.to_le_bytes());
        buf[32..40].copy_from_slice(&self.metadata_size.to_le_bytes());
        buf[40..48].copy_from_slice(&self.records_offset.to_le_bytes());
        buf[48..56].copy_from_slice(&self.records_count.to_le_bytes());
        buf[56..64].copy_from_slice(&self.records_size.to_le_bytes());
        buf[64..72].copy_from_slice(&self.trailer_offset.to_le_bytes());
        buf[72..80].copy_from_slice(&self.trailer_size.to_le_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CaptureError> {
        if bytes.len() < CAPTURE_HEADER_SIZE {
            return Err(CaptureError::TruncatedHeader);
        }

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);
        if magic != CAPTURE_HEADER_MAGIC {
            return Err(CaptureError::BadMagic);
        }

        let format_version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if format_version != FORMAT_VERSION_V1 {
            return Err(CaptureError::UnsupportedFormatVersion(format_version));
        }

        let schema_version = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let header_size = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let raw_arch = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        let target_arch = CaptureArch::from_u32(raw_arch);

        let metadata_offset = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let metadata_size = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let records_offset = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        let records_count = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
        let records_size = u64::from_le_bytes(bytes[56..64].try_into().unwrap());
        let trailer_offset = u64::from_le_bytes(bytes[64..72].try_into().unwrap());
        let trailer_size = u64::from_le_bytes(bytes[72..80].try_into().unwrap());

        Ok(Self {
            magic,
            format_version,
            schema_version,
            header_size,
            target_arch,
            metadata_offset,
            metadata_size,
            records_offset,
            records_count,
            records_size,
            trailer_offset,
            trailer_size,
        })
    }
}

/// Fixed 40-byte integrity trailer written at the end of the capture file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureTrailer {
    pub magic: [u8; 8],
    pub records_count: u64,
    pub records_bytes: u64,
    pub checksum: u32,
    pub status_code: SessionStatusCode,
    pub trailer_size: u32,
    pub _reserved: u32,
}

impl CaptureTrailer {
    pub const fn new(
        records_count: u64,
        records_bytes: u64,
        checksum: u32,
        status_code: SessionStatusCode,
    ) -> Self {
        Self {
            magic: CAPTURE_TRAILER_MAGIC,
            records_count,
            records_bytes,
            checksum,
            status_code,
            trailer_size: CAPTURE_TRAILER_SIZE as u32,
            _reserved: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; CAPTURE_TRAILER_SIZE] {
        let mut buf = [0u8; CAPTURE_TRAILER_SIZE];
        buf[0..8].copy_from_slice(&self.magic);
        buf[8..16].copy_from_slice(&self.records_count.to_le_bytes());
        buf[16..24].copy_from_slice(&self.records_bytes.to_le_bytes());
        buf[24..28].copy_from_slice(&self.checksum.to_le_bytes());
        buf[28..32].copy_from_slice(&self.status_code.as_u32().to_le_bytes());
        buf[32..36].copy_from_slice(&self.trailer_size.to_le_bytes());
        buf[36..40].copy_from_slice(&self._reserved.to_le_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CaptureError> {
        if bytes.len() < CAPTURE_TRAILER_SIZE {
            return Err(CaptureError::TruncatedTrailer);
        }

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);
        if magic != CAPTURE_TRAILER_MAGIC {
            return Err(CaptureError::BadTrailerMagic);
        }

        let records_count = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let records_bytes = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let checksum = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        let status_code = SessionStatusCode::from_u32(u32::from_le_bytes(bytes[28..32].try_into().unwrap()));
        let trailer_size = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        let _reserved = u32::from_le_bytes(bytes[36..40].try_into().unwrap());

        Ok(Self {
            magic,
            records_count,
            records_bytes,
            checksum,
            status_code,
            trailer_size,
            _reserved,
        })
    }

    pub fn validate_integrity(
        &self,
        actual_record_count: u64,
        actual_payload_bytes: u64,
        actual_checksum: u32,
    ) -> Result<(), CaptureError> {
        if self.records_count != actual_record_count {
            return Err(CaptureError::RecordCountMismatch {
                expected: self.records_count,
                actual: actual_record_count,
            });
        }
        if self.records_bytes != actual_payload_bytes {
            return Err(CaptureError::ByteCountMismatch {
                expected: self.records_bytes,
                actual: actual_payload_bytes,
            });
        }
        if self.checksum != actual_checksum {
            return Err(CaptureError::ChecksumMismatch {
                expected: self.checksum,
                actual: actual_checksum,
            });
        }
        Ok(())
    }
}

/// Deterministic IEEE 802.3 CRC32 checksum over binary capture bytes.
pub fn compute_checksum(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (!((crc & 1).wrapping_sub(1))) ^ 0xFFFF_FFFF;
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}
