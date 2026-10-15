//! Binary BPF capture reader with full integrity and schema validation.

use alloc::vec::Vec;
use crate::framing::{compute_checksum, CaptureError, CaptureHeader, CaptureTrailer};
use crate::record::NormalizedRecord;
use crate::schema::SchemaRegistry;
use crate::session::SessionMetadata;

/// Fully parsed and validated BPF capture artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureData {
    pub header: CaptureHeader,
    pub registry: SchemaRegistry,
    pub metadata: SessionMetadata,
    pub records: Vec<NormalizedRecord>,
    pub trailer: CaptureTrailer,
}

/// Binary reader and validator for independent BPF captures.
pub struct CaptureReader;

impl CaptureReader {
    pub fn from_bytes(bytes: &[u8]) -> Result<CaptureData, CaptureError> {
        let header = CaptureHeader::from_bytes(bytes)?;

        let trailer_offset = header.trailer_offset as usize;
        let trailer_size = header.trailer_size as usize;

        if bytes.len() < trailer_offset + trailer_size {
            return Err(CaptureError::TruncatedTrailer);
        }

        let trailer = CaptureTrailer::from_bytes(&bytes[trailer_offset..trailer_offset + trailer_size])?;

        let computed_checksum = compute_checksum(&bytes[..trailer_offset]);
        trailer.validate_integrity(header.records_count, header.records_size, computed_checksum)?;

        let meta_offset = header.metadata_offset as usize;
        let meta_size = header.metadata_size as usize;
        if bytes.len() < meta_offset + meta_size {
            return Err(CaptureError::TruncatedMetadata);
        }

        let meta_bytes = &bytes[meta_offset..meta_offset + meta_size];
        let (registry, reg_consumed) = SchemaRegistry::from_bytes(meta_bytes)?;
        let (metadata, _meta_consumed) = SessionMetadata::from_bytes(&meta_bytes[reg_consumed..])?;

        let records_offset = header.records_offset as usize;
        let records_size = header.records_size as usize;
        if bytes.len() < records_offset + records_size {
            return Err(CaptureError::TruncatedRecord);
        }

        let mut records = Vec::with_capacity(header.records_count as usize);
        let mut rec_pos = records_offset;
        let rec_end = records_offset + records_size;
        while rec_pos < rec_end {
            let (rec, consumed) = NormalizedRecord::from_bytes(&bytes[rec_pos..rec_end])?;
            registry.validate_record(&rec)?;
            records.push(rec);
            rec_pos += consumed;
        }

        if records.len() as u64 != header.records_count {
            return Err(CaptureError::RecordCountMismatch {
                expected: header.records_count,
                actual: records.len() as u64,
            });
        }

        Ok(CaptureData {
            header,
            registry,
            metadata,
            records,
            trailer,
        })
    }
}

