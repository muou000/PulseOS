//! Binary BPF capture reader with full integrity and schema validation.

use alloc::vec::Vec;
use crate::diagnostics::RuntimeDiagnostics;
use crate::framing::{compute_checksum_ieee, CaptureError, CaptureHeader, CaptureTrailer, KNOWN_EXTENSIONS, REQUIRED_STACK, REQUIRED_MAPPINGS, REQUIRED_SOURCES};
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
    pub diagnostics: Option<RuntimeDiagnostics>,
    pub mappings: Option<crate::mapping::MappingMetadata>,
    pub recorder: Option<crate::recorder::RecorderMetadata>,
}

/// Binary reader and validator for independent BPF captures.
pub struct CaptureReader;

impl CaptureReader {
    pub fn from_bytes(bytes: &[u8]) -> Result<CaptureData, CaptureError> {
        let header = CaptureHeader::from_bytes(bytes)?;

        let trailer_offset = usize::try_from(header.trailer_offset).map_err(|_| CaptureError::InvalidTrailerOffset)?;
        let trailer_size = usize::try_from(header.trailer_size).map_err(|_| CaptureError::InvalidTrailerOffset)?;
        let trailer_end = trailer_offset.checked_add(trailer_size).ok_or(CaptureError::InvalidTrailerOffset)?;
        if trailer_offset < crate::framing::CAPTURE_HEADER_SIZE
            || trailer_size != crate::framing::CAPTURE_TRAILER_SIZE
        { return Err(CaptureError::InvalidTrailerOffset); }
        if trailer_end > bytes.len() { return Err(CaptureError::TruncatedTrailer); }
        if trailer_end != bytes.len() { return Err(CaptureError::InvalidTrailerOffset); }
        let trailer = CaptureTrailer::from_bytes(&bytes[trailer_offset..trailer_end])?;
        if trailer.trailer_size as usize != trailer_size {
            return Err(CaptureError::InvalidTrailerOffset);
        }
        let computed_checksum = compute_checksum_ieee(&bytes[..trailer_offset]);
        trailer.validate_integrity(header.records_count, header.records_size, computed_checksum)?;

        let meta_offset = usize::try_from(header.metadata_offset).map_err(|_| CaptureError::InvalidRecordOffset)?;
        let meta_size = usize::try_from(header.metadata_size).map_err(|_| CaptureError::TruncatedMetadata)?;
        let meta_end = meta_offset.checked_add(meta_size).ok_or(CaptureError::TruncatedMetadata)?;
        let records_offset = usize::try_from(header.records_offset).map_err(|_| CaptureError::InvalidRecordOffset)?;
        let records_size = usize::try_from(header.records_size).map_err(|_| CaptureError::TruncatedRecord)?;
        let rec_end = records_offset.checked_add(records_size).ok_or(CaptureError::TruncatedRecord)?;
        if header.header_size as usize != crate::framing::CAPTURE_HEADER_SIZE
            || meta_offset != crate::framing::CAPTURE_HEADER_SIZE
            || meta_end != records_offset || rec_end != trailer_offset
        { return Err(CaptureError::InvalidRecordOffset); }
        if header.schema_version != crate::framing::SCHEMA_VERSION_V1 {
            return Err(CaptureError::UnsupportedSchemaVersion(header.schema_version));
        }
        // The validated ordering puts every section inside the bounded input.
        let meta_bytes = &bytes[meta_offset..meta_end];
        let (registry, reg_consumed) = SchemaRegistry::from_bytes(meta_bytes)?;
        let (metadata, meta_consumed) = SessionMetadata::from_bytes(&meta_bytes[reg_consumed..])?;
        let used = reg_consumed.checked_add(meta_consumed).ok_or(CaptureError::TruncatedMetadata)?;
        let extensions_at = meta_size.checked_sub(8).ok_or(CaptureError::TruncatedMetadata)?;
        let required = u64::from_le_bytes(meta_bytes.get(extensions_at..).ok_or(CaptureError::TruncatedMetadata)?.try_into().unwrap());
        if required & REQUIRED_SOURCES == 0 || required & !KNOWN_EXTENSIONS != 0 {
            return Err(CaptureError::InvalidRecord("unknown or missing required capture extension"));
        }
        let mut position = used;
        fn section<'a>(bytes: &'a [u8], position: &mut usize, end: usize) -> Result<&'a [u8], CaptureError> {
            let prefix_end = position.checked_add(4).filter(|p| *p <= end).ok_or(CaptureError::TruncatedMetadata)?;
            let size = u32::from_le_bytes(bytes.get(*position..prefix_end).ok_or(CaptureError::TruncatedMetadata)?.try_into().unwrap()) as usize;
            let section_end = prefix_end.checked_add(size).filter(|p| *p <= end).ok_or(CaptureError::TruncatedMetadata)?;
            *position = section_end;
            Ok(&bytes[prefix_end..section_end])
        }
        let raw = section(meta_bytes, &mut position, extensions_at)?;
        let (diagnostics, consumed) = RuntimeDiagnostics::from_bytes(raw)?;
        if consumed != raw.len() { return Err(CaptureError::InvalidRecord("invalid diagnostics length")); }
        let diagnostics = Some(diagnostics);
        let raw = section(meta_bytes, &mut position, extensions_at)?;
        let mappings = if required & REQUIRED_MAPPINGS != 0 {
            let (mappings, consumed) = crate::mapping::MappingMetadata::from_bytes(raw)?;
            if consumed != raw.len() { return Err(CaptureError::InvalidRecord("invalid mappings length")); }
            Some(mappings)
        } else {
            if !raw.is_empty() { return Err(CaptureError::InvalidRecord("undeclared mapping extension")); }
            None
        };
        let recorder = Some(crate::recorder::RecorderMetadata::from_bytes(section(meta_bytes, &mut position, extensions_at)?)?);
        if position != extensions_at || metadata.config.target_arch != header.target_arch {
            return Err(CaptureError::InvalidRecord("inconsistent metadata"));
        }
        // Binding does not prove complete producer, mapping or unwind coverage.
        if metadata.status != trailer.status_code || metadata.status.is_complete()
            || metadata.start_ns == 0 || metadata.stop_ns <= metadata.start_ns {
            return Err(CaptureError::InvalidRecord("inconsistent runtime status/window"));
        }
        if header.records_count.checked_mul(4).and_then(|n| n.checked_add(header.records_size))
            .is_none_or(|n| n > crate::recorder::MAX_RECORDER_RECORD_BYTES as u64) {
            return Err(CaptureError::InvalidRecord("record data exceeds retention budget"));
        }
        if header.records_count > (records_size / crate::record::RECORD_HEADER_SIZE) as u64 {
            return Err(CaptureError::InvalidRecord("record count cannot fit the data section"));
        }

        let mut records = Vec::with_capacity(header.records_count as usize);
        let mut rec_pos = records_offset;
        while rec_pos < rec_end {
            let (rec, consumed) = NormalizedRecord::from_bytes(&bytes[rec_pos..rec_end])?;
            registry.validate_record(&rec)?;
            if rec.event_id == crate::schema::PERF_EVENT_SOFTWARE_STACK_V3_ID
                && required & REQUIRED_STACK == 0 {
                return Err(CaptureError::InvalidRecord("stack record requires the stack extension"));
            }
            records.push(rec);
            rec_pos += consumed;
        }

        if required & REQUIRED_STACK != 0
            && !records.iter().any(|r| r.event_id == crate::schema::PERF_EVENT_SOFTWARE_STACK_V3_ID) {
            return Err(CaptureError::InvalidRecord("required stack extension has no stack records"));
        }
        if records.len() as u64 != header.records_count {
            return Err(CaptureError::RecordCountMismatch {
                expected: header.records_count,
                actual: records.len() as u64,
            });
        }
        if let Some(recorder) = &recorder {
            recorder.validate_registry(&registry)?;
            recorder.validate_records(&records, metadata.start_ns, metadata.stop_ns)?;
        }

        Ok(CaptureData {
            header,
            registry,
            metadata,
            records,
            trailer,
            diagnostics,
            mappings,
            recorder,
        })
    }
}

