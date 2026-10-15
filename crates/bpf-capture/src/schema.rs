//! Event schema definitions and registry.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use crate::framing::CaptureError;
use crate::record::NormalizedRecord;

pub const PERF_EVENT_SOFTWARE_ID: u32 = 0x1000;

/// Primitive field types for normalized BPF event schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldTypeId {
    U8,
    U16,
    U32,
    U64,
    I32,
    I64,
    ByteArray(usize),
}

impl FieldTypeId {
    pub fn to_bytes(&self) -> (u32, u32) {
        match self {
            Self::U8 => (1, 1),
            Self::U16 => (2, 2),
            Self::U32 => (3, 4),
            Self::U64 => (4, 8),
            Self::I32 => (5, 4),
            Self::I64 => (6, 8),
            Self::ByteArray(n) => (7, *n as u32),
        }
    }

    pub fn from_raw(type_id: u32, extra: u32) -> Self {
        match type_id {
            1 => Self::U8,
            2 => Self::U16,
            3 => Self::U32,
            4 => Self::U64,
            5 => Self::I32,
            6 => Self::I64,
            7 => Self::ByteArray(extra as usize),
            _ => Self::ByteArray(extra as usize),
        }
    }
}

/// Metadata description of a single field within an event payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldSchema {
    pub name: String,
    pub offset: u32,
    pub size: u32,
    pub field_type: FieldTypeId,
}

/// Event schema describing the structure of normalized records for a given event ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventSchema {
    pub event_id: u32,
    pub category: String,
    pub name: String,
    pub version: u32,
    pub payload_size: u32,
    pub fields: Vec<FieldSchema>,
}

/// Schema registry storing all known event schemas.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SchemaRegistry {
    schemas: Vec<EventSchema>,
}

impl SchemaRegistry {
    pub fn new() -> Self {
        Self { schemas: Vec::new() }
    }

    pub fn register(&mut self, schema: EventSchema) {
        if let Some(pos) = self.schemas.iter().position(|s| s.event_id == schema.event_id) {
            self.schemas[pos] = schema;
        } else {
            self.schemas.push(schema);
        }
    }

    pub fn schemas(&self) -> &[EventSchema] {
        &self.schemas
    }

    pub fn lookup(&self, event_id: u32) -> Option<&EventSchema> {
        self.schemas.iter().find(|s| s.event_id == event_id)
    }

    pub fn lookup_by_name(&self, category: &str, name: &str) -> Option<&EventSchema> {
        self.schemas
            .iter()
            .find(|s| s.category == category && s.name == name)
    }

    pub fn validate_record(&self, record: &NormalizedRecord) -> Result<(), CaptureError> {
        let Some(schema) = self.lookup(record.event_id) else {
            return Err(CaptureError::SchemaMismatch {
                expected: 0,
                actual: record.event_id,
            });
        };

        if record.schema_version != schema.version {
            return Err(CaptureError::SchemaMismatch {
                expected: schema.version,
                actual: record.schema_version,
            });
        }

        if record.payload.len() != schema.payload_size as usize {
            return Err(CaptureError::ByteCountMismatch {
                expected: schema.payload_size as u64,
                actual: record.payload.len() as u64,
            });
        }

        Ok(())
    }

    /// Construct the default PulseOS registry including all semantic tracepoints and software perf_event.
    pub fn default_pulse_registry() -> Self {
        let mut reg = Self::new();

        // 1. Semantic tracepoints from pulse_bpf_schema
        for tp in pulse_bpf_schema::all_tracepoints() {
            let mut fields = Vec::new();
            for f in tp.fields {
                if f.offset >= 40 {
                    let field_type = match f.field_type {
                        pulse_bpf_schema::FieldType::U8 => FieldTypeId::U8,
                        pulse_bpf_schema::FieldType::U16 => FieldTypeId::U16,
                        pulse_bpf_schema::FieldType::U32 => FieldTypeId::U32,
                        pulse_bpf_schema::FieldType::U64 => FieldTypeId::U64,
                        pulse_bpf_schema::FieldType::I32 => FieldTypeId::I32,
                        pulse_bpf_schema::FieldType::I64 => FieldTypeId::I64,
                        pulse_bpf_schema::FieldType::ByteArray(n) => FieldTypeId::ByteArray(n),
                    };
                    fields.push(FieldSchema {
                        name: String::from(f.name),
                        offset: (f.offset - 40) as u32,
                        size: f.size as u32,
                        field_type,
                    });
                }
            }

            reg.register(EventSchema {
                event_id: tp.id.as_u32(),
                category: String::from(tp.category),
                name: String::from(tp.name),
                version: tp.version,
                payload_size: (tp.context_size.saturating_sub(40)) as u32,
                fields,
            });
        }

        // 2. Software perf_event sampling schema
        reg.register(EventSchema {
            event_id: PERF_EVENT_SOFTWARE_ID,
            category: String::from("pulse"),
            name: String::from("perf_event"),
            version: 1,
            payload_size: 16,
            fields: vec![
                FieldSchema {
                    name: String::from("sample_period"),
                    offset: 0,
                    size: 8,
                    field_type: FieldTypeId::U64,
                },
                FieldSchema {
                    name: String::from("addr"),
                    offset: 8,
                    size: 8,
                    field_type: FieldTypeId::U64,
                },
            ],
        });

        reg
    }

    /// Serialize registry to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let count = self.schemas.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());

        for s in &self.schemas {
            buf.extend_from_slice(&s.event_id.to_le_bytes());
            buf.extend_from_slice(&s.version.to_le_bytes());
            buf.extend_from_slice(&s.payload_size.to_le_bytes());

            crate::codec::encode_string(&mut buf, &s.category);
            crate::codec::encode_string(&mut buf, &s.name);

            let field_count = s.fields.len() as u32;
            buf.extend_from_slice(&field_count.to_le_bytes());

            for f in &s.fields {
                crate::codec::encode_string(&mut buf, &f.name);
                buf.extend_from_slice(&f.offset.to_le_bytes());
                buf.extend_from_slice(&f.size.to_le_bytes());
                let (type_id, extra) = f.field_type.to_bytes();
                buf.extend_from_slice(&type_id.to_le_bytes());
                buf.extend_from_slice(&extra.to_le_bytes());
            }
        }

        buf
    }

    /// Deserialize registry from a byte slice.
    pub fn from_bytes(slice: &[u8]) -> Result<(Self, usize), CaptureError> {
        let mut offset = 0;
        if slice.len() < 4 {
            return Err(CaptureError::TruncatedMetadata);
        }

        let count = u32::from_le_bytes(slice[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        let mut reg = Self::new();

        for _ in 0..count {
            if slice.len() < offset + 12 {
                return Err(CaptureError::TruncatedMetadata);
            }
            let event_id = u32::from_le_bytes(slice[offset..offset + 4].try_into().unwrap());
            let version = u32::from_le_bytes(slice[offset + 4..offset + 8].try_into().unwrap());
            let payload_size = u32::from_le_bytes(slice[offset + 8..offset + 12].try_into().unwrap());
            offset += 12;

            let category = crate::codec::decode_string(slice, &mut offset)?;
            let name = crate::codec::decode_string(slice, &mut offset)?;

            if slice.len() < offset + 4 {
                return Err(CaptureError::TruncatedMetadata);
            }
            let field_count = u32::from_le_bytes(slice[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;

            let mut fields = Vec::with_capacity(field_count);
            for _ in 0..field_count {
                let f_name = crate::codec::decode_string(slice, &mut offset)?;

                if slice.len() < offset + 16 {
                    return Err(CaptureError::TruncatedMetadata);
                }
                let f_offset = u32::from_le_bytes(slice[offset..offset + 4].try_into().unwrap());
                let f_size = u32::from_le_bytes(slice[offset + 4..offset + 8].try_into().unwrap());
                let type_id = u32::from_le_bytes(slice[offset + 8..offset + 12].try_into().unwrap());
                let extra = u32::from_le_bytes(slice[offset + 12..offset + 16].try_into().unwrap());
                offset += 16;

                fields.push(FieldSchema {
                    name: f_name,
                    offset: f_offset,
                    size: f_size,
                    field_type: FieldTypeId::from_raw(type_id, extra),
                });
            }

            reg.register(EventSchema {
                event_id,
                category,
                name,
                version,
                payload_size,
                fields,
            });
        }

        Ok((reg, offset))
    }
}
