#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod codec;
pub mod fixture;
pub mod framing;
pub mod reader;
pub mod record;
pub mod schema;
pub mod session;
pub mod writer;

pub use fixture::generate_deterministic_fixture;
pub use framing::{CaptureArch, CaptureError, CaptureHeader, CaptureTrailer, SessionStatusCode};
pub use reader::{CaptureData, CaptureReader};
pub use record::NormalizedRecord;
pub use schema::{EventSchema, FieldSchema, FieldTypeId, SchemaRegistry};
pub use session::{CaptureScope, LayeredLossCounters, SamplingSession, SessionConfig, SessionMetadata};
pub use writer::CaptureWriter;
