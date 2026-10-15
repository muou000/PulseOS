use bpf_capture::framing::CaptureError;
use std::fmt;

/// Analyzer errors covering binary capture parsing, validation, and I/O.
#[derive(Debug, PartialEq, Eq)]
pub enum AnalyzerError {
    Capture(CaptureError),
    Io(String),
    Validation(String),
}

impl From<CaptureError> for AnalyzerError {
    fn from(err: CaptureError) -> Self {
        Self::Capture(err)
    }
}

impl From<std::io::Error> for AnalyzerError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl fmt::Display for AnalyzerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capture(err) => write!(f, "Capture error: {:?}", err),
            Self::Io(err) => write!(f, "I/O error: {}", err),
            Self::Validation(err) => write!(f, "Validation error: {}", err),
        }
    }
}

impl std::error::Error for AnalyzerError {}
