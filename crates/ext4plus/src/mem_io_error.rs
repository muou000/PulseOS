use core::error::Error;
use core::fmt;
use core::fmt::{Display, Formatter};

/// Error type used by the [`Vec<u8>`] impls of [`crate::Ext4Read`] and [`crate::Ext4Write`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemIoError {
    pub(crate) start: u64,
    pub(crate) read_len: usize,
    pub(crate) src_len: usize,
}

impl Display for MemIoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to read {} bytes at offset {} from a slice of length {}",
            self.read_len, self.start, self.src_len
        )
    }
}

impl Error for MemIoError {}

/// Error type used by the [`Vec<u8>`] impls of [`crate::Ext4Write`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemWriteError {
    pub(crate) start: u64,
    pub(crate) write_len: usize,
    pub(crate) dst_len: usize,
}

impl Display for MemWriteError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to write {} bytes at offset {} to a slice of length {}",
            self.write_len, self.start, self.dst_len
        )
    }
}

impl Error for MemWriteError {}

