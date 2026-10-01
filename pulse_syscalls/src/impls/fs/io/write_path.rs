use alloc::vec::Vec;

use axerrno::LinuxError;
use axio::SeekFrom;
use linux_raw_sys::general::iovec;
use pulse_core::fd_table::{FdObject, FileObject};

use super::{
    MAX_IO_CHUNK, ScratchBuffer, UserWriteSource, is_sigpipe_writer, queue_sigpipe_on_epipe,
    write_from_user,
};
use crate::validation::io::{
    UserIoSegment, iov_len_to_usize, validate_direct_io, validate_user_io_segments,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteOffset {
    Shared,
    Positional(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WriteTransfer {
    pub(super) source: UserWriteSource,
    pub(super) submitted: usize,
    pub(super) written: usize,
    pub(super) scratch_was_present: bool,
}

pub(crate) fn normalize_iovecs(iovecs: &[iovec]) -> Result<Vec<UserIoSegment>, LinuxError> {
    let mut segments = Vec::with_capacity(iovecs.len());
    for iovec in iovecs {
        segments.push(UserIoSegment {
            addr: iovec.iov_base as usize,
            len: iov_len_to_usize(iovec.iov_len)?,
        });
    }
    Ok(segments)
}

pub(crate) fn prepare_write(
    file_obj: Option<&FileObject>,
    segments: &[UserIoSegment],
    offset: WriteOffset,
) -> Result<usize, LinuxError> {
    let total = validate_user_io_segments(
        segments,
        match offset {
            WriteOffset::Shared => None,
            WriteOffset::Positional(file_offset) => Some(file_offset),
        },
    )?;

    let Some(file_obj) = file_obj.filter(|file| file.inner().is_direct_regular_file()) else {
        return Ok(total);
    };
    let file_offset = match offset {
        WriteOffset::Shared => file_obj.seek(SeekFrom::Current(0))?,
        WriteOffset::Positional(file_offset) => file_offset,
    };
    validate_direct_io(
        segments,
        file_offset,
        file_obj.inner().block_size() as usize,
    )?;
    Ok(total)
}

pub(crate) fn write_to_object(
    object: &dyn FdObject,
    file_obj: Option<&FileObject>,
    slice: &[u8],
    offset: Option<u64>,
) -> Result<usize, LinuxError> {
    match offset {
        Some(offset) => match file_obj {
            Some(file_obj) => file_obj.write_at_slice(slice, offset),
            None => object.write_at(slice, offset),
        },
        None => match file_obj {
            Some(file_obj) => file_obj.write_slice(slice),
            None => object.write(slice),
        },
    }
}

/// The caller owns syscall argument decoding, TTY serialization, and any
/// object-specific fast path. This function owns normalized segment traversal,
/// stable user-memory transfer, partial progress, and SIGPIPE precedence.
pub(crate) fn execute_user_write(
    object: &dyn FdObject,
    file_obj: Option<&FileObject>,
    segments: &[UserIoSegment],
    offset: WriteOffset,
    fallback: &mut Option<ScratchBuffer>,
    mut on_written: impl FnMut(&[u8]),
    mut on_transfer: impl FnMut(WriteTransfer),
) -> isize {
    let sigpipe_writer = is_sigpipe_writer(object);
    let mut total = 0usize;

    for segment in segments {
        let mut segment_offset = 0usize;
        while segment_offset < segment.len {
            let chunk = core::cmp::min(MAX_IO_CHUNK, segment.len - segment_offset);
            let user_addr = match segment.addr.checked_add(segment_offset) {
                Some(addr) => addr,
                None => return partial_or_errno(total, LinuxError::EINVAL, sigpipe_writer),
            };
            let file_offset = match offset {
                WriteOffset::Shared => None,
                WriteOffset::Positional(base) => match base.checked_add(total as u64) {
                    Some(file_offset) => Some(file_offset),
                    None => return partial_or_errno(total, LinuxError::EINVAL, sigpipe_writer),
                },
            };
            let scratch_was_present = fallback.is_some();
            let result = write_from_user(user_addr, chunk, fallback, |slice| {
                let written = write_to_object(object, file_obj, slice, file_offset)?;
                if written > slice.len() {
                    return Err(LinuxError::EIO);
                }
                if written > 0 {
                    on_written(&slice[..written]);
                }
                Ok(written)
            });
            let (written, submitted, source) = match result {
                Ok(result) => result,
                Err(error) => return partial_or_errno(total, error, sigpipe_writer),
            };
            on_transfer(WriteTransfer {
                source,
                submitted,
                written,
                scratch_was_present,
            });

            if written == 0 {
                return total as isize;
            }
            total += written;
            segment_offset += written;
            if written < submitted {
                return total as isize;
            }
        }
    }
    total as isize
}

fn partial_or_errno(total: usize, error: LinuxError, sigpipe_writer: bool) -> isize {
    if total > 0 {
        return total as isize;
    }
    let errno = error.code();
    queue_sigpipe_on_epipe(sigpipe_writer, errno);
    -errno as isize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_scalar_and_vectored_segments_with_checked_lengths() {
        let iovecs = [
            iovec {
                iov_base: 0x1000 as _,
                iov_len: 3,
            },
            iovec {
                iov_base: 0x2000 as _,
                iov_len: isize::MAX as u64,
            },
        ];
        let segments = normalize_iovecs(&iovecs).unwrap();
        assert_eq!(
            segments[0],
            UserIoSegment {
                addr: 0x1000,
                len: 3
            }
        );
        assert_eq!(segments[1].len, isize::MAX as usize);
        assert_eq!(
            prepare_write(None, &segments[..1], WriteOffset::Shared),
            Ok(3)
        );
    }
}
