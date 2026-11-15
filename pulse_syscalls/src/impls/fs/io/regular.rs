//! One ordinary-file I/O operation, with bounded user-buffer ownership windows.
//!
//! The file transaction owns position/append serialization across windows. Each
//! window is faulted and pinned before it enters the file's cache-copy path;
//! page-table and address-space guards never survive a file operation.

use axerrno::LinuxError;
use pulse_core::fd_table::{FdObject, FileObject};

use super::WriteOffset;
use crate::{
    impls::utils::{PinnedUserBuffers, UserBufferCursor},
    validation::io::{UserIoSegment, validate_direct_io, validate_user_io_segments},
};

pub(super) fn read(file: &FileObject, segments: &[UserIoSegment], offset: Option<u64>) -> isize {
    execute(file, segments, offset, false, &mut |_| {})
}

pub(super) fn write(
    file: &FileObject,
    segments: &[UserIoSegment],
    offset: WriteOffset,
    on_written: &mut impl FnMut(&[u8]),
) -> isize {
    let offset = match offset {
        WriteOffset::Shared => None,
        WriteOffset::Positional(offset) => Some(offset),
    };
    execute(file, segments, offset, true, on_written)
}

fn execute(
    file: &FileObject,
    segments: &[UserIoSegment],
    offset: Option<u64>,
    write: bool,
    on_written: &mut impl FnMut(&[u8]),
) -> isize {
    let requested = match validate_user_io_segments(segments, offset) {
        Ok(total) => total,
        Err(error) => return -(error.code() as isize),
    };
    if requested == 0 {
        // Scalar zero-count calls return before reaching this path. Vectored
        // direct I/O still validates every base and the offset, even when all
        // iovec lengths are zero. Such validation-only calls need no transfer
        // transaction and are outside the successful-I/O lock-count contract.
        if file.inner().is_direct_regular_file() {
            let position = match offset {
                Some(position) => position,
                None => match file.seek(axio::SeekFrom::Current(0)) {
                    Ok(position) => position,
                    Err(error) => return -(error.code() as isize),
                },
            };
            if let Err(error) =
                validate_direct_io(segments, position, file.inner().block_size() as usize)
            {
                return -(error.code() as isize);
            }
        }
        return 0;
    }
    let operation = if write {
        file.begin_write_io(offset)
    } else {
        file.begin_read_io(offset)
    };
    let mut operation = match operation {
        Ok(operation) => operation,
        Err(error) => return -(error.code() as isize),
    };
    if file.inner().is_direct_regular_file() {
        if let Err(error) = validate_direct_io(
            segments,
            operation.validation_offset(),
            file.inner().block_size() as usize,
        ) {
            return -(error.code() as isize);
        }
    }

    let mut cursor = UserBufferCursor::default();
    let mut completed = 0;
    while completed < requested {
        // The outer transaction can survive this fault preparation; it does
        // not retain a cache/io lock that file-backed faults may re-enter.
        let mut window = match PinnedUserBuffers::pin(segments, &mut cursor, !write) {
            Ok(window) => window,
            Err(error) => return progress_or_error(completed, error),
        };
        let submitted = window.len();
        if submitted == 0 {
            break;
        }
        let result = if write {
            axtask::future::block_on(operation.write_observed(&mut window, on_written))
        } else {
            operation
                .try_read(&mut window)
                .unwrap_or_else(|| axtask::future::block_on(operation.read(&mut window)))
        };
        let transferred = match result {
            Ok(count) if count <= submitted => count,
            Ok(_) => return progress_or_error(completed, LinuxError::EIO),
            Err(error) => return progress_or_error(completed, error.into()),
        };
        completed += transferred;
        if transferred < submitted || window.terminal_error().is_some() {
            break;
        }
        // A full ownership window is not a short syscall result: keep the
        // same transaction while preparing the next physical/iovec fragments.
    }
    completed as isize
}

fn progress_or_error(completed: usize, error: LinuxError) -> isize {
    if completed != 0 {
        completed as isize
    } else {
        -(error.code() as isize)
    }
}
