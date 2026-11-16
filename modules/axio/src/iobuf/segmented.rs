use core::marker::PhantomData;

use crate::{Error, IoBuf, IoBufMut, Read, Result, Write};

/// An ordered buffer assembled from independently owned segments.
///
/// The container can be an array, a borrowed slice, or another `AsRef`/`AsMut`
/// slice container. A single transfer crosses exhausted and empty segments;
/// a short transfer or error within a nonempty segment stops the operation.
/// An error following progress is returned on the next nonempty transfer.
/// No allocation or contiguous-memory assumption is required.
pub struct Segmented<T, S> {
    segments: S,
    current: usize,
    pending_error: Option<Error>,
    marker: PhantomData<fn() -> T>,
}

impl<T, S: AsRef<[T]> + AsMut<[T]>> Segmented<T, S> {
    /// Wraps segments in their current order and I/O positions.
    pub fn new(segments: S) -> Self {
        Self {
            segments,
            current: 0,
            pending_error: None,
            marker: PhantomData,
        }
    }

    /// Returns the segments, including segments already consumed.
    pub fn get_ref(&self) -> &[T] {
        self.segments.as_ref()
    }

    /// Returns the original container with each segment's updated position.
    pub fn into_inner(self) -> S {
        self.segments
    }
}

impl<T: IoBuf, S: AsRef<[T]>> IoBuf for Segmented<T, S> {
    fn remaining(&self) -> usize {
        self.segments
            .as_ref()
            .iter()
            .skip(self.current)
            .fold(0usize, |sum, segment| {
                sum.saturating_add(segment.remaining())
            })
    }
}

impl<T: Read + IoBuf, S: AsRef<[T]> + AsMut<[T]>> Read for Segmented<T, S> {
    fn read(&mut self, dst: &mut [u8]) -> Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        let mut copied = 0;
        while copied < dst.len() {
            let Some(segment) = self.segments.as_mut().get_mut(self.current) else {
                break;
            };
            let requested = segment.remaining().min(dst.len() - copied);
            if requested == 0 {
                self.current += 1;
                continue;
            }
            match segment.read(&mut dst[copied..copied + requested]) {
                Ok(n) if n <= requested => {
                    copied += n;
                    if n < requested {
                        break;
                    }
                }
                Ok(_) if copied == 0 => return Err(Error::Io),
                Err(error) if copied == 0 => return Err(error),
                result => {
                    self.pending_error = Some(result.err().unwrap_or(Error::Io));
                    break;
                }
            }
        }
        Ok(copied)
    }
}

impl<T: IoBufMut, S: AsRef<[T]>> IoBufMut for Segmented<T, S> {
    fn remaining_mut(&self) -> usize {
        self.segments
            .as_ref()
            .iter()
            .skip(self.current)
            .fold(0usize, |sum, segment| {
                sum.saturating_add(segment.remaining_mut())
            })
    }
}

impl<T: Write + IoBufMut, S: AsRef<[T]> + AsMut<[T]>> Write for Segmented<T, S> {
    fn write(&mut self, src: &[u8]) -> Result<usize> {
        if src.is_empty() {
            return Ok(0);
        }
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        let mut copied = 0;
        while copied < src.len() {
            let Some(segment) = self.segments.as_mut().get_mut(self.current) else {
                break;
            };
            let requested = segment.remaining_mut().min(src.len() - copied);
            if requested == 0 {
                self.current += 1;
                continue;
            }
            match segment.write(&src[copied..copied + requested]) {
                Ok(n) if n <= requested => {
                    copied += n;
                    if n < requested {
                        break;
                    }
                }
                Ok(_) if copied == 0 => return Err(Error::Io),
                Err(error) if copied == 0 => return Err(error),
                result => {
                    self.pending_error = Some(result.err().unwrap_or(Error::Io));
                    break;
                }
            }
        }
        Ok(copied)
    }

    fn flush(&mut self) -> Result<()> {
        for segment in self.segments.as_mut() {
            segment.flush()?;
        }
        Ok(())
    }
}
