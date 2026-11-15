//! Bounded ownership of user page fragments for a prepared file I/O window.
//!
//! Only this module constructs or observes the physical fragments. Overlapping
//! iovecs never become overlapping Rust references, and adjacent physical
//! frames never become one Rust allocation or slice.
//!
//! Platform premises: `AddrSpace::pin_user_frame` checks USER and requested
//! permissions while acquiring a frame reference under the leaf-page-table
//! lock; references keep managed RAM and its kernel direct mapping alive.
//! The existing RV64/LA64 `axcpu::user_copy` assembly copies through raw
//! pointers without creating Rust references to user storage and returns the
//! number of uncopied bytes. Destination writes stay inside the requested
//! range. RV64 may round source loads to 8-byte boundaries; each call below
//! supplies readable padding for those loads. These are in-tree memory and
//! assembly dependencies, not properties established by tests.

#![deny(unsafe_op_in_unsafe_fn)]

use axerrno::{AxError, LinuxError};
use axhal::{mem::phys_to_virt, paging::MappingFlags};
use axio::{IoBuf, IoBufMut, Read, Segmented, Write};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, PhysAddr, VirtAddr};

use crate::validation::io::UserIoSegment;

const MAX_WINDOW_BYTES: usize = 64 * 1024;
const MAX_WINDOW_FRAGMENTS: usize = 32;

/// Position in an ordered syscall buffer list. Pinning advances the position;
/// callers stop the request after an I/O short result or a terminal pin error.
#[derive(Default)]
pub(crate) struct UserBufferCursor {
    segment: usize,
    offset: usize,
}

impl UserBufferCursor {
    fn fragment(
        &mut self,
        segments: &[UserIoSegment],
        budget: usize,
    ) -> Result<Option<(usize, usize)>, LinuxError> {
        while let Some(segment) = segments.get(self.segment) {
            if self.offset > segment.len {
                return Err(LinuxError::EINVAL);
            }
            if self.offset == segment.len {
                self.segment += 1;
                self.offset = 0;
                continue;
            }
            let addr = segment
                .addr
                .checked_add(self.offset)
                .ok_or(LinuxError::EFAULT)?;
            let len = (segment.len - self.offset)
                .min(budget)
                .min(PAGE_SIZE_4K - (addr & (PAGE_SIZE_4K - 1)));
            return Ok(Some((addr, len)));
        }
        Ok(None)
    }
}

/// A prepared window of at most 64 KiB and 32 user-page fragments.
///
/// Empty windows denote the end of the segment list. A fault after a valid
/// prefix is reported by `terminal_error`; that prefix can still be consumed.
/// `Read` is available for readable windows and `Write` for writable windows.
/// The opposite direction is rejected without accessing memory.
pub(crate) struct PinnedUserBuffers {
    stream: Segmented<PinnedFragment, PinnedFrames>,
    len: usize,
    terminal_error: Option<LinuxError>,
}

impl PinnedUserBuffers {
    pub(crate) fn pin(
        segments: &[UserIoSegment],
        cursor: &mut UserBufferCursor,
        writable: bool,
    ) -> Result<Self, LinuxError> {
        let process = pulse_core::task::current_process()?;
        let aspace_handle = process.aspace_handle();
        let flags = if writable {
            MappingFlags::WRITE
        } else {
            MappingFlags::READ
        };
        let mut frames = PinnedFrames {
            fragments: heapless::Vec::new(),
        };
        let mut len = 0;
        let mut terminal_error = None;
        let mut faulted_addr = None;

        'window: while len < MAX_WINDOW_BYTES && frames.fragments.len() < MAX_WINDOW_FRAGMENTS {
            let fault;
            {
                let aspace = aspace_handle.read();
                loop {
                    if len == MAX_WINDOW_BYTES || frames.fragments.len() == MAX_WINDOW_FRAGMENTS {
                        break 'window;
                    }
                    let (addr, chunk) = match cursor.fragment(segments, MAX_WINDOW_BYTES - len) {
                        Ok(Some(fragment)) => fragment,
                        Ok(None) => break 'window,
                        Err(error) => {
                            terminal_error = Some(error);
                            break 'window;
                        }
                    };
                    if process.validate_user_range(addr, chunk).is_err() {
                        terminal_error = Some(LinuxError::EFAULT);
                        break 'window;
                    }
                    match aspace.pin_user_frame(VirtAddr::from(addr).align_down_4k(), flags) {
                        Ok(frame) => {
                            // Only managed RAM has the reference-counted lifetime
                            // required by the direct-map copy contract.
                            if !axalloc::frame_table().contains(frame) {
                                terminal_error = Some(LinuxError::EFAULT);
                                break 'window;
                            }
                            #[cfg(feature = "file-io-test")]
                            axfs::file_io_test_pin_acquired();
                            if !frame.is_aligned_4k() {
                                super::release_pinned_user_frame(frame);
                                note_pin_released();
                                terminal_error = Some(LinuxError::EFAULT);
                                break 'window;
                            }
                            let fragment = PinnedFragment {
                                frame,
                                offset: addr & (PAGE_SIZE_4K - 1),
                                len: chunk,
                                consumed: 0,
                                writable,
                            };
                            // Capacity was checked before acquiring the reference.
                            // Still release explicitly if the checked push fails.
                            if let Err(fragment) = frames.fragments.push(fragment) {
                                super::release_pinned_user_frame(fragment.frame);
                                note_pin_released();
                                break 'window;
                            }
                            cursor.offset += chunk;
                            len += chunk;
                            faulted_addr = None;
                        }
                        Err(_) if faulted_addr == Some(addr) => {
                            terminal_error = Some(LinuxError::EFAULT);
                            break 'window;
                        }
                        Err(_) => {
                            fault = (addr, chunk);
                            break;
                        }
                    }
                }
            }
            // File faults and COW may wait and may re-enter the filesystem.
            // Neither an address-space nor leaf-page-table guard survives here.
            if let Err(error) = process.try_fault_in_user_range(fault.0, fault.1, flags) {
                terminal_error = Some(LinuxError::from(error.canonicalize()));
                break;
            }
            faulted_addr = Some(fault.0);
        }
        if len == 0 {
            if let Some(error) = terminal_error {
                return Err(error);
            }
        }
        Ok(Self {
            stream: Segmented::new(frames),
            len,
            terminal_error,
        })
    }

    /// Number of bytes pinned before any consumption of this window.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Failure immediately after this window's valid prefix, if any.
    pub(crate) fn terminal_error(&self) -> Option<LinuxError> {
        self.terminal_error
    }
}

impl IoBuf for PinnedUserBuffers {
    fn remaining(&self) -> usize {
        self.stream.remaining()
    }
}

impl Read for PinnedUserBuffers {
    fn read(&mut self, dst: &mut [u8]) -> axio::Result<usize> {
        self.stream.read(dst)
    }
}

impl IoBufMut for PinnedUserBuffers {
    fn remaining_mut(&self) -> usize {
        self.stream.remaining_mut()
    }
}

impl Write for PinnedUserBuffers {
    fn write(&mut self, src: &[u8]) -> axio::Result<usize> {
        self.stream.write(src)
    }

    fn flush(&mut self) -> axio::Result<()> {
        Ok(())
    }
}

// Each entry owns exactly one frame reference, even if another entry names the
// same frame. PinnedFrames is the only owner and releases every reference once.
struct PinnedFrames {
    fragments: heapless::Vec<PinnedFragment, MAX_WINDOW_FRAGMENTS>,
}

impl AsRef<[PinnedFragment]> for PinnedFrames {
    fn as_ref(&self) -> &[PinnedFragment] {
        &self.fragments
    }
}

impl AsMut<[PinnedFragment]> for PinnedFrames {
    fn as_mut(&mut self) -> &mut [PinnedFragment] {
        &mut self.fragments
    }
}

impl Drop for PinnedFrames {
    fn drop(&mut self) {
        let mut frames: heapless::Vec<PhysAddr, MAX_WINDOW_FRAGMENTS> = heapless::Vec::new();
        for fragment in &self.fragments {
            // The two vectors have the same capacity and one frame per entry.
            let _ = frames.push(fragment.frame);
        }
        super::release_pinned_user_frames(&frames, note_pin_released);
    }
}

#[inline]
fn note_pin_released() {
    #[cfg(feature = "file-io-test")]
    axfs::file_io_test_pin_released();
}

// Invariant: the managed frame is pinned by PinnedFrames; offset + len <= 4096
// and consumed <= len. No physical-memory reference escapes this leaf module.
struct PinnedFragment {
    frame: PhysAddr,
    offset: usize,
    len: usize,
    consumed: usize,
    writable: bool,
}

impl IoBuf for PinnedFragment {
    fn remaining(&self) -> usize {
        self.len - self.consumed
    }
}

impl IoBufMut for PinnedFragment {
    fn remaining_mut(&self) -> usize {
        self.len - self.consumed
    }
}

impl Read for PinnedFragment {
    fn read(&mut self, dst: &mut [u8]) -> axio::Result<usize> {
        if self.writable {
            return Err(AxError::PermissionDenied);
        }
        let count = dst.len().min(self.remaining());
        if count == 0 {
            return Ok(0);
        }
        let source = phys_to_virt(self.frame) + self.offset + self.consumed;
        // SAFETY: PinnedFrames retains the managed source page for this call,
        // and the fragment invariant bounds the requested bytes within it.
        // Word-rounded RV source loads stay in this same 4-KiB-aligned page.
        // `dst` owns count writable kernel bytes; no reference to user storage
        // is created. The module's raw-copy platform contract writes only that
        // destination range and returns an uncopied suffix count.
        let uncopied = unsafe { axcpu::user_copy(dst.as_mut_ptr(), source.as_ptr(), count) };
        let copied = count - uncopied.min(count);
        self.consumed += copied;
        if copied == 0 {
            Err(AxError::BadAddress)
        } else {
            Ok(copied)
        }
    }
}

impl Write for PinnedFragment {
    fn write(&mut self, src: &[u8]) -> axio::Result<usize> {
        if !self.writable {
            return Err(AxError::PermissionDenied);
        }
        let count = src.len().min(self.remaining_mut());
        if count == 0 {
            return Ok(0);
        }
        let target = phys_to_virt(self.frame) + self.offset + self.consumed;
        // RV64 shift-copy rounds source loads to word boundaries. Preserve an
        // eight-byte readable margin for the middle transfer; short head/tail
        // calls use the assembly's exact byte-copy path.
        let mut copied = 0;
        let needs_source_padding = cfg!(target_arch = "riscv64")
            && count >= 71
            && ((src.as_ptr() as usize ^ target.as_usize()) & 7) != 0;
        let parts = if needs_source_padding {
            [8, count - 16, 8]
        } else {
            [count, 0, 0]
        };
        for part in parts {
            if part == 0 {
                continue;
            }
            let source = src.as_ptr().wrapping_add(copied);
            // SAFETY: the owned writable frame and fragment bounds provide
            // part destination bytes at target+copied. The source lies within
            // src[..count]; RV middle loads have eight readable bytes on each
            // side, while short head/tail calls and LA do not overread. The
            // raw-copy platform contract creates no references to user storage
            // and writes only the requested destination range.
            let uncopied =
                unsafe { axcpu::user_copy((target + copied).as_mut_ptr(), source, part) };
            let done = part - uncopied.min(part);
            copied += done;
            if done != part {
                break;
            }
        }
        self.consumed += copied;
        if copied == 0 {
            Err(AxError::BadAddress)
        } else {
            Ok(copied)
        }
    }

    fn flush(&mut self) -> axio::Result<()> {
        Ok(())
    }
}
