//! Bounded ownership of user page fragments and pre-registered `io_uring`
//! fixed buffer pages across execution contexts.
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
//! supplies readable padding for those loads.

#![deny(unsafe_op_in_unsafe_fn)]

use alloc::vec::Vec;

use axalloc::{frame_table, global_allocator};
use axerrno::{AxError, AxResult, LinuxError};
use axhal::{mem::phys_to_virt, paging::MappingFlags};
use axio::{IoBuf, IoBufMut, Read, Segmented, Write};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, PhysAddr, VirtAddr};
pub use pulse_io_uring_core::resources::{
    FixedBufferSlice, FixedBufferSlot, MAX_PIN_WINDOW_BYTES, MAX_PIN_WINDOW_FRAGMENTS,
    UserIoSegment, fits_single_pin_window,
};

use crate::task::{Process, current_process};

const MAX_WINDOW_BYTES: usize = MAX_PIN_WINDOW_BYTES;
const MAX_WINDOW_FRAGMENTS: usize = MAX_PIN_WINDOW_FRAGMENTS;

/// Releases one pinned managed physical frame reference, deallocating the frame
/// when its reference count drops to zero.
pub fn release_pinned_user_frame(frame: PhysAddr) {
    let table = frame_table();
    if table.contains(frame) && table.dec_ref(frame) == 0 {
        global_allocator().dealloc_pages(phys_to_virt(frame).as_usize(), 1);
    }
}

fn dealloc_zero_ref_runs(eligible: &mut [PhysAddr]) {
    if eligible.is_empty() {
        return;
    }
    eligible.sort_unstable_by_key(|frame| frame.as_usize());

    if eligible.len() <= MAX_WINDOW_FRAGMENTS {
        let mut runs: heapless::Vec<(usize, usize), MAX_WINDOW_FRAGMENTS> = heapless::Vec::new();
        coalesce_runs(eligible, |start, len| {
            let _ = runs.push((start, len));
        });
        global_allocator().dealloc_pages_batch(&runs);
    } else {
        let mut runs = Vec::new();
        coalesce_runs(eligible, |start, len| runs.push((start, len)));
        global_allocator().dealloc_pages_batch(&runs);
    }
}

fn coalesce_runs(sorted_eligible: &[PhysAddr], mut push: impl FnMut(usize, usize)) {
    let mut run_start = sorted_eligible[0].as_usize();
    let mut run_len = 1usize;
    for &frame in &sorted_eligible[1..] {
        let paddr = frame.as_usize();
        if paddr == run_start.saturating_add(run_len * PAGE_SIZE_4K) {
            run_len += 1;
        } else {
            push(phys_to_virt(PhysAddr::from(run_start)).as_usize(), run_len);
            run_start = paddr;
            run_len = 1;
        }
    }
    push(phys_to_virt(PhysAddr::from(run_start)).as_usize(), run_len);
}

#[inline]
fn dec_and_collect_zero_ref(frame: PhysAddr, on_release: &mut impl FnMut()) -> Option<PhysAddr> {
    let table = frame_table();
    if table.contains(frame) {
        let remaining = table.dec_ref(frame);
        on_release();
        if remaining == 0 {
            return Some(frame);
        }
    }
    None
}

/// Decrements references for a small fixed-capacity array of pinned frames
/// without heap allocation on the hot path, coalescing contiguous deallocations.
pub fn release_pinned_user_frames<const N: usize>(
    frames: &heapless::Vec<PhysAddr, N>,
    mut on_release: impl FnMut(),
) {
    let mut eligible = [PhysAddr::from(0); N];
    let mut count = 0usize;
    for &frame in frames {
        if let Some(zero_ref) = dec_and_collect_zero_ref(frame, &mut on_release) {
            eligible[count] = zero_ref;
            count += 1;
        }
    }
    dealloc_zero_ref_runs(&mut eligible[..count]);
}

/// Decrements references for an arbitrary-length slice of pinned frames and
/// coalesces contiguous zero-ref runs for batch page deallocation.
pub fn release_pinned_user_frames_slice(frames: &[PhysAddr], mut on_release: impl FnMut()) {
    if frames.len() <= MAX_WINDOW_FRAGMENTS {
        let mut stack_frames: heapless::Vec<PhysAddr, MAX_WINDOW_FRAGMENTS> = heapless::Vec::new();
        for &frame in frames {
            let _ = stack_frames.push(frame);
        }
        release_pinned_user_frames(&stack_frames, on_release);
        return;
    }

    let mut eligible = Vec::new();
    for &frame in frames {
        if let Some(zero_ref) = dec_and_collect_zero_ref(frame, &mut on_release) {
            eligible.push(zero_ref);
        }
    }
    dealloc_zero_ref_runs(&mut eligible);
}

/// Position in an ordered syscall or `io_uring` buffer list. Pinning advances
/// the position; callers stop the request after an I/O short result or a
/// terminal pin error.
#[derive(Clone, Debug, Default)]
pub struct UserBufferCursor {
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
pub struct PinnedUserBuffers {
    stream: Segmented<PinnedFragment, PinnedFrames>,
    len: usize,
    terminal_error: Option<LinuxError>,
}

impl PinnedUserBuffers {
    /// Pins a bounded window against the caller's current process.
    pub fn pin(
        segments: &[UserIoSegment],
        cursor: &mut UserBufferCursor,
        writable: bool,
    ) -> Result<Self, LinuxError> {
        let process = current_process()?;
        Self::pin_with_process(&process, segments, cursor, writable)
    }

    /// Pins a bounded window against an explicit target [`Process`], safe to call
    /// from kernel `io_uring` worker threads that have no `current_process()`.
    pub fn pin_with_process(
        process: &Process,
        segments: &[UserIoSegment],
        cursor: &mut UserBufferCursor,
        writable: bool,
    ) -> Result<Self, LinuxError> {
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
                                release_pinned_user_frame(frame);
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
                            if let Err(fragment) = frames.fragments.push(fragment) {
                                release_pinned_user_frame(fragment.frame);
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
        if len == 0
            && let Some(error) = terminal_error
        {
            return Err(error);
        }
        Ok(Self {
            stream: Segmented::new(frames),
            len,
            terminal_error,
        })
    }

    /// Number of bytes pinned before any consumption of this window.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Failure immediately after this window's valid prefix, if any.
    #[inline]
    pub fn terminal_error(&self) -> Option<LinuxError> {
        self.terminal_error
    }

    /// Copies `dst.len()` bytes out of a readable pinned window.
    pub fn copy_from_user_exact(&mut self, dst: &mut [u8]) -> Result<(), LinuxError> {
        stream_copy_from_user(self, dst)
    }

    /// Copies `src.len()` bytes into a writable pinned window.
    pub fn copy_to_user_exact(&mut self, src: &[u8]) -> Result<(), LinuxError> {
        stream_copy_to_user(self, src)
    }
}

fn stream_copy_from_user<R: Read>(reader: &mut R, dst: &mut [u8]) -> Result<(), LinuxError> {
    let mut done = 0;
    while done < dst.len() {
        match reader.read(&mut dst[done..]) {
            Ok(0) => return Err(LinuxError::EFAULT),
            Ok(n) => done += n,
            Err(err) => return Err(ax_to_user_io_err(err)),
        }
    }
    Ok(())
}

fn stream_copy_to_user<W: Write>(writer: &mut W, src: &[u8]) -> Result<(), LinuxError> {
    let mut done = 0;
    while done < src.len() {
        match writer.write(&src[done..]) {
            Ok(0) => return Err(LinuxError::EFAULT),
            Ok(n) => done += n,
            Err(err) => return Err(ax_to_user_io_err(err)),
        }
    }
    Ok(())
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
            let _ = frames.push(fragment.frame);
        }
        release_pinned_user_frames(&frames, note_pin_released);
    }
}

#[inline]
fn note_pin_released() {
    #[cfg(feature = "file-io-test")]
    axfs::file_io_test_pin_released();
}

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
        let copied = copy_pinned_page_to_kernel(
            self.frame,
            self.offset + self.consumed,
            &mut dst[..count],
        )?;
        self.consumed += copied;
        Ok(copied)
    }
}

impl Write for PinnedFragment {
    fn write(&mut self, src: &[u8]) -> axio::Result<usize> {
        if !self.writable {
            return Err(AxError::PermissionDenied);
        }
        let count = src.len().min(self.remaining_mut());
        let copied =
            copy_kernel_to_pinned_page(self.frame, self.offset + self.consumed, &src[..count])?;
        self.consumed += copied;
        Ok(copied)
    }

    fn flush(&mut self) -> axio::Result<()> {
        Ok(())
    }
}

/// Pinned physical frames backing a registered `io_uring` fixed buffer slot.
#[derive(Debug)]
pub struct FixedBufferPages {
    base_page_offset: usize,
    frames: Vec<PhysAddr>,
}

impl FixedBufferPages {
    #[inline]
    pub fn frames(&self) -> &[PhysAddr] {
        &self.frames
    }
}

impl Drop for FixedBufferPages {
    fn drop(&mut self) {
        release_pinned_user_frames_slice(&self.frames, || {});
    }
}

/// Pins all 4 KiB pages covering `[user_base, user_base + len)` for a registered
/// `io_uring` fixed buffer slot. Read-only VMAs succeed with `writable = false`.
pub fn pin_fixed_buffer_pages(
    process: &Process,
    user_base: usize,
    len: usize,
) -> Result<(Option<FixedBufferPages>, bool), LinuxError> {
    if len == 0 {
        return Ok((None, false));
    }
    match pin_fixed_page_list(process, user_base, len, MappingFlags::WRITE) {
        Ok(pages) => Ok((Some(pages), true)),
        Err(LinuxError::ENOMEM) => Err(LinuxError::ENOMEM),
        Err(_) => {
            let pages = pin_fixed_page_list(process, user_base, len, MappingFlags::READ)?;
            Ok((Some(pages), false))
        }
    }
}

fn pin_fixed_page_list(
    process: &Process,
    user_base: usize,
    len: usize,
    flags: MappingFlags,
) -> Result<FixedBufferPages, LinuxError> {
    let base_page_offset = user_base & (PAGE_SIZE_4K - 1);
    let num_pages = pulse_io_uring_core::resources::page_count_for_range(user_base, len)?;
    let start_vaddr = VirtAddr::from(user_base).align_down_4k();
    let user_end = user_base.checked_add(len).ok_or(LinuxError::EFAULT)?;
    let aspace_handle = process.aspace_handle();

    let mut pages = FixedBufferPages {
        base_page_offset,
        frames: Vec::with_capacity(num_pages),
    };
    let mut page_idx = 0usize;
    let mut faulted_page: Option<usize> = None;

    while page_idx < num_pages {
        let fault;
        {
            let aspace = aspace_handle.read();
            loop {
                if page_idx == num_pages {
                    return Ok(pages);
                }
                let page_vaddr = start_vaddr + page_idx * PAGE_SIZE_4K;
                let seg_start = user_base.max(page_vaddr.as_usize());
                let seg_end = user_end.min(page_vaddr.as_usize() + PAGE_SIZE_4K);
                let seg_len = seg_end - seg_start;
                if process.validate_user_range(seg_start, seg_len).is_err() {
                    return Err(LinuxError::EFAULT);
                }

                match aspace.pin_user_frame(page_vaddr, flags) {
                    Ok(frame) => {
                        if !axalloc::frame_table().contains(frame) {
                            return Err(LinuxError::EFAULT);
                        }
                        if !frame.is_aligned_4k() {
                            release_pinned_user_frame(frame);
                            return Err(LinuxError::EFAULT);
                        }
                        pages.frames.push(frame);
                        page_idx += 1;
                        faulted_page = None;
                    }
                    Err(_) if faulted_page == Some(page_idx) => {
                        return Err(LinuxError::EFAULT);
                    }
                    Err(_) => {
                        fault = (page_idx, seg_start, seg_len);
                        break;
                    }
                }
            }
        }
        if let Err(error) = process.try_fault_in_user_range(fault.1, fault.2, flags) {
            return Err(if error == AxError::NoMemory {
                LinuxError::ENOMEM
            } else {
                LinuxError::EFAULT
            });
        }
        faulted_page = Some(fault.0);
    }

    Ok(pages)
}

/// Adapter exposing a sub-range of a registered [`FixedBufferSlot`] as `axio::{Read, Write}`.
/// Writable slots support both reads (for `WRITE_FIXED`) and writes (for `READ_FIXED`);
/// read-only slots permit only reads and reject writes with `PermissionDenied` / `-EFAULT`.
pub struct FixedBufferIo {
    slice: FixedBufferSlice<FixedBufferPages>,
    cursor: usize,
}

impl FixedBufferIo {
    pub fn new(slice: FixedBufferSlice<FixedBufferPages>) -> Self {
        Self { slice, cursor: 0 }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.slice.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.slice.len == 0
    }

    #[inline]
    pub fn is_writable(&self) -> bool {
        self.slice.slot.writable
    }

    #[inline]
    pub fn remaining_bytes(&self) -> usize {
        self.slice.len - self.cursor
    }

    pub fn copy_from_user_exact(&mut self, dst: &mut [u8]) -> Result<(), LinuxError> {
        stream_copy_from_user(self, dst)
    }

    pub fn copy_to_user_exact(&mut self, src: &[u8]) -> Result<(), LinuxError> {
        stream_copy_to_user(self, src)
    }

    fn step_pages(
        &mut self,
        max_bytes: usize,
        mut copy_page: impl FnMut(PhysAddr, usize, usize, usize) -> AxResult<usize>,
    ) -> axio::Result<usize> {
        let total = max_bytes.min(self.remaining_bytes());
        if total == 0 {
            return Ok(0);
        }
        let mut done = 0;
        while done < total {
            let pages = self.slice.slot.pages.as_ref().ok_or(AxError::BadAddress)?;
            let abs_off = pages.base_page_offset + self.slice.offset + self.cursor;
            let page_idx = abs_off / PAGE_SIZE_4K;
            let page_off = abs_off % PAGE_SIZE_4K;
            let frame = *pages.frames.get(page_idx).ok_or(AxError::BadAddress)?;
            let chunk = (total - done).min(PAGE_SIZE_4K - page_off);
            let copied = copy_page(frame, page_off, done, chunk)?;
            self.cursor += copied;
            done += copied;
            if copied < chunk {
                break;
            }
        }
        Ok(done)
    }
}

impl IoBuf for FixedBufferIo {
    fn remaining(&self) -> usize {
        self.remaining_bytes()
    }
}

impl Read for FixedBufferIo {
    fn read(&mut self, dst: &mut [u8]) -> axio::Result<usize> {
        self.step_pages(dst.len(), |frame, page_off, done, chunk| {
            copy_pinned_page_to_kernel(frame, page_off, &mut dst[done..done + chunk])
        })
    }
}

impl IoBufMut for FixedBufferIo {
    fn remaining_mut(&self) -> usize {
        self.remaining_bytes()
    }
}

impl Write for FixedBufferIo {
    fn write(&mut self, src: &[u8]) -> axio::Result<usize> {
        if !self.slice.slot.writable {
            return Err(AxError::PermissionDenied);
        }
        self.step_pages(src.len(), |frame, page_off, done, chunk| {
            copy_kernel_to_pinned_page(frame, page_off, &src[done..done + chunk])
        })
    }

    fn flush(&mut self) -> axio::Result<()> {
        Ok(())
    }
}

#[inline]
fn ax_to_user_io_err(err: AxError) -> LinuxError {
    if matches!(err, AxError::PermissionDenied | AxError::BadAddress) {
        LinuxError::EFAULT
    } else {
        LinuxError::from(err.canonicalize())
    }
}

fn copy_pinned_page_to_kernel(
    frame: PhysAddr,
    page_offset: usize,
    dst: &mut [u8],
) -> AxResult<usize> {
    let count = dst.len();
    if count == 0 {
        return Ok(0);
    }
    debug_assert!(page_offset.saturating_add(count) <= PAGE_SIZE_4K);
    let source = phys_to_virt(frame) + page_offset;
    // SAFETY: Caller retains the managed source frame and `page_offset + count <= PAGE_SIZE_4K`.
    // Word-rounded RV64 source loads remain inside this same 4-KiB-aligned page, `dst` owns
    // `count` writable kernel bytes, and `axcpu::user_copy` creates no references to user storage.
    let uncopied = unsafe { axcpu::user_copy(dst.as_mut_ptr(), source.as_ptr(), count) };
    let copied = count - uncopied.min(count);
    if copied == 0 {
        Err(AxError::BadAddress)
    } else {
        Ok(copied)
    }
}

fn copy_kernel_to_pinned_page(
    frame: PhysAddr,
    page_offset: usize,
    src: &[u8],
) -> AxResult<usize> {
    let count = src.len();
    if count == 0 {
        return Ok(0);
    }
    debug_assert!(page_offset.saturating_add(count) <= PAGE_SIZE_4K);
    let target = phys_to_virt(frame) + page_offset;
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
        // SAFETY: Caller retains the owned writable frame and `page_offset + count <= PAGE_SIZE_4K`.
        // `source` lies within `src[..count]`; RV64 middle loads have eight readable bytes on each
        // side, while short head/tail calls and LA64 do not overread.
        let uncopied = unsafe { axcpu::user_copy((target + copied).as_mut_ptr(), source, part) };
        let done = part - uncopied.min(part);
        copied += done;
        if done != part {
            break;
        }
    }
    if copied == 0 {
        Err(AxError::BadAddress)
    } else {
        Ok(copied)
    }
}
