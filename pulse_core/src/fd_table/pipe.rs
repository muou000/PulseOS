use core::mem::MaybeUninit;

use super::*;

#[derive(Copy, Clone, Eq, PartialEq)]
enum RingBufferStatus {
    Full,
    Empty,
    Normal,
}

struct PipeRingBuffer {
    // Slots outside the unread range are intentionally left uninitialized.
    // Every read goes through `read_into`, which only copies published bytes.
    arr: alloc::vec::Vec<MaybeUninit<u8>>,
    head: usize,
    tail: usize,
    status: RingBufferStatus,
}

impl PipeRingBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            arr: alloc::vec![MaybeUninit::uninit(); capacity],
            head: 0,
            tail: 0,
            status: RingBufferStatus::Empty,
        }
    }

    fn capacity(&self) -> usize {
        self.arr.len()
    }

    fn available_read(&self) -> usize {
        if matches!(self.status, RingBufferStatus::Empty) {
            0
        } else if self.tail > self.head {
            self.tail - self.head
        } else {
            self.tail + self.capacity() - self.head
        }
    }

    fn resize(&mut self, new_capacity: usize) -> LinuxResult {
        let current_unread = self.available_read();
        if new_capacity < current_unread {
            return Err(LinuxError::EBUSY);
        }
        if new_capacity == self.capacity() {
            return Ok(());
        }

        let mut new_arr = alloc::vec![MaybeUninit::uninit(); new_capacity];
        let cap = self.capacity();

        if current_unread > 0 {
            if self.tail > self.head {
                // SAFETY: the unread range is initialized by `write_from`.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.arr.as_ptr().add(self.head).cast::<u8>(),
                        new_arr.as_mut_ptr().cast::<u8>(),
                        current_unread,
                    );
                }
            } else {
                let first_part = cap - self.head;
                // SAFETY: both source ranges are part of the unread initialized data.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.arr.as_ptr().add(self.head).cast::<u8>(),
                        new_arr.as_mut_ptr().cast::<u8>(),
                        first_part,
                    );
                    core::ptr::copy_nonoverlapping(
                        self.arr.as_ptr().cast::<u8>(),
                        new_arr.as_mut_ptr().add(first_part).cast::<u8>(),
                        current_unread - first_part,
                    );
                }
            }
        }

        self.arr = new_arr;
        self.head = 0;
        self.tail = if current_unread == new_capacity {
            0
        } else {
            current_unread
        };
        self.status = if current_unread == 0 {
            RingBufferStatus::Empty
        } else if current_unread == new_capacity {
            RingBufferStatus::Full
        } else {
            RingBufferStatus::Normal
        };

        Ok(())
    }

    fn read_into(&mut self, dst: &mut [u8]) -> usize {
        let read_len = core::cmp::min(self.available_read(), dst.len());
        if read_len == 0 {
            return 0;
        }

        let cap = self.capacity();
        let first_part = core::cmp::min(read_len, cap - self.head);
        // SAFETY: `read_len` is bounded by `available_read`, so both source
        // ranges contain bytes previously initialized by `write_from`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.arr.as_ptr().add(self.head).cast::<u8>(),
                dst.as_mut_ptr(),
                first_part,
            );
        }
        self.head = (self.head + first_part) % cap;

        let second_part = read_len - first_part;
        if second_part > 0 {
            // SAFETY: the wrapped range is also within the unread initialized data.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.arr.as_ptr().cast::<u8>(),
                    dst.as_mut_ptr().add(first_part),
                    second_part,
                );
            }
            self.head = second_part;
        }

        self.status = if self.head == self.tail {
            RingBufferStatus::Empty
        } else {
            RingBufferStatus::Normal
        };
        read_len
    }

    fn write_from(&mut self, src: &[u8]) -> usize {
        let available = self.capacity() - self.available_read();
        let write_len = core::cmp::min(available, src.len());
        if write_len == 0 {
            return 0;
        }

        let cap = self.capacity();
        let first_part = core::cmp::min(write_len, cap - self.tail);
        // SAFETY: the destination slots are within this vector allocation and
        // become initialized before the new bytes are made readable.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.arr.as_mut_ptr().add(self.tail).cast::<u8>(),
                first_part,
            );
        }
        self.tail = (self.tail + first_part) % cap;

        let second_part = write_len - first_part;
        if second_part > 0 {
            // SAFETY: this is the wrapped free range in the same allocation.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src.as_ptr().add(first_part),
                    self.arr.as_mut_ptr().cast::<u8>(),
                    second_part,
                );
            }
            self.tail = second_part;
        }

        self.status = if self.tail == self.head {
            RingBufferStatus::Full
        } else {
            RingBufferStatus::Normal
        };
        write_len
    }
}

#[derive(Debug)]
pub struct ZeroCopyPage {
    pub paddr: PhysAddr,
    pub offset: usize,
    pub len: usize,
}

const PIPE_PAGE_SIZE: usize = 4096;
const DEFAULT_PIPE_CAPACITY: usize = 256 * 1024;
const MAX_PIPE_CAPACITY: usize = 1024 * 1024;

fn zero_copy_bytes(pages: &alloc::collections::VecDeque<ZeroCopyPage>) -> usize {
    pages
        .iter()
        .fold(0usize, |total, page| total.saturating_add(page.len))
}

fn pipe_available_write_bytes(capacity: usize, ring_bytes: usize, zero_copy_bytes: usize) -> usize {
    capacity.saturating_sub(ring_bytes.saturating_add(zero_copy_bytes))
}

fn dealloc_physical_frame(frame: PhysAddr) {
    if axalloc::frame_table().contains(frame) {
        if axalloc::frame_table().dec_ref(frame) == 0 {
            axalloc::global_allocator()
                .dealloc_pages(axhal::mem::phys_to_virt(frame).as_usize(), 1);
        }
    }
}

fn dealloc_physical_frames(frames: &[PhysAddr]) {
    if frames.is_empty() {
        return;
    }
    if frames.len() == 1 {
        dealloc_physical_frame(frames[0]);
        return;
    }

    let table = axalloc::frame_table();
    let mut eligible = alloc::vec::Vec::with_capacity(frames.len());
    for &frame in frames {
        if table.contains(frame) && table.dec_ref(frame) == 0 {
            eligible.push(frame);
        }
    }
    if eligible.is_empty() {
        return;
    }
    eligible.sort_unstable_by_key(|frame| frame.as_usize());
    let mut runs = alloc::vec::Vec::with_capacity(eligible.len());
    let mut run_start = eligible[0].as_usize();
    let mut run_len = 1;
    for &frame in &eligible[1..] {
        let paddr = frame.as_usize();
        if paddr == run_start.saturating_add(run_len * axhal::mem::PAGE_SIZE_4K) {
            run_len += 1;
        } else {
            runs.push((
                axhal::mem::phys_to_virt(PhysAddr::from(run_start)).as_usize(),
                run_len,
            ));
            run_start = paddr;
            run_len = 1;
        }
    }
    runs.push((
        axhal::mem::phys_to_virt(PhysAddr::from(run_start)).as_usize(),
        run_len,
    ));
    axalloc::global_allocator().dealloc_pages_batch(&runs);
}

const EVENTFD_COUNTER_MAX: u64 = u64::MAX - 1;

pub struct EventFdObject {
    counter: AtomicU64,
    semaphore: bool,
    nonblocking: AtomicBool,
    read_wait_queue: axtask::WaitQueue,
    write_wait_queue: axtask::WaitQueue,
    readable_sequence: AtomicU64,
    writable_sequence: AtomicU64,
}

impl EventFdObject {
    fn new(initval: u32, semaphore: bool, nonblocking: bool) -> Self {
        Self {
            counter: AtomicU64::new(initval as u64),
            semaphore,
            nonblocking: AtomicBool::new(nonblocking),
            read_wait_queue: axtask::WaitQueue::new(),
            write_wait_queue: axtask::WaitQueue::new(),
            readable_sequence: AtomicU64::new(0),
            writable_sequence: AtomicU64::new(0),
        }
    }

    #[inline]
    fn current_has_pending_signal() -> bool {
        crate::task::current_have_signals()
    }

    #[inline]
    fn can_write(counter: u64, value: u64) -> bool {
        u64::MAX - counter > value
    }

    fn ready_for(&self, wait_for_read: bool, wait_for_write: bool) -> bool {
        let counter = self.counter.load(Ordering::Acquire);
        (wait_for_read && counter > 0) || (wait_for_write && counter < EVENTFD_COUNTER_MAX)
    }

    fn wait_for_ready(
        &self,
        wait_queue: &axtask::WaitQueue,
        wait_for_read: bool,
        wait_for_write: bool,
        deadline: Option<Duration>,
    ) -> LinuxResult<bool> {
        let condition =
            || self.ready_for(wait_for_read, wait_for_write) || Self::current_has_pending_signal();

        match deadline {
            Some(deadline) => {
                let now = axhal::time::monotonic_time();
                if now >= deadline {
                    return Ok(self.ready_for(wait_for_read, wait_for_write));
                }
                wait_queue.wait_timeout_until(deadline - now, condition);
            }
            None => wait_queue.wait_until(condition),
        }

        if Self::current_has_pending_signal() {
            return Err(LinuxError::EINTR);
        }
        Ok(self.ready_for(wait_for_read, wait_for_write))
    }
}

impl FdObject for EventFdObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_read_open(&self) -> bool {
        true
    }

    fn is_write_open(&self) -> bool {
        true
    }

    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        if buf.len() < core::mem::size_of::<u64>() {
            return Err(LinuxError::EINVAL);
        }

        loop {
            let counter = self.counter.load(Ordering::Acquire);
            if counter == 0 {
                if self.nonblocking.load(Ordering::Acquire) {
                    return Err(LinuxError::EAGAIN);
                }
                self.read_wait_queue.wait_until(|| {
                    self.counter.load(Ordering::Acquire) > 0 || Self::current_has_pending_signal()
                });
                if Self::current_has_pending_signal() {
                    return Err(LinuxError::EINTR);
                }
                continue;
            }

            let value = if self.semaphore { 1 } else { counter };
            if self
                .counter
                .compare_exchange_weak(
                    counter,
                    counter - value,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                buf[..core::mem::size_of::<u64>()].copy_from_slice(&value.to_ne_bytes());
                self.writable_sequence.fetch_add(1, Ordering::Release);
                if !self.write_wait_queue.is_empty() {
                    self.write_wait_queue.notify_all(true);
                }
                return Ok(core::mem::size_of::<u64>());
            }
        }
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        if buf.len() != core::mem::size_of::<u64>() {
            return Err(LinuxError::EINVAL);
        }
        let value = u64::from_ne_bytes(buf.try_into().unwrap());
        if value == u64::MAX {
            return Err(LinuxError::EINVAL);
        }

        loop {
            let counter = self.counter.load(Ordering::Acquire);
            if !Self::can_write(counter, value) {
                if self.nonblocking.load(Ordering::Acquire) {
                    return Err(LinuxError::EAGAIN);
                }
                self.write_wait_queue.wait_until(|| {
                    Self::can_write(self.counter.load(Ordering::Acquire), value)
                        || Self::current_has_pending_signal()
                });
                if Self::current_has_pending_signal() {
                    return Err(LinuxError::EINTR);
                }
                continue;
            }

            if self
                .counter
                .compare_exchange_weak(
                    counter,
                    counter + value,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                self.readable_sequence.fetch_add(1, Ordering::Release);
                if !self.read_wait_queue.is_empty() {
                    self.read_wait_queue.notify_all(true);
                }
                return Ok(core::mem::size_of::<u64>());
            }
        }
    }

    fn stat(&self) -> LinuxResult<stat> {
        Ok(stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode: S_IFREG | 0o600,
            st_blksize: 4096,
            ..empty_stat()
        })
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let counter = self.counter.load(Ordering::Acquire);
        Ok(PollState {
            readable: counter > 0,
            writable: counter < EVENTFD_COUNTER_MAX,
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult {
        self.nonblocking.store(nonblocking, Ordering::Release);
        Ok(())
    }

    fn nonblocking_state(&self) -> Option<bool> {
        Some(self.nonblocking.load(Ordering::Acquire))
    }

    fn poll_event_sequence(&self) -> Option<PollEventSequence> {
        Some(PollEventSequence {
            readable: self.readable_sequence.load(Ordering::Acquire),
            writable: self.writable_sequence.load(Ordering::Acquire),
        })
    }

    fn wait_ready(&self, events: i16, deadline: Option<Duration>) -> LinuxResult<bool> {
        let wait_for_read = (events & POLLIN as i16) != 0;
        let wait_for_write = (events & POLLOUT as i16) != 0;
        if !wait_for_read && !wait_for_write {
            return Err(LinuxError::EOPNOTSUPP);
        }
        if self.ready_for(wait_for_read, wait_for_write) {
            return Ok(true);
        }

        let wait_queue = if wait_for_read {
            &self.read_wait_queue
        } else {
            &self.write_wait_queue
        };
        self.wait_for_ready(wait_queue, wait_for_read, wait_for_write, deadline)
    }

    fn get_wait_queues<'a>(
        &'a self,
        events: i16,
        wqs: &mut Vec<&'a axtask::WaitQueue>,
    ) -> LinuxResult<bool> {
        let mut supported = false;
        if (events & POLLIN as i16) != 0 {
            wqs.push(&self.read_wait_queue);
            supported = true;
        }
        if (events & POLLOUT as i16) != 0 {
            wqs.push(&self.write_wait_queue);
            supported = true;
        }
        Ok(supported || events == 0)
    }

    fn register_poll(
        self: Arc<Self>,
        cx: &mut core::task::Context<'_>,
        events: axpoll::IoEvents,
        registrations: &mut Vec<PollRegistration>,
    ) -> LinuxResult {
        if events.contains(axpoll::IoEvents::IN) {
            let owner = self.clone();
            let registration = owner.read_wait_queue.register_owned_waker(cx.waker());
            registrations.push(PollRegistration::new(move || {
                owner.read_wait_queue.unregister_waker(registration);
            }));
        }
        if events.contains(axpoll::IoEvents::OUT) {
            let owner = self.clone();
            let registration = owner.write_wait_queue.register_owned_waker(cx.waker());
            registrations.push(PollRegistration::new(move || {
                owner.write_wait_queue.unregister_waker(registration);
            }));
        }
        Ok(())
    }
}

pub struct PipeShared {
    buffer: SpinNoPreempt<PipeRingBuffer>,
    read_wait_queue: axtask::WaitQueue,
    write_wait_queue: axtask::WaitQueue,
    reader_count: AtomicUsize,
    writer_count: AtomicUsize,
    pub zc_pages: SpinNoPreempt<alloc::collections::VecDeque<ZeroCopyPage>>,
}

impl PipeShared {
    fn new() -> Self {
        Self {
            buffer: SpinNoPreempt::new(PipeRingBuffer::new(DEFAULT_PIPE_CAPACITY)),
            read_wait_queue: axtask::WaitQueue::new(),
            write_wait_queue: axtask::WaitQueue::new(),
            reader_count: AtomicUsize::new(1),
            writer_count: AtomicUsize::new(1),
            zc_pages: SpinNoPreempt::new(alloc::collections::VecDeque::new()),
        }
    }

    fn new_fifo() -> Self {
        Self {
            buffer: SpinNoPreempt::new(PipeRingBuffer::new(DEFAULT_PIPE_CAPACITY)),
            read_wait_queue: axtask::WaitQueue::new(),
            write_wait_queue: axtask::WaitQueue::new(),
            reader_count: AtomicUsize::new(0),
            writer_count: AtomicUsize::new(0),
            zc_pages: SpinNoPreempt::new(alloc::collections::VecDeque::new()),
        }
    }
}

impl Drop for PipeShared {
    fn drop(&mut self) {
        let mut zc = self.zc_pages.lock();
        while let Some(page) = zc.pop_front() {
            dealloc_physical_frame(page.paddr);
        }
    }
}

pub struct PipeObject {
    readable: bool,
    writable: bool,
    shared: Arc<PipeShared>,
    nonblocking: AtomicBool,
    device_inode: Option<(u64, u64)>,
}

impl PipeObject {
    pub fn new_pair() -> (Self, Self) {
        let shared = Arc::new(PipeShared::new());
        (
            Self {
                readable: true,
                writable: false,
                shared: shared.clone(),
                nonblocking: AtomicBool::new(false),
                device_inode: None,
            },
            Self {
                readable: false,
                writable: true,
                shared,
                nonblocking: AtomicBool::new(false),
                device_inode: None,
            },
        )
    }

    pub fn new_fifo(
        shared: Arc<PipeShared>,
        readable: bool,
        writable: bool,
        device_inode: Option<(u64, u64)>,
    ) -> Self {
        Self {
            readable,
            writable,
            shared,
            nonblocking: AtomicBool::new(false),
            device_inode,
        }
    }

    const fn writable(&self) -> bool {
        self.writable
    }

    fn write_end_closed(&self) -> bool {
        self.shared.writer_count.load(Ordering::Acquire) == 0
    }

    fn read_end_closed(&self) -> bool {
        self.shared.reader_count.load(Ordering::Acquire) == 0
    }

    fn available_pipe_write(&self) -> usize {
        let zc = self.shared.zc_pages.lock();
        let buffer = self.shared.buffer.lock();
        pipe_available_write_bytes(
            buffer.capacity(),
            buffer.available_read(),
            zero_copy_bytes(&zc),
        )
    }

    fn ready_for(&self, wait_for_read: bool, wait_for_write: bool) -> bool {
        let zc = self.shared.zc_pages.lock();
        let buffer = self.shared.buffer.lock();
        let zc_len = zero_copy_bytes(&zc);
        let limit = core::cmp::min(PIPE_PAGE_SIZE, buffer.capacity());
        let avail_read = buffer.available_read().saturating_add(zc_len);
        let avail_write =
            pipe_available_write_bytes(buffer.capacity(), buffer.available_read(), zc_len);
        (wait_for_read && (avail_read > 0 || self.write_end_closed()))
            || (wait_for_write && (avail_write >= limit || self.read_end_closed()))
    }

    fn current_has_pending_signal() -> bool {
        crate::task::current_thread()
            .map(|thread| thread.has_pending_signal())
            .unwrap_or(false)
    }

    pub fn write_zerocopy(&self, writer_vaddr: usize, count: usize) -> LinuxResult<usize> {
        if !self.writable() {
            return Err(LinuxError::EPERM);
        }
        if count == 0 {
            return Ok(0);
        }
        if writer_vaddr % PIPE_PAGE_SIZE != 0 || count % PIPE_PAGE_SIZE != 0 {
            return Err(LinuxError::EINVAL);
        }
        if writer_vaddr.checked_add(count).is_none() {
            return Err(LinuxError::EFAULT);
        }

        let process = crate::task::current_process()?;
        let aspace = process.aspace_handle();
        let mut write_size = 0usize;

        while write_size < count {
            if self.read_end_closed() {
                return if write_size > 0 {
                    Ok(write_size)
                } else {
                    Err(LinuxError::EPIPE)
                };
            }

            let available_pages = self.available_pipe_write() / PIPE_PAGE_SIZE;
            if available_pages == 0 {
                if self.nonblocking.load(Ordering::Acquire) {
                    return if write_size > 0 {
                        Ok(write_size)
                    } else {
                        Err(LinuxError::EAGAIN)
                    };
                }
                self.shared.write_wait_queue.wait_until(|| {
                    self.available_pipe_write() >= PIPE_PAGE_SIZE
                        || self.read_end_closed()
                        || Self::current_has_pending_signal()
                });
                if Self::current_has_pending_signal() {
                    return if write_size > 0 {
                        Ok(write_size)
                    } else {
                        Err(LinuxError::EINTR)
                    };
                }
                continue;
            }

            let remaining_pages = (count - write_size) / PIPE_PAGE_SIZE;
            let pages_to_pin = core::cmp::min(available_pages, remaining_pages);
            let mut paddrs = alloc::vec::Vec::with_capacity(pages_to_pin);
            let aspace_guard = aspace.read();
            for i in 0..pages_to_pin {
                let page_offset = write_size + i * PIPE_PAGE_SIZE;
                let page_vaddr = VirtAddr::from(writer_vaddr + page_offset);
                match aspace_guard.pin_user_frame(page_vaddr, MappingFlags::READ) {
                    Ok(paddr) => paddrs.push(paddr),
                    Err(_) => {
                        drop(aspace_guard);
                        for paddr in paddrs {
                            dealloc_physical_frame(paddr);
                        }
                        return if write_size > 0 {
                            Ok(write_size)
                        } else {
                            Err(LinuxError::EFAULT)
                        };
                    }
                }
            }
            drop(aspace_guard);

            let accepted = {
                let mut zc = self.shared.zc_pages.lock();
                let accepted = {
                    let buffer = self.shared.buffer.lock();
                    let available_pages = pipe_available_write_bytes(
                        buffer.capacity(),
                        buffer.available_read(),
                        zero_copy_bytes(&zc),
                    ) / PIPE_PAGE_SIZE;
                    if self.read_end_closed() {
                        0
                    } else {
                        core::cmp::min(available_pages, paddrs.len())
                    }
                };
                for paddr in paddrs.drain(..accepted) {
                    zc.push_back(ZeroCopyPage {
                        paddr,
                        offset: 0,
                        len: PIPE_PAGE_SIZE,
                    });
                }
                accepted
            };
            for paddr in paddrs {
                dealloc_physical_frame(paddr);
            }

            if accepted == 0 {
                continue;
            }

            write_size += accepted * PIPE_PAGE_SIZE;
            // Readers must be able to drain this batch before a later iteration
            // waits for capacity again. Do not rely on WaitQueue::is_empty here:
            // poll registrations are independent from queued tasks.
            self.shared.read_wait_queue.notify_all(false);
        }

        if write_size > 0 {
            self.shared.read_wait_queue.notify_all(true);
        }
        Ok(write_size)
    }

    pub fn read_zerocopy(&self, reader_vaddr: usize, count: usize) -> LinuxResult<usize> {
        if !self.readable {
            return Err(LinuxError::EPERM);
        }
        if count == 0 {
            return Ok(0);
        }

        loop {
            let zc_empty = self.shared.zc_pages.lock().is_empty();
            let rb_empty = self.shared.buffer.lock().available_read() == 0;
            if !zc_empty || !rb_empty {
                break;
            }

            if self.write_end_closed() {
                return Ok(0);
            }
            if self.nonblocking.load(Ordering::Acquire) {
                return Err(LinuxError::EAGAIN);
            }
            self.shared.read_wait_queue.wait_until(|| {
                !self.shared.zc_pages.lock().is_empty()
                    || self.shared.buffer.lock().available_read() > 0
                    || self.write_end_closed()
                    || Self::current_has_pending_signal()
            });
            if Self::current_has_pending_signal() {
                return Err(LinuxError::EINTR);
            }
        }

        let process = crate::task::current_process()?;
        let aspace = process.aspace_handle();

        let num_pages = count / PIPE_PAGE_SIZE;
        let mut gathered_pages = alloc::vec::Vec::new();
        if num_pages > 0 {
            let mut zc = self.shared.zc_pages.lock();
            while gathered_pages.len() < num_pages {
                if let Some(page) = zc.front() {
                    if page.offset == 0 && page.len == PIPE_PAGE_SIZE {
                        let page = zc.pop_front().unwrap();
                        gathered_pages.push(page);
                        continue;
                    }
                }
                break;
            }
        }

        let total_gathered = gathered_pages.len();
        let mut read_pages = 0;
        let mut pending_shootdown: Option<axmm::TlbShootdown> = None;
        let mut remap_err = None;

        if total_gathered > 0 {
            let mut aspace_guard = aspace.write();
            for (i, page) in gathered_pages.iter().enumerate() {
                let page_vaddr = VirtAddr::from(reader_vaddr + i * PIPE_PAGE_SIZE);
                let (remap_res, shootdown) = aspace_guard
                    .remap_page(
                        page_vaddr,
                        page.paddr,
                        MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
                    )
                    .into_parts();
                if let Some(shootdown) = shootdown {
                    if let Some(pending) = pending_shootdown.as_mut() {
                        pending.merge(shootdown);
                    } else {
                        pending_shootdown = Some(shootdown);
                    }
                }

                match remap_res {
                    Ok(()) => {
                        read_pages += 1;
                    }
                    Err(e) => {
                        remap_err = Some(e);
                        break;
                    }
                }
            }
            drop(aspace_guard);

            if read_pages < total_gathered {
                let unconsumed: alloc::vec::Vec<ZeroCopyPage> =
                    gathered_pages.drain(read_pages..).collect();
                let mut zc = self.shared.zc_pages.lock();
                if self.read_end_closed() {
                    drop(zc);
                    let paddrs: alloc::vec::Vec<PhysAddr> =
                        unconsumed.into_iter().map(|p| p.paddr).collect();
                    dealloc_physical_frames(&paddrs);
                } else {
                    for page in unconsumed.into_iter().rev() {
                        zc.push_front(page);
                    }
                }
            }
        }

        if let Some(shootdown) = pending_shootdown
            && shootdown.complete_after_unlock().is_err()
        {
            return Err(LinuxError::EIO);
        }

        if read_pages > 0 {
            if !self.shared.write_wait_queue.is_empty() {
                self.shared.write_wait_queue.notify_all(true);
            }
            return Ok(read_pages * PIPE_PAGE_SIZE);
        }

        if let Some(err) = remap_err {
            return Err(LinuxError::from(err));
        }

        let chunk_size = count.min(65536);
        let mut buf = alloc::vec![0u8; chunk_size];
        let bytes_read = self.read(&mut buf)?;
        if bytes_read > 0 {
            process.write_user_bytes(reader_vaddr, &buf[..bytes_read])?;
        }
        Ok(bytes_read)
    }
}

impl FdObject for PipeObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_read_open(&self) -> bool {
        self.readable
    }

    fn is_write_open(&self) -> bool {
        self.writable
    }

    fn fifo_device_inode(&self) -> Option<(u64, u64)> {
        self.device_inode
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> LinuxResult<isize> {
        match cmd {
            FIONREAD => {
                let n = {
                    let zc = self.shared.zc_pages.lock();
                    let buffer = self.shared.buffer.lock();
                    buffer.available_read().saturating_add(zero_copy_bytes(&zc)) as i32
                };
                let process = crate::task::current_process()?;
                process.write_user_bytes(arg, &n.to_ne_bytes())?;
                Ok(0)
            }
            FIONBIO => {
                let process = crate::task::current_process()?;
                let enabled = process.read_user_u32(arg)? != 0;
                self.nonblocking.store(enabled, Ordering::Release);
                Ok(0)
            }
            _ => Err(LinuxError::ENOTTY),
        }
    }

    fn set_pipe_size(&self, size: usize) -> LinuxResult<usize> {
        if size > (1 << 30) {
            return Err(LinuxError::EINVAL);
        }
        if size > MAX_PIPE_CAPACITY {
            return Err(LinuxError::EPERM);
        }
        let mut new_capacity = size;
        if new_capacity == 0 {
            new_capacity = PIPE_PAGE_SIZE;
        }
        new_capacity = (new_capacity + PIPE_PAGE_SIZE - 1) & !(PIPE_PAGE_SIZE - 1);

        let capacity = {
            let zc = self.shared.zc_pages.lock();
            let mut buffer = self.shared.buffer.lock();
            let used = buffer.available_read().saturating_add(zero_copy_bytes(&zc));
            if new_capacity < used {
                return Err(LinuxError::EBUSY);
            }
            buffer.resize(new_capacity)?;
            buffer.capacity()
        };

        // Waking up any waiting writers since buffer expanded, and readers as well
        self.shared.write_wait_queue.notify_all(true);
        self.shared.read_wait_queue.notify_all(true);

        Ok(capacity)
    }

    fn get_pipe_size(&self) -> LinuxResult<usize> {
        Ok(self.shared.buffer.lock().capacity())
    }

    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        if !self.readable {
            return Err(LinuxError::EPERM);
        }
        let mut read_size = 0usize;
        while read_size < buf.len() {
            let mut freed_frames = alloc::vec::Vec::new();
            {
                let mut zc = self.shared.zc_pages.lock();
                while read_size < buf.len() {
                    let Some(page) = zc.front_mut() else {
                        break;
                    };
                    let chunk_limit = core::cmp::min(page.len, buf.len() - read_size);
                    let src_kvaddr = axhal::mem::phys_to_virt(page.paddr) + page.offset;
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            src_kvaddr.as_ptr(),
                            buf[read_size..].as_mut_ptr(),
                            chunk_limit,
                        );
                    }
                    page.offset += chunk_limit;
                    page.len -= chunk_limit;
                    read_size += chunk_limit;
                    if page.len == 0 {
                        let popped = zc.pop_front().unwrap();
                        freed_frames.push(popped.paddr);
                    } else {
                        break;
                    }
                }
            }
            if !freed_frames.is_empty() {
                dealloc_physical_frames(&freed_frames);
            }

            if read_size == buf.len() {
                break;
            }

            let mut ring_buffer = self.shared.buffer.lock();
            let available = ring_buffer.available_read();
            if available == 0 {
                if read_size > 0 {
                    drop(ring_buffer);
                    if !self.shared.write_wait_queue.is_empty() {
                        self.shared.write_wait_queue.notify_all(true);
                    }
                    return Ok(read_size);
                }
                if self.write_end_closed() {
                    return Ok(read_size);
                }
                if self.nonblocking.load(Ordering::Acquire) {
                    return Err(LinuxError::EAGAIN);
                }
                axlog::debug!(
                    "pipe read wait: tid={} shared={:p} write_closed={} nonblocking={} \
                     read_size={} want={}",
                    axtask::current().id().as_u64(),
                    Arc::as_ptr(&self.shared),
                    self.write_end_closed(),
                    self.nonblocking.load(Ordering::Acquire),
                    read_size,
                    buf.len()
                );
                drop(ring_buffer);
                self.shared.read_wait_queue.wait_until(|| {
                    !self.shared.zc_pages.lock().is_empty()
                        || self.shared.buffer.lock().available_read() > 0
                        || self.write_end_closed()
                        || Self::current_has_pending_signal()
                });
                if Self::current_has_pending_signal() {
                    return Err(LinuxError::EINTR);
                }
                continue;
            }

            let chunk_limit = core::cmp::min(available, buf.len() - read_size);
            let read = ring_buffer.read_into(&mut buf[read_size..read_size + chunk_limit]);
            debug_assert_eq!(read, chunk_limit);
            read_size += read;

            drop(ring_buffer);
        }

        if read_size > 0 {
            if !self.shared.write_wait_queue.is_empty() {
                self.shared.write_wait_queue.notify_all(true);
            }
        }
        Ok(read_size)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        if !self.writable() {
            return Err(LinuxError::EPERM);
        }
        let mut write_size = 0usize;
        while write_size < buf.len() {
            if self.read_end_closed() {
                return if write_size > 0 {
                    Ok(write_size)
                } else {
                    Err(LinuxError::EPIPE)
                };
            }
            let zc = self.shared.zc_pages.lock();
            let mut ring_buffer = self.shared.buffer.lock();
            let available = pipe_available_write_bytes(
                ring_buffer.capacity(),
                ring_buffer.available_read(),
                zero_copy_bytes(&zc),
            );
            if available == 0 {
                let nonblocking = self.nonblocking.load(Ordering::Acquire);
                drop(ring_buffer);
                drop(zc);
                if write_size > 0 {
                    if !self.shared.read_wait_queue.is_empty() {
                        self.shared.read_wait_queue.notify_all(true);
                    }
                }
                if nonblocking {
                    return if write_size > 0 {
                        Ok(write_size)
                    } else {
                        Err(LinuxError::EAGAIN)
                    };
                }
                axlog::debug!(
                    "pipe write wait: tid={} shared={:p} read_closed={} nonblocking={} \
                     write_size={} want={}",
                    axtask::current().id().as_u64(),
                    Arc::as_ptr(&self.shared),
                    self.read_end_closed(),
                    self.nonblocking.load(Ordering::Acquire),
                    write_size,
                    buf.len()
                );
                self.shared.write_wait_queue.wait_until(|| {
                    self.available_pipe_write() > 0
                        || self.read_end_closed()
                        || Self::current_has_pending_signal()
                });
                if Self::current_has_pending_signal() {
                    return if write_size > 0 {
                        Ok(write_size)
                    } else {
                        Err(LinuxError::EINTR)
                    };
                }
                continue;
            }

            let chunk_limit = core::cmp::min(available, buf.len() - write_size);
            let written = ring_buffer.write_from(&buf[write_size..write_size + chunk_limit]);
            debug_assert_eq!(written, chunk_limit);
            write_size += written;

            drop(ring_buffer);
            drop(zc);
        }

        if write_size > 0 {
            if !self.shared.read_wait_queue.is_empty() {
                self.shared.read_wait_queue.notify_all(true);
            }
        }
        Ok(write_size)
    }

    fn stat(&self) -> LinuxResult<stat> {
        Ok(stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode: 0o10000 | 0o600u32,
            st_uid: 1000,
            st_gid: 1000,
            st_blksize: PIPE_PAGE_SIZE as _,
            ..empty_stat()
        })
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let zc = self.shared.zc_pages.lock();
        let buffer = self.shared.buffer.lock();
        let zc_len = zero_copy_bytes(&zc);
        let limit = core::cmp::min(PIPE_PAGE_SIZE, buffer.capacity());
        let avail_read = buffer.available_read().saturating_add(zc_len);
        let avail_write =
            pipe_available_write_bytes(buffer.capacity(), buffer.available_read(), zc_len);
        Ok(PollState {
            readable: self.readable && (avail_read > 0 || self.write_end_closed()),
            writable: self.writable() && (avail_write >= limit || self.read_end_closed()),
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult {
        self.nonblocking.store(nonblocking, Ordering::Release);
        Ok(())
    }

    fn wait_ready(&self, events: i16, deadline: Option<Duration>) -> LinuxResult<bool> {
        let wait_for_read = self.readable && (events & (POLLIN as i16)) != 0;
        let wait_for_write = self.writable() && (events & (POLLOUT as i16)) != 0;
        if !wait_for_read && !wait_for_write {
            return Err(LinuxError::EOPNOTSUPP);
        }

        if self.ready_for(wait_for_read, wait_for_write) {
            return Ok(true);
        }

        let wq = if wait_for_read {
            &self.shared.read_wait_queue
        } else {
            &self.shared.write_wait_queue
        };

        match deadline {
            Some(deadline) => {
                let now = axhal::time::monotonic_time();
                if now >= deadline {
                    return Ok(self.ready_for(wait_for_read, wait_for_write));
                }
                let remain = deadline - now;
                wq.wait_timeout_until(remain, || {
                    self.ready_for(wait_for_read, wait_for_write)
                        || Self::current_has_pending_signal()
                });
                if Self::current_has_pending_signal() {
                    return Err(LinuxError::EINTR);
                }
                Ok(self.ready_for(wait_for_read, wait_for_write))
            }
            None => {
                wq.wait_until(|| {
                    self.ready_for(wait_for_read, wait_for_write)
                        || Self::current_has_pending_signal()
                });
                if Self::current_has_pending_signal() {
                    return Err(LinuxError::EINTR);
                }
                Ok(true)
            }
        }
    }

    fn get_wait_queues<'a>(
        &'a self,
        events: i16,
        wqs: &mut alloc::vec::Vec<&'a axtask::WaitQueue>,
    ) -> LinuxResult<bool> {
        let mut supported = false;
        if self.readable && (events & (POLLIN as i16)) != 0 {
            wqs.push(&self.shared.read_wait_queue);
            supported = true;
        }
        if self.writable && (events & (POLLOUT as i16)) != 0 {
            wqs.push(&self.shared.write_wait_queue);
            supported = true;
        }
        Ok(supported || events == 0)
    }

    fn register_poll(
        self: Arc<Self>,
        cx: &mut core::task::Context<'_>,
        events: axpoll::IoEvents,
        registrations: &mut Vec<PollRegistration>,
    ) -> LinuxResult {
        if self.readable && events.intersects(axpoll::IoEvents::IN | axpoll::IoEvents::RDHUP) {
            let owner = self.clone();
            let registration = owner
                .shared
                .read_wait_queue
                .register_owned_waker(cx.waker());
            registrations.push(PollRegistration::new(move || {
                owner.shared.read_wait_queue.unregister_waker(registration);
            }));
        }
        if self.writable && events.contains(axpoll::IoEvents::OUT) {
            let owner = self.clone();
            let registration = owner
                .shared
                .write_wait_queue
                .register_owned_waker(cx.waker());
            registrations.push(PollRegistration::new(move || {
                owner.shared.write_wait_queue.unregister_waker(registration);
            }));
        }
        Ok(())
    }

    fn allocate(&self, _mode: u32, _offset: u64, _len: u64) -> LinuxResult {
        Err(LinuxError::ESPIPE)
    }
}

impl Drop for PipeObject {
    fn drop(&mut self) {
        let owner = self as *const PipeObject as *const () as usize;
        crate::flock::flock_release_owner(owner);
        if self.readable {
            self.shared.reader_count.fetch_sub(1, Ordering::AcqRel);
            self.shared.write_wait_queue.notify_all(false);
        }
        if self.writable {
            self.shared.writer_count.fetch_sub(1, Ordering::AcqRel);
            self.shared.read_wait_queue.notify_all(false);
        }
    }
}
pub fn pipe_entries(flags: FdFlags) -> (FdEntry, FdEntry) {
    let (read_end, write_end) = PipeObject::new_pair();
    let read_object: Arc<dyn FdObject> = Arc::new(read_end);
    let write_object: Arc<dyn FdObject> = Arc::new(write_end);
    if flags.contains(FdFlags::NONBLOCK) {
        let _ = read_object.set_nonblocking(true);
        let _ = write_object.set_nonblocking(true);
    }
    (
        FdEntry::new(read_object, flags),
        FdEntry::new(write_object, flags),
    )
}

pub fn eventfd_entry(initval: u32, semaphore: bool, flags: FdFlags) -> FdEntry {
    let object: Arc<dyn FdObject> = Arc::new(EventFdObject::new(
        initval,
        semaphore,
        flags.contains(FdFlags::NONBLOCK),
    ));
    FdEntry::new(object, flags)
}

const FIFO_REGISTRY_SHARDS: usize = 32;

fn fifo_registry_shard(device: u64, inode: u64) -> usize {
    ((device as usize).rotate_left(13) ^ (inode as usize).rotate_right(7)) % FIFO_REGISTRY_SHARDS
}

static FIFO_REGISTRY: Lazy<[Mutex<BTreeMap<(u64, u64), Weak<PipeShared>>>; FIFO_REGISTRY_SHARDS]> =
    Lazy::new(|| core::array::from_fn(|_| Mutex::new(BTreeMap::new())));

pub fn get_or_create_fifo_shared(device: u64, inode: u64) -> Arc<PipeShared> {
    let mut registry = FIFO_REGISTRY[fifo_registry_shard(device, inode)].lock();
    registry.retain(|_, w| w.strong_count() > 0);
    let key = (device, inode);
    if let Some(shared) = registry.get(&key).and_then(|w| w.upgrade()) {
        shared
    } else {
        let shared = Arc::new(PipeShared::new_fifo());
        registry.insert(key, Arc::downgrade(&shared));
        shared
    }
}

pub fn create_fifo_entry(
    device: u64,
    inode: u64,
    readable: bool,
    writable: bool,
    flags: FdFlags,
) -> LinuxResult<FdEntry> {
    let shared = get_or_create_fifo_shared(device, inode);
    let nonblock = flags.contains(FdFlags::NONBLOCK);

    if writable && !readable && nonblock && shared.reader_count.load(Ordering::Acquire) == 0 {
        return Err(LinuxError::ENXIO);
    }

    if readable {
        shared.reader_count.fetch_add(1, Ordering::AcqRel);
        // Wake up any waiting writers
        shared.write_wait_queue.notify_all(true);
    }
    if writable {
        shared.writer_count.fetch_add(1, Ordering::AcqRel);
        // Wake up any waiting readers
        shared.read_wait_queue.notify_all(true);
    }

    if readable && !nonblock && shared.writer_count.load(Ordering::Acquire) == 0 {
        shared.read_wait_queue.wait_until(|| {
            shared.writer_count.load(Ordering::Acquire) > 0 || crate::task::current_have_signals()
        });
        if crate::task::current_have_signals() {
            shared.reader_count.fetch_sub(1, Ordering::AcqRel);
            return Err(LinuxError::EINTR);
        }
    }

    if writable && !nonblock && shared.reader_count.load(Ordering::Acquire) == 0 {
        shared.write_wait_queue.wait_until(|| {
            shared.reader_count.load(Ordering::Acquire) > 0 || crate::task::current_have_signals()
        });
        if crate::task::current_have_signals() {
            shared.writer_count.fetch_sub(1, Ordering::AcqRel);
            return Err(LinuxError::EINTR);
        }
    }

    let object = Arc::new(PipeObject::new_fifo(
        shared,
        readable,
        writable,
        Some((device, inode)),
    ));
    if flags.contains(FdFlags::NONBLOCK) {
        let _ = object.set_nonblocking(true);
    }
    Ok(FdEntry::new(object, flags))
}

pub fn run_pipe_guest_checks() -> Result<(), LinuxError> {
    axlog::ax_println!("[PIPE_GUEST] Starting pipe zero-copy and batch dealloc checks...");

    let process = crate::task::current_process()?;
    let aspace = process.aspace_handle();

    // Helper to allocate and mark a physical frame
    let alloc_frame = || -> Result<PhysAddr, LinuxError> {
        let vaddr = axalloc::global_allocator()
            .alloc_pages(1, axhal::mem::PAGE_SIZE_4K)
            .map_err(|_| LinuxError::ENOMEM)?;
        let frame = axhal::mem::virt_to_phys(VirtAddr::from(vaddr));
        let table = axalloc::frame_table();
        if table.contains(frame) {
            table.mark_used(frame);
        }
        Ok(frame)
    };

    // 1. Multi-page zero-copy read batching:
    // Gather and scatter 3 pages in a single batch.
    {
        let (read_end, _write_end) = PipeObject::new_pair();
        let f0 = alloc_frame()?;
        let f1 = alloc_frame()?;
        let f2 = alloc_frame()?;

        unsafe {
            let p0 = axhal::mem::phys_to_virt(f0).as_mut_ptr();
            core::ptr::write_bytes(p0, 0x11, PIPE_PAGE_SIZE);
            let p1 = axhal::mem::phys_to_virt(f1).as_mut_ptr();
            core::ptr::write_bytes(p1, 0x22, PIPE_PAGE_SIZE);
            let p2 = axhal::mem::phys_to_virt(f2).as_mut_ptr();
            core::ptr::write_bytes(p2, 0x33, PIPE_PAGE_SIZE);
        }

        {
            let mut zc = read_end.shared.zc_pages.lock();
            zc.push_back(ZeroCopyPage { paddr: f0, offset: 0, len: PIPE_PAGE_SIZE });
            zc.push_back(ZeroCopyPage { paddr: f1, offset: 0, len: PIPE_PAGE_SIZE });
            zc.push_back(ZeroCopyPage { paddr: f2, offset: 0, len: PIPE_PAGE_SIZE });
        }

        let test_va = 0x2000_0000;
        let bytes_read = read_end.read_zerocopy(test_va, 3 * PIPE_PAGE_SIZE)?;
        assert_eq!(bytes_read, 3 * PIPE_PAGE_SIZE, "multi-page read_zerocopy byte count");
        assert!(read_end.shared.zc_pages.lock().is_empty(), "zc_pages queue should be empty");

        let mut verify_buf = alloc::vec![0u8; PIPE_PAGE_SIZE];
        process.read_user_bytes(test_va, &mut verify_buf)?;
        assert_eq!(verify_buf[0], 0x11);
        assert_eq!(verify_buf[PIPE_PAGE_SIZE - 1], 0x11);

        process.read_user_bytes(test_va + PIPE_PAGE_SIZE, &mut verify_buf)?;
        assert_eq!(verify_buf[0], 0x22);
        assert_eq!(verify_buf[PIPE_PAGE_SIZE - 1], 0x22);

        process.read_user_bytes(test_va + 2 * PIPE_PAGE_SIZE, &mut verify_buf)?;
        assert_eq!(verify_buf[0], 0x33);
        assert_eq!(verify_buf[PIPE_PAGE_SIZE - 1], 0x33);

        let _ = aspace.write().unmap(VirtAddr::from(test_va), 3 * PIPE_PAGE_SIZE);
    }
    axlog::ax_println!("[PIPE_GUEST] Multi-page zero-copy read: PASS");

    // 2. Partial page fallback:
    {
        let (read_end, _write_end) = PipeObject::new_pair();
        let f = alloc_frame()?;
        unsafe {
            let p = axhal::mem::phys_to_virt(f).as_mut_ptr();
            core::ptr::write_bytes(p.add(64), 0x77, 128);
        }
        {
            let mut zc = read_end.shared.zc_pages.lock();
            zc.push_back(ZeroCopyPage { paddr: f, offset: 64, len: 128 });
        }

        let test_va = crate::config::USER_STACK_TOP - 0x10000;
        let bytes_read = read_end.read_zerocopy(test_va, PIPE_PAGE_SIZE)?;
        assert_eq!(bytes_read, 128, "partial-page fallback byte count");
        assert!(read_end.shared.zc_pages.lock().is_empty(), "partial page should be consumed");

        let mut verify_buf = [0u8; 128];
        process.read_user_bytes(test_va, &mut verify_buf)?;
        assert!(verify_buf.iter().all(|&b| b == 0x77), "partial page content verified");
    }
    axlog::ax_println!("[PIPE_GUEST] Partial-page fallback: PASS");

    // 3. Remap failure rollback & FIFO restoration:
    // 3a. Failure on first page (unaligned user address): returns error, all pages restored in FIFO order
    {
        let (read_end, _write_end) = PipeObject::new_pair();
        let f0 = alloc_frame()?;
        let f1 = alloc_frame()?;
        let f2 = alloc_frame()?;

        {
            let mut zc = read_end.shared.zc_pages.lock();
            zc.push_back(ZeroCopyPage { paddr: f0, offset: 0, len: PIPE_PAGE_SIZE });
            zc.push_back(ZeroCopyPage { paddr: f1, offset: 0, len: PIPE_PAGE_SIZE });
            zc.push_back(ZeroCopyPage { paddr: f2, offset: 0, len: PIPE_PAGE_SIZE });
        }

        // Unaligned address 0x2200_0001 causes remap_page to fail on page 0
        let res = read_end.read_zerocopy(0x2200_0001, 3 * PIPE_PAGE_SIZE);
        assert!(res.is_err(), "unaligned address must return error");

        let zc = read_end.shared.zc_pages.lock();
        assert_eq!(zc.len(), 3, "all 3 pages restored to queue");
        assert_eq!(zc[0].paddr, f0, "page 0 in front");
        assert_eq!(zc[1].paddr, f1, "page 1 in middle");
        assert_eq!(zc[2].paddr, f2, "page 2 in back");
        drop(zc);

        // Clean up
        let mut zc = read_end.shared.zc_pages.lock();
        let paddrs: alloc::vec::Vec<PhysAddr> = zc.drain(..).map(|p| p.paddr).collect();
        drop(zc);
        dealloc_physical_frames(&paddrs);
    }
    axlog::ax_println!("[PIPE_GUEST] Remap failure total rollback: PASS");

    // 3b. Failure on subsequent page: short read returned, remaining pages restored in FIFO order
    {
        let (read_end, _write_end) = PipeObject::new_pair();
        let f0 = alloc_frame()?;
        let f1 = alloc_frame()?;
        let f2 = alloc_frame()?;

        {
            let mut zc = read_end.shared.zc_pages.lock();
            zc.push_back(ZeroCopyPage { paddr: f0, offset: 0, len: PIPE_PAGE_SIZE });
            zc.push_back(ZeroCopyPage { paddr: f1, offset: 0, len: PIPE_PAGE_SIZE });
            zc.push_back(ZeroCopyPage { paddr: f2, offset: 0, len: PIPE_PAGE_SIZE });
        }

        // Address at the end of user space so page 0 succeeds but page 1 is out of range
        let border_va = crate::config::USER_SPACE_BASE + crate::config::USER_SPACE_SIZE - PIPE_PAGE_SIZE;
        let bytes_read = read_end.read_zerocopy(border_va, 3 * PIPE_PAGE_SIZE)?;
        assert_eq!(bytes_read, PIPE_PAGE_SIZE, "short read returns mapped page count");

        let zc = read_end.shared.zc_pages.lock();
        assert_eq!(zc.len(), 2, "2 unconsumed pages restored to queue");
        assert_eq!(zc[0].paddr, f1, "page 1 in front");
        assert_eq!(zc[1].paddr, f2, "page 2 in back");
        drop(zc);

        // Clean up
        let mut zc = read_end.shared.zc_pages.lock();
        let paddrs: alloc::vec::Vec<PhysAddr> = zc.drain(..).map(|p| p.paddr).collect();
        drop(zc);
        dealloc_physical_frames(&paddrs);

        let _ = aspace.write().unmap(VirtAddr::from(border_va), PIPE_PAGE_SIZE);
    }
    axlog::ax_println!("[PIPE_GUEST] Remap partial failure short read & restoration: PASS");

    // 4. PipeObject::read multi-page consumption & lock-free batch frame deallocation
    {
        let (read_end, _write_end) = PipeObject::new_pair();
        let f0 = alloc_frame()?;
        let f1 = alloc_frame()?;
        let f2 = alloc_frame()?;
        let f3 = alloc_frame()?;

        unsafe {
            let p0 = axhal::mem::phys_to_virt(f0).as_mut_ptr();
            core::ptr::write_bytes(p0, 0x41, PIPE_PAGE_SIZE);
            let p1 = axhal::mem::phys_to_virt(f1).as_mut_ptr();
            core::ptr::write_bytes(p1, 0x42, PIPE_PAGE_SIZE);
            let p2 = axhal::mem::phys_to_virt(f2).as_mut_ptr();
            core::ptr::write_bytes(p2, 0x43, PIPE_PAGE_SIZE);
            let p3 = axhal::mem::phys_to_virt(f3).as_mut_ptr();
            core::ptr::write_bytes(p3, 0x44, PIPE_PAGE_SIZE);
        }

        {
            let mut zc = read_end.shared.zc_pages.lock();
            zc.push_back(ZeroCopyPage { paddr: f0, offset: 0, len: PIPE_PAGE_SIZE });
            zc.push_back(ZeroCopyPage { paddr: f1, offset: 0, len: PIPE_PAGE_SIZE });
            zc.push_back(ZeroCopyPage { paddr: f2, offset: 0, len: PIPE_PAGE_SIZE });
            zc.push_back(ZeroCopyPage { paddr: f3, offset: 0, len: PIPE_PAGE_SIZE });
        }

        let mut read_buf = alloc::vec![0u8; 4 * PIPE_PAGE_SIZE];
        let bytes_read = read_end.read(&mut read_buf)?;
        assert_eq!(bytes_read, 4 * PIPE_PAGE_SIZE, "read consumes all 4 pages");
        assert!(read_end.shared.zc_pages.lock().is_empty(), "zc_pages is empty");

        assert_eq!(read_buf[0], 0x41);
        assert_eq!(read_buf[PIPE_PAGE_SIZE], 0x42);
        assert_eq!(read_buf[2 * PIPE_PAGE_SIZE], 0x43);
        assert_eq!(read_buf[3 * PIPE_PAGE_SIZE], 0x44);

        // Frames were freed; verify refcount dropped to 0
        let table = axalloc::frame_table();
        assert_eq!(table.get_ref(f0), 0);
        assert_eq!(table.get_ref(f1), 0);
        assert_eq!(table.get_ref(f2), 0);
        assert_eq!(table.get_ref(f3), 0);
    }
    axlog::ax_println!("[PIPE_GUEST] Lock-outside batch dealloc in read: PASS");

    // 5. Closed-pipe unconsumed pages cleanup during rollback:
    {
        let (read_end, _write_end) = PipeObject::new_pair();
        let f0 = alloc_frame()?;
        let f1 = alloc_frame()?;

        {
            let mut zc = read_end.shared.zc_pages.lock();
            zc.push_back(ZeroCopyPage { paddr: f0, offset: 0, len: PIPE_PAGE_SIZE });
            zc.push_back(ZeroCopyPage { paddr: f1, offset: 0, len: PIPE_PAGE_SIZE });
        }

        // Simulate closed reader count on this pipe
        read_end.shared.reader_count.store(0, Ordering::Release);
        assert!(read_end.read_end_closed());

        // Calling read_zerocopy with an invalid/unaligned address causes remap to fail on page 0
        let res = read_end.read_zerocopy(0x2200_0001, 2 * PIPE_PAGE_SIZE);
        assert!(res.is_err(), "must fail remap");

        // Because read_end_closed() was true, rollback directly frees unconsumed pages outside lock
        assert!(read_end.shared.zc_pages.lock().is_empty(), "zc_pages must be empty");

        let table = axalloc::frame_table();
        assert_eq!(table.get_ref(f0), 0, "frame 0 freed");
        assert_eq!(table.get_ref(f1), 0, "frame 1 freed");
    }
    axlog::ax_println!("[PIPE_GUEST] Closed-pipe cleanup: PASS");

    axlog::ax_println!("[PIPE_GUEST] All pipe checks PASSED!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_order_preserves_fifo_sequence() {
        let mut queue = alloc::collections::VecDeque::new();
        let gathered = alloc::vec![
            ZeroCopyPage { paddr: PhysAddr::from(0x1000), offset: 0, len: 4096 },
            ZeroCopyPage { paddr: PhysAddr::from(0x2000), offset: 0, len: 4096 },
            ZeroCopyPage { paddr: PhysAddr::from(0x3000), offset: 0, len: 4096 },
        ];
        queue.push_back(ZeroCopyPage { paddr: PhysAddr::from(0x4000), offset: 0, len: 4096 });

        let unconsumed: alloc::vec::Vec<ZeroCopyPage> = gathered.into_iter().skip(1).collect();
        for page in unconsumed.into_iter().rev() {
            queue.push_front(page);
        }

        assert_eq!(queue.len(), 3);
        assert_eq!(queue[0].paddr, PhysAddr::from(0x2000));
        assert_eq!(queue[1].paddr, PhysAddr::from(0x3000));
        assert_eq!(queue[2].paddr, PhysAddr::from(0x4000));
    }

    #[test]
    fn zero_copy_pages_cannot_bypass_pipe_capacity() {
        let capacity = 64 * 1024;
        assert_eq!(pipe_available_write_bytes(capacity, 0, 0), capacity);
        let trailing_bytes =
            pipe_available_write_bytes(capacity, 15 * PIPE_PAGE_SIZE, PIPE_PAGE_SIZE - 1);
        assert_eq!(trailing_bytes, 1);
        assert_eq!(trailing_bytes / PIPE_PAGE_SIZE, 0);
        assert_eq!(
            pipe_available_write_bytes(capacity, 0, 15 * PIPE_PAGE_SIZE) / PIPE_PAGE_SIZE,
            1
        );
        assert_eq!(
            pipe_available_write_bytes(capacity, 0, 16 * PIPE_PAGE_SIZE),
            0
        );
    }

    #[test]
    fn ring_buffer_wraps_without_exposing_uninitialized_slots() {
        let mut ring = PipeRingBuffer::new(8);
        assert_eq!(ring.write_from(b"abcdef"), 6);

        let mut first = [0u8; 4];
        assert_eq!(ring.read_into(&mut first), 4);
        assert_eq!(&first, b"abcd");

        assert_eq!(ring.write_from(b"WXYZ"), 4);
        let mut remaining = [0u8; 6];
        assert_eq!(ring.read_into(&mut remaining), 6);
        assert_eq!(&remaining, b"efWXYZ");
        assert_eq!(ring.available_read(), 0);
    }

    #[test]
    fn same_size_resize_keeps_the_existing_backing_allocation() {
        let mut ring = PipeRingBuffer::new(8);
        assert_eq!(ring.write_from(b"abcdef"), 6);
        let backing = ring.arr.as_ptr();

        ring.resize(8).unwrap();
        assert_eq!(ring.arr.as_ptr(), backing);

        let mut data = [0u8; 6];
        assert_eq!(ring.read_into(&mut data), 6);
        assert_eq!(&data, b"abcdef");
    }

    #[test]
    fn resize_preserves_unread_bytes_across_wraparound() {
        let mut ring = PipeRingBuffer::new(8);
        assert_eq!(ring.write_from(b"abcdef"), 6);
        let mut first = [0u8; 4];
        assert_eq!(ring.read_into(&mut first), 4);
        assert_eq!(ring.write_from(b"WXYZ"), 4);

        ring.resize(16).unwrap();
        let mut remaining = [0u8; 6];
        assert_eq!(ring.read_into(&mut remaining), 6);
        assert_eq!(&remaining, b"efWXYZ");
    }
}
