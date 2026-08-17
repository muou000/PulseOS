use super::*;

const KERNEL_SIGSET_SIZE: usize = core::mem::size_of::<u64>();
// Some POSIX software uses select(0, ..., 1us) as a cooperative barrier
// poll.  Programming a task timer for such a duration costs substantially
// more than the requested delay and can flood the per-CPU timer heap.
const SHORT_TIMEOUT_YIELD_LIMIT: Duration = Duration::from_micros(10);

#[repr(C)]
#[derive(Clone, Copy)]
struct Pselect6Sigmask {
    sigmask: usize,
    sigsetsize: usize,
}

fn read_temporary_signal_mask(
    process: &pulse_core::task::Process,
    sigmask: usize,
    sigsetsize: usize,
) -> Result<Option<u64>, LinuxError> {
    if sigmask == 0 {
        return Ok(None);
    }
    if sigsetsize != KERNEL_SIGSET_SIZE {
        return Err(LinuxError::EINVAL);
    }
    process
        .read_user_usize(sigmask)
        .map(|mask| Some(mask as u64))
        .map_err(|_| LinuxError::EFAULT)
}

fn read_pselect6_signal_mask(
    process: &pulse_core::task::Process,
    sigmask_arg: usize,
) -> Result<Option<u64>, LinuxError> {
    if sigmask_arg == 0 {
        return Ok(None);
    }
    let arg = uaccess::read_user_plain::<Pselect6Sigmask>(process, sigmask_arg)
        .map_err(|_| LinuxError::EFAULT)?;
    read_temporary_signal_mask(process, arg.sigmask, arg.sigsetsize)
}

/// Waits for an unblocked signal or the supplied timeout.  A zero timeout is
/// still interrupted by an already-pending signal, as Linux's poll/select
/// paths test for signals after their nonblocking readiness scan.
fn wait_for_signal_or_timeout(
    thread: &pulse_core::task::Thread,
    timeout: Option<Duration>,
) -> bool {
    if thread.has_pending_signal() {
        return true;
    }

    match timeout {
        Some(timeout) if timeout > Duration::ZERO && timeout <= SHORT_TIMEOUT_YIELD_LIMIT => {
            let deadline = axhal::time::monotonic_time() + timeout;

            // Keep the wait cooperative without creating a timer entry.  A
            // scheduler handoff normally exceeds this tiny interval; the
            // bounded busy wait only preserves the timeout lower bound when
            // it returns unusually early.
            axtask::yield_now();
            if thread.has_pending_signal() {
                return true;
            }
            if axhal::time::monotonic_time() < deadline {
                axhal::time::busy_wait_until(deadline);
            }
            thread.has_pending_signal()
        }
        Some(timeout) if timeout > Duration::ZERO => {
            thread
                .signal_wait_queue()
                .wait_timeout_until(timeout, || thread.has_pending_signal());
            thread.has_pending_signal()
        }
        Some(_) => false,
        None => {
            thread
                .signal_wait_queue()
                .wait_until(|| thread.has_pending_signal());
            true
        }
    }
}

type PollObject = alloc::sync::Arc<dyn FdObject>;

fn snapshot_poll_objects(
    pollfds: &[pollfd],
) -> Result<alloc::vec::Vec<Option<PollObject>>, LinuxError> {
    get_fd_objects(pollfds.iter().map(|pfd| pfd.fd as usize))
}

fn poll_fds_once(pollfds: &mut [pollfd], objects: &[Option<PollObject>]) -> usize {
    let mut ready = 0usize;
    for (index, pfd) in pollfds.iter_mut().enumerate() {
        pfd.revents = 0;
        if pfd.fd < 0 {
            continue;
        }

        match objects.get(index).and_then(Option::as_ref) {
            Some(object) => match object.poll() {
                Ok(state) => {
                    pfd.revents = requested_poll_revents(pfd.events, state);
                    if pfd.revents != 0 {
                        ready += 1;
                    }
                }
                Err(_) => {
                    pfd.revents = POLLERR as i16;
                    ready += 1;
                }
            },
            None => {
                pfd.revents = POLLNVAL as i16;
                ready += 1;
            }
        }
    }
    ready
}

pub fn sys_ppoll(
    fds: usize,
    nfds: usize,
    timeout: usize,
    sigmask: usize,
    sigsetsize: usize,
) -> isize {
    let timeout_dur = match read_ppoll_timeout(timeout) {
        Ok(timeout_dur) => timeout_dur,
        Err(e) => return -e.code() as isize,
    };

    let thread = match pulse_core::task::current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    let temporary_mask =
        match read_temporary_signal_mask(thread.process().as_ref(), sigmask, sigsetsize) {
            Ok(mask) => mask,
            Err(e) => return -e.code() as isize,
        };
    let _mask_guard = pulse_core::task::SignalMaskGuard::install(thread.clone(), temporary_mask);

    if nfds == 0 {
        if wait_for_signal_or_timeout(thread.as_ref(), timeout_dur) {
            return -LinuxError::EINTR.code() as isize;
        }
        return 0;
    }
    if fds == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if nfds > FD_LIMIT {
        return -LinuxError::EINVAL.code() as isize;
    }

    let mut pollfds = match with_process(|process| {
        uaccess::read_user_plain_array::<pollfd>(process, fds, nfds)
    }) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => match e {
            AxError::NoMemory => return -LinuxError::ENOMEM.code() as isize,
            _ => return -LinuxError::EFAULT.code() as isize,
        },
        Err(e) => return -e.code() as isize,
    };

    let deadline = timeout_dur.map(|timeout_dur| axhal::time::monotonic_time() + timeout_dur);

    let write_back = |pollfds: &[pollfd], ready: isize| -> isize {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                pollfds.as_ptr().cast::<u8>(),
                pollfds.len() * core::mem::size_of::<pollfd>(),
            )
        };
        write_user_bytes(fds, bytes)
            .map(|_| ready)
            .unwrap_or_else(|_| -LinuxError::EFAULT.code() as isize)
    };

    let objects = match snapshot_poll_objects(&pollfds) {
        Ok(objects) => objects,
        Err(e) => return -e.code() as isize,
    };

    // Linux poll reports an invalid descriptor in-band through POLLNVAL.  Do
    // this scan before gathering wait queues so the blocking path never turns
    // that per-entry result into an EBADF syscall failure.
    let ready = poll_fds_once(&mut pollfds, &objects);
    if ready > 0 {
        return write_back(&pollfds, ready as isize);
    }

    // Try to retrieve wait queues for all monitored file descriptors.
    // If all monitored fds support wait queues, we can block on them event-driven.
    let mut wait_objects = alloc::vec::Vec::with_capacity(nfds.min(128));
    let mut all_wqs_supported = true;
    for (pfd, object) in pollfds.iter().zip(objects.iter()) {
        if pfd.fd < 0 {
            continue;
        }
        if all_wqs_supported {
            if let Some(object) = object {
                let mut dummy = alloc::vec::Vec::new();
                match object.get_wait_queues(pfd.events, &mut dummy) {
                    Ok(true) => {
                        // Keep the same object reference for the wait and
                        // every readiness recheck in this syscall.
                        wait_objects.push((object.clone(), pfd.events));
                    }
                    _ => {
                        all_wqs_supported = false;
                    }
                }
            } else {
                all_wqs_supported = false;
            }
        }
    }

    if all_wqs_supported && !wait_objects.is_empty() {
        let mut wqs = alloc::vec::Vec::with_capacity(wait_objects.len().saturating_add(1).min(128));
        for (obj, events) in &wait_objects {
            let _ = obj.get_wait_queues(*events, &mut wqs);
        }
        wqs.push(thread.signal_wait_queue());

        // Wait until one or more monitored objects become ready, a signal is pending,
        // or the timeout is reached.
        let check_ready = || {
            for (obj, events) in &wait_objects {
                if let Ok(state) = obj.poll() {
                    if requested_poll_revents(*events, state) != 0 {
                        return true;
                    }
                } else {
                    return true;
                }
            }
            thread.has_pending_signal()
        };

        // Hybrid active-yield strategy for event-driven path:
        // - For high-frequency IPC, keep a short active-yield phase;
        // - If ready, we can return immediately without enrolling in any wait queues.
        const POLL_ACTIVE_YIELD_ROUNDS: usize = 64;
        let mut yield_success = false;
        for _ in 0..POLL_ACTIVE_YIELD_ROUNDS {
            if check_ready() {
                yield_success = true;
                break;
            }
            if let Some(ddl) = deadline {
                if axhal::time::monotonic_time() >= ddl {
                    break;
                }
            }
            axtask::yield_now();
        }

        if !yield_success {
            loop {
                if check_ready() {
                    break;
                }

                // Recalculate the remaining duration after every wake. A wait queue
                // notification only means that readiness may have changed; it is not
                // itself a reason for ppoll() to return.
                let remain_dur = deadline.map(|ddl| {
                    let now = axhal::time::monotonic_time();
                    if now >= ddl {
                        Duration::ZERO
                    } else {
                        ddl - now
                    }
                });

                if let Some(Duration::ZERO) = remain_dur {
                    break;
                }

                let wait_result =
                    axtask::WaitQueue::wait_multiple_timeout_until(&wqs, remain_dur, || {
                        check_ready()
                    });
                if matches!(wait_result, Err(true)) {
                    break;
                }
            }
        }

        // Poll readiness takes precedence over a concurrently pending signal.
        let ready = poll_fds_once(&mut pollfds, &objects);
        if ready > 0 {
            return write_back(&pollfds, ready as isize);
        }
        if thread.has_pending_signal() {
            return write_back(&pollfds, -LinuxError::EINTR.code() as isize);
        }
        return write_back(&pollfds, 0);
    }

    // Hybrid wait strategy:
    // - keep a short active-yield phase for high-frequency IPC readiness;
    // - then fall back to short sleeps to avoid permanent hot spinning.
    const POLL_ACTIVE_YIELD_ROUNDS: usize = 64;
    const POLL_SLEEP_QUANTUM: Duration = Duration::from_micros(100);
    let mut idle_rounds: usize = 0;

    loop {
        let ready = poll_fds_once(&mut pollfds, &objects);

        if ready > 0 {
            return write_back(&pollfds, ready as isize);
        }

        if thread.has_pending_signal() {
            return write_back(&pollfds, -LinuxError::EINTR.code() as isize);
        }

        if let Some(deadline) = deadline {
            let now = axhal::time::monotonic_time();
            if now >= deadline {
                return write_back(&pollfds, 0);
            }
            idle_rounds = idle_rounds.saturating_add(1);
            if idle_rounds <= POLL_ACTIVE_YIELD_ROUNDS {
                axtask::yield_now();
            } else {
                let sleep_dur = core::cmp::min(deadline - now, POLL_SLEEP_QUANTUM);
                if sleep_dur > Duration::ZERO {
                    thread
                        .signal_wait_queue()
                        .wait_timeout_until(sleep_dur, || thread.has_pending_signal());
                } else {
                    axtask::yield_now();
                }
            }
        } else {
            idle_rounds = idle_rounds.saturating_add(1);
            if idle_rounds <= POLL_ACTIVE_YIELD_ROUNDS {
                axtask::yield_now();
            } else {
                thread
                    .signal_wait_queue()
                    .wait_timeout_until(POLL_SLEEP_QUANTUM, || thread.has_pending_signal());
            }
        }
    }
}
// Complete pselect6 implementation.
#[repr(C)]
#[derive(Clone, Copy)]
struct FdSet {
    fds_bits: [u64; 16],
}

impl FdSet {
    fn is_set(&self, fd: usize) -> bool {
        if fd >= 1024 {
            return false;
        }
        let idx = fd / 64;
        let bit = fd % 64;
        (self.fds_bits[idx] & (1 << bit)) != 0
    }

    fn set(&mut self, fd: usize) {
        if fd >= 1024 {
            return;
        }
        let idx = fd / 64;
        let bit = fd % 64;
        self.fds_bits[idx] |= 1 << bit;
    }

    fn zero() -> Self {
        Self { fds_bits: [0; 16] }
    }
}

#[inline]
fn pselect_events_for_fd(
    fd: usize,
    has_read: bool,
    in_read: &FdSet,
    has_write: bool,
    in_write: &FdSet,
    has_except: bool,
    in_except: &FdSet,
) -> i16 {
    let mut events = 0i16;
    if has_read && in_read.is_set(fd) {
        events |= POLLIN as i16;
    }
    if has_write && in_write.is_set(fd) {
        events |= POLLOUT as i16;
    }
    if has_except && in_except.is_set(fd) {
        events |= linux_raw_sys::general::POLLPRI as i16;
    }
    events
}

pub fn sys_pselect6(
    nfds: usize,
    readfds: usize,
    writefds: usize,
    exceptfds: usize,
    timeout: usize,
    sigmask: usize,
) -> isize {
    axlog::debug!(
        "sys_pselect6 <= nfds: {nfds}, readfds: {readfds:#x}, writefds: {writefds:#x}, exceptfds: \
         {exceptfds:#x}, timeout: {timeout:#x}"
    );

    if nfds > 1024 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let thread = match pulse_core::task::current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();

    let timeout_dur = if timeout != 0 {
        let ts = match read_user_timespec(timeout) {
            Ok(ts) => ts,
            Err(e) => return -e.code() as isize,
        };
        if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
            return -LinuxError::EINVAL.code() as isize;
        }
        Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
    } else {
        None
    };

    let temporary_mask = match read_pselect6_signal_mask(process.as_ref(), sigmask) {
        Ok(mask) => mask,
        Err(e) => return -e.code() as isize,
    };
    let _mask_guard = pulse_core::task::SignalMaskGuard::install(thread.clone(), temporary_mask);

    let mut in_read = FdSet::zero();
    let mut in_write = FdSet::zero();
    let mut in_except = FdSet::zero();

    let has_read = readfds != 0;
    let has_write = writefds != 0;
    let has_except = exceptfds != 0;

    if has_read {
        match uaccess::read_user_plain::<FdSet>(process.as_ref(), readfds) {
            Ok(fds) => in_read = fds,
            Err(_) => return -LinuxError::EFAULT.code() as isize,
        }
    }
    if has_write {
        match uaccess::read_user_plain::<FdSet>(process.as_ref(), writefds) {
            Ok(fds) => in_write = fds,
            Err(_) => return -LinuxError::EFAULT.code() as isize,
        }
    }
    if has_except {
        match uaccess::read_user_plain::<FdSet>(process.as_ref(), exceptfds) {
            Ok(fds) => in_except = fds,
            Err(_) => return -LinuxError::EFAULT.code() as isize,
        }
    }

    if axlog::log_enabled!(axlog::Level::Debug) {
        let mut read_fds = alloc::vec::Vec::with_capacity(nfds.min(1024));
        let mut write_fds = alloc::vec::Vec::with_capacity(nfds.min(1024));
        let mut except_fds = alloc::vec::Vec::with_capacity(nfds.min(1024));
        for fd in 0..nfds.min(1024) {
            if has_read && in_read.is_set(fd) {
                read_fds.push(fd);
            }
            if has_write && in_write.is_set(fd) {
                write_fds.push(fd);
            }
            if has_except && in_except.is_set(fd) {
                except_fds.push(fd);
            }
        }
        axlog::debug!(
            "sys_pselect6 => read_fds: {:?}, write_fds: {:?}, except_fds: {:?}",
            read_fds,
            write_fds,
            except_fds
        );
    }

    let limit = nfds.min(1024);
    let mut pollfds = alloc::vec::Vec::with_capacity(limit);
    let word_count = limit.saturating_add(63) / 64;
    for word_idx in 0..word_count {
        let mut bits = 0u64;
        if has_read {
            bits |= in_read.fds_bits[word_idx];
        }
        if has_write {
            bits |= in_write.fds_bits[word_idx];
        }
        if has_except {
            bits |= in_except.fds_bits[word_idx];
        }
        if word_idx + 1 == word_count && limit % 64 != 0 {
            bits &= (1u64 << (limit % 64)) - 1;
        }
        while bits != 0 {
            let bit = bits.trailing_zeros() as usize;
            let fd = word_idx * 64 + bit;
            let events = pselect_events_for_fd(
                fd, has_read, &in_read, has_write, &in_write, has_except, &in_except,
            );
            if events != 0 {
                pollfds.push(pollfd {
                    fd: fd as i32,
                    events,
                    revents: 0,
                });
            }
            bits &= bits - 1;
        }
    }

    if axlog::log_enabled!(axlog::Level::Debug) {
        axlog::debug!(
            "sys_pselect6 => pollfds collected: {:?}",
            pollfds
                .iter()
                .map(|p| (p.fd, p.events))
                .collect::<alloc::vec::Vec<_>>()
        );
    }

    if pollfds.is_empty() {
        if wait_for_signal_or_timeout(thread.as_ref(), timeout_dur) {
            return -LinuxError::EINTR.code() as isize;
        }
        axlog::debug!("sys_pselect6 => empty pollfds, returning 0");
        return 0;
    }

    let objects = match get_fd_objects(pollfds.iter().map(|pfd| pfd.fd as usize)) {
        Ok(objects) => objects,
        Err(e) => return -e.code() as isize,
    };
    if objects.iter().any(Option::is_none) {
        return -LinuxError::EBADF.code() as isize;
    }

    let deadline = timeout_dur.map(|timeout_dur| axhal::time::monotonic_time() + timeout_dur);

    const POLL_ACTIVE_YIELD_ROUNDS: usize = 64;
    const POLL_SLEEP_QUANTUM: Duration = Duration::from_micros(100);
    let mut idle_rounds: usize = 0;

    loop {
        let mut ready = 0usize;
        for (pfd, object) in pollfds.iter_mut().zip(objects.iter()) {
            pfd.revents = 0;
            if pfd.fd < 0 {
                continue;
            }
            let Some(object) = object.as_ref() else {
                return -LinuxError::EBADF.code() as isize;
            };
            match object.poll() {
                Ok(state) => {
                    pfd.revents = requested_poll_revents(pfd.events, state);
                    if pfd.revents != 0 {
                        ready += 1;
                    }
                }
                Err(_) => {
                    pfd.revents = POLLERR as i16;
                    ready += 1;
                }
            }
        }

        if ready > 0 {
            if axlog::log_enabled!(axlog::Level::Debug) {
                axlog::debug!(
                    "sys_pselect6 => ready fds detected: {:?}",
                    pollfds
                        .iter()
                        .filter(|p| p.revents != 0)
                        .map(|p| (p.fd, p.revents))
                        .collect::<alloc::vec::Vec<_>>()
                );
            }
            break;
        }

        if thread.has_pending_signal() {
            axlog::debug!("sys_pselect6 => interrupted by signal");
            return -LinuxError::EINTR.code() as isize;
        }

        if let Some(deadline) = deadline {
            let now = axhal::time::monotonic_time();
            if now >= deadline {
                axlog::debug!("sys_pselect6 => deadline reached");
                break;
            }
            idle_rounds = idle_rounds.saturating_add(1);
            if idle_rounds <= POLL_ACTIVE_YIELD_ROUNDS {
                axtask::yield_now();
            } else {
                let sleep_dur = core::cmp::min(deadline - now, POLL_SLEEP_QUANTUM);
                if sleep_dur > Duration::ZERO {
                    thread
                        .signal_wait_queue()
                        .wait_timeout_until(sleep_dur, || thread.has_pending_signal());
                } else {
                    axtask::yield_now();
                }
            }
        } else {
            idle_rounds = idle_rounds.saturating_add(1);
            if idle_rounds <= POLL_ACTIVE_YIELD_ROUNDS {
                axtask::yield_now();
            } else {
                thread
                    .signal_wait_queue()
                    .wait_timeout_until(POLL_SLEEP_QUANTUM, || thread.has_pending_signal());
            }
        }
    }

    let mut ready_count = 0isize;
    let mut out_read = FdSet::zero();
    let mut out_write = FdSet::zero();
    let mut out_except = FdSet::zero();

    for pfd in &pollfds {
        let fd = pfd.fd as usize;
        let revents = pfd.revents;
        if (revents & (POLLIN as i16 | POLLERR as i16 | POLLHUP as i16 | POLLNVAL as i16) != 0)
            && in_read.is_set(fd)
        {
            out_read.set(fd);
            ready_count += 1;
        }
        if (revents & (POLLOUT as i16 | POLLERR as i16 | POLLHUP as i16 | POLLNVAL as i16) != 0)
            && in_write.is_set(fd)
        {
            out_write.set(fd);
            ready_count += 1;
        }
        if (revents
            & (linux_raw_sys::general::POLLPRI as i16
                | POLLERR as i16
                | POLLHUP as i16
                | POLLNVAL as i16)
            != 0)
            && in_except.is_set(fd)
        {
            out_except.set(fd);
            ready_count += 1;
        }
    }

    if has_read {
        if let Err(_) = uaccess::write_user_plain(process.as_ref(), readfds, &out_read) {
            return -LinuxError::EFAULT.code() as isize;
        }
    }
    if has_write {
        if let Err(_) = uaccess::write_user_plain(process.as_ref(), writefds, &out_write) {
            return -LinuxError::EFAULT.code() as isize;
        }
    }
    if has_except {
        if let Err(_) = uaccess::write_user_plain(process.as_ref(), exceptfds, &out_except) {
            return -LinuxError::EFAULT.code() as isize;
        }
    }

    axlog::debug!("sys_pselect6 => returning ready: {ready_count}");
    ready_count
}
