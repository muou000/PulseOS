use super::*;

pub fn sys_ppoll(
    fds: usize,
    nfds: usize,
    timeout: usize,
    _sigmask: usize,
    _sigsetsize: usize,
) -> isize {
    let timeout_dur = match read_ppoll_timeout(timeout) {
        Ok(timeout_dur) => timeout_dur,
        Err(e) => return -e.code() as isize,
    };

    if nfds == 0 {
        if let Some(timeout_dur) = timeout_dur {
            if timeout_dur > Duration::ZERO {
                axtask::sleep(timeout_dur);
            }
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

    if nfds == 1 {
        pollfds[0].revents = 0;
        if pollfds[0].fd < 0 {
            return write_back(&pollfds, 0);
        }

        let fd = pollfds[0].fd as usize;
        let entry = match get_fd_entry(fd) {
            Ok(entry) => entry,
            Err(_) => {
                pollfds[0].revents = POLLNVAL as i16;
                return write_back(&pollfds, 1);
            }
        };

        match entry.object.poll() {
            Ok(state) => {
                pollfds[0].revents = requested_poll_revents(pollfds[0].events, state);
                if pollfds[0].revents != 0 {
                    return write_back(&pollfds, 1);
                }
            }
            Err(_) => {
                pollfds[0].revents = POLLERR as i16;
                return write_back(&pollfds, 1);
            }
        }

        if pollfds[0].events != 0 {
            loop {
                match entry.object.wait_ready(pollfds[0].events, deadline) {
                    Ok(false) => return write_back(&pollfds, 0),
                    Ok(true) => {
                        pollfds[0].revents = 0;
                        match entry.object.poll() {
                            Ok(state) => {
                                pollfds[0].revents =
                                    requested_poll_revents(pollfds[0].events, state);
                                if pollfds[0].revents != 0 {
                                    return write_back(&pollfds, 1);
                                }
                            }
                            Err(_) => {
                                pollfds[0].revents = POLLERR as i16;
                                return write_back(&pollfds, 1);
                            }
                        }
                        if deadline.is_some_and(|ddl| axhal::time::monotonic_time() >= ddl) {
                            return write_back(&pollfds, 0);
                        }
                    }
                    Err(LinuxError::EOPNOTSUPP) => break,
                    Err(_) => {
                        pollfds[0].revents = POLLERR as i16;
                        return write_back(&pollfds, 1);
                    }
                }
            }
        }
    }

    // Try to retrieve wait queues for all monitored file descriptors.
    // If all monitored fds support wait queues, we can block on them event-driven.
    let mut objects = alloc::vec::Vec::with_capacity(nfds.min(128));
    let mut all_wqs_supported = true;
    for pfd in &pollfds {
        if pfd.fd < 0 {
            continue;
        }
        let fd = pfd.fd as usize;
        match get_fd_entry(fd) {
            Ok(entry) => {
                if all_wqs_supported {
                    let mut dummy = alloc::vec::Vec::new();
                    match entry.object.get_wait_queues(pfd.events, &mut dummy) {
                        Ok(true) => {
                            objects.push((entry.object.clone(), pfd.events));
                        }
                        _ => {
                            all_wqs_supported = false;
                        }
                    }
                }
            }
            Err(_) => {
                return -LinuxError::EBADF.code() as isize;
            }
        }
    }

    if all_wqs_supported && !objects.is_empty() {
        let mut wqs = alloc::vec::Vec::with_capacity(objects.len().min(128));
        for (obj, events) in &objects {
            let _ = obj.get_wait_queues(*events, &mut wqs);
        }
        // Fast-path poll
        let mut ready = 0usize;
        for pfd in pollfds.iter_mut() {
            pfd.revents = 0;
            if pfd.fd < 0 {
                continue;
            }
            let fd = pfd.fd as usize;
            if let Ok(entry) = get_fd_entry(fd) {
                if let Ok(state) = entry.object.poll() {
                    pfd.revents = requested_poll_revents(pfd.events, state);
                    if pfd.revents != 0 {
                        ready += 1;
                    }
                }
            }
        }
        if ready > 0 {
            return write_back(&pollfds, ready as isize);
        }

        // Wait until one or more monitored objects become ready, a signal is pending,
        // or the timeout is reached.
        let check_ready = || {
            if let Ok(thread) = pulse_core::task::current_thread() {
                if thread.has_pending_signal() {
                    return true;
                }
            }
            for (obj, events) in &objects {
                if let Ok(state) = obj.poll() {
                    if requested_poll_revents(*events, state) != 0 {
                        return true;
                    }
                }
            }
            false
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

        if let Ok(thread) = pulse_core::task::current_thread() {
            if thread.has_pending_signal() {
                return -LinuxError::EINTR.code() as isize;
            }
        }

        // Final poll pass
        let mut ready = 0usize;
        for pfd in pollfds.iter_mut() {
            pfd.revents = 0;
            if pfd.fd < 0 {
                continue;
            }
            let fd = pfd.fd as usize;
            if let Ok(entry) = get_fd_entry(fd) {
                if let Ok(state) = entry.object.poll() {
                    pfd.revents = requested_poll_revents(pfd.events, state);
                    if pfd.revents != 0 {
                        ready += 1;
                    }
                }
            }
        }
        return write_back(&pollfds, ready as isize);
    }

    // Hybrid wait strategy:
    // - keep a short active-yield phase for high-frequency IPC readiness;
    // - then fall back to short sleeps to avoid permanent hot spinning.
    const POLL_ACTIVE_YIELD_ROUNDS: usize = 64;
    const POLL_SLEEP_QUANTUM: Duration = Duration::from_micros(100);
    let mut idle_rounds: usize = 0;

    loop {
        let mut ready = 0usize;
        for pfd in pollfds.iter_mut() {
            pfd.revents = 0;
            if pfd.fd < 0 {
                continue;
            }
            let fd = pfd.fd as usize;
            let entry = match get_fd_entry(fd) {
                Ok(entry) => entry,
                Err(_) => {
                    return -LinuxError::EBADF.code() as isize;
                }
            };
            match entry.object.poll() {
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
            return write_back(&pollfds, ready as isize);
        }

        if let Ok(thread) = pulse_core::task::current_thread() {
            if thread.has_pending_signal() {
                return -LinuxError::EINTR.code() as isize;
            }
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
                    axtask::sleep(sleep_dur);
                } else {
                    axtask::yield_now();
                }
            }
        } else {
            idle_rounds = idle_rounds.saturating_add(1);
            if idle_rounds <= POLL_ACTIVE_YIELD_ROUNDS {
                axtask::yield_now();
            } else {
                axtask::sleep(POLL_SLEEP_QUANTUM);
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

pub fn sys_pselect6(
    nfds: usize,
    readfds: usize,
    writefds: usize,
    exceptfds: usize,
    timeout: usize,
    _sigmask: usize,
) -> isize {
    axlog::debug!(
        "sys_pselect6 <= nfds: {nfds}, readfds: {readfds:#x}, writefds: {writefds:#x}, exceptfds: \
         {exceptfds:#x}, timeout: {timeout:#x}"
    );

    if nfds > 1024 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let process = match pulse_core::task::current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };

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

    let mut pollfds = alloc::vec::Vec::with_capacity(nfds.min(1024));
    for fd in 0..nfds.min(1024) {
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
        if events != 0 {
            pollfds.push(pollfd {
                fd: fd as i32,
                events,
                revents: 0,
            });
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
        if let Some(timeout_dur) = timeout_dur {
            if timeout_dur > Duration::ZERO {
                axtask::sleep(timeout_dur);
            }
        }
        axlog::debug!("sys_pselect6 => empty pollfds, returning 0");
        return 0;
    }

    let deadline = timeout_dur.map(|timeout_dur| axhal::time::monotonic_time() + timeout_dur);

    const POLL_ACTIVE_YIELD_ROUNDS: usize = 64;
    const POLL_SLEEP_QUANTUM: Duration = Duration::from_micros(100);
    let mut idle_rounds: usize = 0;

    loop {
        let mut ready = 0usize;
        for pfd in pollfds.iter_mut() {
            pfd.revents = 0;
            if pfd.fd < 0 {
                continue;
            }
            let fd = pfd.fd as usize;
            let entry = match get_fd_entry(fd) {
                Ok(entry) => entry,
                Err(_) => {
                    return -LinuxError::EBADF.code() as isize;
                }
            };
            match entry.object.poll() {
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

        if let Ok(thread) = pulse_core::task::current_thread() {
            if thread.has_pending_signal() {
                axlog::debug!("sys_pselect6 => interrupted by signal");
                return -LinuxError::EINTR.code() as isize;
            }
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
                    axtask::sleep(sleep_dur);
                } else {
                    axtask::yield_now();
                }
            }
        } else {
            idle_rounds = idle_rounds.saturating_add(1);
            if idle_rounds <= POLL_ACTIVE_YIELD_ROUNDS {
                axtask::yield_now();
            } else {
                axtask::sleep(POLL_SLEEP_QUANTUM);
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
