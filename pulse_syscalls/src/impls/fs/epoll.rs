use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use axerrno::LinuxError;
use linux_raw_sys::general::{
    epoll_event, EPOLLERR, EPOLLHUP, EPOLLIN, EPOLLOUT, EPOLL_CLOEXEC, EPOLL_CTL_ADD,
    EPOLL_CTL_DEL, EPOLL_CTL_MOD, EPOLLET, EPOLLONESHOT, EPOLLRDHUP,
};
use pulse_core::fd_table::{
    FdEntry, FdFlags, EpollObject, EpollRegistration, FdObject, PipeObject, StdinObject,
    StdoutObject, PidfdObject,
};

use crate::impls::{
    fs::common::{get_fd_entry, insert_fd_entry},
    utils::{read_user_timespec, with_process, write_user_bytes},
};

fn check_epoll_nesting(
    target_obj: &dyn FdObject,
    root_epoll: &EpollObject,
    current_depth: usize,
) -> Result<usize, LinuxError> {
    if let Some(epoll_obj) = target_obj.as_any().downcast_ref::<EpollObject>() {
        let target_ptr = epoll_obj as *const EpollObject;
        let root_ptr = root_epoll as *const EpollObject;
        if target_ptr == root_ptr {
            return Err(LinuxError::ELOOP);
        }
        if current_depth >= 5 {
            return Err(LinuxError::EINVAL);
        }
        let monitored = epoll_obj.events.lock();
        let mut max_depth = current_depth + 1;
        for &fd in monitored.keys() {
            if let Ok(entry) = get_fd_entry(fd) {
                let depth = check_epoll_nesting(entry.object.as_ref(), root_epoll, current_depth + 1)?;
                if depth > max_depth {
                    max_depth = depth;
                }
            }
        }
        Ok(max_depth)
    } else {
        Ok(current_depth)
    }
}

pub fn sys_epoll_create1(flags: usize) -> isize {
    axlog::debug!("sys_epoll_create1: flags={:#x}", flags);
    if (flags & !EPOLL_CLOEXEC as usize) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let fd_flags = if (flags & EPOLL_CLOEXEC as usize) != 0 {
        FdFlags::CLOEXEC
    } else {
        FdFlags::empty()
    };
    let epoll_obj = EpollObject::new();
    let entry = FdEntry::new(Arc::new(epoll_obj), fd_flags);
    match insert_fd_entry(entry) {
        Ok(fd) => fd as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_epoll_ctl(
    epfd: usize,
    op: usize,
    fd: usize,
    event: usize,
) -> isize {
    axlog::debug!("sys_epoll_ctl: epfd={}, op={}, fd={}, event={:#x}", epfd, op, fd, event);

    let epoll_entry = match get_fd_entry(epfd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };

    let epoll_obj = match epoll_entry.object.as_any().downcast_ref::<EpollObject>() {
        Some(obj) => obj,
        None => return -LinuxError::EINVAL.code() as isize,
    };

    let target_entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };

    // epoll targets must be pollable: epoll, pipe, socket, stdin, stdout, pidfd
    let target_obj = target_entry.object.as_ref();
    let is_pollable = target_obj.as_any().is::<EpollObject>()
        || target_obj.as_any().is::<PipeObject>()
        || target_obj.as_any().is::<StdinObject>()
        || target_obj.as_any().is::<StdoutObject>()
        || target_obj.as_any().is::<PidfdObject>()
        || target_obj.as_any().is::<crate::net::Socket>();

    if !is_pollable {
        return -LinuxError::EPERM.code() as isize;
    }

    if op as u32 == EPOLL_CTL_ADD {
        if let Err(e) = check_epoll_nesting(target_entry.object.as_ref(), epoll_obj, 0) {
            return -e.code() as isize;
        }
    }

    let mut user_event = epoll_event {
        events: 0,
        data: 0,
    };

    if op as u32 != EPOLL_CTL_DEL {
        if event == 0 {
            return -LinuxError::EFAULT.code() as isize;
        }
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                (&mut user_event as *mut epoll_event).cast::<u8>(),
                core::mem::size_of::<epoll_event>(),
            )
        };
        if let Err(e) = with_process(|p| p.read_user_bytes(event, bytes)) {
            return -e.code() as isize;
        }
    }

    let mut events = epoll_obj.events.lock();
    match op as u32 {
        EPOLL_CTL_ADD => {
            if events.contains_key(&fd) {
                return -LinuxError::EEXIST.code() as isize;
            }
            events.insert(fd, EpollRegistration {
                event: user_event,
                reported_in: false,
                reported_out: false,
            });
        }
        EPOLL_CTL_MOD => {
            if let Some(ev) = events.get_mut(&fd) {
                ev.event = user_event;
                ev.reported_in = false;
                ev.reported_out = false;
            } else {
                return -LinuxError::ENOENT.code() as isize;
            }
        }
        EPOLL_CTL_DEL => {
            if events.remove(&fd).is_none() {
                return -LinuxError::ENOENT.code() as isize;
            }
        }
        _ => return -LinuxError::EINVAL.code() as isize,
    }
    0
}

fn sys_epoll_pwait_inner(
    epfd: usize,
    events: usize,
    maxevents: usize,
    deadline: Option<axhal::time::TimeValue>,
    sigmask: usize,
    sigsetsize: usize,
) -> isize {
    if maxevents == 0 || maxevents > 4096 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if events == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if sigmask != 0 && sigsetsize != 0 && sigsetsize != core::mem::size_of::<u64>() {
        return -LinuxError::EINVAL.code() as isize;
    }

    let thread = match pulse_core::task::current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();

    let old_mask = thread.signal_blocked_mask();
    let mut changed = false;

    if sigmask != 0 {
        let new_mask = match process.read_user_usize(sigmask) {
            Ok(v) => v as u64,
            Err(_) => return -LinuxError::EFAULT.code() as isize,
        };
        thread.set_signal_blocked_mask(new_mask);
        changed = true;
    }

    struct SigmaskGuard {
        thread: Arc<pulse_core::task::Thread>,
        old_mask: u64,
        changed: bool,
    }

    impl Drop for SigmaskGuard {
        fn drop(&mut self) {
            if self.changed {
                self.thread.set_signal_blocked_mask(self.old_mask);
            }
        }
    }

    let _guard = SigmaskGuard {
        thread: thread.clone(),
        old_mask,
        changed,
    };

    let epoll_entry = match get_fd_entry(epfd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };

    let epoll_obj = match epoll_entry.object.as_any().downcast_ref::<EpollObject>() {
        Some(obj) => obj,
        None => return -LinuxError::EINVAL.code() as isize,
    };

    const POLL_ACTIVE_YIELD_ROUNDS: usize = 64;
    const POLL_SLEEP_QUANTUM: Duration = Duration::from_micros(100);
    let mut idle_rounds: usize = 0;

    loop {
        let mut ready_list = Vec::new();
        let mut oneshots_to_disable = Vec::new();
        {
            let mut monitored = epoll_obj.events.lock();
            for (&fd, ev) in monitored.iter_mut() {
                if ready_list.len() >= maxevents {
                    break;
                }
                match get_fd_entry(fd) {
                    Err(_) => {
                        if (ev.event.events & (EPOLLERR | EPOLLHUP)) != 0 {
                            ready_list.push(epoll_event {
                                events: ev.event.events & (EPOLLERR | EPOLLHUP),
                                data: ev.event.data,
                            });
                            if ev.event.events & EPOLLONESHOT != 0 {
                                oneshots_to_disable.push(fd);
                            }
                        }
                    }
                    Ok(entry) => {
                        match entry.object.poll() {
                            Ok(state) => {
                                let mut revents = 0u32;
                                
                                // Check readable
                                if state.readable {
                                    if ev.event.events & EPOLLIN != 0 {
                                        if ev.event.events & EPOLLET != 0 {
                                            if !ev.reported_in {
                                                revents |= EPOLLIN;
                                                ev.reported_in = true;
                                            }
                                        } else {
                                            revents |= EPOLLIN;
                                        }
                                    }
                                } else {
                                    ev.reported_in = false;
                                }

                                // Check writable
                                if state.writable {
                                    if ev.event.events & EPOLLOUT != 0 {
                                        if ev.event.events & EPOLLET != 0 {
                                            if !ev.reported_out {
                                                revents |= EPOLLOUT;
                                                ev.reported_out = true;
                                            }
                                        } else {
                                            revents |= EPOLLOUT;
                                        }
                                    }
                                } else {
                                    ev.reported_out = false;
                                }

                                // Check EPOLLRDHUP
                                if ev.event.events & EPOLLRDHUP != 0 && entry.object.is_rdhup() {
                                    if ev.event.events & EPOLLET != 0 {
                                        if !ev.reported_in {
                                            revents |= EPOLLRDHUP;
                                            ev.reported_in = true;
                                        }
                                    } else {
                                        revents |= EPOLLRDHUP;
                                    }
                                }

                                if revents != 0 {
                                    ready_list.push(epoll_event {
                                        events: revents,
                                        data: ev.event.data,
                                    });
                                    if ev.event.events & EPOLLONESHOT != 0 {
                                        oneshots_to_disable.push(fd);
                                    }
                                }
                            }
                            Err(_) => {
                                if (ev.event.events & EPOLLERR) != 0 {
                                    ready_list.push(epoll_event {
                                        events: EPOLLERR,
                                        data: ev.event.data,
                                    });
                                    if ev.event.events & EPOLLONESHOT != 0 {
                                        oneshots_to_disable.push(fd);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            for fd in oneshots_to_disable {
                if let Some(ev) = monitored.get_mut(&fd) {
                    ev.event.events = 0;
                }
            }
        }

        if !ready_list.is_empty() {
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    ready_list.as_ptr().cast::<u8>(),
                    ready_list.len() * core::mem::size_of::<epoll_event>(),
                )
            };
            if let Err(e) = write_user_bytes(events, bytes) {
                return -e.code() as isize;
            }
            return ready_list.len() as isize;
        }

        if let Ok(thread) = pulse_core::task::current_thread() {
            if thread.has_pending_signal() {
                return -LinuxError::EINTR.code() as isize;
            }
        }

        if let Some(deadline) = deadline {
            let now = axhal::time::monotonic_time();
            if now >= deadline {
                return 0;
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

pub fn sys_epoll_pwait(
    epfd: usize,
    events: usize,
    maxevents: usize,
    timeout: isize,
    sigmask: usize,
) -> isize {
    axlog::debug!(
        "sys_epoll_pwait: epfd={}, events={:#x}, maxevents={}, timeout={}, sigmask={:#x}",
        epfd,
        events,
        maxevents,
        timeout,
        sigmask
    );
    let deadline = if timeout >= 0 {
        Some(axhal::time::monotonic_time() + Duration::from_millis(timeout as u64))
    } else {
        None
    };
    sys_epoll_pwait_inner(epfd, events, maxevents, deadline, sigmask, core::mem::size_of::<u64>())
}

pub fn sys_epoll_pwait2(
    epfd: usize,
    events: usize,
    maxevents: usize,
    timeout_ptr: usize,
    sigmask: usize,
    sigsetsize: usize,
) -> isize {
    axlog::debug!(
        "sys_epoll_pwait2: epfd={}, events={:#x}, maxevents={}, timeout_ptr={:#x}, sigmask={:#x}, sigsetsize={}",
        epfd,
        events,
        maxevents,
        timeout_ptr,
        sigmask,
        sigsetsize
    );
    let deadline = if timeout_ptr != 0 {
        let ts = match read_user_timespec(timeout_ptr) {
            Ok(t) => t,
            Err(e) => return -e.code() as isize,
        };
        if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
            return -LinuxError::EINVAL.code() as isize;
        }
        let dur = Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);
        Some(axhal::time::monotonic_time() + dur)
    } else {
        None
    };
    sys_epoll_pwait_inner(epfd, events, maxevents, deadline, sigmask, sigsetsize)
}
