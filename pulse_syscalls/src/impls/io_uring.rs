//! Linux-compatible `io_uring_setup`, `io_uring_enter`, and `io_uring_register` syscalls.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use axerrno::LinuxError;
use linux_raw_sys::io_uring::{
    __kernel_timespec, IORING_ENTER_GETEVENTS, IORING_ENTER_SQ_WAIT, IORING_ENTER_SQ_WAKEUP, io_uring_files_update, io_uring_getevents_arg,
    io_uring_params, io_uring_probe, io_uring_register_op,
};
use pulse_core::fd_table::{FdEntry, FdFlags};
use pulse_core::io_uring::IoUringObject;
use pulse_core::io_uring::context::AsyncExecContext;
use pulse_core::mm::UserIoSegment;
use pulse_core::task::{SignalMaskGuard, current_have_signals, current_process, current_thread};
use pulse_io_uring_core::whitelist::{populate_probe, validate_register_op_v1};

use super::fs::common::{get_fd_entry, insert_fd_entry};
use super::utils::{
    read_user_iovec_array, read_user_value, read_user_value_array, write_user_value,
    write_user_value_array,
};
use crate::validation::io_uring::{
    EnterArgKind, decide_enter_return, validate_enter_args, validate_getevents_arg,
    validate_kernel_timespec,
};

struct IoUringFdHandle(Arc<dyn pulse_core::fd_table::FdObject>);

impl IoUringFdHandle {
    #[inline]
    fn state(&self) -> &Arc<pulse_core::io_uring::IoUringState> {
        self.0
            .as_any()
            .downcast_ref::<IoUringObject>()
            .expect("IoUringFdHandle verified IoUringObject at construction")
            .state()
    }
}

fn get_io_uring_object(fd: i32) -> Result<IoUringFdHandle, LinuxError> {
    let fd_usize = usize::try_from(fd).map_err(|_| LinuxError::EBADF)?;
    let entry = get_fd_entry(fd_usize)?;
    if !entry.object.as_any().is::<IoUringObject>() {
        return Err(LinuxError::EOPNOTSUPP);
    }
    Ok(IoUringFdHandle(entry.object))
}

pub(crate) fn sys_io_uring_setup(entries: u32, params_ptr: usize) -> isize {
    let mut params: io_uring_params = match read_user_value(params_ptr) {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };

    let obj = match IoUringObject::new(entries, &mut params) {
        Ok(obj) => Arc::new(obj),
        Err(e) => return -e.code() as isize,
    };

    if let Err(e) = write_user_value(params_ptr, &params) {
        return -e.code() as isize;
    }

    match insert_fd_entry(FdEntry::new(obj, FdFlags::CLOEXEC)) {
        Ok(fd) => fd as isize,
        Err(e) => -e.code() as isize,
    }
}

pub(crate) fn sys_io_uring_enter(
    fd: i32,
    to_submit: u32,
    min_complete: u32,
    flags: u32,
    argp: usize,
    argsz: usize,
) -> isize {
    // Resolve the FD once in the observation build, even if argument validation
    // rejects the call. Keep the ABI's original error precedence in both builds.
    #[cfg(feature = "guest-checks")]
    let ring = {
        let ring = get_io_uring_object(fd);
        if let Ok(handle) = &ring {
            handle.state().observe_enter_call();
        }
        ring
    };
    let arg_kind = match validate_enter_args(flags, argp, argsz) {
        Ok(k) => k,
        Err(e) => return -e.code() as isize,
    };

    #[cfg(not(feature = "guest-checks"))]
    let ring = get_io_uring_object(fd);
    let ring = match ring {
        Ok(r) => r,
        Err(e) => return -e.code() as isize,
    };
    let state = ring.state();
    let _inflight = match state.try_enter_inflight() {
        Ok(g) => g,
        Err(e) => return -e.code() as isize,
    };

    let (sigmask_ptr, timeout_dur) = match arg_kind {
        EnterArgKind::None => (None, None),
        EnterArgKind::LegacySigmask { sigmask_ptr } => (Some(sigmask_ptr), None),
        EnterArgKind::ExtArg { arg_ptr } => {
            let ext: io_uring_getevents_arg = match read_user_value(arg_ptr) {
                Ok(v) => v,
                Err(e) => return -e.code() as isize,
            };
            let (sig_ptr, ts_ptr) = match validate_getevents_arg(&ext) {
                Ok(pair) => pair,
                Err(e) => return -e.code() as isize,
            };
            let timeout = match ts_ptr {
                Some(addr) => {
                    let ts: __kernel_timespec = match read_user_value(addr) {
                        Ok(v) => v,
                        Err(e) => return -e.code() as isize,
                    };
                    match validate_kernel_timespec(&ts) {
                        Ok(d) => Some(d),
                        Err(e) => return -e.code() as isize,
                    }
                }
                None => None,
            };
            (sig_ptr, timeout)
        }
    };

    let temporary_mask = match sigmask_ptr {
        Some(ptr) => match read_user_value::<u64>(ptr) {
            Ok(mask) => Some(mask),
            Err(e) => return -e.code() as isize,
        },
        None => None,
    };

    let (submitted, stopped_on_inline_error, all_inline_fast_path) = if state.is_sqpoll() {
        let wake = flags & IORING_ENTER_SQ_WAKEUP != 0;
        let wait = flags & IORING_ENTER_SQ_WAIT != 0;
        if let Err(e) = state.sqpoll_enter(wake, wait) {
            return -e.code() as isize;
        }
        (to_submit, false, false)
    } else {
        let exec_ctx = match AsyncExecContext::capture_current() {
            Ok(ctx) => ctx,
            Err(e) => return -e.code() as isize,
        };
        state.submit_sqes(to_submit, &exec_ctx)
    };
    if all_inline_fast_path
        && temporary_mask.is_none()
        && (stopped_on_inline_error
            || (flags & IORING_ENTER_GETEVENTS) == 0
            || submitted >= min_complete.min(state.cq_entries()))
    {
        return submitted as isize;
    }
    task::future::drive_ready(64);

    if (flags & IORING_ENTER_GETEVENTS) == 0 || stopped_on_inline_error {
        return submitted as isize;
    }

    let thread = match current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };
    let _mask_guard = SignalMaskGuard::install(Arc::clone(&thread), temporary_mask);

    let effective_min = min_complete.min(state.cq_entries());
    let initial_timeout_expiries = state.timeout_expiries();
    let (mut cq_ready, _) = state.check_cq_ready_and_ebadr(false);
    let mut pending_ebadr = false;
    let mut wait_err = None;

    if submitted == 0 && cq_ready == 0 {
        let (_, ebadr_now) = state.check_cq_ready_and_ebadr(true);
        if ebadr_now {
            pending_ebadr = true;
            wait_err = Some(LinuxError::EBADR);
        }
    }

    if wait_err.is_none() && effective_min > 0 && cq_ready < effective_min {
        if timeout_dur == Some(Duration::ZERO) {
            wait_err = Some(LinuxError::ETIME);
        } else {
            let deadline = timeout_dur.map(|d| hal::time::monotonic_time().saturating_add(d));
            let wait_queues = [&state.cq_wait_queue, thread.signal_wait_queue()];
            loop {
                task::future::drive_ready(32);
                let (ready_now, _) = state.check_cq_ready_and_ebadr(false);
                cq_ready = ready_now;

                if cq_ready >= effective_min
                    || state.timeout_expiries() != initial_timeout_expiries
                {
                    break;
                }
                if submitted == 0 && cq_ready == 0 {
                    let (_, ebadr_now) = state.check_cq_ready_and_ebadr(true);
                    if ebadr_now {
                        pending_ebadr = true;
                        wait_err = Some(LinuxError::EBADR);
                        break;
                    }
                }
                if state.is_dying() {
                    wait_err = Some(LinuxError::EBADF);
                    break;
                }
                if state.sqpoll_stopped() {
                    wait_err = Some(LinuxError::EOWNERDEAD);
                    break;
                }
                if current_have_signals() {
                    wait_err = Some(LinuxError::EINTR);
                    break;
                }
                let remain = match deadline {
                    Some(dl) => {
                        let now = hal::time::monotonic_time();
                        if now >= dl {
                            wait_err = Some(LinuxError::ETIME);
                            break;
                        }
                        Some(dl - now)
                    }
                    None => None,
                };

                let res = task::WaitQueue::wait_multiple_timeout_until(
                    &wait_queues,
                    remain,
                    || {
                        let _ = task::future::drive_ready(16);
                        state.is_dying()
                            || state.sqpoll_stopped()
                            || current_have_signals()
                            || state.timeout_expiries() != initial_timeout_expiries
                            || state.check_cq_ready_and_ebadr(false).0 >= effective_min
                    },
                );
                task::future::drive_ready(32);
                let (ready_after, _) = state.check_cq_ready_and_ebadr(false);
                cq_ready = ready_after;
                if cq_ready >= effective_min
                    || state.timeout_expiries() != initial_timeout_expiries
                {
                    break;
                }
                if state.is_dying() {
                    wait_err = Some(LinuxError::EBADF);
                    break;
                }
                if state.sqpoll_stopped() {
                    wait_err = Some(LinuxError::EOWNERDEAD);
                    break;
                }
                if current_have_signals() {
                    wait_err = Some(LinuxError::EINTR);
                    break;
                }
                if matches!(res, Err(true)) && cq_ready < effective_min && timeout_dur.is_some() {
                    wait_err = Some(LinuxError::ETIME);
                    break;
                }
            }
        }
    }

    // Re-check ready futures and overflow FIFO once more before final decision so any
    // last-moment CQE wins cleanly over `-EINTR` / `-ETIME` (ADR-0002 / #231).
    task::future::drive_ready(32);
    let (final_ready, final_ebadr) = state.check_cq_ready_and_ebadr(submitted == 0 && wait_err.is_none());
    cq_ready = final_ready;
    if final_ebadr {
        pending_ebadr = true;
    }

    match decide_enter_return(submitted, cq_ready, effective_min, wait_err, pending_ebadr) {
        Ok(n) => n as isize,
        Err(e) => -e.code() as isize,
    }
}

pub(crate) fn sys_io_uring_register(
    fd: i32,
    opcode: u32,
    arg: usize,
    nr_args: u32,
) -> isize {
    let op = match validate_register_op_v1(opcode) {
        Ok(op) => op,
        Err(e) => return -e.code() as isize,
    };

    let ring = match get_io_uring_object(fd) {
        Ok(r) => r,
        Err(e) => return -e.code() as isize,
    };
    let state = ring.state();
    let _inflight = match state.try_enter_inflight() {
        Ok(g) => g,
        Err(e) => return -e.code() as isize,
    };

    match op {
        x if x == io_uring_register_op::IORING_REGISTER_PROBE as u32 => {
            let mut header: io_uring_probe = match read_user_value(arg) {
                Ok(h) => h,
                Err(e) => return -e.code() as isize,
            };
            let ops = match populate_probe(&mut header, nr_args) {
                Ok(ops) => ops,
                Err(e) => return -e.code() as isize,
            };
            if let Err(e) = write_user_value(arg, &header) {
                return -e.code() as isize;
            }
            let ops_len = header.ops_len as usize;
            if ops_len > 0 {
                let Some(ops_addr) = arg.checked_add(core::mem::size_of::<io_uring_probe>()) else {
                    return -LinuxError::EFAULT.code() as isize;
                };
                if let Err(e) = write_user_value_array(ops_addr, &ops[..ops_len]) {
                    return -e.code() as isize;
                }
            }
            0
        }
        x if x == io_uring_register_op::IORING_REGISTER_EVENTFD as u32
            || x == io_uring_register_op::IORING_REGISTER_EVENTFD_ASYNC as u32 =>
        {
            if nr_args != 1 {
                return -LinuxError::EINVAL.code() as isize;
            }
            let ev_fd: i32 = match read_user_value(arg) {
                Ok(v) => v,
                Err(e) => return -e.code() as isize,
            };
            let Ok(ev_fd_usize) = usize::try_from(ev_fd) else {
                return -LinuxError::EBADF.code() as isize;
            };
            let ev_entry = match get_fd_entry(ev_fd_usize) {
                Ok(e) => e,
                Err(e) => return -e.code() as isize,
            };
            let async_only = x == io_uring_register_op::IORING_REGISTER_EVENTFD_ASYNC as u32;
            match state.register_eventfd(&ev_entry, async_only) {
                Ok(()) => 0,
                Err(e) => -e.code() as isize,
            }
        }
        x if x == io_uring_register_op::IORING_UNREGISTER_EVENTFD as u32 => {
            if arg != 0 || nr_args != 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
            match state.unregister_eventfd() {
                Ok(()) => 0,
                Err(e) => -e.code() as isize,
            }
        }
        x if x == io_uring_register_op::IORING_REGISTER_BUFFERS as u32 => {
            if let Err(e) = state.check_can_register_buffers(nr_args as usize) {
                return -e.code() as isize;
            }
            let iovecs = match read_user_iovec_array(arg, nr_args as usize) {
                Ok(v) => v,
                Err(e) => return -e.code() as isize,
            };
            let specs: Vec<UserIoSegment> = match iovecs
                .into_iter()
                .map(|iov| {
                    usize::try_from(iov.iov_len)
                        .map(|len| UserIoSegment::new(iov.iov_base as usize, len))
                        .map_err(|_| LinuxError::EINVAL)
                })
                .collect()
            {
                Ok(v) => v,
                Err(e) => return -e.code() as isize,
            };
            let process = match current_process() {
                Ok(p) => p,
                Err(e) => return -e.code() as isize,
            };
            match state.register_buffers(&process, &specs) {
                Ok(()) => 0,
                Err(e) => -e.code() as isize,
            }
        }
        x if x == io_uring_register_op::IORING_UNREGISTER_BUFFERS as u32 => {
            match state.unregister_buffers(arg, nr_args) {
                Ok(()) => 0,
                Err(e) => -e.code() as isize,
            }
        }
        x if x == io_uring_register_op::IORING_REGISTER_FILES as u32 => {
            if let Err(e) = state.check_can_register_files(nr_args as usize) {
                return -e.code() as isize;
            }
            let raw_fds: Vec<i32> = match read_user_value_array(arg, nr_args as usize) {
                Ok(v) => v,
                Err(e) => return -e.code() as isize,
            };
            let process = match current_process() {
                Ok(p) => p,
                Err(e) => return -e.code() as isize,
            };
            match state.register_files(&process.fd_table(), &raw_fds) {
                Ok(()) => 0,
                Err(e) => -e.code() as isize,
            }
        }
        x if x == io_uring_register_op::IORING_UNREGISTER_FILES as u32 => {
            match state.unregister_files(arg, nr_args) {
                Ok(()) => 0,
                Err(e) => -e.code() as isize,
            }
        }
        x if x == io_uring_register_op::IORING_REGISTER_FILES_UPDATE as u32 => {
            if nr_args == 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
            let up: io_uring_files_update = match read_user_value(arg) {
                Ok(v) => v,
                Err(e) => return -e.code() as isize,
            };
            if let Err(e) = state.validate_files_update(up.offset, nr_args, up.resv) {
                return -e.code() as isize;
            }
            let raw_fds: Vec<i32> = match read_user_value_array(up.fds as usize, nr_args as usize) {
                Ok(v) => v,
                Err(e) => return -e.code() as isize,
            };
            let process = match current_process() {
                Ok(p) => p,
                Err(e) => return -e.code() as isize,
            };
            match state.update_fixed_files(&process.fd_table(), up.offset, &raw_fds, up.resv) {
                Ok(done) => done as isize,
                Err(e) => -e.code() as isize,
            }
        }
        _ => -LinuxError::EINVAL.code() as isize,
    }
}
