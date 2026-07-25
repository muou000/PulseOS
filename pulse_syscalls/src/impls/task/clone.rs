use core::sync::atomic::{AtomicBool, Ordering};

use axerrno::AxError;
use axhal::context::TrapFrame;
use bitflags::bitflags;
use memory_addr::PAGE_SIZE_4K;
use pulse_core::task::{CloneParams, ForkParams, Process, current_process, current_thread};

use crate::LinuxError;

static CLONE_SIGHAND_WARNED: AtomicBool = AtomicBool::new(false);

bitflags! {
    /// Flags for sys_clone
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct CloneFlags: usize {
        const CSIGNAL              = 0x0000_00ff; // signal mask to be sent at exit
        const CLONE_VM             = 0x0000_0100; // set if VM shared between processes
        const CLONE_FS             = 0x0000_0200; // set if fs info shared between processes
        const CLONE_FILES          = 0x0000_0400; // set if open files shared between processes
        const CLONE_SIGHAND        = 0x0000_0800; // set if signal handlers and blocked signals shared
        const CLONE_PIDFD          = 0x0000_1000; // set if a pidfd should be placed in parent
        const CLONE_PTRACE         = 0x0000_2000; // set if we want to let tracing continue on the child too
        const CLONE_VFORK          = 0x0000_4000; // set if the parent wants the child to wake it up on mm_release
        const CLONE_PARENT         = 0x0000_8000; // set if we want to have the same parent as the cloner
        const CLONE_THREAD         = 0x0001_0000; // Same thread group?
        const CLONE_NEWNS          = 0x0002_0000; // New mount namespace group
        const CLONE_SYSVSEM        = 0x0004_0000; // share system V SEM_UNDO semantics
        const CLONE_SETTLS         = 0x0008_0000; // create a new TLS for the child
        const CLONE_PARENT_SETTID  = 0x0010_0000; // set the TID in the parent
        const CLONE_CHILD_CLEARTID = 0x0020_0000; // clear the TID in the child
        const CLONE_DETACHED       = 0x0040_0000; // Unused, ignored
        const CLONE_UNTRACED       = 0x0080_0000; // set if the tracing process can't force CLONE_PTRACE on this clone
        const CLONE_CHILD_SETTID   = 0x0100_0000; // set the TID in the child
        const CLONE_NEWCGROUP      = 0x0200_0000; // New cgroup namespace
        const CLONE_NEWUTS         = 0x0400_0000; // New utsname namespace
        const CLONE_NEWIPC         = 0x0800_0000; // New ipc namespace
        const CLONE_NEWUSER        = 0x1000_0000; // New user namespace
        const CLONE_NEWPID         = 0x2000_0000; // New pid namespace
        const CLONE_NEWNET         = 0x4000_0000; // New network namespace
        const CLONE_IO             = 0x8000_0000; // Clone io context
        const CLONE_CLEAR_SIGHAND  = 0x1_0000_0000; // Reset caught signals to SIG_DFL
        const CLONE_INTO_CGROUP    = 0x2_0000_0000; // Clone into cgroup
    }
}

fn ax_error_to_linux_ret(e: AxError) -> isize {
    let errno: LinuxError = e.into();
    -errno.code() as isize
}

struct PidfdReservation<'a> {
    parent: &'a Process,
    fd: usize,
    object: alloc::sync::Arc<pulse_core::fd_table::PidfdObject>,
    committed: bool,
}

impl PidfdReservation<'_> {
    fn commit(mut self, pid: usize) {
        self.object.bind_pid(pid as u64);
        self.committed = true;
    }
}

impl Drop for PidfdReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.parent.remove_fd_entry(self.fd);
        }
    }
}

fn reserve_pidfd(parent: &Process, user_addr: usize) -> Result<PidfdReservation<'_>, isize> {
    let object = alloc::sync::Arc::new(pulse_core::fd_table::PidfdObject::new(0));
    let entry =
        pulse_core::fd_table::FdEntry::new(object.clone(), pulse_core::fd_table::FdFlags::CLOEXEC);
    let fd = parent
        .insert_fd_entry(entry)
        .map_err(|e| -e.code() as isize)?;
    if let Err(e) = parent.write_user_i32(user_addr, fd as i32) {
        let _ = parent.remove_fd_entry(fd);
        return Err(ax_error_to_linux_ret(e));
    }
    Ok(PidfdReservation {
        parent,
        fd,
        object,
        committed: false,
    })
}

pub fn sys_clone(tf: &TrapFrame, args: [usize; 6]) -> isize {
    let raw_flags = args[0];
    let legacy_flags = raw_flags & u32::MAX as usize;
    let flags = CloneFlags::from_bits_truncate(legacy_flags);
    let exit_signal = legacy_flags & CloneFlags::CSIGNAL.bits();
    let child_stack = args[1];
    let parent_tid = args[2];
    let share_uts = !flags.contains(CloneFlags::CLONE_NEWUTS);
    #[cfg(target_arch = "loongarch64")]
    let (child_tid, tls) = (args[3], args[4]);
    #[cfg(not(target_arch = "loongarch64"))]
    let (tls, child_tid) = (args[3], args[4]);

    axlog::debug!(
        "sys_clone: flags={:?}, child_stack={:#x}, parent_tid={:#x}, child_tid={:#x}, tls={:#x}",
        flags,
        child_stack,
        parent_tid,
        child_tid,
        tls
    );

    if flags.contains(CloneFlags::CLONE_THREAD)
        && (!flags.contains(CloneFlags::CLONE_VM) || !flags.contains(CloneFlags::CLONE_SIGHAND))
    {
        return -LinuxError::EINVAL.code() as isize;
    }

    if flags.contains(CloneFlags::CLONE_SIGHAND) && !flags.contains(CloneFlags::CLONE_VM) {
        return -LinuxError::EINVAL.code() as isize;
    }

    if flags.contains(CloneFlags::CLONE_VFORK) && flags.contains(CloneFlags::CLONE_THREAD) {
        return -LinuxError::EINVAL.code() as isize;
    }

    if flags.contains(CloneFlags::CLONE_PIDFD)
        && flags.intersects(CloneFlags::CLONE_PARENT_SETTID | CloneFlags::CLONE_DETACHED)
    {
        return -LinuxError::EINVAL.code() as isize;
    }

    if flags.contains(CloneFlags::CLONE_PIDFD) && flags.contains(CloneFlags::CLONE_THREAD) {
        return -LinuxError::EOPNOTSUPP.code() as isize;
    }

    if exit_signal != 0 && flags.contains(CloneFlags::CLONE_THREAD) {
        return -LinuxError::EINVAL.code() as isize;
    }

    if !flags.contains(CloneFlags::CLONE_FILES) || !flags.contains(CloneFlags::CLONE_FS) {
        axlog::debug!("sys_clone: child will use private FS and/or FD tables");
    }

    // CLONE_SIGHAND
    if flags.contains(CloneFlags::CLONE_SIGHAND)
        && !CLONE_SIGHAND_WARNED.swap(true, Ordering::AcqRel)
    {
        axlog::debug!(
            "sys_clone: CLONE_SIGHAND requested; shared signal handlers are not fully implemented \
             yet."
        );
    }

    let parent_proc = match current_process() {
        Ok(process) => process,
        Err(_) => return -LinuxError::ESRCH.code() as isize,
    };
    let pidfd_reservation = if flags.contains(CloneFlags::CLONE_PIDFD) {
        match reserve_pidfd(parent_proc.as_ref(), parent_tid) {
            Ok(reservation) => Some(reservation),
            Err(ret) => return ret,
        }
    } else {
        None
    };
    let current_tid = match current_thread() {
        Ok(thread) => thread.tid(),
        Err(_) => 0,
    };
    axlog::debug!(
        "sys_clone context: parent_pid={}, parent_tid={}",
        parent_proc.pid(),
        current_tid
    );

    let mut new_tf = *tf;
    // The syscall trap handler already advanced the user PC before dispatching
    // this syscall, so the copied trap frame is already positioned at the
    // correct post-syscall instruction for the child.
    if flags.contains(CloneFlags::CLONE_SETTLS) {
        new_tf.regs.tp = tls;
    }

    let share_fs = flags.contains(CloneFlags::CLONE_FS);
    let share_files = flags.contains(CloneFlags::CLONE_FILES);
    let is_thread_clone = flags.contains(CloneFlags::CLONE_THREAD);
    let is_vfork = flags.contains(CloneFlags::CLONE_VFORK);
    let child_set_tid = flags
        .contains(CloneFlags::CLONE_CHILD_SETTID)
        .then_some(child_tid)
        .filter(|addr| *addr != 0);
    let child_clear_tid = flags
        .contains(CloneFlags::CLONE_CHILD_CLEARTID)
        .then_some(child_tid)
        .filter(|addr| *addr != 0);
    let parent_set_tid = flags
        .contains(CloneFlags::CLONE_PARENT_SETTID)
        .then_some(parent_tid)
        .filter(|addr| *addr != 0);

    let (child_tid_value, child_proc_for_vfork) = if !flags.contains(CloneFlags::CLONE_VM) {
        // Create an entirely new process memory space (Fork / Deep Copy)
        match parent_proc.spawn_fork_from_trap_frame(
            &new_tf,
            ForkParams {
                child_stack: (child_stack != 0).then_some(child_stack),
                is_vfork,
                share_fs,
                share_files,
                parent_set_tid,
                child_set_tid,
                child_clear_tid,
                share_sighand: flags.contains(CloneFlags::CLONE_SIGHAND),
                clear_sighand: false,
                share_uts,
                exit_signal: Some(exit_signal as i32),
            },
        ) {
            Ok(child_proc) => {
                let child_pid = child_proc.pid() as usize;
                (child_pid, is_vfork.then_some(child_proc))
            }
            Err(e) => {
                axlog::debug!("fork error: {:?}", e);
                return ax_error_to_linux_ret(e);
            }
        }
    } else {
        // Create a new task in the same memory space.
        match parent_proc.spawn_from_trap_frame(
            &new_tf,
            CloneParams {
                child_stack: (child_stack != 0).then_some(child_stack),
                is_thread_clone,
                is_vfork,
                share_fs,
                share_files,
                parent_set_tid,
                child_set_tid,
                child_clear_tid,
                share_sighand: flags.contains(CloneFlags::CLONE_SIGHAND),
                clear_sighand: false,
                share_uts,
                exit_signal: Some(exit_signal as i32),
            },
        ) {
            Ok((tid, child_proc)) => (tid as usize, child_proc),
            Err(e) => {
                axlog::debug!("clone error: {:?}", e);
                return ax_error_to_linux_ret(e);
            }
        }
    };

    if let Some(reservation) = pidfd_reservation {
        reservation.commit(child_tid_value);
    }

    if is_vfork {
        let Some(child_proc) = child_proc_for_vfork else {
            return -LinuxError::EINVAL.code() as isize;
        };
        child_proc.wait_for_vfork_completion();
    }

    child_tid_value as isize
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

pub fn sys_clone3(tf: &TrapFrame, args: [usize; 6]) -> isize {
    let cl_args_ptr = args[0];
    let size = args[1];

    axlog::debug!("sys_clone3: cl_args_ptr={:#x}, size={}", cl_args_ptr, size);

    if size < 64 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if size > PAGE_SIZE_4K {
        return -LinuxError::E2BIG.code() as isize;
    }

    let parent_proc = match current_process() {
        Ok(process) => process,
        Err(e) => {
            axlog::warn!(
                "sys_clone3: failed to get current process: cl_args_ptr={:#x}, size={}, err={:?}",
                cl_args_ptr,
                size,
                e
            );
            return -LinuxError::ESRCH.code() as isize;
        }
    };

    let mut clone_args = CloneArgs::default();
    let copy_size = core::cmp::min(size, core::mem::size_of::<CloneArgs>());

    let mut buf = [0u8; 88];
    let slice = &mut buf[..copy_size];
    if let Err(e) = parent_proc.read_user_bytes(cl_args_ptr, slice) {
        let errno = LinuxError::from(e.canonicalize());
        axlog::warn!(
            "sys_clone3: failed to copy clone_args: pid={}, cl_args_ptr={:#x}, size={}, \
             copy_size={}, err={:?}, errno={:?}",
            parent_proc.pid(),
            cl_args_ptr,
            size,
            copy_size,
            e,
            errno
        );
        return -errno.code() as isize;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(
            slice.as_ptr(),
            (&mut clone_args as *mut CloneArgs).cast::<u8>(),
            copy_size,
        );
    }

    if size > core::mem::size_of::<CloneArgs>() {
        let mut remaining = size - core::mem::size_of::<CloneArgs>();
        let mut check_ptr = match cl_args_ptr.checked_add(core::mem::size_of::<CloneArgs>()) {
            Some(ptr) => ptr,
            None => return -LinuxError::EFAULT.code() as isize,
        };
        let mut temp = [0u8; 256];
        while remaining > 0 {
            let chunk = core::cmp::min(remaining, temp.len());
            if let Err(e) = parent_proc.read_user_bytes(check_ptr, &mut temp[..chunk]) {
                let errno = LinuxError::from(e.canonicalize());
                axlog::warn!(
                    "sys_clone3: failed to copy trailing clone_args bytes: pid={}, addr={:#x}, \
                     chunk={}, remaining={}, err={:?}, errno={:?}",
                    parent_proc.pid(),
                    check_ptr,
                    chunk,
                    remaining,
                    e,
                    errno
                );
                return -errno.code() as isize;
            }
            if temp[..chunk].iter().any(|&b| b != 0) {
                return -LinuxError::E2BIG.code() as isize;
            }
            remaining -= chunk;
            check_ptr = match check_ptr.checked_add(chunk) {
                Some(ptr) => ptr,
                None => return -LinuxError::EFAULT.code() as isize,
            };
        }
    }

    if clone_args.flags & !(CloneFlags::all().bits() as u64) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let flags = CloneFlags::from_bits_truncate(clone_args.flags as usize);
    let exit_signal = clone_args.exit_signal;

    if (clone_args.flags & 0xff) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if exit_signal > 64 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if (clone_args.stack == 0) != (clone_args.stack_size == 0) {
        return -LinuxError::EINVAL.code() as isize;
    }

    if flags.contains(CloneFlags::CLONE_VM) && clone_args.stack == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if flags.contains(CloneFlags::CLONE_THREAD)
        && (!flags.contains(CloneFlags::CLONE_VM) || !flags.contains(CloneFlags::CLONE_SIGHAND))
    {
        return -LinuxError::EINVAL.code() as isize;
    }

    if flags.contains(CloneFlags::CLONE_SIGHAND) && !flags.contains(CloneFlags::CLONE_VM) {
        return -LinuxError::EINVAL.code() as isize;
    }

    if flags.contains(CloneFlags::CLONE_SIGHAND) && flags.contains(CloneFlags::CLONE_CLEAR_SIGHAND)
    {
        return -LinuxError::EINVAL.code() as isize;
    }

    if flags.contains(CloneFlags::CLONE_PIDFD) && flags.contains(CloneFlags::CLONE_DETACHED) {
        return -LinuxError::EINVAL.code() as isize;
    }

    if flags.contains(CloneFlags::CLONE_VFORK) && flags.contains(CloneFlags::CLONE_THREAD) {
        return -LinuxError::EINVAL.code() as isize;
    }

    if flags.contains(CloneFlags::CLONE_PIDFD) && flags.contains(CloneFlags::CLONE_THREAD) {
        return -LinuxError::EOPNOTSUPP.code() as isize;
    }

    if exit_signal != 0 && flags.intersects(CloneFlags::CLONE_THREAD | CloneFlags::CLONE_PARENT) {
        return -LinuxError::EINVAL.code() as isize;
    }

    if flags.contains(CloneFlags::CLONE_FS) && flags.contains(CloneFlags::CLONE_NEWNS) {
        return -LinuxError::EINVAL.code() as isize;
    }

    if clone_args.set_tid != 0 || clone_args.set_tid_size != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if flags.contains(CloneFlags::CLONE_INTO_CGROUP) {
        return -LinuxError::EOPNOTSUPP.code() as isize;
    }

    if clone_args.cgroup != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let pidfd_reservation = if flags.contains(CloneFlags::CLONE_PIDFD) {
        match reserve_pidfd(parent_proc.as_ref(), clone_args.pidfd as usize) {
            Ok(reservation) => Some(reservation),
            Err(ret) => return ret,
        }
    } else {
        None
    };

    let share_uts = !flags.contains(CloneFlags::CLONE_NEWUTS);

    let mut new_tf = *tf;
    if flags.contains(CloneFlags::CLONE_SETTLS) {
        new_tf.regs.tp = clone_args.tls as usize;
    }

    let share_fs = flags.contains(CloneFlags::CLONE_FS);
    let share_files = flags.contains(CloneFlags::CLONE_FILES);
    let is_thread_clone = flags.contains(CloneFlags::CLONE_THREAD);
    let is_vfork = flags.contains(CloneFlags::CLONE_VFORK);
    let child_stack = if clone_args.stack != 0 {
        let stack = clone_args.stack as usize;
        let stack_size = clone_args.stack_size as usize;
        if parent_proc.validate_user_range(stack, stack_size).is_err() {
            return -LinuxError::EINVAL.code() as isize;
        }
        match stack.checked_add(stack_size) {
            Some(stack_top) => stack_top,
            None => return -LinuxError::EINVAL.code() as isize,
        }
    } else {
        0
    };

    let child_set_tid = flags
        .contains(CloneFlags::CLONE_CHILD_SETTID)
        .then_some(clone_args.child_tid as usize)
        .filter(|addr| *addr != 0);
    let child_clear_tid = flags
        .contains(CloneFlags::CLONE_CHILD_CLEARTID)
        .then_some(clone_args.child_tid as usize)
        .filter(|addr| *addr != 0);
    let parent_set_tid = flags
        .contains(CloneFlags::CLONE_PARENT_SETTID)
        .then_some(clone_args.parent_tid as usize)
        .filter(|addr| *addr != 0);

    if flags.contains(CloneFlags::CLONE_SIGHAND)
        && !CLONE_SIGHAND_WARNED.swap(true, Ordering::AcqRel)
    {
        axlog::debug!(
            "sys_clone3: CLONE_SIGHAND requested; shared signal handlers are not fully \
             implemented yet."
        );
    }

    let (child_tid_value, child_proc_for_vfork) = if !flags.contains(CloneFlags::CLONE_VM) {
        match parent_proc.spawn_fork_from_trap_frame(
            &new_tf,
            ForkParams {
                child_stack: (child_stack != 0).then_some(child_stack),
                is_vfork,
                share_fs,
                share_files,
                parent_set_tid,
                child_set_tid,
                child_clear_tid,
                share_sighand: flags.contains(CloneFlags::CLONE_SIGHAND),
                clear_sighand: flags.contains(CloneFlags::CLONE_CLEAR_SIGHAND),
                share_uts,
                exit_signal: Some(exit_signal as i32),
            },
        ) {
            Ok(child_proc) => {
                let child_pid = child_proc.pid() as usize;
                (child_pid, is_vfork.then_some(child_proc))
            }
            Err(e) => {
                axlog::debug!("fork error: {:?}", e);
                return ax_error_to_linux_ret(e);
            }
        }
    } else {
        match parent_proc.spawn_from_trap_frame(
            &new_tf,
            CloneParams {
                child_stack: (child_stack != 0).then_some(child_stack),
                is_thread_clone,
                is_vfork,
                share_fs,
                share_files,
                parent_set_tid,
                child_set_tid,
                child_clear_tid,
                share_sighand: flags.contains(CloneFlags::CLONE_SIGHAND),
                clear_sighand: flags.contains(CloneFlags::CLONE_CLEAR_SIGHAND),
                share_uts,
                exit_signal: Some(exit_signal as i32),
            },
        ) {
            Ok((tid, child_proc)) => (tid as usize, child_proc),
            Err(e) => {
                let ret = ax_error_to_linux_ret(e);
                axlog::warn!(
                    "sys_clone3: spawn_from_trap_frame failed: pid={}, flags={:?}, \
                     cl_args_ptr={:#x}, size={}, err={:?}, ret={}",
                    parent_proc.pid(),
                    flags,
                    cl_args_ptr,
                    size,
                    e,
                    ret
                );
                return ret;
            }
        }
    };

    if let Some(reservation) = pidfd_reservation {
        reservation.commit(child_tid_value);
    }

    if is_vfork {
        let Some(child_proc) = child_proc_for_vfork else {
            return -LinuxError::EINVAL.code() as isize;
        };
        child_proc.wait_for_vfork_completion();
    }

    child_tid_value as isize
}

pub fn sys_unshare(flags: usize) -> isize {
    let clone_flags = CloneFlags::from_bits_truncate(flags);
    axlog::debug!(
        "sys_unshare: raw_flags={:#x}, flags={:?}",
        flags,
        clone_flags
    );

    // If there are any unrecognized bits in flags, return EINVAL
    if flags & !CloneFlags::all().bits() != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let process = match current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    if clone_flags.contains(CloneFlags::CLONE_FILES) {
        if let Err(e) = process.unshare_files() {
            return -e.code() as isize;
        }
    }

    if clone_flags.contains(CloneFlags::CLONE_FS) {
        if let Err(e) = process.unshare_fs() {
            return -e.code() as isize;
        }
    }

    if clone_flags.contains(CloneFlags::CLONE_NEWUTS) {
        process.unshare_uts();
    }

    // Other namespace flags (CLONE_NEWUSER, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWIPC, CLONE_NEWUTS, CLONE_NEWCGROUP, CLONE_NEWPID)
    // are supported as stubs (returning success) to satisfy compatibility for user-space programs.

    0
}

pub fn sys_setns(fd: usize, nstype: usize) -> isize {
    let process = match current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    let entry = match process.get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };

    let (ns_pid, fd_ns_type) = match entry.object.as_ns_fd() {
        Some(val) => val,
        None => return -LinuxError::EINVAL.code() as isize,
    };

    if nstype != 0 && (nstype as u32) != fd_ns_type {
        return -LinuxError::EINVAL.code() as isize;
    }

    if !process.is_root_user() {
        return -LinuxError::EPERM.code() as isize;
    }

    match fd_ns_type {
        0x0400_0000 /* CLONE_NEWUTS */ => {
            if let Some(target_proc) = pulse_core::task::process_by_pid(ns_pid) {
                process.set_hostname_handle(target_proc.hostname_handle());
            }
        }
        // Others are no-op stubs for now.
        _ => {}
    }

    0
}
