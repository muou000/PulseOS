use core::sync::atomic::{AtomicBool, Ordering};

use axerrno::AxError;
use axhal::context::TrapFrame;
use bitflags::bitflags;
use pulse_core::task::{CloneParams, ForkParams, current_process, current_thread};

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
    }
}

fn ax_error_to_linux_ret(e: AxError) -> isize {
    let errno: LinuxError = e.into();
    -errno.code() as isize
}

pub fn sys_clone(tf: &TrapFrame, args: [usize; 6]) -> isize {
    let raw_flags = args[0];
    let flags = CloneFlags::from_bits_truncate(raw_flags);
    let exit_signal = raw_flags & CloneFlags::CSIGNAL.bits();
    let child_stack = args[1];
    let parent_tid = args[2];
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

    if flags.contains(CloneFlags::CLONE_SETTLS) && tls == 0 {
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

    if flags.contains(CloneFlags::CLONE_VFORK)
        && (!flags.contains(CloneFlags::CLONE_VM) || flags.contains(CloneFlags::CLONE_THREAD))
    {
        return -LinuxError::EINVAL.code() as isize;
    }

    if exit_signal != 0 && flags.contains(CloneFlags::CLONE_THREAD) {
        return -LinuxError::EINVAL.code() as isize;
    }

    // CLONE_VM: Process fork vs Thread clone
    if !flags.contains(CloneFlags::CLONE_VM) {
        axlog::debug!(
            "sys_clone: CLONE_VM=0 requested. Using Deep Copy fork instead of safe COW due to \
             missing physical frame reference tracking."
        );
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
    let current_tid = current_thread().map(|t| t.tid()).unwrap_or_default();
    axlog::debug!(
        "sys_clone context: parent_pid={}, parent_tid={}",
        parent_proc.pid(),
        current_tid
    );

    let mut new_tf = *tf;
    // Child resumes right after the syscall instruction.
    #[cfg(target_arch = "riscv64")]
    {
        new_tf.sepc = new_tf.sepc.wrapping_add(4);
    }
    #[cfg(target_arch = "loongarch64")]
    {
        new_tf.era = new_tf.era.wrapping_add(4);
    }
    if flags.contains(CloneFlags::CLONE_SETTLS) {
        #[cfg(target_arch = "riscv64")]
        {
            new_tf.regs.tp = tls;
        }
        #[cfg(target_arch = "loongarch64")]
        {
            new_tf.regs.tp = tls;
        }
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
                is_vfork: false,
                share_fs,
                share_files,
                parent_set_tid,
                child_set_tid,
                child_clear_tid,
            },
        ) {
            Ok(child_proc) => (child_proc.pid() as usize, None),
            Err(e) => {
                axlog::error!("fork error: {:?}", e);
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
            },
        ) {
            Ok((tid, child_proc)) => (tid as usize, child_proc),
            Err(e) => {
                axlog::error!("clone error: {:?}", e);
                return ax_error_to_linux_ret(e);
            }
        }
    };

    if is_vfork {
        let Some(child_proc) = child_proc_for_vfork else {
            return -LinuxError::EINVAL.code() as isize;
        };
        child_proc.wait_for_vfork_completion();
    }

    child_tid_value as isize
}
