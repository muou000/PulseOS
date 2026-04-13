use crate::LinuxError;
use alloc::string::String;
use alloc::vec::Vec;
use axerrno::{AxError, AxErrorKind};
use axhal::context::TrapFrame;
use bitflags::bitflags;

bitflags! {
    /// Flags for sys_clone
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CloneFlags: usize {
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

pub fn sys_getpid() -> isize {
    axlog::debug!("sys_getpid");
    pulse_core::task::current_process()
        .expect("getpid without current process")
        .pid() as isize
}

pub fn sys_getppid() -> isize {
    pulse_core::task::current_process()
        .expect("getppid without current process")
        .parent_pid() as isize
}

fn ax_error_to_linux_ret(e: AxError) -> isize {
    let errno: LinuxError = e.into();
    -errno.code() as isize
}

fn read_user_bytes(
    process: &pulse_core::task::Process,
    user_addr: usize,
    bytes: &mut [u8],
) -> Result<(), isize> {
    process
        .read_user_bytes(user_addr, bytes)
        .map_err(|_| -LinuxError::EFAULT.code() as isize)
}

fn read_user_usize(process: &pulse_core::task::Process, user_addr: usize) -> Result<usize, isize> {
    let mut bytes = [0u8; core::mem::size_of::<usize>()];
    read_user_bytes(process, user_addr, &mut bytes)?;
    Ok(usize::from_ne_bytes(bytes))
}

fn read_user_cstring(
    process: &pulse_core::task::Process,
    user_addr: usize,
) -> Result<String, isize> {
    if user_addr == 0 {
        return Err(-LinuxError::EFAULT.code() as isize);
    }
    const STR_MAX: usize = 4096;
    let mut bytes = Vec::new();
    for i in 0..STR_MAX {
        let mut byte = [0u8; 1];
        read_user_bytes(process, user_addr + i, &mut byte)?;
        if byte[0] == 0 {
            return String::from_utf8(bytes).map_err(|_| -LinuxError::EINVAL.code() as isize);
        }
        bytes.push(byte[0]);
    }
    Err(-LinuxError::ENAMETOOLONG.code() as isize)
}

fn read_user_string_array(
    process: &pulse_core::task::Process,
    array_addr: usize,
) -> Result<Vec<String>, isize> {
    const ARG_MAX_COUNT: usize = 256;
    let mut out = Vec::new();
    if array_addr == 0 {
        return Ok(out);
    }
    for i in 0..ARG_MAX_COUNT {
        let ptr = read_user_usize(process, array_addr + i * core::mem::size_of::<usize>())?;
        if ptr == 0 {
            return Ok(out);
        }
        out.push(read_user_cstring(process, ptr)?);
    }
    Err(-LinuxError::E2BIG.code() as isize)
}

fn write_user_i32(process: &pulse_core::task::Process, user_addr: usize, value: i32) -> isize {
    process
        .write_user_i32(user_addr, value)
        .map(|_| 0)
        .unwrap_or_else(|e| {
            axlog::warn!(
                "user write failed: addr={:#x}, value={}, err={:?}",
                user_addr,
                value,
                e
            );
            -LinuxError::EFAULT.code() as isize
        })
}

pub fn sys_exit(exit_code: i32) -> ! {
    axlog::debug!("sys_exit: exit_code={}", exit_code);
    axlog::info!("Task exit with code: {}", exit_code);
    let thread = pulse_core::task::current_thread().expect("exit without Thread");
    thread.exit_current(exit_code);
}

pub fn sys_exit_group(exit_code: i32) -> ! {
    axlog::debug!("sys_exit_group: exit_code={}", exit_code);
    axlog::info!("Task group exit with code: {}", exit_code);
    let thread = pulse_core::task::current_thread().expect("exit_group without Thread");
    thread.process().begin_group_exit(exit_code);
    thread.exit_current(exit_code);
}

pub fn sys_yield() -> isize {
    axtask::yield_now();
    0
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
            "sys_clone: CLONE_VM=0 requested. Using Deep Copy fork instead of safe COW due to missing physical frame reference tracking."
        );
    }

    if !flags.contains(CloneFlags::CLONE_FILES) || !flags.contains(CloneFlags::CLONE_FS) {
        axlog::debug!("sys_clone: child will use private FS and/or FD tables");
    }

    // CLONE_SIGHAND
    if flags.contains(CloneFlags::CLONE_SIGHAND) {
        axlog::warn!(
            "sys_clone: CLONE_SIGHAND requested but signal handler infrastructure is totally missing."
        );
    }

    let parent_proc = match pulse_core::task::current_process() {
        Ok(process) => process,
        Err(_) => return -LinuxError::ESRCH.code() as isize,
    };
    let current_tid = pulse_core::task::current_thread()
        .map(|t| t.tid())
        .unwrap_or_default();
    axlog::warn!(
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
            pulse_core::task::ForkParams {
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
            pulse_core::task::CloneParams {
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

pub fn sys_execve(_tf: &TrapFrame, pathname: usize, argv: usize, envp: usize) -> isize {
    axlog::debug!(
        "sys_execve: pathname={:#x}, argv={:#x}, envp={:#x}",
        pathname,
        argv,
        envp
    );
    if pathname == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let thread = pulse_core::task::current_thread().expect("execve without Thread");
    let process = thread.process();

    if process.thread_count() > 1 {
        axlog::warn!("sys_execve: multi-thread exec is not supported yet");
        return -LinuxError::EAGAIN.code() as isize;
    }

    let path_str = match read_user_cstring(process, pathname) {
        Ok(path) => path,
        Err(e) => return e,
    };
    axlog::debug!("sys_execve path: {}", path_str);
    if let Ok(cwd) = process.fs_context.lock().current_dir().absolute_path() {
        axlog::debug!("sys_execve cwd: {}", cwd);
    }

    if path_str.is_empty() {
        return -LinuxError::ENOENT.code() as isize;
    }

    let mut args = match read_user_string_array(process, argv) {
        Ok(args) => args,
        Err(e) => return e,
    };
    if args.is_empty() {
        args.push(path_str.clone());
    }

    // Convert to Vec<&str>
    let mut args_strs: Vec<&str> = Vec::new();
    for s in &args {
        args_strs.push(s.as_str());
    }

    let envs = match read_user_string_array(process, envp) {
        Ok(envs) => envs,
        Err(e) => return e,
    };

    let mut envs_strs: Vec<&str> = Vec::new();
    for s in &envs {
        envs_strs.push(s.as_str());
    }

    if let Err(e) = process.exec(&path_str, &args_strs, &envs_strs) {
        if matches!(
            AxErrorKind::try_from(e.canonicalize()),
            Ok(AxErrorKind::InvalidExecutable)
        ) {
            // Compatibility fallback: execute text scripts via /bin/sh when
            // direct image loading fails with ENOEXEC-equivalent.
            let mut sh_args_owned = Vec::with_capacity(args.len() + 1);
            sh_args_owned.push(String::from("/bin/sh"));
            sh_args_owned.push(path_str.clone());
            sh_args_owned.extend(args.into_iter().skip(1));
            let sh_args: Vec<&str> = sh_args_owned.iter().map(|s| s.as_str()).collect();
            if let Err(sh_e) = process.exec("/bin/sh", &sh_args, &envs_strs) {
                axlog::error!(
                    "sys_execve failed: {:?}, shell-fallback failed: {:?}",
                    e,
                    sh_e
                );
                let errno: LinuxError = sh_e.into();
                return -errno.code() as isize;
            }
        } else {
            axlog::error!("sys_execve failed: {:?}", e);
            let errno: LinuxError = e.into();
            return -errno.code() as isize;
        }
    }
    thread.clear_thread_tid_state();
    process.enter_user_mode();
}

pub fn sys_wait4(pid: isize, status: usize, options: i32, rusage: usize) -> isize {
    axlog::debug!(
        "sys_wait4: pid={}, status={:#x}, options={}, rusage={:#x}",
        pid,
        status,
        options,
        rusage
    );
    let thread = pulse_core::task::current_thread().expect("wait4 without Thread");
    let process = thread.process();

    loop {
        if !process.has_matching_child(pid) {
            return -LinuxError::ECHILD.code() as isize;
        }

        if let Some(child_proc) = process.reap_zombie_child(pid) {
            let exited_pid = child_proc.pid() as isize;
            let exit_code = child_proc.exit_code();
            let now_ns = axhal::time::monotonic_time_nanos() as u64;
            let (child_utime_ns, child_stime_ns) = child_proc.snapshot_cpu_time_ns(now_ns);
            process.add_child_time_ns(child_utime_ns, child_stime_ns);

            if status != 0 {
                // In Linux, WIFEXITED is true and WEXITSTATUS is `exit_code & 0xff`,
                // so the status word is `(exit_code & 0xff) << 8`.
                let wait_status = (exit_code & 0xff) << 8;
                let write_result = write_user_i32(process, status, wait_status);
                if write_result < 0 {
                    process.add_child(child_proc);
                    return write_result;
                }
            }
            if rusage != 0 {
                // Not supported yet: simply ignore or zero out
            }
            child_proc.wait_task_refs_exited();
            child_proc.release_task_refs();
            // Keep a bounded cache of reaped child process objects, but release
            // heavy user resources first to prevent fork/exec workloads from
            // exhausting memory.
            if let Err(e) = child_proc.shrink_reaped_resources() {
                axlog::warn!("failed to shrink reaped child resources: {:?}", e);
            }
            process.stash_reaped_child(child_proc);
            return exited_pid;
        }

        // No matching child has exited yet.
        // options & WNOHANG == 1
        if (options & 1) != 0 {
            return 0; // WNOHANG
        }

        process.wait_for_child_exit(pid);
    }
}
