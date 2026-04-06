use crate::LinuxError;
use alloc::string::String;
use alloc::vec::Vec;
use axhal::context::TrapFrame;
use axtask::TaskExtRef;
use bitflags::bitflags;
use core::ffi::c_char;
use memory_addr::VirtAddr;

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
    axtask::current().id().as_u64() as isize
}

pub fn sys_getppid() -> isize {
    let curr = axtask::current();
    let process: &pulse_core::task::Process = curr.task_ext();
    *process.parent_pid.lock() as isize
}

fn write_user_i32(process: &pulse_core::task::Process, user_addr: usize, value: i32) -> isize {
    let bytes = value.to_ne_bytes();
    process
        .aspace
        .lock()
        .write(VirtAddr::from(user_addr), &bytes)
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
    axlog::info!("Task exit with code: {}", exit_code);
    axtask::exit(exit_code);
}

pub fn sys_yield() -> isize {
    axtask::yield_now();
    0
}

pub fn sys_clone(tf: &TrapFrame, args: [usize; 6]) -> isize {
    let raw_flags = args[0];
    let flags = CloneFlags::from_bits_truncate(raw_flags);
    let child_stack = args[1];
    let parent_tid = args[2];
    let tls = args[3];
    let child_tid = args[4];

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

    // CLONE_VM: Process fork vs Thread clone
    if !flags.contains(CloneFlags::CLONE_VM) {
        axlog::debug!(
            "sys_clone: CLONE_VM=0 requested. Using Deep Copy fork instead of safe COW due to missing physical frame reference tracking."
        );
    }

    // CLONE_FILES & CLONE_FS
    if !flags.contains(CloneFlags::CLONE_FILES) || !flags.contains(CloneFlags::CLONE_FS) {
        axlog::debug!(
            "sys_clone: Independent file descriptor tables or FS info are not fully supported yet in ArceOS."
        );
    }

    // CLONE_SIGHAND
    if flags.contains(CloneFlags::CLONE_SIGHAND) {
        axlog::warn!(
            "sys_clone: CLONE_SIGHAND requested but signal handler infrastructure is totally missing."
        );
    }

    let parent = axtask::current();
    let parent_proc: &pulse_core::task::Process = parent.task_ext();

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
        axlog::warn!(
            "sys_clone: CLONE_SETTLS is requested. Modifying TLS register (e.g. tp on RISC-V) in TrapFrame is missing from infrastructure."
        );
        // We'd do something like `new_tf.regs.tp = tls;` if TrapFrame architecture details were exposed properly.
    }

    let child_tid_value = if !flags.contains(CloneFlags::CLONE_VM) {
        // Create an entirely new process memory space (Fork / Deep Copy)
        match parent_proc
            .spawn_fork_from_trap_frame(&new_tf, (child_stack != 0).then_some(child_stack))
        {
            Ok(tid) => tid as usize,
            Err(e) => {
                axlog::error!("fork error: {:?}", e);
                return -LinuxError::ENOMEM.code() as isize;
            }
        }
    } else {
        // Create a new thread in the same memory space (Thread Clone)
        parent_proc.spawn_from_trap_frame(&new_tf, (child_stack != 0).then_some(child_stack))
            as usize
    };

    if flags.contains(CloneFlags::CLONE_PARENT_SETTID) && parent_tid != 0 {
        unsafe {
            *(parent_tid as *mut u32) = child_tid_value as u32;
        }
    }

    if flags.contains(CloneFlags::CLONE_CHILD_SETTID) && child_tid != 0 {
        unsafe {
            *(child_tid as *mut u32) = child_tid_value as u32;
        }
    }

    if flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) && child_tid != 0 {
        axlog::warn!(
            "sys_clone: CLONE_CHILD_CLEARTID accepted but axtask lacks the clear_child_tid thread-exit mechanism to wake futex."
        );
        // Needs a field in Task structure: clear_child_tid_addr = child_tid;
    }

    child_tid_value as isize
}

pub fn sys_execve(pathname: usize, argv: usize, envp: usize) -> isize {
    if pathname == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    // Copy the pathname into a String to ensure it survives the exec switch
    let path_str = String::from(
        unsafe { core::ffi::CStr::from_ptr(pathname as *const c_char) }
            .to_str()
            .unwrap_or(""),
    );

    if path_str.is_empty() {
        return -LinuxError::ENOENT.code() as isize;
    }

    // Parse argv
    let mut args: Vec<String> = Vec::new();
    if argv != 0 {
        let mut ptr = argv as *const *const c_char;
        unsafe {
            while !(*ptr).is_null() {
                if let Ok(s) = core::ffi::CStr::from_ptr(*ptr).to_str() {
                    args.push(String::from(s));
                }
                ptr = ptr.add(1);
            }
        }
    } else {
        args.push(path_str.clone());
    }

    // Convert to Vec<&str>
    let mut args_strs: Vec<&str> = Vec::new();
    for s in &args {
        args_strs.push(s.as_str());
    }

    // Parse envp
    let mut envs: Vec<String> = Vec::new();
    if envp != 0 {
        let mut ptr = envp as *const *const c_char;
        unsafe {
            while !(*ptr).is_null() {
                if let Ok(s) = core::ffi::CStr::from_ptr(*ptr).to_str() {
                    envs.push(String::from(s));
                }
                ptr = ptr.add(1);
            }
        }
    }

    let mut envs_strs: Vec<&str> = Vec::new();
    for s in &envs {
        envs_strs.push(s.as_str());
    }

    let curr = axtask::current();
    let process = curr.task_ext();

    if let Err(e) = process.exec(&path_str, &args_strs, &envs_strs) {
        axlog::error!("sys_execve failed: {:?}", e);
        let errno: LinuxError = e.into();
        return -errno.code() as isize;
    }

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
    let curr = axtask::current();
    let process: &pulse_core::task::Process = curr.task_ext();

    loop {
        let mut children = process.children.lock();
        if children.is_empty() {
            return -LinuxError::ECHILD.code() as isize;
        }

        let mut exited_idx = None;
        let mut exited_pid = 0;
        let mut exit_code = 0;

        for (i, child) in children.iter().enumerate() {
            let child_id = child.id().as_u64() as isize;
            if pid == -1 || child_id == pid || pid == 0 || (pid < -1 && child_id == -pid) {
                if let Some(code) = child.try_join() {
                    exited_idx = Some(i);
                    exited_pid = child_id;
                    exit_code = code;
                    break;
                }
            }
        }

        if let Some(idx) = exited_idx {
            let exited_child = children.remove(idx);
            if status != 0 {
                // In Linux, WIFEXITED is true and WEXITSTATUS is `exit_code & 0xff`,
                // so the status word is `(exit_code & 0xff) << 8`.
                let wait_status = (exit_code & 0xff) << 8;
                let write_result = write_user_i32(process, status, wait_status);
                if write_result < 0 {
                    children.insert(idx, exited_child);
                    return write_result;
                }
            }
            if rusage != 0 {
                // Not supported yet: simply ignore or zero out
            }
            return exited_pid;
        }

        // No matching child has exited yet.
        // options & WNOHANG == 1
        if (options & 1) != 0 {
            return 0; // WNOHANG
        }

        // drop lock before yielding
        drop(children);
        axtask::yield_now();
    }
}
