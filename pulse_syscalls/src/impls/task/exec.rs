use alloc::vec::Vec;
use alloc::string::ToString;

use axerrno::LinuxError;
use axhal::context::TrapFrame;
use pulse_core::task::current_thread;

use super::common::{read_user_cstring, read_user_string_array};

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

    let thread = match current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process_arc();

    if process.thread_count() > 1 {
        axlog::warn!("sys_execve: multi-thread exec is not supported yet");
        return -LinuxError::EAGAIN.code() as isize;
    }

    let path_str = match read_user_cstring(&process, pathname) {
        Ok(path) => path,
        Err(e) => return e,
    };
    let mut args = match read_user_string_array(&process, argv) {
        Ok(args) => args,
        Err(e) => return e,
    };

    if args.is_empty() {
        args.push(path_str.clone());
    }

    let mut args_strs: Vec<&str> = Vec::new();
    for s in &args {
        args_strs.push(s.as_str());
    }

    let envs = match read_user_string_array(&process, envp) {
        Ok(envs) => envs,
        Err(e) => return e,
    };

    let mut envs_strs: Vec<&str> = Vec::new();
    for s in &envs {
        envs_strs.push(s.as_str());
    }

    if let Err(e) = process.exec(&path_str, &args_strs, &envs_strs) {
        axlog::error!("sys_execve failed: {:?}", e);
        let errno: LinuxError = e.into();
        return -errno.code() as isize;
    }
    thread.clear_thread_tid_state();

    drop(args_strs);
    drop(args);
    drop(envs_strs);
    drop(envs);
    drop(path_str);

    process.enter_user_mode_and_drop(thread)
}

pub fn sys_execveat(
    _tf: &TrapFrame,
    dirfd: i32,
    pathname: usize,
    argv: usize,
    envp: usize,
    flags: i32,
) -> isize {
    axlog::debug!(
        "sys_execveat: dirfd={}, pathname={:#x}, argv={:#x}, envp={:#x}, flags={:#x}",
        dirfd,
        pathname,
        argv,
        envp,
        flags
    );

    let supported_flags = linux_raw_sys::general::AT_EMPTY_PATH as i32
        | linux_raw_sys::general::AT_SYMLINK_NOFOLLOW as i32;
    if (flags & !supported_flags) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let thread = match current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process_arc();

    if process.thread_count() > 1 {
        axlog::warn!("sys_execveat: multi-thread exec is not supported yet");
        return -LinuxError::EAGAIN.code() as isize;
    }

    let loc = match crate::impls::fs::common::resolve_location_at_ptr(dirfd, pathname, flags as usize) {
        Ok(loc) => loc,
        Err(e) => return -e.code() as isize,
    };

    let metadata = match loc.metadata() {
        Ok(m) => m,
        Err(e) => {
            let errno: LinuxError = e.into();
            return -errno.code() as isize;
        }
    };

    if (flags & linux_raw_sys::general::AT_SYMLINK_NOFOLLOW as i32) != 0
        && metadata.node_type == axfs_ng_vfs::NodeType::Symlink
    {
        return -LinuxError::ELOOP.code() as isize;
    }

    let path_str = match loc.absolute_path() {
        Ok(p) => p.to_string(),
        Err(e) => {
            let errno: LinuxError = e.into();
            return -errno.code() as isize;
        }
    };

    let mut args = match read_user_string_array(&process, argv) {
        Ok(args) => args,
        Err(e) => return e,
    };

    if args.is_empty() {
        args.push(path_str.clone());
    }

    let mut args_strs: Vec<&str> = Vec::new();
    for s in &args {
        args_strs.push(s.as_str());
    }

    let envs = match read_user_string_array(&process, envp) {
        Ok(envs) => envs,
        Err(e) => return e,
    };

    let mut envs_strs: Vec<&str> = Vec::new();
    for s in &envs {
        envs_strs.push(s.as_str());
    }

    if let Err(e) = process.exec(&path_str, &args_strs, &envs_strs) {
        axlog::error!("sys_execveat failed: {:?}", e);
        let errno: LinuxError = e.into();
        return -errno.code() as isize;
    }
    thread.clear_thread_tid_state();

    drop(args_strs);
    drop(args);
    drop(envs_strs);
    drop(envs);
    drop(path_str);
    drop(loc);
    drop(metadata);

    process.enter_user_mode_and_drop(thread)
}
