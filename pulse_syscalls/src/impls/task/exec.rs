use alloc::vec::Vec;

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
        axlog::error!("sys_execve failed: {:?}", e);
        let errno: LinuxError = e.into();
        return -errno.code() as isize;
    }
    thread.clear_thread_tid_state();
    process.enter_user_mode();
}
