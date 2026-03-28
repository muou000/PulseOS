use crate::LinuxError;
use axtask::TaskExtRef;
use core::ffi::c_char;
use alloc::vec::Vec;
use alloc::string::String;

pub fn sys_getpid() -> isize {
    axtask::current().id().as_u64() as isize
}

pub fn sys_exit(exit_code: i32) -> ! {
    axlog::info!("Task exit with code: {}", exit_code);
    axtask::exit(exit_code);
}

pub fn sys_yield() -> isize {
    axtask::yield_now();
    0
}

pub fn sys_clone(args: [usize; 6]) -> isize {
    let _flags = args[0];
    let _stack = args[1];
    let _parent_tid = args[2];
    let _tls = args[3];
    let _child_tid = args[4];

    axlog::warn!("sys_clone not fully implemented");
    -LinuxError::ENOSYS.code() as isize
}

pub fn sys_execve(pathname: usize, argv: usize, envp: usize) -> isize {
    if pathname == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    
    // Copy the pathname into a String to ensure it survives the exec switch
    let path_str = String::from(unsafe { core::ffi::CStr::from_ptr(pathname as *const c_char) }
        .to_str()
        .unwrap_or(""));

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

    let curr = axtask::current();
    let process = curr.task_ext();

    if let Err(e) = process.exec(&path_str, &args_strs) {
        axlog::error!("sys_execve failed: {:?}", e);
        return -LinuxError::ENOENT.code() as isize;
    }

    process.enter_user_mode();
}
