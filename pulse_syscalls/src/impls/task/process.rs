use pulse_core::task::current_process;

pub fn sys_getpid() -> isize {
    axlog::debug!("sys_getpid");
    match current_process() {
        Ok(process) => process.pid() as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_getppid() -> isize {
    match current_process() {
        Ok(process) => process.parent_pid() as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_getuid() -> isize {
    match current_process() {
        Ok(process) => {
            let uid = process.ruid() as isize;
            axlog::debug!("sys_getuid: {}", uid);
            uid
        }
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_geteuid() -> isize {
    match current_process() {
        Ok(process) => {
            let euid = process.euid() as isize;
            axlog::debug!("sys_geteuid: {}", euid);
            euid
        }
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_getgid() -> isize {
    match current_process() {
        Ok(process) => {
            let gid = process.rgid() as isize;
            axlog::debug!("sys_getgid: {}", gid);
            gid
        }
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_getegid() -> isize {
    match current_process() {
        Ok(process) => {
            let egid = process.egid() as isize;
            axlog::debug!("sys_getegid: {}", egid);
            egid
        }
        Err(e) => -e.code() as isize,
    }
}
