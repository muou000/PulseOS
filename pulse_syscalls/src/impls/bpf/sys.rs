use axerrno::LinuxError;

use super::abi::{self, BpfPermissions};

pub fn sys_bpf(cmd: i32, attr: usize, size: usize) -> isize {
    let thread = match pulse_core::task::current_thread() {
        Ok(t) => t,
        Err(e) => return -LinuxError::from(e).code() as isize,
    };
    let process = thread.process();

    let perms = BpfPermissions::new(
        process.is_root_user(),
        process.has_capability(21),
        process.has_capability(39),
    );

    let (bpf_cmd, _attr_buf) = match abi::validate_bpf_syscall(
        perms,
        cmd,
        attr,
        size,
        |addr, buf| {
            if pulse_core::task::uaccess::validate_user_range(addr, buf.len()).is_err() {
                return Err(LinuxError::EFAULT);
            }
            process.read_user_bytes(addr, buf).map_err(|_| LinuxError::EFAULT)
        },
    ) {
        Ok(res) => res,
        Err(e) => return -e.code() as isize,
    };

    if bpf_cmd.is_deferred() {
        return -LinuxError::EOPNOTSUPP.code() as isize;
    }

    -LinuxError::EOPNOTSUPP.code() as isize
}

