use alloc::sync::Arc;

use axerrno::LinuxError;
use pulse_core::{
    bpf::{BpfMap, BpfMapCreateRequest, BpfMapObject, BpfMapSpec},
    fd_table::{FdEntry, FdFlags},
    task::Process,
};

use super::{
    abi::{self, BpfCmd, BpfMapCreateAttr, BpfObjGetInfoAttr, BpfPermissions},
    info::copy_obj_info_to_user,
};

impl From<&BpfMapCreateAttr> for BpfMapCreateRequest {
    fn from(attr: &BpfMapCreateAttr) -> Self {
        Self {
            map_type: attr.map_type,
            key_size: attr.key_size,
            value_size: attr.value_size,
            max_entries: attr.max_entries,
            map_flags: attr.map_flags,
            inner_map_fd: attr.inner_map_fd,
            numa_node: attr.numa_node,
            map_name: attr.map_name,
            map_ifindex: attr.map_ifindex,
            btf_fd: attr.btf_fd,
            btf_key_type_id: attr.btf_key_type_id,
            btf_value_type_id: attr.btf_value_type_id,
            btf_vmlinux_value_type_id: attr.btf_vmlinux_value_type_id,
            map_extra: attr.map_extra,
        }
    }
}

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

    let (bpf_cmd, attr_buf) = match abi::validate_bpf_syscall(
        perms,
        cmd,
        attr,
        size,
        |addr, buf| read_user(&process, addr, buf),
    ) {
        Ok(res) => res,
        Err(e) => return -e.code() as isize,
    };

    if bpf_cmd.is_deferred() {
        return -LinuxError::EOPNOTSUPP.code() as isize;
    }

    let result = attr_buf.check_unused_tail(bpf_cmd).and_then(|()| match bpf_cmd {
        // SAFETY: the union is fully initialized; each arm reads the member
        // that matches the decoded command.
        BpfCmd::MapCreate => map_create(&process, unsafe { &attr_buf.map_create }),
        BpfCmd::ObjGetInfoByFd => obj_get_info_by_fd(&process, unsafe { &attr_buf.info }, attr),
        _ => Err(LinuxError::EOPNOTSUPP),
    });

    match result {
        Ok(ret) => ret,
        Err(e) => -e.code() as isize,
    }
}

fn read_user(process: &Process, addr: usize, buf: &mut [u8]) -> Result<(), LinuxError> {
    process.read_user_bytes(addr, buf).map_err(|_| LinuxError::EFAULT)
}

fn write_user(process: &Process, addr: usize, buf: &[u8]) -> Result<(), LinuxError> {
    process.write_user_bytes(addr, buf).map_err(|_| LinuxError::EFAULT)
}

fn map_create(process: &Process, attr: &BpfMapCreateAttr) -> Result<isize, LinuxError> {
    process.check_next_fd_limit()?;
    let spec = BpfMapSpec::validate(&BpfMapCreateRequest::from(attr))?;
    let map = Arc::new(BpfMap::create(spec)?);
    // Linux BPF object FDs are always close-on-exec. If the FD table is full
    // (RLIMIT_NOFILE), the entry and with it the last Map reference drop here.
    let entry = FdEntry::new(Arc::new(BpfMapObject::new(map)), FdFlags::CLOEXEC);
    process.insert_fd_entry(entry).map(|fd| fd as isize)
}

fn obj_get_info_by_fd(
    process: &Process,
    attr: &BpfObjGetInfoAttr,
    attr_addr: usize,
) -> Result<isize, LinuxError> {
    let object = process.get_fd_object(attr.bpf_fd as usize)?;
    let Some(map_object) = object.as_any().downcast_ref::<BpfMapObject>() else {
        return Err(LinuxError::EINVAL);
    };
    let info = map_object.info();
    let info_len = copy_obj_info_to_user(
        attr.info as usize,
        attr.info_len,
        info.as_bytes(),
        |addr, buf| read_user(process, addr, buf),
        |addr, buf| write_user(process, addr, buf),
    )?;
    let info_len_addr = attr_addr + core::mem::offset_of!(BpfObjGetInfoAttr, info_len);
    write_user(process, info_len_addr, &info_len.to_ne_bytes())?;
    Ok(0)
}
