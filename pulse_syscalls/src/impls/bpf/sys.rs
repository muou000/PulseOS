use alloc::sync::Arc;

use axerrno::LinuxError;
use pulse_core::{
    bpf::{BpfMap, BpfMapCreateRequest, BpfMapObject, BpfMapSpec, BpfProgramObject},
    fd_table::{FdEntry, FdFlags},
    task::Process,
};

use super::{
    abi::{self, BpfCmd, BpfMapCreateAttr, BpfObjGetInfoAttr, BpfPermissions},
    elem,
    info::copy_obj_info_to_user,
    prog,
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
        BpfCmd::MapLookupElem => {
            let attr = unsafe { &attr_buf.map_elem };
            if attr.flags != 0 {
                return Err(LinuxError::EINVAL);
            }
            let map = get_bpf_map(&process, attr.map_fd)?;
            elem::bpf_map_lookup_elem(
                map.as_ref(),
                attr,
                |addr, buf| read_user(&process, addr, buf),
                |addr, buf| write_user(&process, addr, buf),
            )
        }
        BpfCmd::MapUpdateElem => {
            let attr = unsafe { &attr_buf.map_elem };
            let map = get_bpf_map(&process, attr.map_fd)?;
            elem::bpf_map_update_elem(
                map.as_ref(),
                attr,
                |addr, buf| read_user(&process, addr, buf),
            )
        }
        BpfCmd::MapDeleteElem => {
            let attr = unsafe { &attr_buf.map_elem };
            if attr.flags != 0 || attr.value_or_next_key != 0 {
                return Err(LinuxError::EINVAL);
            }
            let map = get_bpf_map(&process, attr.map_fd)?;
            elem::bpf_map_delete_elem(
                map.as_ref(),
                attr,
                |addr, buf| read_user(&process, addr, buf),
            )
        }
        BpfCmd::MapGetNextKey => {
            let attr = unsafe { &attr_buf.map_elem };
            if attr.flags != 0 {
                return Err(LinuxError::EINVAL);
            }
            let map = get_bpf_map(&process, attr.map_fd)?;
            elem::bpf_map_get_next_key(
                map.as_ref(),
                attr,
                |addr, buf| read_user(&process, addr, buf),
                |addr, buf| write_user(&process, addr, buf),
            )
        }
        BpfCmd::ObjGetInfoByFd => obj_get_info_by_fd(&process, unsafe { &attr_buf.info }, attr),
        BpfCmd::ProgLoad => {
            let prog_attr = unsafe { &attr_buf.prog_load };
            prog::bpf_prog_load(
                &process,
                prog_attr,
                attr,
                size,
                |addr, buf| read_user(&process, addr, buf),
                |addr, buf| write_user(&process, addr, buf),
            )
        }
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

fn get_bpf_map(process: &Process, map_fd: u32) -> Result<Arc<BpfMap>, LinuxError> {
    let object = process.get_fd_object(map_fd as usize)?;
    let Some(map_object) = object.as_any().downcast_ref::<BpfMapObject>() else {
        return Err(LinuxError::EINVAL);
    };
    Ok(map_object.map().clone())
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
    let info_bytes = if let Some(map_object) = object.as_any().downcast_ref::<BpfMapObject>() {
        let info = map_object.info();
        alloc::vec::Vec::from(info.as_bytes())
    } else if let Some(prog_object) = object.as_any().downcast_ref::<BpfProgramObject>() {
        let info = prog_object.info();
        alloc::vec::Vec::from(info.as_bytes())
    } else {
        return Err(LinuxError::EINVAL);
    };

    let info_len = copy_obj_info_to_user(
        attr.info as usize,
        attr.info_len,
        &info_bytes,
        |addr, buf| read_user(process, addr, buf),
        |addr, buf| write_user(process, addr, buf),
    )?;
    let info_len_addr = attr_addr + core::mem::offset_of!(BpfObjGetInfoAttr, info_len);
    write_user(process, info_len_addr, &info_len.to_ne_bytes())?;
    Ok(0)
}

pub fn run_bpf_guest_checks() -> Result<(), LinuxError> {
    axlog::ax_println!("[BPF_GUEST] Starting BPF Map element control plane checks...");

    // 1. Hash map: key_size=8, val_size=1024, max_entries=1
    let hash_req = BpfMapCreateRequest {
        map_type: pulse_core::bpf::BPF_MAP_TYPE_HASH,
        key_size: 8,
        value_size: 1024,
        max_entries: 1,
        ..Default::default()
    };
    let hash_map = BpfMap::create(BpfMapSpec::validate(&hash_req)?)?;

    let mut key8 = [0u8; 8];
    key8.copy_from_slice(b"12345678");
    let mut val_get = alloc::vec![0x55u8; 1024];
    let mut val_set = alloc::vec![0u8; 1024];
    for i in 0..1024 {
        val_set[i] = (i % 256) as u8;
    }

    // Empty hash map lookup fails with ENOENT
    if hash_map.lookup(&key8, &mut val_get) != Err(LinuxError::ENOENT) {
        return Err(LinuxError::EINVAL);
    }

    // Update with BPF_ANY succeeds
    hash_map.update(&key8, &val_set, pulse_core::bpf::BPF_ANY)?;

    // Lookup returns updated value
    hash_map.lookup(&key8, &mut val_get)?;
    if val_get != val_set {
        return Err(LinuxError::EINVAL);
    }

    // 2. Array map: key_size=4, val_size=1024, max_entries=1
    let array_req = BpfMapCreateRequest {
        map_type: pulse_core::bpf::BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: 1024,
        max_entries: 1,
        ..Default::default()
    };
    let array_map = BpfMap::create(BpfMapSpec::validate(&array_req)?)?;

    let key4 = 0u32.to_ne_bytes();
    val_get.fill(0x77);

    // Preallocated array map lookup returns zeroes
    array_map.lookup(&key4, &mut val_get)?;
    if !val_get.iter().all(|&b| b == 0) {
        return Err(LinuxError::EINVAL);
    }

    // Update array map with BPF_ANY
    array_map.update(&key4, &val_set, pulse_core::bpf::BPF_ANY)?;
    array_map.lookup(&key4, &mut val_get)?;
    if val_get != val_set {
        return Err(LinuxError::EINVAL);
    }

    // Array map delete fails with EINVAL
    if array_map.delete(&key4) != Err(LinuxError::EINVAL) {
        return Err(LinuxError::EINVAL);
    }

    // Array map update with BPF_NOEXIST fails with EEXIST
    if array_map.update(&key4, &val_set, pulse_core::bpf::BPF_NOEXIST) != Err(LinuxError::EEXIST) {
        return Err(LinuxError::EINVAL);
    }

    // Hash map delete succeeds
    hash_map.delete(&key8)?;
    if hash_map.lookup(&key8, &mut val_get) != Err(LinuxError::ENOENT) {
        return Err(LinuxError::EINVAL);
    }

    axlog::ax_println!("[BPF_GUEST] BPF_MAP01 assertions: PASS");

    axlog::ax_println!("[BPF_GUEST] Starting BPF Program load and verifier checks...");

    // 1. Valid TRACEPOINT program: r0 = 0; exit
    let valid_insns = [
        pulse_core::bpf::BpfInsn::new(
            pulse_core::bpf::BPF_ALU64 | pulse_core::bpf::BPF_MOV | pulse_core::bpf::BPF_K,
            pulse_core::bpf::BPF_REG_0,
            0,
            0,
            0,
        ),
        pulse_core::bpf::BpfInsn::new(
            pulse_core::bpf::BPF_JMP | pulse_core::bpf::BPF_EXIT,
            0,
            0,
            0,
            0,
        ),
    ];
    let config = pulse_core::bpf::verifier::VerifierConfig::new(
        pulse_core::bpf::BpfProgType::Tracepoint,
        1,
    );
    let mut log = pulse_core::bpf::verifier::VerifierLog::new();
    let verified = pulse_core::bpf::verifier::verify_program(&config, &valid_insns, None, &mut log)?;
    if verified.insns.len() != 2 || verified.prog_type != pulse_core::bpf::BpfProgType::Tracepoint {
        return Err(LinuxError::EINVAL);
    }

    // 2. Malformed program: missing exit
    let bad_insns = [
        pulse_core::bpf::BpfInsn::new(
            pulse_core::bpf::BPF_ALU64 | pulse_core::bpf::BPF_MOV | pulse_core::bpf::BPF_K,
            pulse_core::bpf::BPF_REG_0,
            0,
            0,
            0,
        ),
    ];
    let mut bad_log = pulse_core::bpf::verifier::VerifierLog::new();
    if pulse_core::bpf::verifier::verify_program(&config, &bad_insns, None, &mut bad_log).is_ok() {
        return Err(LinuxError::EINVAL);
    }
    if !bad_log.as_str().contains("0:") {
        return Err(LinuxError::EINVAL);
    }

    axlog::ax_println!("[BPF_GUEST] BPF_PROG_LOAD verifier assertions: PASS");

    axlog::ax_println!("[BPF_GUEST] Starting BPF Program execution and Map helper checks...");

    struct GuestMapResolver {
        map: Arc<BpfMap>,
    }
    impl pulse_core::bpf::verifier::MapResolver for GuestMapResolver {
        fn resolve_map(&self, _fd: u32) -> Result<Arc<BpfMap>, LinuxError> {
            Ok(self.map.clone())
        }
    }

    let arr_req = BpfMapCreateRequest {
        map_type: pulse_core::bpf::BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: 8,
        max_entries: 1,
        ..Default::default()
    };
    let arr_map = Arc::new(BpfMap::create(BpfMapSpec::validate(&arr_req)?)?);
    let resolver = GuestMapResolver { map: arr_map.clone() };

    let prog_insns = [
        pulse_core::bpf::BpfInsn::new(
            pulse_core::bpf::BPF_LD | pulse_core::bpf::BPF_IMM | pulse_core::bpf::BPF_DW,
            pulse_core::bpf::BPF_REG_1,
            pulse_core::bpf::BPF_PSEUDO_MAP_FD,
            0,
            1,
        ),
        pulse_core::bpf::BpfInsn::new(0, 0, 0, 0, 0),
        pulse_core::bpf::BpfInsn::new(
            pulse_core::bpf::BPF_ALU64 | pulse_core::bpf::BPF_MOV | pulse_core::bpf::BPF_X,
            pulse_core::bpf::BPF_REG_2,
            pulse_core::bpf::BPF_REG_10,
            0,
            0,
        ),
        pulse_core::bpf::BpfInsn::new(
            pulse_core::bpf::BPF_ALU64 | pulse_core::bpf::BPF_ADD | pulse_core::bpf::BPF_K,
            pulse_core::bpf::BPF_REG_2,
            0,
            0,
            -8,
        ),
        pulse_core::bpf::BpfInsn::new(
            pulse_core::bpf::BPF_ST | pulse_core::bpf::BPF_MEM | pulse_core::bpf::BPF_DW,
            pulse_core::bpf::BPF_REG_2,
            0,
            0,
            0,
        ),
        pulse_core::bpf::BpfInsn::new(
            pulse_core::bpf::BPF_JMP | pulse_core::bpf::BPF_CALL,
            0,
            0,
            0,
            pulse_core::bpf::BPF_FUNC_MAP_LOOKUP_ELEM,
        ),
        pulse_core::bpf::BpfInsn::new(
            pulse_core::bpf::BPF_JMP | pulse_core::bpf::BPF_JEQ | pulse_core::bpf::BPF_K,
            pulse_core::bpf::BPF_REG_0,
            0,
            3,
            0,
        ),
        pulse_core::bpf::BpfInsn::new(
            pulse_core::bpf::BPF_ALU64 | pulse_core::bpf::BPF_MOV | pulse_core::bpf::BPF_X,
            pulse_core::bpf::BPF_REG_1,
            pulse_core::bpf::BPF_REG_0,
            0,
            0,
        ),
        pulse_core::bpf::BpfInsn::new(
            pulse_core::bpf::BPF_ST | pulse_core::bpf::BPF_MEM | pulse_core::bpf::BPF_DW,
            pulse_core::bpf::BPF_REG_1,
            0,
            0,
            12345,
        ),
        pulse_core::bpf::BpfInsn::new(
            pulse_core::bpf::BPF_ALU64 | pulse_core::bpf::BPF_MOV | pulse_core::bpf::BPF_K,
            pulse_core::bpf::BPF_REG_0,
            0,
            0,
            0,
        ),
        pulse_core::bpf::BpfInsn::new(
            pulse_core::bpf::BPF_JMP | pulse_core::bpf::BPF_EXIT,
            0,
            0,
            0,
            0,
        ),
    ];

    let mut guest_log = pulse_core::bpf::verifier::VerifierLog::new();
    let guest_verified = pulse_core::bpf::verifier::verify_program(&config, &prog_insns, Some(&resolver), &mut guest_log)?;
    let guest_prog = pulse_core::bpf::BpfProgram::new(
        guest_verified.prog_type,
        [0u8; 16],
        guest_verified.insns,
        guest_verified.referenced_maps,
    );

    let ret = guest_prog.run(&[]).map_err(LinuxError::from)?;
    if ret != 0 {
        return Err(LinuxError::EINVAL);
    }

    let mut out_val = [0u8; 8];
    arr_map.lookup(&0u32.to_ne_bytes(), &mut out_val)?;
    if u64::from_ne_bytes(out_val) != 12345 {
        return Err(LinuxError::EINVAL);
    }

    axlog::ax_println!("[BPF_GUEST] BPF Program execution assertions: PASS");

    axlog::ax_println!("[BPF_GUEST] Starting software perf event control checks...");

    // 1. CPU clock event: disabled by default
    let cpu_spec = pulse_core::bpf::PerfEventSpec {
        clock: pulse_core::bpf::PerfEventClock::CpuClock,
        scope: pulse_core::bpf::PerfEventScope::PerCpu { cpu: 0 },
        sample_period: 0,
        disabled: true,
        cloexec: true,
    };
    let cpu_now_ns = pulse_core::bpf::PerfEventObject::current_time_ns_for_spec(&cpu_spec);
    let cpu_event = alloc::sync::Arc::new(pulse_core::bpf::PerfEvent::new(cpu_spec, cpu_now_ns));
    let cpu_obj = pulse_core::bpf::PerfEventObject::new(cpu_event.clone());

    let mut count_buf = [0u8; 8];
    // Initial read is 0
    use pulse_core::fd_table::FdObject;
    cpu_obj.read(&mut count_buf)?;
    if u64::from_ne_bytes(count_buf) != 0 {
        return Err(LinuxError::EINVAL);
    }

    // Reset via ioctl
    cpu_obj.ioctl(pulse_core::bpf::PERF_EVENT_IOC_RESET, 0)?;

    // Enable via ioctl
    cpu_obj.ioctl(pulse_core::bpf::PERF_EVENT_IOC_ENABLE, 0)?;
    if !cpu_event.is_enabled() {
        return Err(LinuxError::EINVAL);
    }

    // Busy work loop to consume CPU clock
    for i in 0..1000000usize {
        core::hint::black_box(i);
    }

    // Disable via ioctl
    cpu_obj.ioctl(pulse_core::bpf::PERF_EVENT_IOC_DISABLE, 0)?;
    if cpu_event.is_enabled() {
        return Err(LinuxError::EINVAL);
    }

    // Read counter: must have accumulated > 0 nanoseconds
    cpu_obj.read(&mut count_buf)?;
    let elapsed = u64::from_ne_bytes(count_buf);
    if elapsed == 0 {
        return Err(LinuxError::EINVAL);
    }

    // Reset via ioctl: must be 0
    cpu_obj.ioctl(pulse_core::bpf::PERF_EVENT_IOC_RESET, 0)?;
    cpu_obj.read(&mut count_buf)?;
    if u64::from_ne_bytes(count_buf) != 0 {
        return Err(LinuxError::EINVAL);
    }

    // 2. Task clock event
    let task_spec = pulse_core::bpf::PerfEventSpec {
        clock: pulse_core::bpf::PerfEventClock::TaskClock,
        scope: pulse_core::bpf::PerfEventScope::Task { pid: 1 },
        sample_period: 0,
        disabled: true,
        cloexec: false,
    };
    let task_now_ns = pulse_core::bpf::PerfEventObject::current_time_ns_for_spec(&task_spec);
    let task_event = alloc::sync::Arc::new(pulse_core::bpf::PerfEvent::new(task_spec, task_now_ns));
    let task_obj = pulse_core::bpf::PerfEventObject::new(task_event.clone());

    task_obj.ioctl(pulse_core::bpf::PERF_EVENT_IOC_RESET, 0)?;
    task_obj.ioctl(pulse_core::bpf::PERF_EVENT_IOC_ENABLE, 0)?;
    for i in 0..1000000usize {
        core::hint::black_box(i);
    }
    task_obj.ioctl(pulse_core::bpf::PERF_EVENT_IOC_DISABLE, 0)?;
    task_obj.read(&mut count_buf)?;
    let task_elapsed = u64::from_ne_bytes(count_buf);
    if task_elapsed == 0 {
        return Err(LinuxError::EINVAL);
    }

    // Stat anon_inode regular file
    let st = task_obj.stat()?;
    if (st.st_mode & linux_raw_sys::general::S_IFMT) != linux_raw_sys::general::S_IFREG {
        return Err(LinuxError::EINVAL);
    }

    axlog::ax_println!("[BPF_GUEST] Perf Event assertions: PASS (cpu_ns={}, task_ns={})", elapsed, task_elapsed);

    Ok(())
}
