use alloc::{sync::Arc, vec, vec::Vec};
use axerrno::LinuxError;
use pulse_core::{
    bpf::{
        verifier::{verify_program, MapResolver, VerifierConfig, VerifierLog, BPF_MAXINSNS},
        BpfInsn, BpfMap, BpfMapObject, BpfProgType, BpfProgram, BpfProgramObject,
    },
    fd_table::{FdEntry, FdFlags},
    task::Process,
};

use super::abi::BpfProgLoadAttr;

struct ProcessMapResolver<'a> {
    process: &'a Process,
}

impl<'a> MapResolver for ProcessMapResolver<'a> {
    fn resolve_map(&self, fd: u32) -> Result<Arc<BpfMap>, LinuxError> {
        let object = self.process.get_fd_object(fd as usize)?;
        let Some(map_object) = object.as_any().downcast_ref::<BpfMapObject>() else {
            return Err(LinuxError::EINVAL);
        };
        Ok(map_object.map().clone())
    }
}

pub fn bpf_prog_load<R, W>(
    process: &Process,
    attr: &BpfProgLoadAttr,
    attr_addr: usize,
    attr_size: usize,
    mut read_user: R,
    mut write_user: W,
) -> Result<isize, LinuxError>
where
    R: FnMut(usize, &mut [u8]) -> Result<(), LinuxError>,
    W: FnMut(usize, &[u8]) -> Result<(), LinuxError>,
{
    process.check_next_fd_limit()?;

    // 1. Validate prog_type: only TRACEPOINT (5) and PERF_EVENT (7) accepted
    let prog_type = BpfProgType::from_raw(attr.prog_type)?;

    // 2. Validate unsupported flags / fields
    if attr.prog_flags != 0
        || attr.expected_attach_type != 0
        || attr.prog_ifindex != 0
        || attr.prog_btf_fd != 0
        || attr.func_info_cnt != 0
        || attr.line_info_cnt != 0
        || attr.attach_btf_id != 0
        || attr.attach_prog_or_btf_fd != 0
        || attr.core_relo_cnt != 0
    {
        return Err(LinuxError::EINVAL);
    }

    // 3. Validate insn_cnt
    let insn_cnt = attr.insn_cnt as usize;
    if insn_cnt == 0 {
        return Err(LinuxError::EINVAL);
    }
    if insn_cnt > BPF_MAXINSNS {
        return Err(LinuxError::E2BIG);
    }

    // 4. Validate instructions pointer
    if attr.insns == 0 {
        return Err(LinuxError::EFAULT);
    }
    let total_insn_bytes = insn_cnt
        .checked_mul(core::mem::size_of::<BpfInsn>())
        .ok_or(LinuxError::EFAULT)?;
    let mut insns: Vec<BpfInsn> = vec![BpfInsn::default(); insn_cnt];
    let insns_raw = unsafe {
        core::slice::from_raw_parts_mut(
            insns.as_mut_ptr() as *mut u8,
            total_insn_bytes,
        )
    };
    read_user(attr.insns as usize, insns_raw)?;

    // 5. Validate license pointer if provided
    if attr.license != 0 {
        let mut lic_buf = [0u8; 128];
        read_user(attr.license as usize, &mut lic_buf)?;
    }

    // 6. Validate log buffer parameters
    if attr.log_size == 0 {
        if attr.log_buf != 0 || attr.log_level != 0 {
            return Err(LinuxError::EINVAL);
        }
    } else {
        if attr.log_buf == 0 {
            return Err(LinuxError::EINVAL);
        }
        if attr.log_size < 128 {
            return Err(LinuxError::EINVAL);
        }
        // Probe user buffer writeability
        let test_zero = [0u8; 1];
        write_user(attr.log_buf as usize, &test_zero)?;
    }

    // 7. Run verifier
    let config = VerifierConfig::new(prog_type, attr.log_level);
    let mut log = VerifierLog::new();
    let resolver = ProcessMapResolver { process };
    let verify_result = verify_program(&config, &insns, Some(&resolver), &mut log);

    // 8. Copy log to user buffer if requested
    if attr.log_size > 0 {
        let mut user_log = vec![0u8; attr.log_size as usize];
        log.copy_to_user_slice(&mut user_log);
        write_user(attr.log_buf as usize, &user_log)?;

        let log_true_size_end =
            core::mem::offset_of!(BpfProgLoadAttr, log_true_size) + core::mem::size_of::<u32>();
        if attr_size >= log_true_size_end {
            let log_true_size_addr = attr_addr + core::mem::offset_of!(BpfProgLoadAttr, log_true_size);
            let true_size = log.true_size() as u32;
            let _ = write_user(log_true_size_addr, &true_size.to_ne_bytes());
        }
    }

    let verified = verify_result?;

    // 9. Publish verified program object FD
    let program = Arc::new(BpfProgram::new(
        verified.prog_type,
        attr.prog_name,
        verified.insns,
        verified.referenced_maps,
    ));
    let entry = FdEntry::new(Arc::new(BpfProgramObject::new(program)), FdFlags::CLOEXEC);
    process.insert_fd_entry(entry).map(|fd| fd as isize)
}
