use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use axerrno::{AxError, AxResult};
use axfs::FsContext;
use axfs_ng_vfs::{NodePermission, NodeType};
use axhal::paging::MappingFlags;
use memory_addr::va;
use spin::Mutex;

use super::Process;
use crate::config::*;

const SHEBANG_MAX_DEPTH: usize = 4;
const SHEBANG_PROBE_LEN: usize = 256;

fn parse_shebang_line(file_data: &[u8]) -> AxResult<Option<(String, Option<String>)>> {
    if !file_data.starts_with(b"#!") {
        return Ok(None);
    }

    let line_end = file_data
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(file_data.len());
    let line = core::str::from_utf8(&file_data[2..line_end]).map_err(|_| AxError::InvalidData)?;
    let line = line.trim_end_matches('\r').trim();
    if line.is_empty() {
        return Err(AxError::InvalidExecutable);
    }

    let mut parts = line.splitn(2, char::is_whitespace);
    let interp = parts.next().unwrap().trim();
    if interp.is_empty() {
        return Err(AxError::InvalidExecutable);
    }

    let interp_arg = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);

    Ok(Some((String::from(interp), interp_arg)))
}

fn check_txt_busy(path: &str) -> AxResult<()> {
    let procs = super::processes_snapshot();
    for proc in procs {
        if proc.fd_table().lock().is_file_write_open(path) {
            return Err(axerrno::LinuxError::ETXTBSY.into());
        }
    }
    Ok(())
}

fn resolve_exec_path_and_args(
    fs: &FsContext,
    path: &str,
    args: &[&str],
) -> AxResult<(String, Vec<String>)> {
    let normalize_path = |candidate: &str| -> AxResult<String> {
        let loc = fs.resolve(candidate)?;
        let path = loc.absolute_path()?;

        // Check if the file is a regular file
        let meta = loc.metadata()?;
        if meta.node_type != NodeType::RegularFile {
            return Err(AxError::PermissionDenied);
        }

        // Check if the file is currently open for writing by any process
        check_txt_busy(path.as_str())?;

        // Check execute permission based on credentials (uid/gid)
        if let Some((uid, gid)) = fs.credentials {
            if uid == 0 {
                // For root, can execute if any of the execute bits are set
                let any_x = meta.mode.contains(NodePermission::OWNER_EXEC)
                    || meta.mode.contains(NodePermission::GROUP_EXEC)
                    || meta.mode.contains(NodePermission::OTHER_EXEC);
                if !any_x {
                    return Err(AxError::PermissionDenied);
                }
            } else {
                let is_owner = uid == meta.uid;
                let is_group = gid == meta.gid;
                let has_x = if is_owner {
                    meta.mode.contains(NodePermission::OWNER_EXEC)
                } else if is_group {
                    meta.mode.contains(NodePermission::GROUP_EXEC)
                } else {
                    meta.mode.contains(NodePermission::OTHER_EXEC)
                };
                if !has_x {
                    return Err(AxError::PermissionDenied);
                }
            }
        }

        Ok(path.to_string())
    };

    let mut current_path = normalize_path(path)?;
    let mut current_args: Vec<String> = if args.is_empty() {
        alloc::vec![current_path.clone()]
    } else {
        args.iter().map(|s| String::from(*s)).collect()
    };

    for _ in 0..SHEBANG_MAX_DEPTH {
        current_path = normalize_path(&current_path)?;
        axlog::debug!("resolve_exec_path_and_args: probing {}", current_path);
        let file_data = fs
            .read_prefix(&current_path, SHEBANG_PROBE_LEN)
            .map_err(|_| AxError::NotFound)?;
        let Some((interp, interp_arg)) = parse_shebang_line(&file_data)? else {
            axlog::debug!("resolve_exec_path_and_args: final {}", current_path);
            return Ok((current_path, current_args));
        };

        let mut next_args = Vec::new();
        next_args.push(interp.clone());
        if let Some(arg) = interp_arg {
            next_args.push(arg);
        }
        next_args.push(current_path.clone());
        next_args.extend(current_args.into_iter().skip(1));

        current_path = interp;
        current_args = next_args;
    }

    Err(AxError::Unsupported)
}

impl Process {
    pub fn load_elf(&self, path: &str, args: &[&str], envs: &[&str]) -> AxResult<()> {
        let mut fs_ctx = self.fs_context_handle().lock().clone();
        fs_ctx.credentials = Some((self.euid(), self.egid()));
        let (path, argv) = resolve_exec_path_and_args(&fs_ctx, path, args)?;
        let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        let aspace_handle = self.aspace_handle();
        let mut aspace = aspace_handle.lock();
        let load_info = crate::mm::load_user_app(&mut aspace, &path, &argv_refs, envs)?;
        *self.entry.lock() = load_info.entry;
        *self.stack_top.lock() = load_info.user_sp;
        self.set_signal_trampoline(load_info.signal_trampoline);
        self.set_exec_path(path.clone());
        *self.args.lock() = argv;
        Ok(())
    }

    pub fn enter_user_mode(&self) -> ! {
        let entry = *self.entry.lock();
        let stack_top = *self.stack_top.lock();
        let uctx = axhal::context::UspaceContext::new(entry, va!(stack_top), 0);
        self.mark_user_resume();
        if let Ok(thread) = super::current_thread() {
            thread.mark_user_resume();
        }
        let kstack_top = axtask::current()
            .kernel_stack_top()
            .expect("current task has no kernel stack")
            .as_usize();
        unsafe {
            uctx.enter_uspace(va!(kstack_top));
        }
    }

    pub fn exec(&self, path: &str, args: &[&str], envs: &[&str]) -> AxResult<()> {
        let mut fs_ctx = self.fs_context_handle().lock().clone();
        fs_ctx.credentials = Some((self.euid(), self.egid()));
        let (path, argv) = resolve_exec_path_and_args(&fs_ctx, path, args)?;
        let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();

        // Build the new image in an isolated address space first.
        // If loading fails, the current process image remains intact.
        let mut new_aspace = axmm::new_user_aspace(va!(USER_SPACE_BASE), USER_SPACE_SIZE)?;
        let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
        new_aspace.map_alloc(
            va!(stack_bottom),
            USER_STACK_SIZE,
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
            false,
        )?;
        new_aspace.map_alloc(
            va!(USER_HEAP_BASE),
            USER_HEAP_SIZE,
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
            false,
        )?;

        let load_info = crate::mm::load_user_app(&mut new_aspace, &path, &argv_refs, envs)?;

        let new_aspace_handle = Arc::new(Mutex::new(new_aspace));
        let new_pt_root = new_aspace_handle.lock().page_table_root();
        let _old_aspace = self.replace_aspace_handle(new_aspace_handle);

        axtask::set_current_page_table_root(new_pt_root);
        self.activate();
        self.complete_vfork();

        {
            let mut shm = self.shared_memory.lock();
            for inner_arc in shm.values() {
                inner_arc.lock().detach_process(self.pid());
            }
            shm.clear();
        }

        let cloexec_entries = {
            let binding = self.fd_table();
            let mut fd_table = binding.lock();
            fd_table.take_cloexec_on_exec()
        };
        drop(cloexec_entries);
        *self.heap_top.lock() = USER_HEAP_BASE + USER_HEAP_SIZE;
        *self.stack_top.lock() = load_info.user_sp;
        *self.entry.lock() = load_info.entry;
        self.set_signal_trampoline(load_info.signal_trampoline);
        self.signal_shared().reset_on_exec();
        self.set_exec_path(path.clone());
        *self.args.lock() = argv;
        if let Ok(thread) = super::current_thread() {
            if thread.process().pid() == self.pid() {
                thread.signal().reset_on_exec();
            }
        }
        Ok(())
    }
}
