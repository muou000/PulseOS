use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use axerrno::{AxError, AxResult};
use axfs::FsContext;
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

fn resolve_exec_path_and_args(
    fs: &FsContext,
    path: &str,
    args: &[&str],
) -> AxResult<(String, Vec<String>)> {
    let normalize_path = |candidate: &str| -> AxResult<String> {
        fs.resolve(candidate)
            .map_err(|_| AxError::NotFound)?
            .absolute_path()
            .map(|p| p.to_string())
            .map_err(|_| AxError::NotFound)
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
        let fs_ctx = self.fs_context.lock().clone();
        let (path, argv) = resolve_exec_path_and_args(&fs_ctx, path, args)?;
        let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        let aspace_handle = self.aspace_handle();
        let mut aspace = aspace_handle.lock();
        let load_info = crate::mm::load_user_app(&mut aspace, &path, &argv_refs, envs)?;
        *self.entry.lock() = load_info.entry;
        *self.stack_top.lock() = load_info.user_sp;
        Ok(())
    }

    pub fn enter_user_mode(&self) -> ! {
        let entry = *self.entry.lock();
        let stack_top = *self.stack_top.lock();
        let uctx = axhal::context::UspaceContext::new(entry, va!(stack_top), 0);
        self.mark_user_resume();
        let kstack_top = axtask::current()
            .kernel_stack_top()
            .expect("current task has no kernel stack")
            .as_usize();
        unsafe {
            uctx.enter_uspace(va!(kstack_top));
        }
    }

    pub fn exec(&self, path: &str, args: &[&str], envs: &[&str]) -> AxResult<()> {
        let fs_ctx = self.fs_context.lock().clone();
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
            true,
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
        let cloexec_entries = {
            let mut fd_table = self.fd_table.lock();
            fd_table.take_cloexec_on_exec()
        };
        drop(cloexec_entries);
        *self.heap_top.lock() = USER_HEAP_BASE + USER_HEAP_SIZE;
        *self.stack_top.lock() = load_info.user_sp;
        *self.entry.lock() = load_info.entry;
        Ok(())
    }
}
