use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::Ordering;

use axerrno::{AxError, AxResult};
use axfs::FsContext;
use axfs_ng_vfs::{Location, NodePermission, NodeType};
use axhal::paging::MappingFlags;
use memory_addr::va;

use super::{AddressSpaceLock, Process, Thread};
use crate::config::*;

const SHEBANG_MAX_DEPTH: usize = 4;
const SHEBANG_PROBE_LEN: usize = 256;

struct PreparedExec {
    aspace: Arc<AddressSpaceLock>,
    load_info: crate::mm::UserAppLoadInfo,
    path: String,
    argv: Vec<String>,
}

struct ResolvedExec {
    location: Location,
    exec_access: axfs::ExecAccessGuard,
    path: String,
    execfn_path: String,
    argv: Vec<String>,
}

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

fn read_exec_prefix(location: &Location) -> AxResult<Vec<u8>> {
    let file = axfs::CachedFile::get_or_create(location.clone())?;
    let mut prefix = alloc::vec![0u8; SHEBANG_PROBE_LEN];
    let read = file.read_at(&mut prefix[..], 0)?;
    prefix.truncate(read);
    Ok(prefix)
}

fn resolve_exec_target_and_args(
    fs: &FsContext,
    path: &str,
    args: &[&str],
) -> AxResult<ResolvedExec> {
    // Keep the pathname supplied to execve separately from a shebang's final
    // interpreter. Linux exposes the former through AT_EXECFN.
    let execfn_path = path.to_string();
    let normalize_path = |candidate: &str| -> AxResult<(Location, String)> {
        let loc = axtask::future::block_on(fs.resolve(candidate))?;
        let path = loc.absolute_path()?;

        // Check if the file is a regular file
        let meta = axtask::future::block_on(loc.metadata())?;
        if meta.node_type != NodeType::RegularFile {
            return Err(AxError::PermissionDenied);
        }

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

        Ok((loc, path.to_string()))
    };

    let (mut current_location, mut current_path) = normalize_path(path)?;
    let mut current_args: Vec<String> = if args.is_empty() {
        alloc::vec![current_path.clone()]
    } else {
        args.iter().map(|s| String::from(*s)).collect()
    };

    for _ in 0..SHEBANG_MAX_DEPTH {
        let exec_access = axfs::acquire_exec_access(&current_location)?;
        axlog::debug!("resolve_exec_path_and_args: probing {}", current_path);
        let file_data = read_exec_prefix(&current_location).map_err(|_| AxError::NotFound)?;
        let Some((interp, interp_arg)) = parse_shebang_line(&file_data)? else {
            axlog::debug!("resolve_exec_path_and_args: final {}", current_path);
            return Ok(ResolvedExec {
                location: current_location,
                exec_access,
                path: current_path,
                execfn_path,
                argv: current_args,
            });
        };
        drop(exec_access);

        let mut next_args = Vec::new();
        next_args.push(interp.clone());
        if let Some(arg) = interp_arg {
            next_args.push(arg);
        }
        next_args.push(current_path.clone());
        next_args.extend(current_args.into_iter().skip(1));

        (current_location, current_path) = normalize_path(&interp)?;
        current_args = next_args;
    }

    Err(AxError::Unsupported)
}

pub fn resolve_exec_path_and_args(
    fs: &FsContext,
    path: &str,
    args: &[&str],
) -> AxResult<(String, Vec<String>)> {
    let resolved = resolve_exec_target_and_args(fs, path, args)?;
    Ok((resolved.path, resolved.argv))
}

impl Process {
    pub fn load_elf(&self, path: &str, args: &[&str], envs: &[&str]) -> AxResult<()> {
        let mut fs_ctx = self.fs_context_handle().lock().clone();
        fs_ctx.credentials = Some((self.fsuid(), self.fsgid()));
        let ResolvedExec {
            location,
            exec_access,
            path,
            execfn_path,
            argv,
        } = resolve_exec_target_and_args(&fs_ctx, path, args)?;
        let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        let exec_credentials = {
            let credentials = self.credentials.read();
            crate::mm::ExecCredentials::new(
                credentials.ruid,
                credentials.euid,
                credentials.rgid,
                credentials.egid,
            )
        };

        let mut new_aspace = axmm::new_user_aspace(va!(USER_SPACE_BASE), USER_SPACE_SIZE)?;
        let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
        new_aspace.map_alloc(
            va!(stack_bottom),
            USER_STACK_SIZE,
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
            false,
        )?;
        let load_info = crate::mm::load_user_app(
            &mut new_aspace,
            &fs_ctx,
            exec_credentials,
            location,
            exec_access,
            &path,
            &execfn_path,
            &argv_refs,
            envs,
        )?;
        let new_aspace_handle = Arc::new(AddressSpaceLock::new(new_aspace));
        let new_pt_root = new_aspace_handle.read().page_table_root();
        let new_asid = new_aspace_handle.read().asid();
        let old_aspace = self.replace_aspace_handle(new_aspace_handle);
        axtask::set_current_page_table_root(new_pt_root, new_asid);
        self.reset_brk_state(
            load_info.start_brk,
            load_info.start_brk,
            load_info.start_data,
            load_info.end_data,
        );
        let old_exec_access = self.replace_exec_access(load_info.exec_access);
        drop(old_aspace);
        drop(old_exec_access);

        self.entry.store(load_info.entry, Ordering::Release);
        self.stack_top.store(load_info.user_sp, Ordering::Release);
        self.set_signal_trampoline(load_info.signal_trampoline);
        self.set_exec_path(path.clone());
        *self.args.write() = argv;
        self.set_dumpable(1);
        self.mark_execed();
        axtask::current().set_name(&self.name());
        #[cfg(feature = "qperf-trace")]
        super::emit_current_qperf_task_metadata();
        Ok(())
    }

    pub fn enter_user_mode(&self) -> ! {
        let entry = self.entry.load(Ordering::Acquire);
        let stack_top = self.stack_top.load(Ordering::Acquire);
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

    pub fn enter_user_mode_and_drop(self: Arc<Self>, thread: Arc<super::Thread>) -> ! {
        let entry = self.entry.load(Ordering::Acquire);
        let stack_top = self.stack_top.load(Ordering::Acquire);
        self.mark_user_resume();
        thread.mark_user_resume();

        drop(thread);
        drop(self);

        let uctx = axhal::context::UspaceContext::new(entry, va!(stack_top), 0);
        let kstack_top = axtask::current()
            .kernel_stack_top()
            .expect("current task has no kernel stack")
            .as_usize();
        unsafe {
            uctx.enter_uspace(va!(kstack_top));
        }
    }

    pub fn exec(
        &self,
        caller: &Arc<Thread>,
        path: &str,
        args: &[&str],
        envs: &[&str],
    ) -> AxResult<()> {
        if caller.process().pid() != self.pid() {
            return Err(AxError::InvalidInput);
        }

        let exec_guard = loop {
            if caller.exec_exit_requested() || self.group_exiting() {
                return Err(AxError::Interrupted);
            }
            if let Some(guard) = self.try_lock_exec() {
                break guard;
            }
            axtask::yield_now();
        };

        let mut fs_ctx = self.fs_context_handle().lock().clone();
        fs_ctx.credentials = Some((self.fsuid(), self.fsgid()));
        let ResolvedExec {
            location,
            exec_access,
            path,
            execfn_path,
            argv,
        } = resolve_exec_target_and_args(&fs_ctx, path, args)?;
        let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        let exec_credentials = {
            let credentials = self.credentials.read();
            crate::mm::ExecCredentials::new(
                credentials.ruid,
                credentials.euid,
                credentials.rgid,
                credentials.egid,
            )
        };

        // Complete every fallible load step before changing the old image or
        // terminating sibling threads.
        let mut new_aspace = axmm::new_user_aspace(va!(USER_SPACE_BASE), USER_SPACE_SIZE)?;
        let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
        new_aspace.map_alloc(
            va!(stack_bottom),
            USER_STACK_SIZE,
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
            false,
        )?;
        let load_info = crate::mm::load_user_app(
            &mut new_aspace,
            &fs_ctx,
            exec_credentials,
            location,
            exec_access,
            &path,
            &execfn_path,
            &argv_refs,
            envs,
        )?;
        drop(argv_refs);
        let prepared = PreparedExec {
            aspace: Arc::new(AddressSpaceLock::new(new_aspace)),
            load_info,
            path,
            argv,
        };

        if self.group_exiting() {
            return Err(AxError::Interrupted);
        }

        let caller_tid = caller.tid();
        self.begin_exec_teardown(caller_tid);
        self.terminate_exec_siblings(caller_tid);
        if self.group_exiting() {
            self.end_exec_teardown();
            drop(exec_guard);
            caller.exit_current(self.group_exit_code());
        }
        self.end_exec_teardown();

        if caller_tid != self.pid() {
            self.rebind_exec_thread(caller, caller_tid, self.pid());
        }

        let PreparedExec {
            aspace: new_aspace_handle,
            load_info,
            path,
            argv,
        } = prepared;
        let new_pt_root = new_aspace_handle.read().page_table_root();
        let new_asid = new_aspace_handle.read().asid();
        let old_aspace = self.replace_aspace_handle(new_aspace_handle);

        axtask::set_current_page_table_root(new_pt_root, new_asid);
        self.activate();
        unsafe {
            #[cfg(target_arch = "riscv64")]
            core::arch::asm!("fence.i", options(nostack, preserves_flags));
            #[cfg(target_arch = "loongarch64")]
            core::arch::asm!("dbar 0; ibar 0", options(nostack, preserves_flags));
        }
        // A vfork child must stop sharing its parent's break state before waking it.
        self.reset_brk_state(
            load_info.start_brk,
            load_info.start_brk,
            load_info.start_data,
            load_info.end_data,
        );
        let old_exec_access = self.replace_exec_access(load_info.exec_access);
        drop(old_aspace);
        drop(old_exec_access);

        self.complete_vfork();

        self.detach_all_shared_memory();

        self.ipc.sem_undos.lock().clear();

        let cloexec_entries = {
            let binding = self.fd_table();
            let mut fd_table = binding.write();
            fd_table.take_cloexec_on_exec()
        };
        self.release_posix_locks_for_entries(&cloexec_entries);
        drop(cloexec_entries);
        self.stack_top.store(load_info.user_sp, Ordering::Release);
        self.entry.store(load_info.entry, Ordering::Release);
        self.set_signal_trampoline(load_info.signal_trampoline);
        self.signal_shared().reset_dispositions_on_exec();
        self.clear_posix_timers_on_exec();
        self.set_exec_path(path.clone());
        *self.args.write() = argv;
        self.mark_execed();
        axtask::current().set_name(&self.name());
        #[cfg(feature = "qperf-trace")]
        super::emit_current_qperf_task_metadata();
        Ok(())
    }
}
