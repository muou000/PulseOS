use super::*;
use crate::task::{
    self, SIG_IGN, queue_signal_to_process, queue_signal_to_process_with_info,
    signal_info_for_child,
};
use linux_raw_sys::general::{
    CLD_CONTINUED, CLD_DUMPED, CLD_EXITED, CLD_KILLED, CLD_STOPPED, SA_NOCLDSTOP, SA_NOCLDWAIT,
    SIGCHLD, SIGCONT, WCONTINUED, WEXITED, WNOWAIT, WUNTRACED,
};

impl Process {
    pub fn pgid(&self) -> u64 {
        self.pgid.load(Ordering::Acquire)
    }

    pub fn set_pgid(&self, pgid: u64) {
        self.pgid.store(pgid, Ordering::Release);
    }

    pub fn sid(&self) -> u64 {
        self.sid.load(Ordering::Acquire)
    }

    /// Changes the two process identifiers that must move together when a
    /// process creates a new session. Callers hold the job-control lock.
    pub fn set_session_and_group(&self, sid: u64, pgid: u64) {
        self.sid.store(sid, Ordering::Release);
        self.pgid.store(pgid, Ordering::Release);
    }

    pub fn has_execed(&self) -> bool {
        self.has_execed.load(Ordering::Acquire)
    }

    /// Marks a successful exec transition while excluding a parent's
    /// concurrent setpgid(2) operation.
    pub fn mark_execed(&self) {
        crate::task::with_job_control_lock(|| {
            self.has_execed.store(true, Ordering::Release);
        });
    }

    pub fn pdeath_sig(&self) -> i32 {
        self.pdeath_sig.load(Ordering::Acquire)
    }

    pub fn set_pdeath_sig(&self, sig: i32) {
        self.pdeath_sig.store(sig, Ordering::Release);
    }

    pub fn dumpable(&self) -> i32 {
        self.dumpable.load(Ordering::Acquire)
    }

    pub fn set_dumpable(&self, dumpable: i32) {
        self.dumpable.store(dumpable, Ordering::Release);
    }

    pub fn parent_exit_signal(&self) -> i32 {
        self.parent_exit_signal.load(Ordering::Acquire)
    }

    pub fn set_parent_exit_signal(&self, sig: i32) {
        self.parent_exit_signal.store(sig, Ordering::Release);
    }

    pub fn signal_shared(&self) -> Arc<SignalShared> {
        self.signal_shared.clone()
    }

    pub fn handle_page_fault(
        &self,
        vaddr: VirtAddr,
        flags: axhal::trap::PageFaultFlags,
    ) -> AxResult<bool> {
        let aspace_handle = self.aspace_handle();
        self.resolve_page_fault(&aspace_handle, vaddr, flags)
    }

    pub(super) fn resolve_page_fault(
        &self,
        aspace_handle: &Arc<AddressSpaceLock>,
        vaddr: VirtAddr,
        flags: axhal::trap::PageFaultFlags,
    ) -> AxResult<bool> {
        let result = {
            let aspace = aspace_handle.read();
            aspace.handle_page_fault(vaddr, flags)
        };
        let mut outcome = result.complete_after_unlock()?;

        loop {
            outcome = match outcome {
                axmm::PageFaultOutcome::Handled(handled) => return Ok(handled),
                axmm::PageFaultOutcome::LoadFilePage(load) => {
                    let mut prepared = load.prepare()?;
                    let result = {
                        let aspace = aspace_handle.read();
                        aspace.handle_prepared_file_page(vaddr, flags, &mut prepared)
                    };
                    result.complete_after_unlock()?
                }
                axmm::PageFaultOutcome::PrepareAnonPage(load) => {
                    let mut prepared = load.prepare()?;
                    let result = {
                        let aspace = aspace_handle.read();
                        aspace.handle_prepared_anon_page(vaddr, flags, &mut prepared)
                    };
                    result.complete_after_unlock()?
                }
                axmm::PageFaultOutcome::RetryWithWriteLock => {
                    let result = {
                        let mut aspace = aspace_handle.write();
                        aspace.handle_page_fault_write(vaddr, flags)
                    };
                    let outcome = result.complete_after_unlock()?;
                    if matches!(outcome, axmm::PageFaultOutcome::RetryWithWriteLock) {
                        return Err(AxError::BadState);
                    }
                    outcome
                }
            };
        }
    }

    pub fn activate(&self) {
        let pt_root = self.page_table_root();
        let asid = self.asid();
        unsafe {
            #[cfg(target_arch = "riscv64")]
            {
                axhal::asm::write_user_page_table(pt_root, asid);
                axhal::asm::flush_tlb(None);
            }
            #[cfg(target_arch = "loongarch64")]
            {
                axhal::asm::write_user_page_table(pt_root);
                axhal::asm::write_user_asid(asid);
                axhal::asm::flush_tlb(None);
            }
            #[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
            {
                axhal::asm::write_user_page_table(pt_root);
                axhal::asm::flush_tlb(None);
            }
        }
    }

    pub fn close_all_files(&self) {
        crate::record_lock::release_posix_owner(self.pid());
        let _drained = {
            let binding = self.fd_table();
            let mut table = binding.write();
            table.drain_all()
        };
    }

    pub fn detach_all_shared_memory(&self) {
        let mut shm = self.ipc.shared_memory.write();
        for inner_arc in shm.values() {
            let mut inner = inner_arc.lock();
            inner.detach_process(self.pid());
            if inner.rmid && inner.attach_count() == 0 {
                let shmid = inner.shmid;
                drop(inner);
                let mut manager = crate::ipc::shm::SHM_MANAGER.lock();
                manager.remove_shmid(shmid);
            }
        }
        shm.clear();
    }

    fn release_zombie_resources(&self, switch_current_aspace: bool) -> AxResult<()> {
        if self.user_resources_released.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        let new_handle = ZOMBIE_ASPACE_HANDLE.clone();
        let new_pt_root = new_handle.read().page_table_root();
        let new_asid = new_handle.read().asid();
        let old_handle = self.replace_aspace_handle(new_handle);
        if switch_current_aspace {
            axtask::set_current_page_table_root(new_pt_root, new_asid);
            self.activate();
        }
        drop(old_handle);
        self.reset_brk_state(USER_HEAP_BASE, USER_HEAP_BASE, 0, 0);
        self.stack_top.store(USER_STACK_TOP, Ordering::Release);
        self.entry.store(0, Ordering::Release);

        // Linux completes vfork from mm_release(): the child must stop using
        // the shared address space before its parent is allowed to resume.
        self.complete_vfork();

        self.detach_all_shared_memory();

        {
            let undos = {
                let mut guard = self.ipc.sem_undos.lock();
                core::mem::take(&mut *guard)
            };
            crate::ipc::sem::exit_sem_undos(self.pid() as i32, undos);
        }

        self.close_all_files();
        self.futex_table.clear();
        self.memlock_unlock_all();

        // Release fs_context, credentials, uts_ns, args, and exec_path early during exit phase.
        if let Some(root_context) = axfs::ROOT_FS_CONTEXT.get() {
            *self.fs_context.write() = Arc::new(Mutex::new(root_context.clone()));
        }

        // Keep original UIDs/GIDs to preserve status and signal permission checks (like kill(pid, 0)),
        // but drop group vectors and capabilities.
        let (ruid, euid, suid, fsuid, rgid, egid, sgid, fsgid) = {
            let creds = self.credentials.read();
            (
                creds.ruid,
                creds.euid,
                creds.suid,
                creds.fsuid,
                creds.rgid,
                creds.egid,
                creds.sgid,
                creds.fsgid,
            )
        };
        let dummy_credentials = Credentials::new(
            ruid,
            euid,
            suid,
            fsuid,
            rgid,
            egid,
            sgid,
            fsgid,
            0,
            0,
            0,
            0o022,
            Vec::new(),
        );
        *self.credentials.write() = Arc::new(dummy_credentials);

        let mut hostname_buf = [0u8; 65];
        let default_name = b"pulseos";
        hostname_buf[..default_name.len()].copy_from_slice(default_name);
        let dummy_uts_ns = UtsNamespace {
            hostname: Arc::new(RwLock::new(hostname_buf)),
        };
        *self.uts_ns.write() = Arc::new(dummy_uts_ns);

        self.args.write().clear();
        *self.exec_path.write() = None;
        self.exec_access.write().clear();

        axlog::debug!("release_zombie_resources: pid={}", self.pid());
        Ok(())
    }

    pub fn shrink_reaped_resources(&self) -> AxResult<()> {
        self.release_zombie_resources(false)
    }

    pub fn sync_fs_context(&self) {
        let mut fs = self.fs_context_handle().lock().clone();
        fs.credentials = Some((self.fsuid(), self.fsgid()));
        *axfs::FS_CONTEXT.lock() = fs;
    }

    pub fn save_fs_context(&self) {
        *self.fs_context_handle().lock() = axfs::FS_CONTEXT.lock().clone();
    }

    pub fn register_task_ref(&self, task: AxTaskRef) {
        let thread = task::thread_handle_from_task(&task).map(|handle| {
            handle.attach_task_ref(task.clone());
            handle.thread_arc()
        });
        let mut registry = self.threads.lock();
        let tid = thread
            .as_ref()
            .map(|thread| thread.tid())
            .unwrap_or_else(|| task.id().as_u64());
        registry.insert(tid, ThreadState::Active(task.clone()));
        let exec_owner = self.exec_teardown_owner.load(Ordering::Acquire);
        drop(registry);

        if exec_owner != 0
            && exec_owner != tid
            && let Some(thread) = thread
        {
            thread.request_exec_exit();
            axtask::interrupt_task(task, true);
        }
    }

    pub fn task_ref_by_tid(&self, tid: u64) -> Option<AxTaskRef> {
        let registry = self.threads.lock();
        match registry.get(&tid) {
            Some(ThreadState::Active(task)) => Some(task.clone()),
            _ => None,
        }
    }

    pub fn take_task_ref_by_tid(&self, tid: u64) -> Option<AxTaskRef> {
        let mut registry = self.threads.lock();
        match registry.remove(&tid) {
            Some(ThreadState::Active(task)) => Some(task),
            _ => None,
        }
    }

    pub fn wait_task_refs_exited(&self) {
        let tasks = {
            let registry = self.threads.lock();
            let mut tasks = Vec::with_capacity(registry.len());
            for state in registry.values() {
                if let ThreadState::Active(task) = state {
                    tasks.push(task.clone());
                }
            }
            tasks
        };
        for task in tasks {
            let _ = task.join();
        }
    }

    pub fn release_task_refs(&self) {
        self.threads.lock().clear();
    }

    fn take_exiting_thread(&self, tid: u64) -> (Option<AxTaskRef>, usize) {
        let mut registry = self.threads.lock();
        let task = match registry.remove(&tid) {
            Some(ThreadState::Active(task)) => Some(task),
            _ => None,
        };
        (task, registry.len())
    }

    pub fn begin_group_exit(&self, exit_code: i32) {
        crate::task::with_job_control_lock(|| {
            self.group_exit_code.store(exit_code, Ordering::Release);
            self.group_exiting.store(true, Ordering::Release);
            self.job_control_stop_signal.store(0, Ordering::Release);
        });
        self.job_control_event.notify_all(false);
        self.futex_table.wake_all();

        let tasks = {
            let registry = self.threads.lock();
            let mut tasks = Vec::with_capacity(registry.len());
            for state in registry.values() {
                if let ThreadState::Active(task) = state {
                    tasks.push(task.clone());
                }
            }
            tasks
        };

        for task in tasks {
            axlog::debug!("begin_group_exit: waking task {}", task.id_name());
            if let Some(handle) = thread_handle_from_task(&task) {
                handle.signal_wait_queue().notify_all(false);
            }
            axtask::interrupt_task(task, true);
        }
    }

    pub fn group_exiting(&self) -> bool {
        self.group_exiting.load(Ordering::Acquire)
    }

    pub fn group_exit_code(&self) -> i32 {
        self.group_exit_code.load(Ordering::Acquire)
    }

    /// Returns whether this thread group is stopped by a job-control signal.
    pub fn group_stopped(&self) -> bool {
        self.job_control_stop_signal.load(Ordering::Acquire) != 0
    }

    /// Enters a job-control stop exactly once for a running thread group.
    /// The separate pending marker is solely for the parent's next WSTOPPED.
    pub fn enter_group_stop(&self, signo: i32) -> bool {
        let entered = crate::task::with_job_control_lock(|| {
            if signo <= 0 || self.group_exiting() {
                return false;
            }
            if self
                .job_control_stop_signal
                .compare_exchange(0, signo, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return false;
            }

            // Keep the running/stopped state and the parent's one-shot
            // wait-status markers coherent with SIGCONT.
            self.stopped_signal_pending.store(signo, Ordering::Release);
            self.continued_signal_pending.store(false, Ordering::Release);
            true
        });
        if !entered {
            return false;
        }

        self.wake_group_for_stop(signo);
        self.notify_parent_job_control(CLD_STOPPED as i32, signo);
        true
    }

    /// Makes every live thread leave interruptible work so it can observe the
    /// shared group-stop state at the next user-return boundary.  This matters
    /// for thread-directed stop signals: only one thread dequeues the signal,
    /// but all members of the thread group must stop.
    fn wake_group_for_stop(&self, signo: i32) {
        let tasks = {
            let registry = self.threads.lock();
            registry
                .values()
                .filter_map(|state| match state {
                    ThreadState::Active(task) => Some(task.clone()),
                    ThreadState::Pending => None,
                })
                .collect::<Vec<_>>()
        };

        let wake_context = WakeContext::new(|| (WakeSource::Signal, signo as u64));
        for task in tasks {
            if let Some(handle) = thread_handle_from_task(&task) {
                handle
                    .signal_wait_queue()
                    .notify_all_with_context(true, wake_context);
            }
            axtask::interrupt_task_with_context(task, true, wake_context);
        }
    }

    /// SIGCONT resumes a stopped group irrespective of its disposition or
    /// current signal mask.  The SIGCONT itself may still remain pending for a
    /// user handler, but execution must resume immediately.
    pub fn continue_group(&self) -> bool {
        let continued = crate::task::with_job_control_lock(|| {
            let stopped = self.job_control_stop_signal.swap(0, Ordering::AcqRel);
            if stopped == 0 {
                return false;
            }

            self.continued_signal_pending.store(true, Ordering::Release);
            // SIGCONT supersedes an unconsumed WSTOPPED report for this group.
            self.stopped_signal_pending.store(0, Ordering::Release);
            true
        });
        if !continued {
            return false;
        }

        self.job_control_event.notify_all_with_context(
            true,
            WakeContext::new(|| (WakeSource::Signal, SIGCONT as u64)),
        );
        self.notify_parent_job_control(CLD_CONTINUED as i32, SIGCONT as i32);
        true
    }

    /// Sleeps the current group member while the process is job-control
    /// stopped.  A pending deliverable signal is also a wake condition so a
    /// fatal signal can be consumed before the task is parked again.
    pub fn wait_while_group_stopped(&self, thread: &Thread) {
        if !self.group_stopped() {
            return;
        }
        let wait_context = WaitContext::new(|| (WaitReason::Signal, self.pid(), 0));
        self.job_control_event.wait_until_with_context(wait_context, || {
            !self.group_stopped()
                || self.group_exiting()
                || thread.exec_exit_requested()
                || thread.signal().has_deliverable_pending_signal()
        });
    }

    fn notify_parent_job_control(&self, code: i32, status: i32) {
        if let Some(parent) = self.parent_process() {
            let action = parent.signal_shared().action(SIGCHLD as usize);
            if action.handler != SIG_IGN && (action.flags & SA_NOCLDSTOP as usize) == 0 {
                let info = signal_info_for_child(self.pid(), self.ruid(), code, status);
                let _ = queue_signal_to_process_with_info(
                    parent.as_ref(),
                    SIGCHLD as usize,
                    Some(info),
                );
            }
            parent.child_exit_event.notify_all_with_context(
                false,
                WakeContext::new(|| (WakeSource::Signal, status as u64)),
            );
        }
    }

    pub fn is_zombie(&self) -> bool {
        self.zombie.load(Ordering::Acquire)
    }

    pub fn exit_code(&self) -> i32 {
        self.exit_code.load(Ordering::Acquire)
    }

    /// 设置信号终止信息。
    /// - `signo`：终止进程的信号号（SIGABRT=6, SIGSEGV=11 等）
    /// - `coredump`：是否设置 core dump 标志位（不需要实际写文件）
    pub fn set_exit_signal(&self, signo: i32, coredump: bool) {
        let val = if coredump { signo | 0x100 } else { signo };
        self.exit_signal.store(val, Ordering::Release);
    }

    /// 计算 Linux `wait4` 的 status word。
    /// - 正常退出：`(exit_code & 0xff) << 8`（WIFEXITED 为真）
    /// - 信号终止：`signo & 0x7f`（WIFSIGNALED 为真）
    /// - 信号终止且 core dump：`(signo & 0x7f) | 0x80`（WCOREDUMP 也为真）
    pub fn wait_status_word(&self) -> i32 {
        let sig_val = self.exit_signal.load(Ordering::Acquire);
        if sig_val == 0 {
            // 正常退出：(exit_code & 0xff) << 8
            (self.exit_code.load(Ordering::Acquire) & 0xff) << 8
        } else {
            let signo = sig_val & 0x7f;
            let coredump = if (sig_val & 0x100) != 0 { 0x80i32 } else { 0 };
            signo | coredump
        }
    }

    pub fn exit_siginfo_status(exit_code: i32, exit_signal: i32) -> (i32, i32) {
        if exit_signal == 0 {
            (CLD_EXITED as i32, exit_code & 0xff)
        } else if (exit_signal & 0x100) != 0 {
            (CLD_DUMPED as i32, exit_signal & 0x7f)
        } else {
            (CLD_KILLED as i32, exit_signal & 0x7f)
        }
    }

    fn child_exit_siginfo_status(&self) -> (i32, i32) {
        Self::exit_siginfo_status(
            self.exit_code(),
            self.exit_signal.load(Ordering::Acquire),
        )
    }

    /// Publishes the terminal child state to its parent and returns whether
    /// the child must be reaped immediately by the exiting task.
    fn notify_parent_exit(&self, parent: &Process) -> bool {
        let sig = self.parent_exit_signal();
        if sig <= 0 {
            return false;
        }
        if sig != SIGCHLD as i32 {
            let _ = queue_signal_to_process(parent, sig as usize);
            return false;
        }

        let action = parent.signal_shared().action(SIGCHLD as usize);
        let auto_reap = action.handler == SIG_IGN || (action.flags & SA_NOCLDWAIT as usize) != 0;
        // Linux still generates SIGCHLD for SA_NOCLDWAIT, but not when the
        // parent explicitly ignores SIGCHLD.
        if action.handler != SIG_IGN {
            let (code, status) = self.child_exit_siginfo_status();
            let info = signal_info_for_child(self.pid(), self.ruid(), code, status);
            let _ = queue_signal_to_process_with_info(parent, SIGCHLD as usize, Some(info));
        }
        auto_reap
    }

    pub fn finish_thread_exit(&self, tid: u64, exit_code: i32) {
        task::unregister_thread_global(tid);
        let (task, remaining) = self.take_exiting_thread(tid);
        if let Some(task) = task {
            if let Some(handle) = task::thread_handle_from_task(&task) {
                let now_ns = axhal::time::monotonic_time_nanos() as u64;
                let (u, s) = handle.snapshot_cpu_time_ns(now_ns);
                self.time_context
                    .user_time_ns
                    .fetch_add(u, Ordering::Relaxed);
                self.time_context
                    .sys_time_ns
                    .fetch_add(s, Ordering::Relaxed);
            }
        }
        self.thread_exit_event.notify_all(false);
        axlog::debug!(
            "finish_thread_exit: pid={}, tid={}, remaining_threads={}, group_exiting={}",
            self.pid(),
            tid,
            remaining,
            self.group_exiting()
        );
        if remaining != 0 {
            return;
        }

        let final_code = if self.group_exiting() {
            self.group_exit_code()
        } else {
            exit_code
        };
        self.exit_code.store(final_code, Ordering::Release);
        if let Err(e) = self.release_zombie_resources(true) {
            axlog::warn!(
                "finish_thread_exit: failed to release zombie resources for pid={}: {:?}",
                self.pid(),
                e
            );
        }

        // Linux performs child reparenting in exit_notify() before publishing
        // EXIT_ZOMBIE. Keep the same ordering so waiters cannot reap this
        // process while its child relationships are still being updated.
        if let Some(init) = task::init_process() {
            if self.pid() != init.pid() {
                let children_to_reparent = core::mem::take(&mut *self.children.lock());
                for child in children_to_reparent {
                    if child.is_zombie() {
                        // Reap zombie child immediately instead of reparenting it
                        let exited_pid = child.pid();
                        child.wait_task_refs_exited();
                        let _ = child.take_task_ref_by_tid(exited_pid);
                        if let Err(e) = child.shrink_reaped_resources() {
                            axlog::warn!("failed to shrink reaped child resources: {:?}", e);
                        }
                        child.release_task_refs();
                        task::unregister_process(exited_pid);
                    } else {
                        child.parent_pid.store(init.pid(), Ordering::Release);
                        child.reparented.store(true, Ordering::Release);
                        child
                            .parent_exit_signal
                            .store(SIGCHLD as i32, Ordering::Release);
                        *child.parent.write() = Some(Arc::downgrade(&init));
                        init.add_child(child.clone());

                        let pdeath_sig = child.pdeath_sig();
                        if pdeath_sig != 0 {
                            let _ = queue_signal_to_process(child.as_ref(), pdeath_sig as usize);
                        }

                        if child.is_zombie() {
                            let _ = queue_signal_to_process(init.as_ref(), SIGCHLD as usize);
                            init.child_exit_event
                                .notify_all_with_context(false, WakeContext::task());
                        }
                    }
                }
            } else {
                self.children.lock().clear();
            }
        } else {
            self.children.lock().clear();
        }

        let is_reparented = self.reparented.load(Ordering::Acquire);
        let parent = self
            .parent
            .read()
            .as_ref()
            .and_then(|parent| parent.upgrade());

        // Match Linux do_exit(): exit_files() and the rest of resource
        // teardown happen before exit_notify() exposes EXIT_ZOMBIE. The
        // release store makes all cleanup visible to wait4/waitid and pidfd
        // observers that acquire-load the zombie state.
        debug_assert!(self.user_resources_released.load(Ordering::Acquire));
        self.zombie.store(true, Ordering::Release);
        self.pid_exit_event.notify_all(false);

        if is_reparented {
            // Reap it immediately from the parent (which is init)!
            if let Some(parent) = parent {
                let mut children = parent.children.lock();
                if let Some(idx) = children.iter().position(|c| c.pid() == self.pid()) {
                    children.remove(idx);
                }
            }
            // Ensure all underlying tasks are joined before releasing resources
            self.wait_task_refs_exited();
            if let Err(e) = self.shrink_reaped_resources() {
                axlog::warn!(
                    "finish_thread_exit (reparented): failed to release zombie resources for \
                     pid={}: {:?}",
                    self.pid(),
                    e
                );
            }
            self.release_task_refs();
            task::unregister_process(self.pid());
        } else {
            if let Some(parent) = parent {
                let auto_reap = self.notify_parent_exit(parent.as_ref());
                // The exiting task is still on its own kernel stack here.
                // Wake waiters without forcing an immediate reschedule from inside
                // the teardown path.
                parent
                    .child_exit_event
                    .notify_all_with_context(false, WakeContext::task());

                if auto_reap && parent.reap_zombie_child(self.pid() as isize).is_some() {
                    let now_ns = axhal::time::monotonic_time_nanos() as u64;
                    let (child_utime_ns, child_stime_ns) = self.snapshot_cpu_time_ns(now_ns);
                    parent.add_child_time_ns(child_utime_ns, child_stime_ns);
                    self.wait_task_refs_exited();
                    if let Err(e) = self.shrink_reaped_resources() {
                        axlog::warn!("failed to shrink automatically reaped child resources: {:?}", e);
                    }
                    self.release_task_refs();
                    task::unregister_process(self.pid());
                }
            }
        }
    }

    pub fn add_child(&self, child: Arc<Process>) {
        self.children.lock().push(child);
    }

    pub fn parent_process(&self) -> Option<Arc<Process>> {
        self.parent.read().as_ref().and_then(|p| p.upgrade())
    }

    pub fn waitid_find_and_reap(
        &self,
        idtype: usize,
        id: usize,
        options: i32,
    ) -> Result<Option<(Arc<Process>, WaitidStatusType)>, isize> {
        let is_match = |child: &Process| -> bool {
            match idtype {
                0 => true,                     // P_ALL
                1 => child.pid() == id as u64, // P_PID
                2 => {
                    // P_PGID
                    let target_pgid = if id == 0 { self.pgid() } else { id as u64 };
                    child.pgid() == target_pgid
                }
                _ => false,
            }
        };

        let mut children = self.children.lock();
        let mut has_matching_child = false;
        let mut found_idx = None;
        let mut found_status = None;

        for (idx, child) in children.iter().enumerate() {
            if is_match(child) {
                has_matching_child = true;

                // Linux gives a requested zombie exit priority over stale
                // stopped/continued reports for the same child.  If WEXITED
                // is absent, fall through and allow those one-shot reports.
                if (options & WEXITED as i32) != 0 && child.is_zombie() {
                    let wnowait = (options & WNOWAIT as i32) != 0;
                    found_idx = Some((idx, !wnowait));
                    let exit_code = child.exit_code.load(Ordering::Acquire);
                    let exit_signal = child.exit_signal.load(Ordering::Acquire);
                    found_status = Some(WaitidStatusType::Exited {
                        exit_code,
                        exit_signal,
                    });
                    break;
                }

                // 1. Check STOPPED
                if (options & WUNTRACED as i32) != 0 {
                    // WSTOPPED
                    let stop_sig = child.stopped_signal_pending.load(Ordering::Acquire);
                    if stop_sig != 0 {
                        found_idx = Some((idx, false));
                        found_status = Some(WaitidStatusType::Stopped { signo: stop_sig });
                        break;
                    }
                }
                // 2. Check CONTINUED
                if (options & WCONTINUED as i32) != 0 {
                    // WCONTINUED
                    if child.continued_signal_pending.load(Ordering::Acquire) {
                        found_idx = Some((idx, false));
                        found_status = Some(WaitidStatusType::Continued);
                        break;
                    }
                }
            }
        }

        if !has_matching_child {
            return Err(-axerrno::LinuxError::ECHILD.code() as isize);
        }

        if let Some((idx, remove)) = found_idx {
            let child = if remove {
                children.remove(idx)
            } else {
                children[idx].clone()
            };

            let wnowait = (options & WNOWAIT as i32) != 0;
            if !wnowait {
                match found_status.as_ref().unwrap() {
                    WaitidStatusType::Stopped { .. } => {
                        child.stopped_signal_pending.store(0, Ordering::Release);
                    }
                    WaitidStatusType::Continued => {
                        child
                            .continued_signal_pending
                            .store(false, Ordering::Release);
                    }
                    _ => {}
                }
            }

            Ok(Some((child, found_status.unwrap())))
        } else {
            Ok(None)
        }
    }

    pub fn wait_for_child_state_change_interruptible(
        &self,
        idtype: usize,
        id: usize,
        options: i32,
    ) -> Result<(), i32> {
        let thread = match current_thread() {
            Ok(t) => t,
            Err(e) => return Err(e.code()),
        };

        let is_match = |child: &Process| -> bool {
            match idtype {
                0 => true,
                1 => child.pid() == id as u64,
                2 => {
                    let target_pgid = if id == 0 { self.pgid() } else { id as u64 };
                    child.pgid() == target_pgid
                }
                _ => false,
            }
        };

        let check_state = || -> bool {
            let children = self.children.lock();
            for child in children.iter() {
                if is_match(child) {
                    if (options & WUNTRACED as i32) != 0
                        && child.stopped_signal_pending.load(Ordering::Acquire) != 0
                    {
                        return true;
                    }
                    if (options & WCONTINUED as i32) != 0
                        && child.continued_signal_pending.load(Ordering::Acquire)
                    {
                        return true;
                    }
                    if (options & WEXITED as i32) != 0 && child.is_zombie() {
                        return true;
                    }
                }
            }
            false
        };

        let selector = match idtype {
            0 => -1,
            1 => i64::try_from(id).unwrap_or(i64::MAX),
            2 => {
                let pgid = if id == 0 { self.pgid() } else { id as u64 };
                i64::try_from(pgid).unwrap_or(i64::MAX).saturating_neg()
            }
            _ => 0,
        };
        let wait_context =
            WaitContext::new(|| (WaitReason::ChildWait, self.pid(), selector as u64));
        self.child_exit_event
            .wait_until_with_context(wait_context, || {
                check_state() || thread.has_pending_signal() || self.group_exiting()
            });

        if check_state() {
            return Ok(());
        }

        if thread.has_pending_signal() {
            return Err(task::ERESTARTSYS);
        }
        Ok(())
    }

    fn child_matches(&self, child: &Process, pid: isize) -> bool {
        if pid == -1 {
            true
        } else if pid > 0 {
            child.pid() as isize == pid
        } else if pid == 0 {
            child.pgid() == self.pgid()
        } else {
            child.pgid() as isize == -pid
        }
    }

    pub fn has_matching_child(&self, pid: isize) -> bool {
        self.children
            .lock()
            .iter()
            .any(|child| self.child_matches(child, pid))
    }

    pub fn reap_zombie_child(&self, pid: isize) -> Option<Arc<Process>> {
        let mut children = self.children.lock();
        let idx = children
            .iter()
            .position(|child| self.child_matches(child, pid) && child.is_zombie())?;
        Some(children.remove(idx))
    }

    pub fn wait_for_child_exit(&self, pid: isize) {
        let wait_context =
            WaitContext::new(|| (WaitReason::ChildWait, self.pid(), pid as i64 as u64));
        self.child_exit_event
            .wait_until_with_context(wait_context, || {
                self.children
                    .lock()
                    .iter()
                    .any(|child| self.child_matches(child, pid) && child.is_zombie())
            });
    }

    pub fn wait_for_child_exit_interruptible(&self, pid: isize) -> Result<(), i32> {
        let thread = match current_thread() {
            Ok(t) => t,
            Err(e) => return Err(e.code()),
        };
        // wait_until 会在持有 WaitQueue 锁的同时执行闭包
        let wait_context =
            WaitContext::new(|| (WaitReason::ChildWait, self.pid(), pid as i64 as u64));
        self.child_exit_event
            .wait_until_with_context(wait_context, || {
                self.children
                    .lock()
                    .iter()
                    .any(|child| self.child_matches(child, pid) && child.is_zombie())
                    || thread.has_pending_signal()
            });

        // 优先检查是否有子进程已经退出，如果有，即使有挂起信号也返回 Ok(())
        // 这样 sys_wait4 的 loop 会在下一次调用 reap_zombie_child 时成功。
        if self
            .children
            .lock()
            .iter()
            .any(|child| self.child_matches(child, pid) && child.is_zombie())
        {
            return Ok(());
        }

        if thread.has_pending_signal() {
            return Err(task::ERESTARTSYS);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_siginfo_status_matches_waitid_encoding() {
        assert_eq!(Process::exit_siginfo_status(0x1ff, 0), (CLD_EXITED as i32, 0xff));
        assert_eq!(
            Process::exit_siginfo_status(0, SIGCONT as i32),
            (CLD_KILLED as i32, SIGCONT as i32)
        );
        assert_eq!(
            Process::exit_siginfo_status(0, 0x100 | SIGCONT as i32),
            (CLD_DUMPED as i32, SIGCONT as i32)
        );
    }
}
