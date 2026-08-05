use super::*;
use crate::task;

impl Process {
    pub fn spawn_fork_from_trap_frame(
        self: &Arc<Self>,
        tf: &TrapFrame,
        params: ForkParams,
    ) -> AxResult<Arc<Process>> {
        let mut child_uctx = UspaceContext::from(tf);
        child_uctx.set_retval(0);
        if let Some(sp) = params.child_stack {
            child_uctx.set_sp(sp);
        }

        let parent_brk_state = self.brk_state_handle();
        let parent_brk_state_guard = parent_brk_state.lock();
        let parent_aspace_handle = self.aspace_handle();
        let clone_result = parent_aspace_handle.write().try_clone();
        let child_brk_state = Arc::new(Mutex::new(*parent_brk_state_guard));
        drop(parent_brk_state_guard);
        let new_aspace = clone_result.complete_after_unlock()?;
        let _guard = NoPreemptIrqSave::new();

        let inner = TaskInner::try_new(
            move || {
                let thread = task::current_thread().expect("fork child without Thread context");
                if let Err(e) = thread.prepare_for_user_entry() {
                    panic!("fork child failed to prepare user entry: {:?}", e);
                }
                let kstack_top = axtask::current()
                    .kernel_stack_top()
                    .expect("child task has no kernel stack")
                    .as_usize();
                unsafe {
                    child_uctx.enter_uspace(va!(kstack_top));
                }
            },
            axtask::current().name(),
            TASK_STACK_SIZE,
        )?;

        let child_tid = inner.id().as_u64();
        let new_aspace_arc = Arc::new(AddressSpaceLock::new(new_aspace));
        let child_proc = Self::new_child_process(
            child_tid,
            self.clone(),
            new_aspace_arc,
            child_brk_state,
            false,
            params.is_vfork,
            params.share_fs,
            params.share_files,
            params.share_sighand,
            params.clear_sighand,
            params.share_uts,
        )?;

        if let Some(sig) = params.exit_signal {
            child_proc.set_parent_exit_signal(sig);
        }

        if let Some(addr) = params.parent_set_tid {
            let child_tid = child_tid as u32;
            self.write_user_bytes(addr, &child_tid.to_ne_bytes())?;
        }
        let child_thread = Thread::new(child_proc.clone(), child_tid);
        task::register_thread_global(child_tid, child_thread.clone());
        if let Ok(parent_thread) = current_thread() {
            child_thread.set_signal_blocked_mask(parent_thread.signal_blocked_mask());
            child_thread.inherit_scheduler_from(&parent_thread);
        }
        if let Some(addr) = params.child_set_tid {
            child_thread.set_child_tid_addr(addr);
        }
        if let Some(addr) = params.child_clear_tid {
            child_thread.set_clear_child_tid(addr);
        }

        self.add_child(child_proc.clone());
        task::spawn_task_with_thread(inner, child_thread, true);
        Ok(child_proc)
    }

    pub fn spawn_from_trap_frame(
        self: &Arc<Self>,
        tf: &TrapFrame,
        params: CloneParams,
    ) -> AxResult<(u64, Option<Arc<Process>>)> {
        let mut child_uctx = UspaceContext::from(tf);
        child_uctx.set_retval(0);
        if let Some(sp) = params.child_stack {
            child_uctx.set_sp(sp);
        }

        let inner = TaskInner::try_new(
            move || {
                let thread = task::current_thread().expect("clone child without Thread context");
                if let Err(e) = thread.prepare_for_user_entry() {
                    panic!("clone child failed to prepare user entry: {:?}", e);
                }
                let kstack_top = axtask::current()
                    .kernel_stack_top()
                    .expect("child task has no kernel stack")
                    .as_usize();
                unsafe {
                    child_uctx.enter_uspace(va!(kstack_top));
                }
            },
            axtask::current().name(),
            TASK_STACK_SIZE,
        )?;

        let child_tid = inner.id().as_u64();
        let child_proc = if params.is_thread_clone {
            self.clone()
        } else {
            let parent_aspace_handle = self.aspace_handle();
            let brk_state = self.brk_state_handle();
            let proc = Self::new_child_process(
                child_tid,
                self.clone(),
                parent_aspace_handle.clone(),
                brk_state,
                true,
                params.is_vfork,
                params.share_fs,
                params.share_files,
                params.share_sighand,
                params.clear_sighand,
                params.share_uts,
            )?;
            if let Some(sig) = params.exit_signal {
                proc.set_parent_exit_signal(sig);
            }
            proc
        };

        if let Some(parent_tid_addr) = params.parent_set_tid {
            if let Err(e) = self.write_user_u32(parent_tid_addr, child_tid as u32) {
                return Err(e);
            }
        }

        let child_thread = Thread::new(child_proc.clone(), child_tid);
        task::register_thread_global(child_tid, child_thread.clone());
        if let Ok(parent_thread) = current_thread() {
            child_thread.set_signal_blocked_mask(parent_thread.signal_blocked_mask());
            child_thread.inherit_scheduler_from(&parent_thread);
        }
        if let Some(addr) = params.child_set_tid {
            child_thread.set_child_tid_addr(addr);
        }
        if let Some(addr) = params.child_clear_tid {
            child_thread.set_clear_child_tid(addr);
        }

        if !params.is_thread_clone {
            self.add_child(child_proc.clone());
        }
        task::spawn_task_with_thread(inner, child_thread, !params.is_thread_clone);
        Ok((child_tid, (!params.is_thread_clone).then_some(child_proc)))
    }
}
