use super::*;

impl Process {
    pub fn new_uspace(pid: u64) -> AxResult<Arc<Self>> {
        let mut aspace = axmm::new_user_aspace(va!(USER_SPACE_BASE), USER_SPACE_SIZE)?;
        let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
        aspace.map_alloc(
            va!(stack_bottom),
            USER_STACK_SIZE,
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
            false,
        )?;
        let fs_context = axfs::ROOT_FS_CONTEXT
            .get()
            .expect("root fs context not initialized")
            .clone();

        let mut fd_table = FdTable::new();
        for (fd, entry) in stdio_entries().into_iter().enumerate() {
            let _ = fd_table.insert_at(fd, entry);
        }

        let mut hostname_buf = [0u8; 65];
        let default_name = b"pulseos";
        hostname_buf[..default_name.len()].copy_from_slice(default_name);

        let uts_ns = RwLock::new(Arc::new(UtsNamespace {
            hostname: Arc::new(RwLock::new(hostname_buf)),
        }));

        Ok(Arc::new(Self {
            pid,
            parent_pid: AtomicU64::new(0),
            parent: RwLock::new(None),
            start_mono_ns: axhal::time::monotonic_time_nanos() as u64,
            aspace: RwLock::new(Arc::new(AddressSpaceLock::new(aspace))),
            fs_context: RwLock::new(Arc::new(Mutex::new(fs_context))),
            fd_table: RwLock::new(Arc::new(RwLock::new(fd_table))),
            time_context: TimeContext::new(),
            stack_top: AtomicUsize::new(USER_STACK_TOP),
            entry: AtomicUsize::new(0),
            threads: SpinNoIrq::new({
                let mut map = BTreeMap::new();
                map.insert(pid, ThreadState::Pending);
                map
            }),
            exec_lock: Mutex::new(()),
            exec_teardown_owner: AtomicU64::new(0),
            thread_exit_event: WaitQueue::new(),
            children: SpinNoIrq::new(Vec::new()),
            child_exit_event: WaitQueue::new(),
            pid_exit_event: WaitQueue::new(),
            zombie: AtomicBool::new(false),
            user_resources_released: AtomicBool::new(false),
            exit_code: AtomicI32::new(0),
            exit_signal: AtomicI32::new(0),
            group_exiting: AtomicBool::new(false),
            group_exit_code: AtomicI32::new(0),
            futex_table: FutexTable::new(),
            vfork_context: None,
            brk_state: RwLock::new(Arc::new(Mutex::new(BrkState::new(
                USER_HEAP_BASE,
                USER_HEAP_BASE,
                0,
                0,
            )))),
            credentials: RwLock::new(Arc::new(Credentials::new(
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                u64::MAX,
                u64::MAX,
                0,
                0o022,
                Vec::new(),
            ))),
            resources: Mutex::new(ResourceContext {
                rlimit_state: RlimitState::default(),
                memlock_state: MemlockState::new(),
            }),
            signal_shared: SignalShared::new(),
            exec_path: RwLock::new(None),
            exec_access: RwLock::new(Vec::new()),
            args: RwLock::new(alloc::vec![String::from("pulse_init")]),
            signal_trampoline: AtomicUsize::new(0),
            ipc: IpcContext {
                shared_memory: Arc::new(RwLock::new(BTreeMap::new())),
                sem_undos: Mutex::new(Vec::new()),
            },
            stopped_signal_pending: AtomicI32::new(0),
            continued_signal_pending: AtomicBool::new(false),
            pgid: AtomicU64::new(pid),
            pdeath_sig: AtomicI32::new(0),
            dumpable: AtomicI32::new(1),
            reparented: AtomicBool::new(false),
            uts_ns,
            parent_exit_signal: AtomicI32::new(SIGCHLD as i32),
            posix_timers: SpinNoIrq::new([None; MAX_POSIX_TIMER_COUNT]),
            posix_timer_generation: AtomicU64::new(1),
        }))
    }

    pub(super) fn new_child_process(
        pid: u64,
        parent: Arc<Process>,
        aspace: Arc<AddressSpaceLock>,
        brk_state: Arc<Mutex<BrkState>>,
        share_vm: bool,
        is_vfork: bool,
        share_fs: bool,
        share_files: bool,
        share_sighand: bool,
        clear_sighand: bool,
        share_uts: bool,
    ) -> AxResult<Arc<Self>> {
        let parent_arc = parent;
        let parent = parent_arc.as_ref();
        let shared_memory = if share_vm {
            parent.ipc.shared_memory.clone()
        } else {
            let mut new_shm = BTreeMap::new();
            let parent_shm = parent.ipc.shared_memory.read();
            for (vaddr, inner_arc) in parent_shm.iter() {
                inner_arc.lock().attach_process(pid);
                new_shm.insert(*vaddr, inner_arc.clone());
            }
            Arc::new(RwLock::new(new_shm))
        };
        let fs_context = if share_fs {
            RwLock::new(parent.fs_context_handle())
        } else {
            RwLock::new(Self::clone_private_fs_context(parent)?)
        };
        let fd_table = if share_files {
            RwLock::new(parent.fd_table())
        } else {
            RwLock::new(Arc::new(RwLock::new(
                parent.fd_table().read().clone_for_fork(),
            )))
        };
        let parent_creds = parent.credentials.read();
        let creds = Credentials::new(
            parent_creds.ruid,
            parent_creds.euid,
            parent_creds.suid,
            parent_creds.fsuid,
            parent_creds.rgid,
            parent_creds.egid,
            parent_creds.sgid,
            parent_creds.fsgid,
            parent_creds.cap_permitted,
            parent_creds.cap_effective,
            parent_creds.cap_inheritable,
            parent_creds.umask,
            parent.groups(),
        );
        let parent_resources = parent.resources.lock();
        let resources = ResourceContext {
            rlimit_state: parent_resources.rlimit_state,
            memlock_state: MemlockState::new_with_limits(
                parent_resources.memlock_state.soft_limit,
                parent_resources.memlock_state.hard_limit,
            ),
        };
        drop(parent_resources);
        let signal_shared = if share_sighand {
            SignalShared::clone_sighand_only(&parent.signal_shared)
        } else {
            SignalShared::clone_actions_only(&parent.signal_shared)
        };
        if clear_sighand {
            signal_shared.reset_dispositions_on_exec();
        }
        let signal_trampoline = parent.signal_trampoline.load(Ordering::Acquire);
        let exec_path = parent.exec_path();
        let exec_access = parent.exec_access.read().clone();
        let uts_ns = if share_uts {
            parent.uts_ns.read().clone()
        } else {
            Arc::new(UtsNamespace {
                hostname: Arc::new(RwLock::new(*parent.hostname_handle().read())),
            })
        };

        let vfork_context = if is_vfork {
            Some(VforkContext {
                wait_enabled: true,
                done: AtomicBool::new(false),
                event: WaitQueue::new(),
            })
        } else {
            None
        };

        Ok(Arc::new(Self {
            pid,
            parent_pid: AtomicU64::new(parent.pid()),
            parent: RwLock::new(Some(Arc::downgrade(&parent_arc))),
            aspace: RwLock::new(aspace),
            brk_state: RwLock::new(brk_state),
            fs_context,
            fd_table,
            start_mono_ns: axhal::time::monotonic_time_nanos() as u64,
            time_context: TimeContext::new(),
            stack_top: AtomicUsize::new(parent.stack_top.load(Ordering::Acquire)),
            entry: AtomicUsize::new(parent.entry.load(Ordering::Acquire)),
            threads: SpinNoIrq::new({
                let mut map = BTreeMap::new();
                map.insert(pid, ThreadState::Pending);
                map
            }),
            exec_lock: Mutex::new(()),
            exec_teardown_owner: AtomicU64::new(0),
            thread_exit_event: WaitQueue::new(),
            children: SpinNoIrq::new(Vec::new()),
            child_exit_event: WaitQueue::new(),
            pid_exit_event: WaitQueue::new(),
            zombie: AtomicBool::new(false),
            user_resources_released: AtomicBool::new(false),
            exit_code: AtomicI32::new(0),
            exit_signal: AtomicI32::new(0),
            group_exiting: AtomicBool::new(false),
            group_exit_code: AtomicI32::new(0),
            futex_table: FutexTable::new(),
            vfork_context,
            credentials: RwLock::new(Arc::new(creds)),
            resources: Mutex::new(resources),
            signal_shared,
            exec_path: RwLock::new(exec_path),
            exec_access: RwLock::new(exec_access),
            args: RwLock::new(parent.args.read().clone()),
            signal_trampoline: AtomicUsize::new(signal_trampoline),
            ipc: IpcContext {
                shared_memory,
                sem_undos: Mutex::new(Vec::new()),
            },
            stopped_signal_pending: AtomicI32::new(0),
            continued_signal_pending: AtomicBool::new(false),
            pgid: AtomicU64::new(parent.pgid()),
            pdeath_sig: AtomicI32::new(0),
            dumpable: AtomicI32::new(parent.dumpable()),
            reparented: AtomicBool::new(false),
            uts_ns: RwLock::new(uts_ns),
            parent_exit_signal: AtomicI32::new(SIGCHLD as i32),
            posix_timers: SpinNoIrq::new([None; MAX_POSIX_TIMER_COUNT]),
            posix_timer_generation: AtomicU64::new(1),
        }))
    }
}
