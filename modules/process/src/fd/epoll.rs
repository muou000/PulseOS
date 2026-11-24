use super::*;

#[derive(Clone, Copy, Debug)]
pub struct EpollRegistration {
    pub event: epoll_event,
    pub reported_in: bool,
    pub reported_out: bool,
    pub reported_in_sequence: Option<u64>,
    pub reported_out_sequence: Option<u64>,
}

pub struct EpollObject {
    pub events: Mutex<BTreeMap<usize, EpollRegistration>>,
    control_wait_queue: Arc<task::WaitQueue>,
}

impl EpollObject {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(BTreeMap::new()),
            control_wait_queue: Arc::new(task::WaitQueue::new()),
        }
    }

    pub fn notify_control(&self) {
        self.control_wait_queue.notify_all(false);
    }

    fn poll_for_process(
        &self,
        process: &crate::Process,
        thread: Option<&crate::Thread>,
    ) -> LinuxResult<PollState> {
        let monitored: Vec<(usize, u32)> = {
            let events = self.events.lock();
            events
                .iter()
                .map(|(&fd, ev)| (fd, ev.event.events))
                .collect()
        };
        for (fd, ev_events) in monitored {
            if let Ok(entry) = process.get_fd_entry(fd) {
                if let Ok(st) = entry.object.poll_readiness_with_context(process, thread) {
                    let mut revents = 0u32;
                    if st.readable && (ev_events & EPOLLIN != 0) {
                        revents |= EPOLLIN;
                    }
                    if st.writable && (ev_events & EPOLLOUT != 0) {
                        revents |= EPOLLOUT;
                    }
                    if ev_events & EPOLLRDHUP != 0 && st.rdhup {
                        revents |= EPOLLRDHUP;
                    }
                    if st.hup {
                        revents |= EPOLLHUP;
                    }
                    if st.err {
                        revents |= EPOLLERR;
                    }
                    if revents != 0 {
                        return Ok(PollState {
                            readable: true,
                            writable: false,
                        });
                    }
                }
            }
        }
        Ok(PollState {
            readable: false,
            writable: false,
        })
    }

    fn register_poll_for_process(
        self: Arc<Self>,
        process: &Arc<crate::Process>,
        thread: Option<&Arc<crate::Thread>>,
        cx: &mut core::task::Context<'_>,
        registrations: &mut Vec<PollRegistration>,
    ) -> LinuxResult {
        let control_wait_queue = self.control_wait_queue.clone();
        let registration = control_wait_queue.register_owned_waker(cx.waker());
        registrations.push(PollRegistration::new(move || {
            control_wait_queue.unregister_waker(registration);
        }));

        let targets: Vec<(Arc<dyn FdObject>, poll::IoEvents)> = {
            let monitored = self.events.lock();
            let mut list = Vec::new();
            for (&fd, ev) in monitored.iter() {
                if let Ok(entry) = process.get_fd_entry(fd) {
                    let mut target_events = poll::IoEvents::ALWAYS_POLL;
                    if ev.event.events & EPOLLIN != 0 {
                        target_events |= poll::IoEvents::IN;
                    }
                    if ev.event.events & EPOLLOUT != 0 {
                        target_events |= poll::IoEvents::OUT;
                    }
                    if ev.event.events & EPOLLRDHUP != 0 {
                        target_events |= poll::IoEvents::RDHUP;
                    }
                    list.push((entry.object.clone(), target_events));
                }
            }
            list
        };

        for (object, target_events) in targets {
            object.register_poll_with_context(process, thread, cx, target_events, registrations)?;
        }
        Ok(())
    }
}

impl FdObject for EpollObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn stat(&self) -> LinuxResult<stat> {
        let mut st = empty_stat();
        st.st_ino = 1;
        st.st_nlink = 1;
        st.st_mode = S_IFREG | 0o600;
        st.st_blksize = 4096;
        Ok(st)
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let process = crate::current_process()?;
        self.poll_for_process(&process, None)
    }

    fn poll_with_context(
        &self,
        process: &crate::Process,
        thread: Option<&crate::Thread>,
    ) -> LinuxResult<PollState> {
        self.poll_for_process(process, thread)
    }

    fn register_poll(
        self: Arc<Self>,
        cx: &mut core::task::Context<'_>,
        _events: poll::IoEvents,
        registrations: &mut Vec<PollRegistration>,
    ) -> LinuxResult {
        let process = crate::current_process()?;
        self.register_poll_for_process(&process, None, cx, registrations)
    }

    fn register_poll_with_context(
        self: Arc<Self>,
        process: &Arc<crate::Process>,
        thread: Option<&Arc<crate::Thread>>,
        cx: &mut core::task::Context<'_>,
        _events: poll::IoEvents,
        registrations: &mut Vec<PollRegistration>,
    ) -> LinuxResult {
        self.register_poll_for_process(process, thread, cx, registrations)
    }
}
