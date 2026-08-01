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
    control_wait_queue: Arc<axtask::WaitQueue>,
}

impl EpollObject {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(BTreeMap::new()),
            control_wait_queue: Arc::new(axtask::WaitQueue::new()),
        }
    }

    pub fn notify_control(&self) {
        self.control_wait_queue.notify_all(false);
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
        let events = self.events.lock();
        for (&fd, ev) in events.iter() {
            if let Ok(entry) = crate::task::current_process()?.get_fd_entry(fd) {
                if let Ok(state) = entry.object.poll() {
                    let mut revents = 0u32;
                    if state.readable && (ev.event.events & EPOLLIN != 0) {
                        revents |= EPOLLIN;
                    }
                    if state.writable && (ev.event.events & EPOLLOUT != 0) {
                        revents |= EPOLLOUT;
                    }
                    if ev.event.events & EPOLLRDHUP != 0 && entry.object.is_rdhup() {
                        revents |= EPOLLRDHUP;
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

    fn register_poll(
        self: Arc<Self>,
        cx: &mut core::task::Context<'_>,
        _events: axpoll::IoEvents,
        registrations: &mut Vec<PollRegistration>,
    ) -> LinuxResult {
        let control_wait_queue = self.control_wait_queue.clone();
        let registration = control_wait_queue.register_owned_waker(cx.waker());
        registrations.push(PollRegistration::new(move || {
            control_wait_queue.unregister_waker(registration);
        }));

        let targets: Vec<(Arc<dyn FdObject>, axpoll::IoEvents)> = {
            let monitored = self.events.lock();
            let mut list = Vec::new();
            for (&fd, ev) in monitored.iter() {
                if let Ok(entry) = crate::task::current_process()?.get_fd_entry(fd) {
                    let mut target_events = axpoll::IoEvents::empty();
                    if ev.event.events & EPOLLIN != 0 {
                        target_events |= axpoll::IoEvents::IN;
                    }
                    if ev.event.events & EPOLLOUT != 0 {
                        target_events |= axpoll::IoEvents::OUT;
                    }
                    if ev.event.events & EPOLLRDHUP != 0 {
                        target_events |= axpoll::IoEvents::RDHUP;
                    }

                    if !target_events.is_empty() {
                        list.push((entry.object.clone(), target_events));
                    }
                }
            }
            list
        };

        for (object, target_events) in targets {
            object.register_poll(cx, target_events, registrations)?;
        }
        Ok(())
    }
}
