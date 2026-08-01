use super::*;

struct StdinRaw;
struct StdoutRaw;

fn console_read_bytes(buf: &mut [u8]) -> axio::Result<usize> {
    let len = axhal::console::read_bytes(buf);
    for c in &mut buf[..len] {
        if *c == b'\r' {
            *c = b'\n';
        }
    }
    Ok(len)
}

fn console_write_bytes(buf: &[u8]) -> axio::Result<usize> {
    axhal::console::write_bytes(buf);
    Ok(buf.len())
}

static STDIN_BUFFER: Lazy<SpinNoIrq<VecDeque<u8>>> = Lazy::new(|| SpinNoIrq::new(VecDeque::new()));
pub static STDIN_WAIT_QUEUE: axtask::WaitQueue = axtask::WaitQueue::new();

static FOREGROUND_PGID: AtomicU64 = AtomicU64::new(0);

pub fn get_foreground_pgid() -> u64 {
    FOREGROUND_PGID.load(Ordering::Acquire)
}

pub fn set_foreground_pgid(pgid: u64) {
    FOREGROUND_PGID.store(pgid, Ordering::Release);
}

fn deliver_ctrl_c_signal() {
    let pgid = get_foreground_pgid();
    let target_pgid = if pgid > 0 {
        Some(pgid)
    } else {
        // Find the newest non-init process (highest PID > 1)
        let procs = crate::task::processes_snapshot();
        procs
            .iter()
            .filter(|p| p.pid() > 1 && !p.is_zombie())
            .max_by_key(|p| p.pid())
            .map(|p| p.pgid())
    };

    if let Some(t_pgid) = target_pgid {
        let procs = crate::task::processes_snapshot();
        for p in procs {
            if p.pgid() == t_pgid && p.pid() > 1 && !p.is_zombie() {
                axlog::info!(
                    "Ctrl+C: Sending SIGINT to process {} (pgid {})",
                    p.pid(),
                    p.pgid()
                );
                crate::task::queue_signal_to_process(&p, SIGINT as usize);
            }
        }
    }
}

impl Read for StdinRaw {
    fn read(&mut self, buf: &mut [u8]) -> axio::Result<usize> {
        let mut stdin_buf = STDIN_BUFFER.lock();
        let len = core::cmp::min(buf.len(), stdin_buf.len());
        for i in 0..len {
            buf[i] = stdin_buf.pop_front().unwrap();
        }
        Ok(len)
    }
}

pub fn poll_stdin() {
    let mut temp_buf = [0u8; 64];
    if let Ok(len) = console_read_bytes(&mut temp_buf) {
        if len > 0 {
            let mut stdin_buf = STDIN_BUFFER.lock();
            let mut has_normal_bytes = false;
            for &c in &temp_buf[..len] {
                if c == 3 {
                    deliver_ctrl_c_signal();
                } else {
                    stdin_buf.push_back(c);
                    has_normal_bytes = true;
                }
            }
            if has_normal_bytes {
                STDIN_WAIT_QUEUE.notify_all(true);
            }
        }
    }
}

impl Write for StdoutRaw {
    fn write(&mut self, buf: &[u8]) -> axio::Result<usize> {
        console_write_bytes(buf)
    }

    fn flush(&mut self) -> axio::Result {
        Ok(())
    }
}

static STDIN_READER: Lazy<Mutex<StdinRaw>> = Lazy::new(|| Mutex::new(StdinRaw));
static STDOUT_WRITER: Lazy<Mutex<StdoutRaw>> = Lazy::new(|| Mutex::new(StdoutRaw));

static TTY_TERMIOS: Lazy<SpinNoIrq<termios2>> = Lazy::new(|| {
    SpinNoIrq::new(termios2 {
        c_iflag: 0x500,
        c_oflag: 0x5,
        c_cflag: 0xbf,
        c_lflag: 0x8a3b,
        c_line: 0,
        c_cc: [
            3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0,
        ],
        c_ispeed: 9600,
        c_ospeed: 9600,
    })
});

pub fn read_tty_termios(user_addr: usize) -> LinuxResult {
    let t = TTY_TERMIOS.lock();
    let term = termios {
        c_iflag: t.c_iflag,
        c_oflag: t.c_oflag,
        c_cflag: t.c_cflag,
        c_lflag: t.c_lflag,
        c_line: t.c_line,
        c_cc: t.c_cc,
    };
    let process = crate::task::current_process()?;
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&term as *const termios).cast::<u8>(),
            core::mem::size_of::<termios>(),
        )
    };
    process.write_user_bytes(user_addr, bytes)?;
    Ok(())
}

pub fn write_tty_termios(user_addr: usize) -> LinuxResult {
    let mut term = termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0; 19],
    };
    let process = crate::task::current_process()?;
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut term as *mut termios).cast::<u8>(),
            core::mem::size_of::<termios>(),
        )
    };
    process.read_user_bytes(user_addr, bytes)?;

    let mut t = TTY_TERMIOS.lock();
    t.c_iflag = term.c_iflag;
    t.c_oflag = term.c_oflag;
    t.c_cflag = term.c_cflag;
    t.c_lflag = term.c_lflag;
    t.c_line = term.c_line;
    t.c_cc = term.c_cc;
    Ok(())
}

pub fn read_tty_termios2(user_addr: usize) -> LinuxResult {
    let termios_data = *TTY_TERMIOS.lock();
    let process = crate::task::current_process()?;
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&termios_data as *const termios2).cast::<u8>(),
            core::mem::size_of::<termios2>(),
        )
    };
    process.write_user_bytes(user_addr, bytes)?;
    Ok(())
}

pub fn write_tty_termios2(user_addr: usize) -> LinuxResult {
    let mut termios_data = termios2 {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0; 19],
        c_ispeed: 0,
        c_ospeed: 0,
    };
    let process = crate::task::current_process()?;
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut termios_data as *mut termios2).cast::<u8>(),
            core::mem::size_of::<termios2>(),
        )
    };
    process.read_user_bytes(user_addr, bytes)?;
    *TTY_TERMIOS.lock() = termios_data;
    Ok(())
}

const TCGETS: u32 = 0x5401;
const TCSETS: u32 = 0x5402;
const TCSETSW: u32 = 0x5403;
const TCSETSF: u32 = 0x5404;
const TCGETS2: u32 = 0x802c542a;
const TCSETS2: u32 = 0x402c542b;
const TCSETSW2: u32 = 0x402c542c;
const TCSETSF2: u32 = 0x402c542d;
const TIOCGPGRP: u32 = 0x540F;
const TIOCSPGRP: u32 = 0x5410;
const TIOCGWINSZ: u32 = 0x5413;

#[repr(C)]
struct WinSize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

pub struct StdinObject;

impl StdinObject {
    fn current_has_pending_signal() -> bool {
        crate::task::current_thread()
            .map(|thread| thread.has_pending_signal())
            .unwrap_or(false)
    }
}

impl FdObject for StdinObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> LinuxResult<isize> {
        match cmd {
            TCGETS => {
                if arg != 0 {
                    read_tty_termios(arg)?;
                }
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF => {
                if arg != 0 {
                    write_tty_termios(arg)?;
                }
                Ok(0)
            }
            TCGETS2 => {
                if arg != 0 {
                    read_tty_termios2(arg)?;
                }
                Ok(0)
            }
            TCSETS2 | TCSETSW2 | TCSETSF2 => {
                if arg != 0 {
                    write_tty_termios2(arg)?;
                }
                Ok(0)
            }
            TIOCGPGRP => {
                if arg != 0 {
                    let mut pgid = get_foreground_pgid();
                    if pgid == 0 {
                        pgid = crate::task::current_process()?.pgid();
                    }
                    let value = (pgid as i32).to_ne_bytes();
                    crate::task::current_process()?.write_user_bytes(arg, &value)?;
                }
                Ok(0)
            }
            TIOCSPGRP => {
                if arg != 0 {
                    let pgid = crate::task::current_process()?.read_user_u32(arg)? as u64;
                    set_foreground_pgid(pgid);
                }
                Ok(0)
            }
            TIOCGWINSZ => {
                if arg != 0 {
                    let ws = WinSize {
                        ws_row: 24,
                        ws_col: 80,
                        ws_xpixel: 0,
                        ws_ypixel: 0,
                    };
                    let bytes = unsafe {
                        core::slice::from_raw_parts(
                            (&ws as *const WinSize).cast::<u8>(),
                            core::mem::size_of::<WinSize>(),
                        )
                    };
                    crate::task::current_process()?.write_user_bytes(arg, bytes)?;
                }
                Ok(0)
            }
            FIONREAD => {
                let n = STDIN_BUFFER.lock().len() as i32;
                crate::task::current_process()?.write_user_bytes(arg, &n.to_ne_bytes())?;
                Ok(0)
            }
            _ => Err(LinuxError::ENOTTY),
        }
    }

    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        let read_len = STDIN_READER.lock().read(buf)?;
        if buf.is_empty() || read_len > 0 {
            return Ok(read_len);
        }
        loop {
            let read_len = STDIN_READER.lock().read(buf)?;
            if read_len > 0 {
                return Ok(read_len);
            }
            if let Ok(thread) = crate::task::current_thread() {
                if thread.has_pending_signal() {
                    return Err(LinuxError::EINTR);
                }
            }
            STDIN_WAIT_QUEUE.wait_until(|| {
                !STDIN_BUFFER.lock().is_empty() || Self::current_has_pending_signal()
            });
            if Self::current_has_pending_signal() {
                return Err(LinuxError::EINTR);
            }
        }
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EPERM)
    }

    fn stat(&self) -> LinuxResult<stat> {
        Ok(stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode: 0o20000 | 0o440u32,
            ..empty_stat()
        })
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let has_data = !STDIN_BUFFER.lock().is_empty();
        Ok(PollState {
            readable: has_data,
            writable: true,
        })
    }

    fn get_wait_queues<'a>(
        &'a self,
        events: i16,
        wqs: &mut alloc::vec::Vec<&'a axtask::WaitQueue>,
    ) -> LinuxResult<bool> {
        if (events & (POLLIN as i16)) != 0 {
            wqs.push(&STDIN_WAIT_QUEUE);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn register_poll(
        self: Arc<Self>,
        cx: &mut core::task::Context<'_>,
        events: axpoll::IoEvents,
        registrations: &mut Vec<PollRegistration>,
    ) -> LinuxResult {
        if events.intersects(axpoll::IoEvents::IN | axpoll::IoEvents::RDHUP) {
            let registration = STDIN_WAIT_QUEUE.register_owned_waker(cx.waker());
            registrations.push(PollRegistration::new(move || {
                STDIN_WAIT_QUEUE.unregister_waker(registration);
            }));
        }
        Ok(())
    }

    fn is_read_open(&self) -> bool {
        true
    }

    fn is_write_open(&self) -> bool {
        false
    }
}

pub struct StdoutObject;

impl FdObject for StdoutObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> LinuxResult<isize> {
        match cmd {
            TCGETS => {
                if arg != 0 {
                    read_tty_termios(arg)?;
                }
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF => {
                if arg != 0 {
                    write_tty_termios(arg)?;
                }
                Ok(0)
            }
            TCGETS2 => {
                if arg != 0 {
                    read_tty_termios2(arg)?;
                }
                Ok(0)
            }
            TCSETS2 | TCSETSW2 | TCSETSF2 => {
                if arg != 0 {
                    write_tty_termios2(arg)?;
                }
                Ok(0)
            }
            TIOCGPGRP => {
                if arg != 0 {
                    let mut pgid = get_foreground_pgid();
                    if pgid == 0 {
                        pgid = crate::task::current_process()?.pgid();
                    }
                    let value = (pgid as i32).to_ne_bytes();
                    crate::task::current_process()?.write_user_bytes(arg, &value)?;
                }
                Ok(0)
            }
            TIOCSPGRP => {
                if arg != 0 {
                    let pgid = crate::task::current_process()?.read_user_u32(arg)? as u64;
                    set_foreground_pgid(pgid);
                }
                Ok(0)
            }
            TIOCGWINSZ => {
                if arg != 0 {
                    let ws = WinSize {
                        ws_row: 24,
                        ws_col: 80,
                        ws_xpixel: 0,
                        ws_ypixel: 0,
                    };
                    let bytes = unsafe {
                        core::slice::from_raw_parts(
                            (&ws as *const WinSize).cast::<u8>(),
                            core::mem::size_of::<WinSize>(),
                        )
                    };
                    crate::task::current_process()?.write_user_bytes(arg, bytes)?;
                }
                Ok(0)
            }
            FIONREAD => {
                let n = 0i32;
                crate::task::current_process()?.write_user_bytes(arg, &n.to_ne_bytes())?;
                Ok(0)
            }
            _ => Err(LinuxError::ENOTTY),
        }
    }

    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::EPERM)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        Ok(STDOUT_WRITER.lock().write(buf)?)
    }

    fn stat(&self) -> LinuxResult<stat> {
        Ok(stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode: 0o20000 | 0o220u32,
            ..empty_stat()
        })
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: false,
            writable: true,
        })
    }

    fn register_poll(
        self: Arc<Self>,
        _cx: &mut core::task::Context<'_>,
        _events: axpoll::IoEvents,
        _registrations: &mut Vec<PollRegistration>,
    ) -> LinuxResult {
        // Stdout writability is static. Non-writable event masks can still be
        // interrupted by a signal, timeout, or a change to the epoll set.
        Ok(())
    }

    fn is_read_open(&self) -> bool {
        false
    }

    fn is_write_open(&self) -> bool {
        true
    }
}

pub fn stdio_entries() -> [FdEntry; 3] {
    [
        FdEntry::new(Arc::new(StdinObject), FdFlags::empty()),
        FdEntry::new(Arc::new(StdoutObject), FdFlags::empty()),
        FdEntry::new(Arc::new(StdoutObject), FdFlags::empty()),
    ]
}

pub fn init_tty_callbacks() {
    struct TtyCallbacksImpl;
    impl axfs::TtyCallbacks for TtyCallbacksImpl {
        fn read(&self, buf: &mut [u8]) -> axfs_ng_vfs::VfsResult<usize> {
            let read_len = STDIN_READER
                .lock()
                .read(buf)
                .map_err(|_| axfs_ng_vfs::VfsError::Io)?;
            if buf.is_empty() || read_len > 0 {
                return Ok(read_len);
            }
            loop {
                let read_len = STDIN_READER
                    .lock()
                    .read(buf)
                    .map_err(|_| axfs_ng_vfs::VfsError::Io)?;
                if read_len > 0 {
                    return Ok(read_len);
                }
                if StdinObject::current_has_pending_signal() {
                    return Err(axfs_ng_vfs::VfsError::Interrupted);
                }
                STDIN_WAIT_QUEUE.wait_until(|| {
                    !STDIN_BUFFER.lock().is_empty() || StdinObject::current_has_pending_signal()
                });
                if StdinObject::current_has_pending_signal() {
                    return Err(axfs_ng_vfs::VfsError::Interrupted);
                }
            }
        }

        fn write(&self, buf: &[u8]) -> axfs_ng_vfs::VfsResult<usize> {
            STDOUT_WRITER
                .lock()
                .write(buf)
                .map_err(|_| axfs_ng_vfs::VfsError::Io)
        }

        fn poll(&self) -> axpoll::IoEvents {
            let has_data = !STDIN_BUFFER.lock().is_empty();
            let mut events = axpoll::IoEvents::OUT;
            if has_data {
                events |= axpoll::IoEvents::IN;
            }
            events
        }
    }
    axfs::register_tty_callbacks(Arc::new(TtyCallbacksImpl));
}
