use alloc::{collections::VecDeque, vec::Vec};
use core::time::Duration;

use linux_raw_sys::{
    general::{
        ECHO, ECHOE, ECHOK, ECHONL, ICANON, ICRNL, IGNCR, INLCR, ISIG, NOFLSH, S_IFCHR, SIGINT,
        SIGQUIT, SIGTSTP, SIGWINCH, VEOF, VERASE, VINTR, VKILL, VMIN, VQUIT, VSUSP, VTIME,
    },
    ioctl::{
        TCGETS, TCGETS2, TCSETS, TCSETS2, TCSETSF, TCSETSF2, TCSETSW, TCSETSW2, TIOCGPGRP,
        TIOCGWINSZ, TIOCSPGRP, TIOCSWINSZ,
    },
};

use super::*;
use crate::task::Process;

struct StdoutRaw;

fn console_read_bytes(buf: &mut [u8]) -> axio::Result<usize> {
    Ok(axhal::console::read_bytes(buf))
}

fn console_write_bytes(buf: &[u8]) -> axio::Result<usize> {
    axhal::console::write_bytes(buf);
    Ok(buf.len())
}

#[derive(Default)]
struct TtyInputState {
    readable: VecDeque<u8>,
    canonical: VecDeque<u8>,
    eof_pending: bool,
    generation: u64,
}

impl TtyInputState {
    fn read_into(&mut self, buf: &mut [u8]) -> (usize, bool) {
        let len = core::cmp::min(buf.len(), self.readable.len());
        for byte in &mut buf[..len] {
            *byte = self
                .readable
                .pop_front()
                .expect("TTY readable queue underflow");
        }
        if len == 0 && self.eof_pending {
            self.eof_pending = false;
            return (0, true);
        }
        (len, false)
    }

    fn make_canonical_readable(&mut self) -> bool {
        if self.canonical.is_empty() {
            return false;
        }
        while let Some(byte) = self.canonical.pop_front() {
            self.readable.push_back(byte);
        }
        self.generation = self.generation.wrapping_add(1);
        true
    }

    fn has_readable_data(&self) -> bool {
        !self.readable.is_empty() || self.eof_pending
    }

    fn readable_len(&self) -> usize {
        self.readable.len()
    }
}

#[derive(Default)]
struct TtyInputEffects {
    echo: Vec<u8>,
    signals: Vec<usize>,
    wake_readers: bool,
}

impl TtyInputEffects {
    fn merge(&mut self, other: Self) {
        self.echo.extend(other.echo);
        self.signals.extend(other.signals);
        self.wake_readers |= other.wake_readers;
    }
}

static STDIN_BUFFER: Lazy<SpinNoIrq<TtyInputState>> =
    Lazy::new(|| SpinNoIrq::new(TtyInputState::default()));
pub static STDIN_WAIT_QUEUE: axtask::WaitQueue = axtask::WaitQueue::new();

#[derive(Clone, Copy, Default)]
struct ForegroundProcessGroup {
    session_id: u64,
    pgid: u64,
}

static FOREGROUND_PROCESS_GROUP: Lazy<SpinNoIrq<ForegroundProcessGroup>> =
    Lazy::new(|| SpinNoIrq::new(ForegroundProcessGroup::default()));

pub fn get_foreground_pgid() -> u64 {
    FOREGROUND_PROCESS_GROUP.lock().pgid
}

fn initial_foreground_process_group(caller: &Process) -> ForegroundProcessGroup {
    crate::task::init_process()
        .map(|init| ForegroundProcessGroup {
            session_id: init.sid(),
            pgid: init.pgid(),
        })
        .unwrap_or(ForegroundProcessGroup {
            session_id: caller.sid(),
            pgid: caller.pgid(),
        })
}

/// Returns the foreground group only when this console is the caller's
/// controlling terminal. PulseOS models one console TTY, whose association is
/// fixed to the init session until a full controlling-terminal implementation
/// exists.
pub fn tty_foreground_pgid(process: &Process) -> LinuxResult<u64> {
    crate::task::with_job_control_lock(|| {
        let mut foreground = FOREGROUND_PROCESS_GROUP.lock();
        if foreground.session_id == 0 {
            *foreground = initial_foreground_process_group(process);
        }
        if foreground.session_id != process.sid() {
            return Err(LinuxError::ENOTTY);
        }
        Ok(foreground.pgid)
    })
}

/// Implements the session and nonempty-group checks shared by `TIOCSPGRP` and
/// `tcsetpgrp(3)`. Background-group `SIGTTOU` handling remains a separate
/// terminal line-discipline concern.
pub fn set_tty_foreground_pgid(process: &Process, pgid: i32) -> LinuxResult<()> {
    if pgid <= 0 {
        return Err(LinuxError::EINVAL);
    }
    let pgid = pgid as u64;

    crate::task::with_job_control_lock(|| {
        let session_id = process.sid();
        let groups = crate::task::processes_snapshot()
            .into_iter()
            .filter(|candidate| !candidate.is_zombie())
            .map(|candidate| (candidate.pgid(), candidate.sid()));
        if !crate::task::process_group_exists_in_session(groups, pgid, session_id) {
            return Err(LinuxError::EPERM);
        }

        let mut foreground = FOREGROUND_PROCESS_GROUP.lock();
        if foreground.session_id == 0 {
            *foreground = initial_foreground_process_group(process);
        }
        if foreground.session_id != session_id {
            return Err(LinuxError::ENOTTY);
        }
        foreground.pgid = pgid;
        Ok(())
    })
}

/// Handles the foreground-process-group ioctls shared by all console TTY
/// objects and the devfs compatibility path.
pub fn tty_pgrp_ioctl(cmd: u32, arg: usize) -> Option<LinuxResult<isize>> {
    let result = match cmd {
        TIOCGPGRP => (|| {
            if arg == 0 {
                return Err(LinuxError::EFAULT);
            }
            let process = crate::task::current_process()?;
            let pgid = tty_foreground_pgid(process.as_ref())?;
            process.write_user_bytes(arg, &(pgid as i32).to_ne_bytes())?;
            Ok(0)
        })(),
        TIOCSPGRP => (|| {
            if arg == 0 {
                return Err(LinuxError::EFAULT);
            }
            let process = crate::task::current_process()?;
            let mut bytes = [0u8; core::mem::size_of::<i32>()];
            process.read_user_bytes(arg, &mut bytes)?;
            set_tty_foreground_pgid(process.as_ref(), i32::from_ne_bytes(bytes))?;
            Ok(0)
        })(),
        _ => return None,
    };
    Some(result)
}

fn deliver_terminal_signal(signal: usize) {
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
                    "TTY: sending signal {} to process {} (pgid {})",
                    signal,
                    p.pid(),
                    p.pgid()
                );
                crate::task::queue_signal_to_process(&p, signal);
            }
        }
    }
}

fn map_input_byte(termios_data: &termios2, byte: u8) -> Option<u8> {
    if byte == b'\r' {
        if (termios_data.c_iflag & IGNCR) != 0 {
            return None;
        }
        if (termios_data.c_iflag & ICRNL) != 0 {
            return Some(b'\n');
        }
    } else if byte == b'\n' && (termios_data.c_iflag & INLCR) != 0 {
        return Some(b'\r');
    }
    Some(byte)
}

fn control_character(termios_data: &termios2, index: u32, byte: u8) -> bool {
    let configured = termios_data.c_cc[index as usize];
    configured != 0 && configured == byte
}

fn echo_byte(effects: &mut TtyInputEffects, termios_data: &termios2, byte: u8) {
    if (termios_data.c_lflag & ECHO) != 0 || (byte == b'\n' && (termios_data.c_lflag & ECHONL) != 0)
    {
        effects.echo.push(byte);
    }
}

fn accept_input_byte(
    input: &mut TtyInputState,
    termios_data: &termios2,
    byte: u8,
) -> TtyInputEffects {
    let mut effects = TtyInputEffects::default();
    let Some(byte) = map_input_byte(termios_data, byte) else {
        return effects;
    };

    if (termios_data.c_lflag & ISIG) != 0 {
        let signal = if control_character(termios_data, VINTR, byte) {
            Some(SIGINT as usize)
        } else if control_character(termios_data, VQUIT, byte) {
            Some(SIGQUIT as usize)
        } else if control_character(termios_data, VSUSP, byte) {
            Some(SIGTSTP as usize)
        } else {
            None
        };
        if let Some(signal) = signal {
            if (termios_data.c_lflag & NOFLSH) == 0 {
                input.canonical.clear();
            }
            effects.signals.push(signal);
            return effects;
        }
    }

    if (termios_data.c_lflag & ICANON) == 0 {
        input.readable.push_back(byte);
        input.generation = input.generation.wrapping_add(1);
        echo_byte(&mut effects, termios_data, byte);
        effects.wake_readers = true;
        return effects;
    }

    if control_character(termios_data, VERASE, byte) {
        if input.canonical.pop_back().is_some()
            && (termios_data.c_lflag & ECHO) != 0
            && (termios_data.c_lflag & ECHOE) != 0
        {
            effects.echo.extend_from_slice(b"\x08 \x08");
        }
        return effects;
    }

    if control_character(termios_data, VKILL, byte) {
        if !input.canonical.is_empty() {
            input.canonical.clear();
            if (termios_data.c_lflag & ECHO) != 0 && (termios_data.c_lflag & ECHOK) != 0 {
                effects.echo.push(b'\n');
            }
        }
        return effects;
    }

    if control_character(termios_data, VEOF, byte) {
        if input.canonical.is_empty() {
            input.eof_pending = true;
            input.generation = input.generation.wrapping_add(1);
        } else {
            input.make_canonical_readable();
        }
        effects.wake_readers = true;
        return effects;
    }

    input.canonical.push_back(byte);
    echo_byte(&mut effects, termios_data, byte);
    if byte == b'\n' {
        effects.wake_readers = input.make_canonical_readable();
    }
    effects
}

pub fn poll_stdin() {
    let mut temp_buf = [0u8; 64];
    let Ok(len) = console_read_bytes(&mut temp_buf) else {
        return;
    };
    if len == 0 {
        return;
    }

    let termios_data = *TTY_TERMIOS.lock();
    let mut effects = TtyInputEffects::default();
    {
        let mut input = STDIN_BUFFER.lock();
        for &byte in &temp_buf[..len] {
            effects.merge(accept_input_byte(&mut input, &termios_data, byte));
        }
    }

    if !effects.echo.is_empty() {
        let _ = STDOUT_WRITER.lock().write(&effects.echo);
    }
    for signal in effects.signals {
        deliver_terminal_signal(signal);
    }
    if effects.wake_readers {
        STDIN_WAIT_QUEUE.notify_all(true);
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

static STDOUT_WRITER: Lazy<Mutex<StdoutRaw>> = Lazy::new(|| Mutex::new(StdoutRaw));
static TTY_WRITE_TRANSACTION: axsync::Mutex<()> = axsync::Mutex::new(());

/// Serializes all fragments of one user TTY write transaction.
///
/// Raw console access remains protected by `STDOUT_WRITER` per fragment, so
/// this sleeping lock is never used from interrupt or early-console paths.
pub fn lock_tty_write_transaction() -> axsync::MutexGuard<'static, ()> {
    TTY_WRITE_TRANSACTION.lock()
}

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

    update_tty_termios(|updated| {
        updated.c_iflag = term.c_iflag;
        updated.c_oflag = term.c_oflag;
        updated.c_cflag = term.c_cflag;
        updated.c_lflag = term.c_lflag;
        updated.c_line = term.c_line;
        updated.c_cc = term.c_cc;
    });
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
    update_tty_termios(|updated| *updated = termios_data);
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct WinSize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

static TTY_WINSIZE: Lazy<SpinNoIrq<WinSize>> = Lazy::new(|| {
    SpinNoIrq::new(WinSize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    })
});

fn update_tty_termios(update: impl FnOnce(&mut termios2)) {
    let (previous, updated) = {
        let mut termios_data = TTY_TERMIOS.lock();
        let previous = *termios_data;
        update(&mut *termios_data);
        (previous, *termios_data)
    };

    if (previous.c_lflag & ICANON) != 0 && (updated.c_lflag & ICANON) == 0 {
        let wake_readers = STDIN_BUFFER.lock().make_canonical_readable();
        if wake_readers {
            STDIN_WAIT_QUEUE.notify_all(true);
        }
    }
}

pub fn read_tty_winsize(user_addr: usize) -> LinuxResult {
    if user_addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    let winsize = *TTY_WINSIZE.lock();
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&winsize as *const WinSize).cast::<u8>(),
            core::mem::size_of::<WinSize>(),
        )
    };
    crate::task::current_process()?.write_user_bytes(user_addr, bytes)?;
    Ok(())
}

pub fn write_tty_winsize(user_addr: usize) -> LinuxResult {
    if user_addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    let mut winsize = WinSize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut winsize as *mut WinSize).cast::<u8>(),
            core::mem::size_of::<WinSize>(),
        )
    };
    crate::task::current_process()?.read_user_bytes(user_addr, bytes)?;

    let changed = {
        let mut current = TTY_WINSIZE.lock();
        if *current == winsize {
            false
        } else {
            *current = winsize;
            true
        }
    };
    if changed {
        deliver_terminal_signal(SIGWINCH as usize);
    }
    Ok(())
}

fn current_has_pending_signal() -> bool {
    crate::task::current_thread()
        .map(|thread| thread.has_pending_signal())
        .unwrap_or(false)
}

fn take_tty_input(buf: &mut [u8]) -> (usize, bool) {
    STDIN_BUFFER.lock().read_into(buf)
}

fn tty_input_snapshot() -> (usize, u64, bool) {
    let input = STDIN_BUFFER.lock();
    (input.readable_len(), input.generation, input.eof_pending)
}

fn tty_has_readable_data() -> bool {
    STDIN_BUFFER.lock().has_readable_data()
}

fn read_canonical_input(buf: &mut [u8]) -> LinuxResult<usize> {
    loop {
        let (len, eof) = take_tty_input(buf);
        if len > 0 || eof {
            return Ok(len);
        }
        if current_has_pending_signal() {
            return Err(LinuxError::EINTR);
        }
        STDIN_WAIT_QUEUE.wait_until(|| tty_has_readable_data() || current_has_pending_signal());
    }
}

fn read_noncanonical_input(
    buf: &mut [u8],
    vmin: usize,
    vtime_deciseconds: u8,
) -> LinuxResult<usize> {
    let required = core::cmp::min(vmin, buf.len());
    if required == 0 && vtime_deciseconds == 0 {
        return Ok(take_tty_input(buf).0);
    }

    let timeout = Duration::from_millis(u64::from(vtime_deciseconds) * 100);
    loop {
        let (available, generation, eof) = tty_input_snapshot();
        if available >= required && (required != 0 || available > 0) {
            return Ok(take_tty_input(buf).0);
        }
        if eof {
            return Ok(take_tty_input(buf).0);
        }
        if current_has_pending_signal() {
            return if available > 0 {
                Ok(take_tty_input(buf).0)
            } else {
                Err(LinuxError::EINTR)
            };
        }

        if required == 0 {
            let _ = STDIN_WAIT_QUEUE.wait_timeout_until(timeout, || {
                tty_has_readable_data() || current_has_pending_signal()
            });
            let (available, _, eof) = tty_input_snapshot();
            if available > 0 || eof {
                return Ok(take_tty_input(buf).0);
            }
            return if current_has_pending_signal() {
                Err(LinuxError::EINTR)
            } else {
                Ok(0)
            };
        }

        if vtime_deciseconds == 0 {
            STDIN_WAIT_QUEUE.wait_until(|| {
                let (available, _, eof) = tty_input_snapshot();
                available >= required || eof || current_has_pending_signal()
            });
            continue;
        }

        if available == 0 {
            STDIN_WAIT_QUEUE.wait_until(|| tty_has_readable_data() || current_has_pending_signal());
            continue;
        }

        let timed_out = STDIN_WAIT_QUEUE.wait_timeout_until(timeout, || {
            let (available, current_generation, eof) = tty_input_snapshot();
            available >= required
                || eof
                || current_generation != generation
                || current_has_pending_signal()
        });
        if timed_out {
            return Ok(take_tty_input(buf).0);
        }
    }
}

fn read_tty_input(buf: &mut [u8]) -> LinuxResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let termios_data = *TTY_TERMIOS.lock();
    if (termios_data.c_lflag & ICANON) != 0 {
        return read_canonical_input(buf);
    }
    read_noncanonical_input(
        buf,
        termios_data.c_cc[VMIN as usize] as usize,
        termios_data.c_cc[VTIME as usize],
    )
}

fn console_tty_stat() -> LinuxResult<stat> {
    // Reuse devfs metadata rather than duplicating its dynamically assigned
    // mount device ID. ttyname(3) compares this identity with /dev entries.
    match axfs::lookup_location("/dev/tty") {
        Ok(location) => location_to_stat(&location),
        Err(_) => Ok(synthetic_console_tty_stat()),
    }
}

fn synthetic_console_tty_stat() -> stat {
    stat {
        st_ino: 1,
        st_nlink: 1,
        st_mode: S_IFCHR | 0o666,
        st_blksize: 4096,
        st_rdev: axfs_ng_vfs::DeviceId::new(5, 0).0 as _,
        ..empty_stat()
    }
}

pub struct StdinObject;

impl FdObject for StdinObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> LinuxResult<isize> {
        if let Some(result) = tty_pgrp_ioctl(cmd, arg) {
            return result;
        }
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
            TIOCGWINSZ => {
                read_tty_winsize(arg)?;
                Ok(0)
            }
            TIOCSWINSZ => {
                write_tty_winsize(arg)?;
                Ok(0)
            }
            FIONREAD => {
                let n = STDIN_BUFFER.lock().readable_len() as i32;
                crate::task::current_process()?.write_user_bytes(arg, &n.to_ne_bytes())?;
                Ok(0)
            }
            _ => Err(LinuxError::ENOTTY),
        }
    }

    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        read_tty_input(buf)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EPERM)
    }

    fn stat(&self) -> LinuxResult<stat> {
        console_tty_stat()
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let has_data = tty_has_readable_data();
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
        if let Some(result) = tty_pgrp_ioctl(cmd, arg) {
            return result;
        }
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
            TIOCGWINSZ => {
                read_tty_winsize(arg)?;
                Ok(0)
            }
            TIOCSWINSZ => {
                write_tty_winsize(arg)?;
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

    fn is_tty_output(&self) -> bool {
        true
    }

    fn stat(&self) -> LinuxResult<stat> {
        console_tty_stat()
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
            read_tty_input(buf).map_err(|error| match error {
                LinuxError::EINTR => axfs_ng_vfs::VfsError::Interrupted,
                _ => axfs_ng_vfs::VfsError::Io,
            })
        }

        fn write(&self, buf: &[u8]) -> axfs_ng_vfs::VfsResult<usize> {
            STDOUT_WRITER
                .lock()
                .write(buf)
                .map_err(|_| axfs_ng_vfs::VfsError::Io)
        }

        fn poll(&self) -> axpoll::IoEvents {
            let has_data = tty_has_readable_data();
            let mut events = axpoll::IoEvents::OUT;
            if has_data {
                events |= axpoll::IoEvents::IN;
            }
            events
        }
    }
    axfs::register_tty_callbacks(Arc::new(TtyCallbacksImpl));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_termios() -> termios2 {
        let mut c_cc = [0; 19];
        c_cc[VINTR as usize] = 3;
        c_cc[VQUIT as usize] = 28;
        c_cc[VERASE as usize] = 127;
        c_cc[VKILL as usize] = 21;
        c_cc[VEOF as usize] = 4;
        c_cc[VMIN as usize] = 1;
        c_cc[VSUSP as usize] = 26;
        termios2 {
            c_iflag: ICRNL,
            c_oflag: 0,
            c_cflag: 0,
            c_lflag: ICANON | ISIG | ECHO | ECHOE | ECHOK,
            c_line: 0,
            c_cc,
            c_ispeed: 0,
            c_ospeed: 0,
        }
    }

    #[test]
    fn canonical_input_waits_for_newline_and_honors_erase() {
        let termios_data = test_termios();
        let mut input = TtyInputState::default();

        assert!(!accept_input_byte(&mut input, &termios_data, b'a').wake_readers);
        assert!(!accept_input_byte(&mut input, &termios_data, b'b').wake_readers);
        assert!(!accept_input_byte(&mut input, &termios_data, 127).wake_readers);
        assert!(!accept_input_byte(&mut input, &termios_data, b'c').wake_readers);
        assert!(accept_input_byte(&mut input, &termios_data, b'\n').wake_readers);

        let mut output = [0; 8];
        let (len, eof) = input.read_into(&mut output);
        assert_eq!(&output[..len], b"ac\n");
        assert!(!eof);
    }

    #[test]
    fn raw_input_is_immediately_readable_and_intr_is_not_buffered() {
        let mut termios_data = test_termios();
        termios_data.c_lflag &= !ICANON;
        let mut input = TtyInputState::default();

        assert!(accept_input_byte(&mut input, &termios_data, b'x').wake_readers);
        let intr = accept_input_byte(&mut input, &termios_data, 3);
        assert_eq!(intr.signals, alloc::vec![SIGINT as usize]);

        let mut output = [0; 1];
        let (len, eof) = input.read_into(&mut output);
        assert_eq!(&output[..len], b"x");
        assert!(!eof);
    }

    #[test]
    fn foreground_group_must_belong_to_the_callers_session() {
        let groups = [(10, 1), (20, 2)];

        assert!(crate::task::process_group_exists_in_session(
            groups.into_iter(),
            10,
            1
        ));
        assert!(!crate::task::process_group_exists_in_session(
            groups.into_iter(),
            10,
            2
        ));
        assert!(!crate::task::process_group_exists_in_session(
            groups.into_iter(),
            30,
            1
        ));
    }
}
