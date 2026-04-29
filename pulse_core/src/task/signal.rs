use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use axerrno::{AxError, AxResult};
use axhal::context::TrapFrame;
use linux_raw_sys::general::{
    SA_NODEFER, SA_RESETHAND, SIGCHLD, SIGCONT, SIGKILL, SIGSTOP, SIGURG, SIGWINCH,
};
use spin::Mutex;

use super::{Process, Thread};

pub const NSIG: usize = 64;
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

#[inline]
fn sig_bit(sig: usize) -> Option<u64> {
    if (1..=NSIG).contains(&sig) {
        Some(1u64 << (sig - 1))
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SigAction {
    pub handler: usize,
    pub flags: usize,
    pub mask: u64,
}

impl SigAction {
    pub const fn dfl() -> Self {
        Self {
            handler: SIG_DFL,
            flags: 0,
            mask: 0,
        }
    }

    pub const fn from_parts(handler: usize, flags: usize, mask: u64) -> Self {
        Self {
            handler,
            flags,
            mask,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DefaultSignalAction {
    Ignore,
    Terminate,
    Stop,
    Continue,
}

#[derive(Clone, Copy, Debug)]
pub enum SignalAction {
    Ignore,
    Default(DefaultSignalAction),
    Handler(SigAction),
}

#[derive(Clone, Copy, Debug)]
pub struct SignalDelivery {
    pub sig: usize,
    pub action: SignalAction,
}

#[derive(Clone, Copy, Debug)]
pub struct SignalAltStack {
    pub sp: usize,
    pub size: usize,
    pub flags: usize,
}

#[derive(Clone, Copy, Debug)]
struct SavedSignalContext {
    tf: TrapFrame,
    old_mask: u64,
}

pub struct SignalShared {
    actions: Mutex<[SigAction; NSIG + 1]>,
    process_pending: AtomicU64,
}

impl SignalShared {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            actions: Mutex::new([SigAction::dfl(); NSIG + 1]),
            process_pending: AtomicU64::new(0),
        })
    }

    pub fn clone_actions_only(from: &Arc<Self>) -> Arc<Self> {
        let actions = *from.actions.lock();
        Arc::new(Self {
            actions: Mutex::new(actions),
            process_pending: AtomicU64::new(0),
        })
    }

    pub fn action(&self, sig: usize) -> SigAction {
        self.actions.lock()[sig]
    }

    pub fn set_action(&self, sig: usize, act: SigAction) {
        self.actions.lock()[sig] = act;
    }

    pub fn reset_on_exec(&self) {
        let mut actions = self.actions.lock();
        for sig in 1..=NSIG {
            let h = actions[sig].handler;
            if h != SIG_IGN {
                actions[sig] = SigAction::dfl();
            }
        }
        self.process_pending.store(0, Ordering::Release);
    }

    pub fn queue_process_signal(&self, sig: usize) -> bool {
        let Some(bit) = sig_bit(sig) else {
            return false;
        };
        let prev = self.process_pending.fetch_or(bit, Ordering::AcqRel);
        (prev & bit) == 0
    }

    fn dequeue_process_unblocked(&self, blocked: u64) -> Option<usize> {
        loop {
            let pending = self.process_pending.load(Ordering::Acquire);
            let ready = pending & !blocked;
            if ready == 0 {
                return None;
            }
            let idx = ready.trailing_zeros() as usize;
            let bit = 1u64 << idx;
            let new_pending = pending & !bit;
            if self
                .process_pending
                .compare_exchange(pending, new_pending, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(idx + 1);
            }
        }
    }

    fn dequeue_process_from_mask(&self, mask: u64) -> Option<usize> {
        loop {
            let pending = self.process_pending.load(Ordering::Acquire);
            let ready = pending & mask;
            if ready == 0 {
                return None;
            }
            let idx = ready.trailing_zeros() as usize;
            let bit = 1u64 << idx;
            let new_pending = pending & !bit;
            if self
                .process_pending
                .compare_exchange(pending, new_pending, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(idx + 1);
            }
        }
    }

    pub fn choose_target_tid(
        &self,
        process: &Process,
        blocked: impl Fn(u64) -> bool,
    ) -> Option<u64> {
        let tids = process.thread_ids_snapshot();
        tids.into_iter()
            .find(|tid| !blocked(*tid))
            .or_else(|| process.thread_ids_snapshot().into_iter().next())
    }
}

pub struct ThreadSignal {
    shared: Arc<SignalShared>,
    thread_pending: AtomicU64,
    blocked: AtomicU64,
    in_handler: AtomicBool,
    skip_once: AtomicBool,
    saved_ctx: Mutex<Option<SavedSignalContext>>,
    altstack: Mutex<SignalAltStack>,
    sigsuspend_restore: Mutex<Option<u64>>,
}

impl ThreadSignal {
    pub fn new(shared: Arc<SignalShared>) -> Arc<Self> {
        Arc::new(Self {
            shared,
            thread_pending: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            in_handler: AtomicBool::new(false),
            skip_once: AtomicBool::new(false),
            saved_ctx: Mutex::new(None),
            altstack: Mutex::new(SignalAltStack {
                sp: 0,
                size: 0,
                flags: 0,
            }),
            sigsuspend_restore: Mutex::new(None),
        })
    }

    pub fn shared(&self) -> Arc<SignalShared> {
        self.shared.clone()
    }

    pub fn blocked_mask(&self) -> u64 {
        self.blocked.load(Ordering::Acquire)
    }

    pub fn set_blocked_mask(&self, mask: u64) -> u64 {
        let sanitized = sanitize_mask(mask);
        self.blocked.swap(sanitized, Ordering::AcqRel)
    }

    pub fn queue_thread_signal(&self, sig: usize) -> bool {
        let Some(bit) = sig_bit(sig) else {
            return false;
        };
        let prev = self.thread_pending.fetch_or(bit, Ordering::AcqRel);
        (prev & bit) == 0
    }

    pub fn queue_process_signal(&self, sig: usize) -> bool {
        self.shared.queue_process_signal(sig)
    }

    pub fn reset_on_exec(&self) {
        self.thread_pending.store(0, Ordering::Release);
        self.blocked.store(0, Ordering::Release);
        self.in_handler.store(false, Ordering::Release);
        self.skip_once.store(false, Ordering::Release);
        *self.saved_ctx.lock() = None;
        *self.sigsuspend_restore.lock() = None;
    }

    pub fn set_altstack(&self, ss: SignalAltStack) {
        *self.altstack.lock() = ss;
    }

    pub fn altstack(&self) -> SignalAltStack {
        *self.altstack.lock()
    }

    pub fn begin_sigsuspend(&self, new_mask: u64) {
        let old = self.set_blocked_mask(new_mask);
        *self.sigsuspend_restore.lock() = Some(old);
    }

    fn maybe_restore_sigsuspend_mask(&self) {
        if let Some(old) = self.sigsuspend_restore.lock().take() {
            self.set_blocked_mask(old);
        }
    }

    pub fn has_pending_unblocked(&self) -> bool {
        let blocked = self.blocked_mask();
        let thread_pending = self.thread_pending.load(Ordering::Acquire);
        let proc_pending = self.shared.process_pending.load(Ordering::Acquire);
        ((thread_pending | proc_pending) & !blocked) != 0
    }

    pub fn has_pending_unblocked_not_in_set(&self, set: u64) -> bool {
        let blocked = self.blocked_mask();
        let thread_pending = self.thread_pending.load(Ordering::Acquire);
        let proc_pending = self.shared.process_pending.load(Ordering::Acquire);
        let unblocked = (thread_pending | proc_pending) & !blocked;
        (unblocked & !set) != 0
    }

    pub fn dequeue_waitset(&self, waitset: u64) -> Option<usize> {
        let waitset = sanitize_mask(waitset);

        loop {
            let pending = self.thread_pending.load(Ordering::Acquire);
            let ready = pending & waitset;
            if ready != 0 {
                let idx = ready.trailing_zeros() as usize;
                let bit = 1u64 << idx;
                let new_pending = pending & !bit;
                if self
                    .thread_pending
                    .compare_exchange(pending, new_pending, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return Some(idx + 1);
                }
                continue;
            }
            break;
        }

        self.shared.dequeue_process_from_mask(waitset)
    }

    pub fn clear_skip_once(&self) -> bool {
        self.skip_once.swap(false, Ordering::AcqRel)
    }

    pub fn restore_from_sigreturn(&self, tf: &mut TrapFrame) -> AxResult<usize> {
        let Some(saved) = self.saved_ctx.lock().take() else {
            return Err(AxError::InvalidInput);
        };
        *tf = saved.tf;
        self.blocked.store(saved.old_mask, Ordering::Release);
        self.in_handler.store(false, Ordering::Release);
        self.skip_once.store(true, Ordering::Release);
        Ok(signal_return_value(tf))
    }

    fn dequeue_unblocked(&self) -> Option<usize> {
        let blocked = self.blocked_mask();

        loop {
            let pending = self.thread_pending.load(Ordering::Acquire);
            let ready = pending & !blocked;
            if ready != 0 {
                let idx = ready.trailing_zeros() as usize;
                let bit = 1u64 << idx;
                let new_pending = pending & !bit;
                if self
                    .thread_pending
                    .compare_exchange(pending, new_pending, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return Some(idx + 1);
                }
                continue;
            }
            break;
        }

        self.shared.dequeue_process_unblocked(blocked)
    }

    fn save_context(&self, tf: &TrapFrame, old_mask: u64) {
        *self.saved_ctx.lock() = Some(SavedSignalContext { tf: *tf, old_mask });
    }
}

fn sanitize_mask(mask: u64) -> u64 {
    let mut mask = mask;
    if let Some(bit) = sig_bit(SIGKILL as usize) {
        mask &= !bit;
    }
    if let Some(bit) = sig_bit(SIGSTOP as usize) {
        mask &= !bit;
    }
    mask
}

fn default_action(sig: usize) -> DefaultSignalAction {
    match sig as u32 {
        SIGCHLD | SIGURG | SIGWINCH => DefaultSignalAction::Ignore,
        SIGCONT => DefaultSignalAction::Continue,
        SIGSTOP => DefaultSignalAction::Stop,
        _ => DefaultSignalAction::Terminate,
    }
}

fn resolve_action(shared: &SignalShared, sig: usize) -> SignalAction {
    let act = shared.action(sig);
    match act.handler {
        SIG_IGN => SignalAction::Ignore,
        SIG_DFL => SignalAction::Default(default_action(sig)),
        _ => SignalAction::Handler(act),
    }
}

#[cfg(target_arch = "riscv64")]
fn set_ip(tf: &mut TrapFrame, ip: usize) {
    tf.sepc = ip;
}
#[cfg(target_arch = "loongarch64")]
fn set_ip(tf: &mut TrapFrame, ip: usize) {
    tf.era = ip;
}

#[cfg(target_arch = "riscv64")]
fn set_ra(tf: &mut TrapFrame, ra: usize) {
    tf.regs.ra = ra;
}
#[cfg(target_arch = "loongarch64")]
fn set_ra(tf: &mut TrapFrame, ra: usize) {
    tf.regs.ra = ra;
}

#[cfg(target_arch = "riscv64")]
fn set_arg0(tf: &mut TrapFrame, arg: usize) {
    tf.regs.a0 = arg;
}
#[cfg(target_arch = "loongarch64")]
fn set_arg0(tf: &mut TrapFrame, arg: usize) {
    tf.regs.a0 = arg;
}

#[cfg(target_arch = "riscv64")]
fn current_ip(tf: &TrapFrame) -> usize {
    tf.sepc
}
#[cfg(target_arch = "loongarch64")]
fn current_ip(tf: &TrapFrame) -> usize {
    tf.era
}

#[cfg(target_arch = "riscv64")]
fn signal_return_value(tf: &TrapFrame) -> usize {
    tf.regs.a0
}
#[cfg(target_arch = "loongarch64")]
fn signal_return_value(tf: &TrapFrame) -> usize {
    tf.regs.a0
}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn signal_return_value(tf: &TrapFrame) -> usize {
    tf.rax as usize
}

#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn set_ip(tf: &mut TrapFrame, ip: usize) {
    tf.rip = ip as u64;
}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn set_ra(_tf: &mut TrapFrame, _ra: usize) {}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn set_arg0(tf: &mut TrapFrame, arg: usize) {
    tf.rdi = arg as u64;
}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn current_ip(tf: &TrapFrame) -> usize {
    tf.rip as usize
}

pub fn can_signal(caller: &Process, target: &Process) -> bool {
    let caller_euid = caller.euid();
    caller_euid == 0 || caller_euid == target.ruid() || caller_euid == target.euid()
}

pub fn queue_signal_to_process(process: &Process, sig: usize) -> bool {
    process.signal_shared().queue_process_signal(sig)
}

pub fn queue_signal_to_thread(thread: &Thread, sig: usize) -> bool {
    thread.signal().queue_thread_signal(sig)
}

pub fn check_signals_and_deliver(thread: &Thread, tf: &mut TrapFrame) -> Option<SignalDelivery> {
    let sig_state = thread.signal();
    if sig_state.clear_skip_once() {
        return None;
    }

    let sig = sig_state.dequeue_unblocked()?;
    let action = resolve_action(&sig_state.shared(), sig);

    match action {
        SignalAction::Ignore => {
            sig_state.maybe_restore_sigsuspend_mask();
            Some(SignalDelivery { sig, action })
        }
        SignalAction::Default(DefaultSignalAction::Terminate)
        | SignalAction::Default(DefaultSignalAction::Stop)
        | SignalAction::Default(DefaultSignalAction::Continue)
        | SignalAction::Default(DefaultSignalAction::Ignore) => {
            sig_state.maybe_restore_sigsuspend_mask();
            Some(SignalDelivery { sig, action })
        }
        SignalAction::Handler(act) => {
            let old_mask = sig_state.blocked_mask();
            let mut new_mask = old_mask | act.mask;
            if (act.flags & (SA_NODEFER as usize)) == 0
                && let Some(bit) = sig_bit(sig)
            {
                new_mask |= bit;
            }
            new_mask = sanitize_mask(new_mask);
            sig_state.save_context(tf, old_mask);
            sig_state.set_blocked_mask(new_mask);
            sig_state.in_handler.store(true, Ordering::Release);

            if (act.flags & (SA_RESETHAND as usize)) != 0 {
                sig_state.shared().set_action(sig, SigAction::dfl());
            }

            let resume_ip = current_ip(tf);
            set_arg0(tf, sig);
            set_ra(tf, thread.process().signal_trampoline());
            set_ip(tf, act.handler);

            // Keep resume IP in the saved frame. We only adjust return address here.
            let _ = resume_ip;
            sig_state.maybe_restore_sigsuspend_mask();
            Some(SignalDelivery { sig, action })
        }
    }
}

#[allow(dead_code)]
pub fn pick_thread_for_process_signal(process: &Process) -> Option<u64> {
    let tids = process.thread_ids_snapshot();
    if tids.is_empty() {
        return None;
    }

    for tid in &tids {
        if process.task_ref_by_tid(*tid).is_some()
            && let Some(thread) = super::thread_by_tid(process, *tid)
            && !thread.signal().has_pending_unblocked()
        {
            return Some(*tid);
        }
    }

    tids.first().copied()
}

pub fn pending_mask(thread: &Thread) -> u64 {
    thread.signal().thread_pending.load(Ordering::Acquire)
        | thread
            .signal()
            .shared()
            .process_pending
            .load(Ordering::Acquire)
}

pub fn blocked_mask(thread: &Thread) -> u64 {
    thread.signal().blocked_mask()
}

#[allow(dead_code)]
pub fn list_threads_for_signal(process: &Process) -> Vec<Arc<Thread>> {
    let mut out = Vec::new();
    for tid in process.thread_ids_snapshot() {
        if let Some(t) = super::thread_by_tid(process, tid) {
            out.push(t);
        }
    }
    out
}
