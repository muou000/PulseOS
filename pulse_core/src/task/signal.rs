use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use axerrno::{AxError, AxResult};
use axhal::context::TrapFrame;
use axtask::{WaitQueue, WakeContext, WakeSource};
use kspin::SpinNoIrq;
use linux_raw_sys::general::{
    SA_NODEFER, SA_ONSTACK, SA_RESETHAND, SIGCHLD, SIGCONT, SIGKILL, SIGSEGV, SIGSTOP, SIGURG,
    SIGWINCH, SS_DISABLE, SS_ONSTACK,
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
    /// 终止进程并设置 core dump 标志位（不需要实际写文件）
    CoreDump,
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

impl SignalAltStack {
    const fn disabled() -> Self {
        Self {
            sp: 0,
            size: 0,
            flags: SS_DISABLE as usize,
        }
    }

    fn is_disabled(self) -> bool {
        (self.flags & SS_DISABLE as usize) != 0
    }

    fn is_active(self) -> bool {
        (self.flags & SS_ONSTACK as usize) != 0
    }

    fn without_runtime_flags(mut self) -> Self {
        self.flags &= !(SS_ONSTACK as usize);
        self
    }
}

#[derive(Clone, Copy, Debug)]
struct SavedSignalContext {
    tf: TrapFrame,
    old_mask: u64,
    user_ucontext: Option<usize>,
    used_altstack: bool,
}

pub struct SignalHandlers {
    actions: SpinNoIrq<[SigAction; NSIG + 1]>,
}

pub struct SignalShared {
    handlers: Arc<SignalHandlers>,
    process_pending: AtomicU64,
    pub pending_siginfo: Mutex<BTreeMap<usize, [u8; 128]>>,
}

impl SignalShared {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            handlers: Arc::new(SignalHandlers {
                actions: SpinNoIrq::new([SigAction::dfl(); NSIG + 1]),
            }),
            process_pending: AtomicU64::new(0),
            pending_siginfo: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn clone_sighand_only(from: &Arc<Self>) -> Arc<Self> {
        Arc::new(Self {
            handlers: from.handlers.clone(),
            process_pending: AtomicU64::new(0),
            pending_siginfo: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn clone_actions_only(from: &Arc<Self>) -> Arc<Self> {
        let actions = *from.handlers.actions.lock();
        Arc::new(Self {
            handlers: Arc::new(SignalHandlers {
                actions: SpinNoIrq::new(actions),
            }),
            process_pending: AtomicU64::new(0),
            pending_siginfo: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn action(&self, sig: usize) -> SigAction {
        self.handlers.actions.lock()[sig]
    }

    pub fn set_action(&self, sig: usize, act: SigAction) {
        self.handlers.actions.lock()[sig] = act;
    }

    pub fn reset_dispositions_on_exec(&self) {
        let mut actions = self.handlers.actions.lock();
        for sig in 1..=NSIG {
            let handler = if actions[sig].handler == SIG_IGN {
                SIG_IGN
            } else {
                SIG_DFL
            };
            actions[sig] = SigAction::from_parts(handler, 0, 0);
        }
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
    signal_wait: WaitQueue,
    saved_ctx: Mutex<Option<SavedSignalContext>>,
    altstack: Mutex<SignalAltStack>,
    sigsuspend_restore: Mutex<Option<u64>>,
    pub pending_siginfo: Mutex<BTreeMap<usize, [u8; 128]>>,
}

impl ThreadSignal {
    pub fn new(shared: Arc<SignalShared>) -> Arc<Self> {
        Arc::new(Self {
            shared,
            thread_pending: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            in_handler: AtomicBool::new(false),
            skip_once: AtomicBool::new(false),
            signal_wait: WaitQueue::new(),
            saved_ctx: Mutex::new(None),
            altstack: Mutex::new(SignalAltStack::disabled()),
            sigsuspend_restore: Mutex::new(None),
            pending_siginfo: Mutex::new(BTreeMap::new()),
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

    pub fn wait_queue(&self) -> &WaitQueue {
        &self.signal_wait
    }

    pub fn notify_waiters(&self) {
        self.signal_wait.notify_all(true);
    }

    pub fn reset_runtime_on_exec(&self) {
        self.in_handler.store(false, Ordering::Release);
        self.skip_once.store(false, Ordering::Release);
        *self.saved_ctx.lock() = None;
        *self.sigsuspend_restore.lock() = None;
        *self.altstack.lock() = SignalAltStack::disabled();
    }

    pub fn set_altstack(&self, ss: SignalAltStack) {
        *self.altstack.lock() = ss.without_runtime_flags();
    }

    pub fn altstack(&self) -> SignalAltStack {
        *self.altstack.lock()
    }

    fn enter_altstack(&self) {
        let mut altstack = self.altstack.lock();
        if !altstack.is_disabled() {
            altstack.flags |= SS_ONSTACK as usize;
        }
    }

    fn leave_altstack(&self) {
        self.altstack.lock().flags &= !(SS_ONSTACK as usize);
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

    pub fn has_pending_or_skip_once(&self) -> bool {
        self.has_pending_unblocked() || self.skip_once.load(Ordering::Acquire)
    }

    pub fn is_in_handler(&self) -> bool {
        self.in_handler.load(Ordering::Acquire)
    }

    fn prepare_for_forced_signal(&self, sig: usize) -> bool {
        let Some(bit) = sig_bit(sig) else {
            return false;
        };
        let action = resolve_action(&self.shared, sig);
        let was_blocked = (self.blocked.load(Ordering::Acquire) & bit) != 0;
        let was_ignored = is_ignored_action(action);

        if was_blocked || was_ignored {
            self.shared.set_action(sig, SigAction::dfl());
        }
        if was_blocked {
            self.blocked.fetch_and(!bit, Ordering::AcqRel);
        }

        // A synchronous fault is a new delivery point, even immediately after
        // rt_sigreturn consumed the normal one-shot delivery suppression.
        self.skip_once.store(false, Ordering::Release);
        true
    }

    pub fn pending_mask(&self) -> u64 {
        self.thread_pending.load(Ordering::Acquire)
            | self.shared.process_pending.load(Ordering::Acquire)
    }

    pub fn has_pending_unblocked_not_in_set(&self, set: u64) -> bool {
        let set = sanitize_mask(set);
        let blocked = self.blocked_mask();
        let thread_pending = self.thread_pending.load(Ordering::Acquire) & !blocked;
        let proc_pending = self.shared.process_pending.load(Ordering::Acquire) & !blocked;
        self.pending_mask_has_unblocked_match(thread_pending, set)
            || self.pending_mask_has_unblocked_match(proc_pending, set)
    }

    pub fn has_waitset_signal(&self, waitset: u64) -> bool {
        let waitset = sanitize_mask(waitset);
        let thread_pending = self.thread_pending.load(Ordering::Acquire);
        let proc_pending = self.shared.process_pending.load(Ordering::Acquire);
        ((thread_pending | proc_pending) & waitset) != 0
    }

    pub fn has_deliverable_pending_signal(&self) -> bool {
        let blocked = self.blocked_mask();
        let thread_pending = self.thread_pending.load(Ordering::Acquire) & !blocked;
        let proc_pending = self.shared.process_pending.load(Ordering::Acquire) & !blocked;
        self.pending_mask_has_deliverable_match(thread_pending)
            || self.pending_mask_has_deliverable_match(proc_pending)
    }

    pub fn dequeue_waitset_with_info(&self, waitset: u64) -> Option<(usize, Option<[u8; 128]>)> {
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
                    let sig = idx + 1;
                    let info = self.pending_siginfo.lock().remove(&sig);
                    return Some((sig, info));
                }
                continue;
            }
            break;
        }

        let sig = self.shared.dequeue_process_from_mask(waitset)?;
        let info = self.shared.pending_siginfo.lock().remove(&sig);
        Some((sig, info))
    }

    pub fn clear_skip_once(&self) -> bool {
        self.skip_once.swap(false, Ordering::AcqRel)
    }

    fn pending_mask_has_unblocked_match(&self, pending: u64, set: u64) -> bool {
        self.pending_mask_has_match(pending, |sig, action| {
            (sig_bit(sig).unwrap_or(0) & !set) != 0 && !is_ignored_action(action)
        })
    }

    fn pending_mask_has_deliverable_match(&self, pending: u64) -> bool {
        self.pending_mask_has_match(pending, |_, action| !is_ignored_action(action))
    }

    fn pending_mask_has_match(
        &self,
        mut pending: u64,
        mut pred: impl FnMut(usize, SignalAction) -> bool,
    ) -> bool {
        let shared = self.shared();
        while pending != 0 {
            let idx = pending.trailing_zeros() as usize;
            pending &= pending - 1;
            let sig = idx + 1;
            let action = resolve_action(&shared, sig);
            if pred(sig, action) {
                return true;
            }
        }
        false
    }

    pub fn restore_from_sigreturn(&self, process: &Process, tf: &mut TrapFrame) -> AxResult<usize> {
        let Some(saved) = self.saved_ctx.lock().take() else {
            return Err(AxError::InvalidInput);
        };
        *tf = saved.tf;
        let mut restored_mask = saved.old_mask;
        if let Some(user_ucontext) = saved.user_ucontext {
            #[cfg(target_arch = "riscv64")]
            {
                let gregs_addr = user_ucontext + 176;
                let mut gregs = [0u64; 32];
                if process
                    .read_user_bytes(gregs_addr, unsafe {
                        core::slice::from_raw_parts_mut(gregs.as_mut_ptr() as *mut u8, 256)
                    })
                    .is_ok()
                {
                    tf.regs.ra = gregs[1] as usize;
                    tf.regs.sp = gregs[2] as usize;
                    tf.regs.gp = gregs[3] as usize;
                    tf.regs.tp = gregs[4] as usize;
                    tf.regs.t0 = gregs[5] as usize;
                    tf.regs.t1 = gregs[6] as usize;
                    tf.regs.t2 = gregs[7] as usize;
                    tf.regs.s0 = gregs[8] as usize;
                    tf.regs.s1 = gregs[9] as usize;
                    tf.regs.a0 = gregs[10] as usize;
                    tf.regs.a1 = gregs[11] as usize;
                    tf.regs.a2 = gregs[12] as usize;
                    tf.regs.a3 = gregs[13] as usize;
                    tf.regs.a4 = gregs[14] as usize;
                    tf.regs.a5 = gregs[15] as usize;
                    tf.regs.a6 = gregs[16] as usize;
                    tf.regs.a7 = gregs[17] as usize;
                    tf.regs.s2 = gregs[18] as usize;
                    tf.regs.s3 = gregs[19] as usize;
                    tf.regs.s4 = gregs[20] as usize;
                    tf.regs.s5 = gregs[21] as usize;
                    tf.regs.s6 = gregs[22] as usize;
                    tf.regs.s7 = gregs[23] as usize;
                    tf.regs.s8 = gregs[24] as usize;
                    tf.regs.s9 = gregs[25] as usize;
                    tf.regs.s10 = gregs[26] as usize;
                    tf.regs.s11 = gregs[27] as usize;
                    tf.regs.t3 = gregs[28] as usize;
                    tf.regs.t4 = gregs[29] as usize;
                    tf.regs.t5 = gregs[30] as usize;
                    tf.regs.t6 = gregs[31] as usize;
                } else {
                    axlog::warn!(
                        "restore_from_sigreturn: failed to read riscv64 gregs from ucontext_t!"
                    );
                }
            }
            #[cfg(target_arch = "loongarch64")]
            {
                let gregs_addr = user_ucontext + 184;
                let mut gregs = [0u64; 32];
                if process
                    .read_user_bytes(gregs_addr, unsafe {
                        core::slice::from_raw_parts_mut(gregs.as_mut_ptr() as *mut u8, 256)
                    })
                    .is_ok()
                {
                    tf.regs.ra = gregs[1] as usize;
                    tf.regs.tp = gregs[2] as usize;
                    tf.regs.sp = gregs[3] as usize;
                    tf.regs.a0 = gregs[4] as usize;
                    tf.regs.a1 = gregs[5] as usize;
                    tf.regs.a2 = gregs[6] as usize;
                    tf.regs.a3 = gregs[7] as usize;
                    tf.regs.a4 = gregs[8] as usize;
                    tf.regs.a5 = gregs[9] as usize;
                    tf.regs.a6 = gregs[10] as usize;
                    tf.regs.a7 = gregs[11] as usize;
                    tf.regs.t0 = gregs[12] as usize;
                    tf.regs.t1 = gregs[13] as usize;
                    tf.regs.t2 = gregs[14] as usize;
                    tf.regs.t3 = gregs[15] as usize;
                    tf.regs.t4 = gregs[16] as usize;
                    tf.regs.t5 = gregs[17] as usize;
                    tf.regs.t6 = gregs[18] as usize;
                    tf.regs.t7 = gregs[19] as usize;
                    tf.regs.t8 = gregs[20] as usize;
                    tf.regs.u0 = gregs[21] as usize;
                    tf.regs.fp = gregs[22] as usize;
                    tf.regs.s0 = gregs[23] as usize;
                    tf.regs.s1 = gregs[24] as usize;
                    tf.regs.s2 = gregs[25] as usize;
                    tf.regs.s3 = gregs[26] as usize;
                    tf.regs.s4 = gregs[27] as usize;
                    tf.regs.s5 = gregs[28] as usize;
                    tf.regs.s6 = gregs[29] as usize;
                    tf.regs.s7 = gregs[30] as usize;
                    tf.regs.s8 = gregs[31] as usize;
                }
            }
            let tp = tf.regs.tp;
            if tp != 0 {
                let mut buf = [0u8; 8];
                if tp >= 156 && process.read_user_bytes(tp - 156, &mut buf).is_ok() {
                    let cancel = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let canceldisable = buf[4];
                    let cancelasync = buf[5];
                    axlog::debug!(
                        "restore_from_sigreturn: tp={:#x} cancel={} canceldisable={} \
                         cancelasync={}",
                        tp,
                        cancel,
                        canceldisable,
                        cancelasync
                    );
                }
            }
            if let Ok(pc) = read_user_signal_pc(process, user_ucontext) {
                axlog::debug!("restore_from_sigreturn: read PC={:#x}", pc);
                // Safety: Do not allow restoring a kernel address as the return PC.
                if pc < axconfig::plat::KERNEL_ASPACE_BASE {
                    set_ip(tf, pc);
                } else {
                    axlog::warn!(
                        "rt_sigreturn: blocked attempt to restore kernel PC {:#x}",
                        pc
                    );
                }
            }
            if let Ok(mask) = read_user_signal_mask(process, user_ucontext) {
                restored_mask = mask;
            }
        }
        self.blocked
            .store(sanitize_mask(restored_mask), Ordering::Release);
        if saved.used_altstack {
            self.leave_altstack();
        }
        self.in_handler.store(false, Ordering::Release);
        self.skip_once.store(true, Ordering::Release);
        axlog::debug!(
            "restore_from_sigreturn complete: tf.sepc={:#x}, tf.sp={:#x}",
            current_ip(tf),
            current_sp(tf)
        );
        Ok(signal_return_value(tf))
    }

    pub fn peek_unblocked(&self) -> Option<usize> {
        let blocked = self.blocked_mask();

        let pending = self.thread_pending.load(Ordering::Acquire);
        let ready = pending & !blocked;
        if ready != 0 {
            return Some(ready.trailing_zeros() as usize + 1);
        }

        let proc_pending = self.shared.process_pending.load(Ordering::Acquire);
        let proc_ready = proc_pending & !blocked;
        if proc_ready != 0 {
            return Some(proc_ready.trailing_zeros() as usize + 1);
        }
        None
    }

    pub fn dequeue_unblocked_with_info(&self) -> (Option<usize>, Option<[u8; 128]>) {
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
                    let sig = idx + 1;
                    let info = self.pending_siginfo.lock().remove(&sig);
                    return (Some(sig), info);
                }
                continue;
            }
            break;
        }

        if let Some(sig) = self.shared.dequeue_process_unblocked(blocked) {
            let info = self.shared.pending_siginfo.lock().remove(&sig);
            return (Some(sig), info);
        }
        (None, None)
    }

    fn save_context(
        &self,
        tf: &TrapFrame,
        old_mask: u64,
        user_ucontext: Option<usize>,
        used_altstack: bool,
    ) {
        *self.saved_ctx.lock() = Some(SavedSignalContext {
            tf: *tf,
            old_mask,
            user_ucontext,
            used_altstack,
        });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_reset_preserves_pending_signals_and_blocked_mask() {
        let shared = SignalShared::new();
        let signal = ThreadSignal::new(shared.clone());

        signal.set_blocked_mask(0b1010);
        signal.queue_thread_signal(1);
        signal.pending_siginfo.lock().insert(1, [1; 128]);
        shared.queue_process_signal(3);
        shared.pending_siginfo.lock().insert(3, [3; 128]);
        shared.set_action(10, SigAction::from_parts(0x1234, 7, 0x55));
        shared.set_action(12, SigAction::from_parts(SIG_IGN, 9, 0xaa));
        signal.set_altstack(SignalAltStack {
            sp: 0x1000,
            size: 0x2000,
            flags: 0,
        });
        signal.in_handler.store(true, Ordering::Release);
        signal.skip_once.store(true, Ordering::Release);
        *signal.sigsuspend_restore.lock() = Some(0x44);

        shared.reset_dispositions_on_exec();
        signal.reset_runtime_on_exec();

        assert_eq!(signal.blocked_mask(), 0b1010);
        assert_ne!(signal.thread_pending.load(Ordering::Acquire), 0);
        assert_ne!(shared.process_pending.load(Ordering::Acquire), 0);
        assert_eq!(signal.pending_mask(), 0b0101);
        assert_eq!(signal.pending_siginfo.lock().get(&1), Some(&[1; 128]));
        assert_eq!(shared.pending_siginfo.lock().get(&3), Some(&[3; 128]));
        assert_eq!(shared.action(10).handler, SIG_DFL);
        assert_eq!(shared.action(12).handler, SIG_IGN);
        assert!(!signal.in_handler.load(Ordering::Acquire));
        assert!(!signal.skip_once.load(Ordering::Acquire));
        assert!(signal.sigsuspend_restore.lock().is_none());
        let altstack = signal.altstack();
        assert_eq!(
            (altstack.sp, altstack.size, altstack.flags),
            (0, 0, SS_DISABLE as usize)
        );
        assert_eq!(
            signal.dequeue_waitset_with_info(1),
            Some((1, Some([1; 128])))
        );
        assert_eq!(
            signal.dequeue_waitset_with_info(1 << 2),
            Some((3, Some([3; 128])))
        );
    }

    #[test]
    fn clear_sighand_resets_only_the_private_child_actions() {
        let parent = SignalShared::new();
        parent.set_action(10, SigAction::from_parts(0x1234, 7, 0x55));
        parent.set_action(12, SigAction::from_parts(SIG_IGN, 9, 0xaa));

        let child = SignalShared::clone_actions_only(&parent);
        child.reset_dispositions_on_exec();

        assert_eq!(parent.action(10).handler, 0x1234);
        let parent_ignored = parent.action(12);
        assert_eq!(
            (
                parent_ignored.handler,
                parent_ignored.flags,
                parent_ignored.mask
            ),
            (SIG_IGN, 9, 0xaa)
        );
        let reset = child.action(10);
        assert_eq!((reset.handler, reset.flags, reset.mask), (SIG_DFL, 0, 0));
        let ignored = child.action(12);
        assert_eq!(
            (ignored.handler, ignored.flags, ignored.mask),
            (SIG_IGN, 0, 0)
        );
    }

    #[test]
    fn forced_signal_unblocks_and_resets_a_blocked_handler() {
        const SIGSEGV: usize = 11;
        let shared = SignalShared::new();
        let signal = ThreadSignal::new(shared.clone());
        let sigsegv_bit = sig_bit(SIGSEGV).unwrap();

        shared.set_action(SIGSEGV, SigAction::from_parts(0x1234, 0, 0));
        signal.set_blocked_mask(sigsegv_bit);
        signal.skip_once.store(true, Ordering::Release);

        assert!(signal.prepare_for_forced_signal(SIGSEGV));
        assert_eq!(signal.blocked_mask() & sigsegv_bit, 0);
        assert!(!signal.skip_once.load(Ordering::Acquire));
        assert_eq!(shared.action(SIGSEGV).handler, SIG_DFL);
        assert!(matches!(
            resolve_action(&shared, SIGSEGV),
            SignalAction::Default(DefaultSignalAction::CoreDump)
        ));

        signal.queue_thread_signal(SIGSEGV);
        assert!(signal.has_pending_unblocked());
    }

    #[test]
    fn forced_signal_preserves_an_unblocked_handler() {
        const SIGSEGV: usize = 11;
        let shared = SignalShared::new();
        let signal = ThreadSignal::new(shared.clone());

        shared.set_action(SIGSEGV, SigAction::from_parts(0x1234, 0, 0));

        assert!(signal.prepare_for_forced_signal(SIGSEGV));
        assert_eq!(shared.action(SIGSEGV).handler, 0x1234);
    }

    #[test]
    fn forced_signal_resets_an_ignored_disposition() {
        const SIGSEGV: usize = 11;
        let shared = SignalShared::new();
        let signal = ThreadSignal::new(shared.clone());

        shared.set_action(SIGSEGV, SigAction::from_parts(SIG_IGN, 0, 0));

        assert!(signal.prepare_for_forced_signal(SIGSEGV));
        assert_eq!(shared.action(SIGSEGV).handler, SIG_DFL);
        assert!(matches!(
            resolve_action(&shared, SIGSEGV),
            SignalAction::Default(DefaultSignalAction::CoreDump)
        ));
    }

    #[test]
    fn alternate_signal_stack_tracks_active_delivery() {
        let signal = ThreadSignal::new(SignalShared::new());
        signal.set_altstack(SignalAltStack {
            sp: 0x10_000,
            size: 0x4_000,
            flags: SS_ONSTACK as usize,
        });

        assert!(!signal.altstack().is_active());
        signal.enter_altstack();
        assert!(signal.altstack().is_active());
        signal.leave_altstack();
        assert!(!signal.altstack().is_active());
    }

    #[test]
    fn signal_frame_uses_enabled_alternate_stack() {
        let altstack = SignalAltStack {
            sp: 0x10_000,
            size: 0x4_000,
            flags: 0,
        };

        let (frame_base, used_altstack) =
            signal_frame_base(0x80_000, SA_ONSTACK as usize, altstack, 0x480).unwrap();

        assert_eq!(frame_base, 0x13_b80);
        assert!(used_altstack);
    }

    #[test]
    fn signal_frame_stays_on_an_active_alternate_stack() {
        let altstack = SignalAltStack {
            sp: 0x10_000,
            size: 0x4_000,
            flags: SS_ONSTACK as usize,
        };

        let (frame_base, used_altstack) =
            signal_frame_base(0x13_c00, SA_ONSTACK as usize, altstack, 0x480).unwrap();

        assert_eq!(frame_base, 0x13_780);
        assert!(!used_altstack);
    }

    #[test]
    fn signal_frame_rejects_an_undersized_alternate_stack() {
        let altstack = SignalAltStack {
            sp: 0x10_000,
            size: 0x100,
            flags: 0,
        };

        assert!(signal_frame_base(0x80_000, SA_ONSTACK as usize, altstack, 0x480).is_err());
    }
}

fn default_action(sig: usize) -> DefaultSignalAction {
    match sig as u32 {
        SIGCHLD | SIGURG | SIGWINCH => DefaultSignalAction::Ignore,
        SIGCONT => DefaultSignalAction::Continue,
        SIGSTOP => DefaultSignalAction::Stop,
        // POSIX 定义：以下信号的默认动作是终止并产生 core dump
        // SIGQUIT=3, SIGILL=4, SIGTRAP=5, SIGABRT=6, SIGBUS=7,
        // SIGFPE=8, SIGSEGV=11, SIGXCPU=24, SIGXFSZ=25, SIGSYS=31
        3 | 4 | 5 | 6 | 7 | 8 | 11 | 24 | 25 | 31 => DefaultSignalAction::CoreDump,
        _ => DefaultSignalAction::Terminate,
    }
}

pub fn resolve_action(shared: &SignalShared, sig: usize) -> SignalAction {
    let act = shared.action(sig);
    match act.handler {
        SIG_IGN => SignalAction::Ignore,
        SIG_DFL => SignalAction::Default(default_action(sig)),
        _ => SignalAction::Handler(act),
    }
}

fn is_ignored_action(action: SignalAction) -> bool {
    matches!(
        action,
        SignalAction::Ignore | SignalAction::Default(DefaultSignalAction::Ignore)
    )
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
#[cfg(target_arch = "riscv64")]
fn set_arg1(tf: &mut TrapFrame, arg: usize) {
    tf.regs.a1 = arg;
}
#[cfg(target_arch = "riscv64")]
fn set_arg2(tf: &mut TrapFrame, arg: usize) {
    tf.regs.a2 = arg;
}
#[cfg(target_arch = "loongarch64")]
fn set_arg0(tf: &mut TrapFrame, arg: usize) {
    tf.regs.a0 = arg;
}
#[cfg(target_arch = "loongarch64")]
fn set_arg1(tf: &mut TrapFrame, arg: usize) {
    tf.regs.a1 = arg;
}
#[cfg(target_arch = "loongarch64")]
fn set_arg2(tf: &mut TrapFrame, arg: usize) {
    tf.regs.a2 = arg;
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
fn current_sp(tf: &TrapFrame) -> usize {
    tf.regs.sp
}
#[cfg(target_arch = "loongarch64")]
fn current_sp(tf: &TrapFrame) -> usize {
    tf.regs.sp
}
#[cfg(target_arch = "riscv64")]
fn set_sp(tf: &mut TrapFrame, sp: usize) {
    tf.regs.sp = sp;
}
#[cfg(target_arch = "loongarch64")]
fn set_sp(tf: &mut TrapFrame, sp: usize) {
    tf.regs.sp = sp;
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
fn set_arg1(tf: &mut TrapFrame, arg: usize) {
    tf.rsi = arg as u64;
}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn set_arg2(tf: &mut TrapFrame, arg: usize) {
    tf.rdx = arg as u64;
}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn current_ip(tf: &TrapFrame) -> usize {
    tf.rip as usize
}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn current_sp(tf: &TrapFrame) -> usize {
    tf.rsp as usize
}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn set_sp(tf: &mut TrapFrame, sp: usize) {
    tf.rsp = sp as u64;
}

const SIGINFO_FRAME_SIZE: usize = 128;
const UCONTEXT_FRAME_SIZE: usize = 1024;
const UCONTEXT_SIGMASK_OFFSET: usize = 40;
const UCONTEXT_PC_OFFSET: usize = 176;

fn signal_frame_base(
    current_sp: usize,
    action_flags: usize,
    altstack: SignalAltStack,
    frame_size: usize,
) -> AxResult<(usize, bool)> {
    let use_altstack = (action_flags & SA_ONSTACK as usize) != 0
        && !altstack.is_disabled()
        && !altstack.is_active();
    let stack_top = if use_altstack {
        altstack
            .sp
            .checked_add(altstack.size)
            .ok_or(AxError::BadAddress)?
    } else {
        current_sp
    };
    let frame_base = stack_top
        .checked_sub(frame_size)
        .ok_or(AxError::BadAddress)?
        & !15;
    if use_altstack && frame_base < altstack.sp {
        return Err(AxError::BadAddress);
    }
    Ok((frame_base, use_altstack))
}

fn write_user_signal_frame(
    thread: &Thread,
    tf: &TrapFrame,
    old_mask: u64,
    siginfo: Option<[u8; 128]>,
    action_flags: usize,
) -> AxResult<(usize, usize, bool)> {
    let frame_size = SIGINFO_FRAME_SIZE + UCONTEXT_FRAME_SIZE;
    let (frame_base, used_altstack) = signal_frame_base(
        current_sp(tf),
        action_flags,
        thread.signal_altstack(),
        frame_size,
    )?;
    let siginfo_addr = frame_base;
    let ucontext_addr = frame_base + SIGINFO_FRAME_SIZE;

    let mut siginfo_bytes = [0u8; SIGINFO_FRAME_SIZE];
    if let Some(info) = siginfo {
        siginfo_bytes.copy_from_slice(&info);
    }
    thread
        .process()
        .write_user_bytes(siginfo_addr, &siginfo_bytes)?;

    let zeroes = [0u8; UCONTEXT_FRAME_SIZE];
    thread.process().write_user_bytes(ucontext_addr, &zeroes)?;

    thread
        .process()
        .write_user_usize(ucontext_addr + UCONTEXT_SIGMASK_OFFSET, old_mask as usize)?;
    #[cfg(target_arch = "riscv64")]
    {
        // On riscv64, __gregs starts at offset 176 in ucontext_t.
        let gregs_addr = ucontext_addr + 176;
        let gregs_bytes =
            unsafe { core::slice::from_raw_parts(&tf.regs as *const _ as *const u8, 32 * 8) };
        let _ = thread.process().write_user_bytes(gregs_addr, gregs_bytes);
    }

    thread
        .process()
        .write_user_usize(ucontext_addr + UCONTEXT_PC_OFFSET, current_ip(tf))?;
    #[cfg(target_arch = "loongarch64")]
    {
        // On loongarch64, sc_regs starts at offset 184 in ucontext_t.
        let gregs_addr = ucontext_addr + 184;
        let gregs_bytes =
            unsafe { core::slice::from_raw_parts(&tf.regs as *const _ as *const u8, 32 * 8) };
        let _ = thread.process().write_user_bytes(gregs_addr, gregs_bytes);
    }

    Ok((siginfo_addr, ucontext_addr, used_altstack))
}

fn read_user_signal_pc(process: &Process, user_ucontext: usize) -> AxResult<usize> {
    process.read_user_usize(user_ucontext + UCONTEXT_PC_OFFSET)
}

fn read_user_signal_mask(process: &Process, user_ucontext: usize) -> AxResult<u64> {
    process
        .read_user_usize(user_ucontext + UCONTEXT_SIGMASK_OFFSET)
        .map(|mask| mask as u64)
}

pub fn can_signal(caller: &Process, target: &Process) -> bool {
    let caller_euid = caller.euid();
    caller_euid == 0 || caller_euid == target.ruid() || caller_euid == target.euid()
}

pub fn queue_signal_to_process(process: &Process, sig: usize) -> bool {
    if sig == SIGSTOP as usize {
        process
            .stopped_signal_pending
            .store(sig as i32, Ordering::Release);
        process
            .continued_signal_pending
            .store(false, Ordering::Release);
        if let Some(parent) = process.parent_process() {
            parent.child_exit_event.notify_all_with_context(
                false,
                WakeContext::new(|| (WakeSource::Signal, sig as u64)),
            );
        }
    } else if sig == SIGCONT as usize {
        process
            .continued_signal_pending
            .store(true, Ordering::Release);
        process.stopped_signal_pending.store(0, Ordering::Release);
        if let Some(parent) = process.parent_process() {
            parent.child_exit_event.notify_all_with_context(
                false,
                WakeContext::new(|| (WakeSource::Signal, sig as u64)),
            );
        }
    }

    let queued = process.signal_shared().queue_process_signal(sig);
    // Always notify even if already queued, to ensure blocked tasks re-check signals.
    for thread in list_threads_for_signal(process) {
        thread.notify_signal_pending(sig);
    }
    queued
}

pub fn queue_signal_to_thread(thread: &Thread, sig: usize) -> bool {
    let process = thread.process();
    if sig == SIGSTOP as usize {
        process
            .stopped_signal_pending
            .store(sig as i32, Ordering::Release);
        process
            .continued_signal_pending
            .store(false, Ordering::Release);
        if let Some(parent) = process.parent_process() {
            parent.child_exit_event.notify_all_with_context(
                false,
                WakeContext::new(|| (WakeSource::Signal, sig as u64)),
            );
        }
    } else if sig == SIGCONT as usize {
        process
            .continued_signal_pending
            .store(true, Ordering::Release);
        process.stopped_signal_pending.store(0, Ordering::Release);
        if let Some(parent) = process.parent_process() {
            parent.child_exit_event.notify_all_with_context(
                false,
                WakeContext::new(|| (WakeSource::Signal, sig as u64)),
            );
        }
    }

    let queued = thread.signal().queue_thread_signal(sig);
    // Always notify even if already queued
    thread.notify_signal_pending(sig);
    queued
}

/// Queues a signal caused synchronously by the current thread's execution.
///
/// A blocked or ignored synchronous fault cannot remain pending while the
/// faulting instruction is retried. Match Linux force-signal behavior by
/// restoring the default disposition and unblocking it before queuing.
pub fn force_signal_to_thread(thread: &Thread, sig: usize) -> bool {
    if !thread.signal().prepare_for_forced_signal(sig) {
        return false;
    }
    queue_signal_to_thread(thread, sig)
}

pub fn queue_signal_to_process_with_info(
    process: &Process,
    sig: usize,
    info: Option<[u8; 128]>,
) -> bool {
    if let Some(data) = info {
        process
            .signal_shared()
            .pending_siginfo
            .lock()
            .insert(sig, data);
    }
    queue_signal_to_process(process, sig)
}

pub fn queue_signal_to_thread_with_info(
    thread: &Thread,
    sig: usize,
    info: Option<[u8; 128]>,
) -> bool {
    if let Some(data) = info {
        thread.signal().pending_siginfo.lock().insert(sig, data);
    }
    queue_signal_to_thread(thread, sig)
}

pub fn check_signals_and_deliver(thread: &Thread, tf: &mut TrapFrame) -> Option<SignalDelivery> {
    let sig_state = thread.signal();
    if sig_state.clear_skip_once() {
        return None;
    }

    if !sig_state.has_pending_unblocked() {
        return None;
    }

    let (sig_opt, siginfo) = sig_state.dequeue_unblocked_with_info();
    let sig = sig_opt?;
    let action = resolve_action(&sig_state.shared(), sig);

    match action {
        SignalAction::Ignore => {
            sig_state.maybe_restore_sigsuspend_mask();
            Some(SignalDelivery { sig, action })
        }
        SignalAction::Default(DefaultSignalAction::Terminate)
        | SignalAction::Default(DefaultSignalAction::CoreDump)
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
            match write_user_signal_frame(thread, tf, old_mask, siginfo, act.flags) {
                Ok((siginfo_addr, ucontext_addr, used_altstack)) => {
                    sig_state.save_context(tf, old_mask, Some(ucontext_addr), used_altstack);
                    if used_altstack {
                        sig_state.enter_altstack();
                    }
                    set_arg1(tf, siginfo_addr);
                    set_arg2(tf, ucontext_addr);
                    set_sp(tf, siginfo_addr);
                }
                Err(e) => {
                    axlog::warn!("failed to build signal frame for sig {}: {:?}", sig, e);
                    sig_state.maybe_restore_sigsuspend_mask();
                    return Some(SignalDelivery {
                        sig: SIGSEGV as usize,
                        action: SignalAction::Default(DefaultSignalAction::CoreDump),
                    });
                }
            }
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
