use core::sync::atomic::{AtomicUsize, Ordering};

static UPDATE_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Set the function called by the timer interrupt to refresh vDSO data.
///
/// PulseOS installs the real implementation at boot. Other users can leave the
/// default no-op hook in place if they do not need vDSO updates.
pub fn set_update_hook(hook: fn()) {
    UPDATE_HOOK.store(hook as usize, Ordering::Release);
}

/// Refresh vDSO data through the installed hook.
pub fn update_vdso_data() {
    let hook = UPDATE_HOOK.load(Ordering::Acquire);
    if hook == 0 {
        return;
    }
    let hook: fn() = unsafe { core::mem::transmute(hook) };
    hook();
}
