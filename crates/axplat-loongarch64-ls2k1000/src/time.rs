use axplat::time::TimeIf;
use lazyinit::LazyInit;
use loongArch64::time::Time;

static NANOS_PER_TICK: LazyInit<u64> = LazyInit::new();

pub(super) fn init_percpu() {
    #[cfg(feature = "irq")]
    {
        use loongArch64::register::{tcfg, ticlr};

        tcfg::set_en(false);
        tcfg::set_periodic(false);
        ticlr::clear_timer_interrupt();
        axplat::irq::set_enable(crate::config::devices::TIMER_IRQ, true);
    }
}

pub(super) fn init_early() {
    NANOS_PER_TICK
        .init_once(axplat::time::NANOS_PER_SEC / loongArch64::time::get_timer_freq() as u64);
}

struct TimeIfImpl;

#[impl_plat_interface]
impl TimeIf for TimeIfImpl {
    fn current_ticks() -> u64 {
        Time::read() as _
    }

    // The initial board port intentionally exposes monotonic time only. RTC
    // register semantics vary between 2K1000 firmware revisions and need a
    // separately validated driver before wall clock time is claimed.
    fn epochoffset_nanos() -> u64 {
        0
    }

    fn ticks_to_nanos(ticks: u64) -> u64 {
        ticks.saturating_mul(*NANOS_PER_TICK)
    }

    fn nanos_to_ticks(nanos: u64) -> u64 {
        nanos.div_ceil(*NANOS_PER_TICK)
    }

    #[cfg(feature = "irq")]
    fn set_oneshot_timer(deadline_ns: u64) {
        use loongArch64::register::{prcfg1, tcfg, ticlr};

        let ticks_now = Self::current_ticks();
        let ticks_deadline = Self::nanos_to_ticks(deadline_ns);
        let timer_bits = prcfg1::read().timer_bits();
        let init_value = axplat::time::oneshot_delta_ticks(ticks_now, ticks_deadline, timer_bits);
        let init_value =
            usize::try_from(init_value).expect("LoongArch64 timer interval must fit in usize");

        tcfg::set_en(false);
        tcfg::set_periodic(false);
        tcfg::set_init_val(init_value);
        ticlr::clear_timer_interrupt();
        tcfg::set_en(true);
    }
}
