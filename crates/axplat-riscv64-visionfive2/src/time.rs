use core::{
    ptr::read_volatile,
    sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering},
};

use axplat::time::TimeIf;
use riscv::register::time;

const NANOS_PER_SEC: u64 = 1_000_000_000;
const NANOS_PER_TICK: u64 = NANOS_PER_SEC / crate::config::devices::TIMER_FREQUENCY as u64;
const RTC_TIME_OFFSET: usize = 0x3c;
const RTC_DATE_OFFSET: usize = 0x40;
const RTC_REQUIRED_SIZE: usize = RTC_DATE_OFFSET + size_of::<u32>();
const RTC_READ_ATTEMPTS: usize = 3;
const RTC_STATUS_UNAVAILABLE: u8 = 0;
const RTC_STATUS_INVALID: u8 = 1;
const RTC_STATUS_UNSTABLE: u8 = 2;
const RTC_STATUS_STALE: u8 = 3;
const RTC_STATUS_USED: u8 = 4;
const CLOCK_SOURCE_NONE: u8 = 0;
const CLOCK_SOURCE_RTC: u8 = 1;
const CLOCK_SOURCE_BUILD: u8 = 2;

static RTC_EPOCHOFFSET_NANOS: AtomicU64 = AtomicU64::new(0);
static RTC_EPOCH_SECONDS: AtomicU64 = AtomicU64::new(0);
static RTC_MMIO_BASE: AtomicUsize = AtomicUsize::new(0);
static RTC_TIME_RAW: AtomicU32 = AtomicU32::new(0);
static RTC_DATE_RAW: AtomicU32 = AtomicU32::new(0);
static RTC_STATUS: AtomicU8 = AtomicU8::new(RTC_STATUS_UNAVAILABLE);
static CLOCK_SOURCE: AtomicU8 = AtomicU8::new(CLOCK_SOURCE_NONE);

struct RtcSample {
    mmio_base: usize,
    time_reg: u32,
    date_reg: u32,
    stable: bool,
    epoch_seconds: Option<u64>,
}

pub(super) fn init_early(dtb_paddr: usize) {
    let build_epoch = env!("PULSE_BUILD_EPOCH")
        .parse::<u64>()
        .expect("validated PULSE_BUILD_EPOCH");
    let rtc_sample = read_rtc_sample(dtb_paddr);
    let rtc_epoch = rtc_sample.as_ref().and_then(|sample| {
        RTC_MMIO_BASE.store(sample.mmio_base, Ordering::Relaxed);
        RTC_TIME_RAW.store(sample.time_reg, Ordering::Relaxed);
        RTC_DATE_RAW.store(sample.date_reg, Ordering::Relaxed);
        if !sample.stable {
            RTC_STATUS.store(RTC_STATUS_UNSTABLE, Ordering::Relaxed);
            None
        } else if sample.epoch_seconds.is_none() {
            RTC_STATUS.store(RTC_STATUS_INVALID, Ordering::Relaxed);
            None
        } else {
            sample.epoch_seconds
        }
    });
    let (epoch_seconds, use_rtc) = crate::rtc_decode::select_boot_epoch(rtc_epoch, build_epoch);
    if rtc_epoch.is_some() {
        RTC_STATUS.store(
            if use_rtc {
                RTC_STATUS_USED
            } else {
                RTC_STATUS_STALE
            },
            Ordering::Relaxed,
        );
    }
    let Some(epoch_nanos) = epoch_seconds.checked_mul(NANOS_PER_SEC) else {
        return;
    };
    let monotonic_nanos = TimeIfImpl::ticks_to_nanos(TimeIfImpl::current_ticks());
    let Some(epoch_offset) = epoch_nanos.checked_sub(monotonic_nanos) else {
        return;
    };

    RTC_EPOCH_SECONDS.store(epoch_seconds, Ordering::Release);
    RTC_EPOCHOFFSET_NANOS.store(epoch_offset, Ordering::Release);
    CLOCK_SOURCE.store(
        if use_rtc {
            CLOCK_SOURCE_RTC
        } else {
            CLOCK_SOURCE_BUILD
        },
        Ordering::Release,
    );
}

pub(super) fn report_init() {
    let epoch_seconds = RTC_EPOCH_SECONDS.load(Ordering::Acquire);
    let source = CLOCK_SOURCE.load(Ordering::Acquire);
    let status = RTC_STATUS.load(Ordering::Relaxed);
    let mmio_base = RTC_MMIO_BASE.load(Ordering::Relaxed);
    let time_reg = RTC_TIME_RAW.load(Ordering::Relaxed);
    let date_reg = RTC_DATE_RAW.load(Ordering::Relaxed);

    match source {
        CLOCK_SOURCE_RTC => info!(
            "JH7110 RTC initialized: base={mmio_base:#x}, time={time_reg:#010x}, \
             date={date_reg:#010x}, epoch_seconds={epoch_seconds}"
        ),
        CLOCK_SOURCE_BUILD => match status {
            RTC_STATUS_INVALID => warn!(
                "JH7110 RTC has invalid registers: base={mmio_base:#x}, time={time_reg:#010x}, \
                 date={date_reg:#010x}; wall clock seeded from build epoch {epoch_seconds}"
            ),
            RTC_STATUS_UNSTABLE => warn!(
                "JH7110 RTC changed during sampling: base={mmio_base:#x}, time={time_reg:#010x}, \
                 date={date_reg:#010x}; wall clock seeded from build epoch {epoch_seconds}"
            ),
            RTC_STATUS_STALE => warn!(
                "JH7110 RTC predates this image: base={mmio_base:#x}, time={time_reg:#010x}, \
                 date={date_reg:#010x}; wall clock seeded from build epoch {epoch_seconds}"
            ),
            _ => {
                warn!("JH7110 RTC unavailable; wall clock seeded from build epoch {epoch_seconds}")
            }
        },
        _ => warn!("JH7110 wall clock initialization failed; wall clock starts at epoch"),
    }
}

pub(super) fn init_percpu() {
    #[cfg(feature = "irq")]
    sbi_rt::set_timer(0);
}

struct TimeIfImpl;

#[impl_plat_interface]
impl TimeIf for TimeIfImpl {
    /// Returns the current clock time in hardware ticks.
    fn current_ticks() -> u64 {
        time::read() as u64
    }

    /// Converts hardware ticks to nanoseconds.
    fn ticks_to_nanos(ticks: u64) -> u64 {
        ticks * NANOS_PER_TICK
    }

    /// Converts nanoseconds to hardware ticks.
    fn nanos_to_ticks(nanos: u64) -> u64 {
        nanos.div_ceil(NANOS_PER_TICK)
    }

    /// Return epoch offset in nanoseconds (wall time offset to monotonic clock start).
    fn epochoffset_nanos() -> u64 {
        RTC_EPOCHOFFSET_NANOS.load(Ordering::Acquire)
    }

    /// Set a one-shot timer.
    ///
    /// A timer interrupt will be triggered at the specified monotonic time deadline (in nanoseconds).
    #[cfg(feature = "irq")]
    fn set_oneshot_timer(deadline_ns: u64) {
        sbi_rt::set_timer(Self::nanos_to_ticks(deadline_ns));
    }
}

fn read_rtc_sample(dtb_paddr: usize) -> Option<RtcSample> {
    let mmio_base = rtc_mmio_from_dtb(dtb_paddr)
        .or_else(configured_rtc_mmio)
        .filter(|base| configured_mmio_contains(*base, RTC_REQUIRED_SIZE))?;

    let mut last_sample = None;
    for _ in 0..RTC_READ_ATTEMPTS {
        // SAFETY: the DT/config address was checked against the configured
        // identity-mapped MMIO ranges, including both registers read below.
        let (date_before, time_reg, date_after) = unsafe {
            (
                read_volatile((mmio_base + RTC_DATE_OFFSET) as *const u32),
                read_volatile((mmio_base + RTC_TIME_OFFSET) as *const u32),
                read_volatile((mmio_base + RTC_DATE_OFFSET) as *const u32),
            )
        };
        last_sample = Some(RtcSample {
            mmio_base,
            time_reg,
            date_reg: date_after,
            stable: false,
            epoch_seconds: None,
        });
        if date_before == date_after {
            return Some(RtcSample {
                mmio_base,
                time_reg,
                date_reg: date_after,
                stable: true,
                epoch_seconds: crate::rtc_decode::decode_rtc_datetime(time_reg, date_after),
            });
        }
    }
    last_sample
}

fn rtc_mmio_from_dtb(dtb_paddr: usize) -> Option<usize> {
    let fdt = crate::topology::fdt_from_phys(dtb_paddr)?;
    let rtc = fdt.all_nodes().find(|node| {
        crate::topology::is_available(node)
            && node.compatibles().any(|compatible| {
                compatible == "starfive,jh7110-rtc" || compatible == "starfive,rtc_hms"
            })
    })?;
    let reg = rtc.reg()?.next()?;
    let base = usize::try_from(reg.address).ok()?;
    let size = usize::try_from(reg.size?).ok()?;
    (size >= RTC_REQUIRED_SIZE).then_some(base)
}

fn configured_rtc_mmio() -> Option<usize> {
    let base = crate::config::devices::RTC_PADDR;
    (base != 0).then_some(base)
}

fn configured_mmio_contains(base: usize, size: usize) -> bool {
    let Some(end) = base.checked_add(size) else {
        return false;
    };
    crate::config::devices::MMIO_RANGES
        .iter()
        .any(|&(range_base, range_size)| {
            range_base
                .checked_add(range_size)
                .is_some_and(|range_end| base >= range_base && end <= range_end)
        })
}
