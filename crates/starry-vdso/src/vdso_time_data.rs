use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use axplat::time::{NANOS_PER_SEC, current_ticks, monotonic_time_nanos, nanos_to_ticks};

static VDSO_EPOCH_OFFSET: AtomicU64 = AtomicU64::new(u64::MAX);

pub fn set_vdso_epoch_offset(offset: u64) {
    VDSO_EPOCH_OFFSET.store(offset, Ordering::Release);
}

const VDSO_BASES: usize = 12;

use crate::config::ClockMode;

/// vDSO timestamp structure
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VdsoTimestamp {
    /// Seconds
    pub sec: u64,
    /// Nanoseconds
    pub nsec: u64,
}

impl VdsoTimestamp {
    /// Create a new zero timestamp
    pub const fn new() -> Self {
        Self { sec: 0, nsec: 0 }
    }
}

#[repr(C)]
pub struct VdsoClock {
    pub seq: AtomicU32,
    pub clock_mode: i32,
    pub cycle_last: AtomicU64,
    #[cfg(target_arch = "x86_64")]
    pub max_cycles: u64,
    pub mask: u64,
    pub mult: u32,
    pub shift: u32,
    pub time_data: [VdsoTimestamp; VDSO_BASES],
}

impl Default for VdsoClock {
    fn default() -> Self {
        Self::new()
    }
}

impl VdsoClock {
    /// Create a new VdsoClock with default values.
    pub const fn new() -> Self {
        Self {
            seq: AtomicU32::new(0),
            clock_mode: 1,
            cycle_last: AtomicU64::new(0),
            // only for x86 because CONFIG_GENERIC_VDSO_OVERFLOW_PROTECT
            #[cfg(target_arch = "x86_64")]
            max_cycles: 0,

            mask: u64::MAX,
            mult: 0,
            shift: 32,
            time_data: [VdsoTimestamp::new(); VDSO_BASES],
        }
    }

    pub fn write_seqcount_begin(&self) {
        let seq = self.seq.load(Ordering::Relaxed);
        self.seq.store(seq.wrapping_add(1), Ordering::Release);
        core::sync::atomic::fence(Ordering::SeqCst);
    }

    pub fn write_seqcount_end(&self) {
        core::sync::atomic::fence(Ordering::SeqCst);
        let seq = self.seq.load(Ordering::Relaxed);
        self.seq.store(seq.wrapping_add(1), Ordering::Release);
    }
}

#[repr(C)]
#[repr(align(4096))]
pub struct VdsoTimeData {
    pub clock_data: [VdsoClock; 2],
    pub aux_clock_data: [VdsoClock; 8],
    pub tz_minuteswest: i32,
    pub tz_dsttime: i32,
    pub hrtimer_res: u32,
    pub __unused: u32,
}

impl Default for VdsoTimeData {
    fn default() -> Self {
        Self::new()
    }
}

impl VdsoTimeData {
    pub const fn new() -> Self {
        Self {
            clock_data: [VdsoClock::new(), VdsoClock::new()],
            aux_clock_data: [
                VdsoClock::new(),
                VdsoClock::new(),
                VdsoClock::new(),
                VdsoClock::new(),
                VdsoClock::new(),
                VdsoClock::new(),
                VdsoClock::new(),
                VdsoClock::new(),
            ],
            tz_minuteswest: 0,
            tz_dsttime: 0,
            hrtimer_res: 1,
            __unused: 0,
        }
    }

    pub fn update(&mut self) {
        let mut offset = VDSO_EPOCH_OFFSET.load(Ordering::Acquire);
        if offset == u64::MAX {
            offset = axplat::time::epochoffset_nanos();
            VDSO_EPOCH_OFFSET.store(offset, Ordering::Release);
        }
        let wall_ns = monotonic_time_nanos() + offset;
        let mono_ns = monotonic_time_nanos();
        let cycle_now = current_ticks();

        static CACHED_MULT_SHIFT: AtomicU64 = AtomicU64::new(0);
        let cached = CACHED_MULT_SHIFT.load(Ordering::Relaxed);
        let mult_shift = if cached != 0 {
            (cached as u32, (cached >> 32) as u32)
        } else {
            let ticks_per_sec = nanos_to_ticks(NANOS_PER_SEC);
            let ms = clocks_calc_mult_shift(ticks_per_sec, NANOS_PER_SEC, 10);
            let val = (ms.0 as u64) | ((ms.1 as u64) << 32);
            CACHED_MULT_SHIFT.store(val, Ordering::Relaxed);
            ms
        };

        for clk in self.clock_data.iter_mut() {
            clk.write_seqcount_begin();
            update_vdso_clock(clk, cycle_now, wall_ns, mono_ns, mult_shift);
            clk.write_seqcount_end();
        }
    }
}

/// Update vDSO clock.
pub fn update_vdso_clock(
    clk: &mut VdsoClock,
    cycle_now: u64,
    wall_ns: u64,
    mono_ns: u64,
    mult_shift: (u32, u32),
) {
    // Check if this is a counter-based clock mode (non-None)
    let is_counter_mode = clk.clock_mode != (ClockMode::None as i32);

    if is_counter_mode {
        // Counter-based modes: Tsc (x86_64), Csr (riscv64/loongarch64), Cntvct
        // (aarch64)
        let (mult, shift) = mult_shift;
        clk.mult = mult;
        clk.shift = shift;
        clk.time_data[1].sec = mono_ns / NANOS_PER_SEC;
        clk.time_data[1].nsec = (mono_ns % NANOS_PER_SEC) << shift;

        // Update CLOCK_MONOTONIC_RAW (index 4)
        clk.time_data[4].sec = mono_ns / NANOS_PER_SEC;
        clk.time_data[4].nsec = (mono_ns % NANOS_PER_SEC) << shift;

        clk.cycle_last.store(cycle_now, Ordering::Relaxed);
    } else {
        // ClockMode::None - No cycle->ns conversion; store direct monotonic ns.
        clk.mult = 0;
        clk.shift = 0;
        clk.time_data[1].sec = mono_ns / NANOS_PER_SEC;
        clk.time_data[1].nsec = mono_ns % NANOS_PER_SEC;

        // Update CLOCK_MONOTONIC_RAW (index 4)
        clk.time_data[4].sec = mono_ns / NANOS_PER_SEC;
        clk.time_data[4].nsec = mono_ns % NANOS_PER_SEC;

        clk.cycle_last.store(0, Ordering::Relaxed);
    }

    // Update realtime and boottime entries.
    let shift = clk.shift;
    clk.time_data[0].sec = wall_ns / NANOS_PER_SEC;
    clk.time_data[0].nsec = (wall_ns % NANOS_PER_SEC) << shift;
    clk.time_data[7].sec = clk.time_data[1].sec;
    clk.time_data[7].nsec = clk.time_data[1].nsec;

    // Update coarse clocks (un-shifted)
    clk.time_data[5].sec = wall_ns / NANOS_PER_SEC;
    clk.time_data[5].nsec = wall_ns % NANOS_PER_SEC;
    clk.time_data[6].sec = mono_ns / NANOS_PER_SEC;
    clk.time_data[6].nsec = mono_ns % NANOS_PER_SEC;

    if clk.seq.load(Ordering::Relaxed) < 10 {
        let cycle_val = clk.cycle_last.load(Ordering::Relaxed);
        log::trace!(
            "vDSO update: seq={}, cycle_last={}, mono_ns={}, mult={}, shift={}",
            clk.seq.load(Ordering::Relaxed),
            cycle_val,
            mono_ns,
            clk.mult,
            clk.shift
        );
    }
}

/// Compute multiplier and shift to convert from timer_frequency to
/// nanos_per_sec.
pub fn clocks_calc_mult_shift(from: u64, to: u64, maxsec: u32) -> (u32, u32) {
    // sftacc starts at 32 and is reduced based on the maximum conversion range
    let mut tmp = ((maxsec as u64).wrapping_mul(from)) >> 32;
    let mut sftacc: i32 = 32;
    while tmp != 0 {
        tmp >>= 1;
        sftacc -= 1;
    }

    // Try shifts from 32 down to 1 and pick the first that fits the range
    for sft in (1..=32).rev() {
        // compute tmp = (to << sft) / from with rounding
        let mut numer = (to as u128) << sft;
        numer += (from as u128) / 2u128;
        let tmp128 = numer / (from as u128);

        // If tmp128 can be represented within the allowed shift range, select it
        if sftacc <= 0 || (tmp128 >> (sftacc as u128)) == 0u128 {
            let mult = if tmp128 > (u32::MAX as u128) {
                u32::MAX
            } else {
                tmp128 as u32
            };
            return (mult, sft as u32);
        }
    }
    // Fallback: return maximum multiplier with shift 0
    (u32::MAX, 0)
}
