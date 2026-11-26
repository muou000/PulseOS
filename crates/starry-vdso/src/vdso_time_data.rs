use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use axplat::time::{NANOS_PER_SEC, current_ticks, nanos_to_ticks, ticks_to_nanos};

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

        static CACHED_MULT_SHIFT: AtomicU64 = AtomicU64::new(0);
        let cached = CACHED_MULT_SHIFT.load(Ordering::Relaxed);
        let mult_shift = if cached != 0 {
            (cached as u32, (cached >> 32) as u32)
        } else {
            let ticks_per_sec = nanos_to_ticks(NANOS_PER_SEC);
            let ms = clocks_calc_mult_shift(ticks_per_sec, ticks_to_nanos(ticks_per_sec), 10);
            let val = (ms.0 as u64) | ((ms.1 as u64) << 32);
            CACHED_MULT_SHIFT.store(val, Ordering::Relaxed);
            ms
        };

        self.update_from_source(offset, mult_shift, current_ticks, ticks_to_nanos);
    }

    fn update_from_source<F, C>(
        &mut self,
        offset: u64,
        mult_shift: (u32, u32),
        mut read_ticks: F,
        ticks_to_nanos: C,
    ) where
        F: FnMut() -> u64,
        C: Fn(u64) -> u64,
    {
        let cycle_now = read_ticks();
        let mono_ns = ticks_to_nanos(cycle_now);
        let wall_ns = mono_ns.wrapping_add(offset);

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

#[cfg(test)]
mod tests {
    use core::{cell::Cell, mem::offset_of, sync::atomic::Ordering};

    use axplat::time::NANOS_PER_SEC;

    use super::{VdsoClock, VdsoTimeData, clocks_calc_mult_shift};
    use crate::config::ClockMode;

    /// Independent model of `__vdso_clock_gettime`'s counter interpolation
    /// matching the embedded `vdso_riscv64.so` and `vdso_loongarch64.so` logic.
    fn simulate_vdso_read(clk: &VdsoClock, clock_id: usize, cycles: u64) -> u64 {
        let seq = clk.seq.load(Ordering::Acquire);
        assert_eq!(seq & 1, 0, "seqcount must be even after publish");
        let base = clk.time_data[clock_id];
        if clk.clock_mode == ClockMode::None as i32 {
            return base.sec * NANOS_PER_SEC + base.nsec;
        }
        let cycle_last = clk.cycle_last.load(Ordering::Relaxed);
        let delta = cycles.wrapping_sub(cycle_last) & clk.mask;
        let ns = (delta.wrapping_mul(clk.mult as u64) + base.nsec) >> clk.shift;
        let sec = base.sec + ns / NANOS_PER_SEC;
        let nsec = ns % NANOS_PER_SEC;
        sec * NANOS_PER_SEC + nsec
    }

    #[test]
    fn single_tick_snapshot_eliminates_skew_and_regression() {
        let mut data = VdsoTimeData::new();
        let ticks_per_sec = 10_000_000u64;
        let ns_per_tick = NANOS_PER_SEC / ticks_per_sec;
        let ticks_to_ns = |t: u64| t * ns_per_tick;
        let mult_shift = clocks_calc_mult_shift(ticks_per_sec, ticks_to_ns(ticks_per_sec), 10);
        let offset = 1_700_000_000_000_000_000u64;

        let calls = Cell::new(0usize);
        let next_tick = Cell::new(10_000_000u64);
        let read_ticks = || {
            calls.set(calls.get() + 1);
            let t = next_tick.get();
            next_tick.set(t + 58_489);
            t
        };

        data.update_from_source(offset, mult_shift, read_ticks, ticks_to_ns);
        assert_eq!(calls.get(), 1, "update must sample hardware counter once");

        let snap_mono = ticks_to_ns(10_000_000);
        let snap_wall = snap_mono.wrapping_add(offset);
        assert_eq!(
            data.clock_data[0].time_data[5].sec * NANOS_PER_SEC
                + data.clock_data[0].time_data[5].nsec,
            snap_wall
        );
        assert_eq!(
            data.clock_data[0].time_data[6].sec * NANOS_PER_SEC
                + data.clock_data[0].time_data[6].nsec,
            snap_mono
        );

        let read_at = next_tick.get() + 100;
        let raw_mono = ticks_to_ns(read_at);
        let vdso_mono = simulate_vdso_read(&data.clock_data[0], 1, read_at);
        let vdso_raw = simulate_vdso_read(&data.clock_data[1], 4, read_at);
        let vdso_boot = simulate_vdso_read(&data.clock_data[0], 7, read_at);
        let vdso_real = simulate_vdso_read(&data.clock_data[0], 0, read_at);

        assert_eq!(vdso_mono, raw_mono);
        assert_eq!(vdso_raw, raw_mono);
        assert_eq!(vdso_boot, raw_mono);
        assert_eq!(vdso_real, raw_mono.wrapping_add(offset));

        // Second update with a normal forward step must stay monotonic.
        calls.set(0);
        next_tick.set(read_at + 10_000);
        data.update_from_source(offset, mult_shift, read_ticks, ticks_to_ns);
        assert_eq!(calls.get(), 1);
        let read_at_2 = next_tick.get() + 50;
        let vdso_mono_2 = simulate_vdso_read(&data.clock_data[0], 1, read_at_2);
        assert!(vdso_mono_2 >= vdso_mono);
        assert_eq!(vdso_mono_2, ticks_to_ns(read_at_2));
    }

    #[test]
    fn mult_shift_matches_ticks_to_nanos_across_pulseos_frequencies() {
        for (freq, ns_per_tick) in [
            (10_000_000u64, 100u64),
            (4_000_000u64, 250u64),
            (100_000_000u64, 10u64),
            (33_333_333u64, 30u64),
        ] {
            let ticks_to_ns = |t: u64| t * ns_per_tick;
            let ticks_per_sec = NANOS_PER_SEC.div_ceil(ns_per_tick);
            let mult_shift = clocks_calc_mult_shift(ticks_per_sec, ticks_to_ns(ticks_per_sec), 10);
            let mut data = VdsoTimeData::new();
            let base_ticks = freq * 3 + 12_345;
            data.update_from_source(0, mult_shift, || base_ticks, ticks_to_ns);

            for delta_ticks in [0u64, 1, 7, freq / 100, freq, freq * 5 + 999] {
                let sample_ticks = base_ticks + delta_ticks;
                let expected = ticks_to_ns(sample_ticks);
                let got = simulate_vdso_read(&data.clock_data[0], 1, sample_ticks);
                assert_eq!(got, expected, "freq={freq} delta={delta_ticks}");
            }
        }
    }

    #[test]
    fn wrapping_epoch_offset_preserves_realtime_without_overflow() {
        let mut data = VdsoTimeData::new();
        let mult_shift = clocks_calc_mult_shift(10_000_000, NANOS_PER_SEC, 10);
        let mono_ticks = 50_000u64; // 5_000_000 ns
        let target_wall_ns = 1_000_000u64;
        let offset = target_wall_ns.wrapping_sub(mono_ticks * 100);

        data.update_from_source(offset, mult_shift, || mono_ticks, |t| t * 100);
        let wall = simulate_vdso_read(&data.clock_data[0], 0, mono_ticks);
        assert_eq!(wall, target_wall_ns);
    }

    #[test]
    fn seqcount_advances_evenly_for_both_clock_slots() {
        let mut data = VdsoTimeData::new();
        let mult_shift = clocks_calc_mult_shift(10_000_000, NANOS_PER_SEC, 10);
        data.update_from_source(0, mult_shift, || 1000, |t| t * 100);
        assert_eq!(data.clock_data[0].seq.load(Ordering::Relaxed), 2);
        assert_eq!(data.clock_data[1].seq.load(Ordering::Relaxed), 2);
        data.update_from_source(0, mult_shift, || 2000, |t| t * 100);
        assert_eq!(data.clock_data[0].seq.load(Ordering::Relaxed), 4);
        assert_eq!(data.clock_data[1].seq.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn clock_mode_none_uses_unshifted_nanos_and_zero_cycle_last() {
        let mut data = VdsoTimeData::new();
        data.clock_data[0].clock_mode = ClockMode::None as i32;
        let mult_shift = clocks_calc_mult_shift(10_000_000, NANOS_PER_SEC, 10);
        data.update_from_source(500, mult_shift, || 12_345, |t| t * 100);
        let clk = &data.clock_data[0];
        assert_eq!(clk.mult, 0);
        assert_eq!(clk.shift, 0);
        assert_eq!(clk.cycle_last.load(Ordering::Relaxed), 0);
        assert_eq!(simulate_vdso_read(clk, 1, 99_999), 1_234_500);
        assert_eq!(simulate_vdso_read(clk, 0, 99_999), 1_235_000);
    }

    #[test]
    fn vdso_clock_abi_layout_matches_embedded_vdso() {
        assert_eq!(offset_of!(VdsoTimeData, clock_data), 0);
        assert_eq!(offset_of!(VdsoClock, seq), 0);
        assert_eq!(offset_of!(VdsoClock, clock_mode), 4);
        assert_eq!(offset_of!(VdsoClock, cycle_last), 8);
        #[cfg(not(target_arch = "x86_64"))]
        {
            assert_eq!(offset_of!(VdsoClock, mask), 16);
            assert_eq!(offset_of!(VdsoClock, mult), 24);
            assert_eq!(offset_of!(VdsoClock, shift), 28);
            assert_eq!(offset_of!(VdsoClock, time_data), 32);
            assert_eq!(size_of::<VdsoClock>(), 224);
        }
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(offset_of!(VdsoClock, max_cycles), 16);
            assert_eq!(offset_of!(VdsoClock, mask), 24);
            assert_eq!(offset_of!(VdsoClock, mult), 32);
            assert_eq!(offset_of!(VdsoClock, shift), 36);
            assert_eq!(offset_of!(VdsoClock, time_data), 40);
            assert_eq!(size_of::<VdsoClock>(), 232);
        }
    }
}
