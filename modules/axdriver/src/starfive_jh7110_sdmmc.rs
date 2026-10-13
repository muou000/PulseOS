use core::{
    sync::atomic::{Ordering, fence},
    time::Duration,
};

use axdriver_base::{BaseDriverOps, DevResult, DeviceType};
use axdriver_block::{AsyncBlockDriverOps, BlockDriverOps, starfive_jh7110::Jh7110SdMmc};
use axhal::mem::phys_to_virt;

const VF2_SDIO1_PADDR: usize = 0x1602_0000;

// The U-Boot control DTB used by the VF2 board does not describe the OS-side
// SDIO1 clock/reset/pinctrl providers. Keep the small, board-specific part of
// that contract here so a warm reboot cannot inherit a stopped CIU clock or a
// stale pinmux from firmware.
const VF2_SYS_CRG_PADDR: usize = 0x1302_0000;
const VF2_SYS_PINCTRL_PADDR: usize = 0x1304_0000;
const VF2_SYSCLK_IOMUX_APB_OFFSET: usize = 112 * 4;
const VF2_SYSCLK_SDIO1_AHB_OFFSET: usize = 92 * 4;
const VF2_SYSCLK_SDIO1_SDCARD_OFFSET: usize = 94 * 4;
const VF2_SYSRST_ASSERT_BASE: usize = 0x2f8;
const VF2_SYSRST_STATUS_BASE: usize = 0x308;
const VF2_SYSRST_IOMUX_APB_OFFSET: usize = VF2_SYSRST_ASSERT_BASE;
const VF2_SYSRST_IOMUX_APB_STATUS_OFFSET: usize = VF2_SYSRST_STATUS_BASE;
const VF2_SYSRST_SDIO1_OFFSET: usize = VF2_SYSRST_ASSERT_BASE + 2 * 4;
const VF2_SYSRST_SDIO1_STATUS_OFFSET: usize = VF2_SYSRST_STATUS_BASE + 2 * 4;
const VF2_SYSRST_IOMUX_APB_MASK: u32 = 1 << 2;
const VF2_SDIO1_RESET_MASK: u32 = 1 << 1;
const VF2_CRG_CLOCK_ENABLE: u32 = 1 << 31;
const VF2_CRG_CLOCK_DIV_MASK: u32 = 0x00ff_ffff;
const VF2_SDIO1_CLOCK_DIVIDER: u32 = 8; // 400 MHz parent / 8 = 50 MHz.
const VF2_RESET_POLL_LIMIT: usize = 100_000;
const VF2_RESET_SETTLE: Duration = Duration::from_micros(10);

const VF2_PINCTRL_DOEN_OFFSET: usize = 0x000;
const VF2_PINCTRL_DOUT_OFFSET: usize = 0x040;
const VF2_PINCTRL_GPI_OFFSET: usize = 0x080;
const VF2_PINCTRL_PADCFG_BASE: usize = 0x120;
const VF2_PINCTRL_FUNCTION_OFFSET: usize = 0x29c;
const VF2_PINCTRL_DOEN_MASK: u32 = 0x3f;
const VF2_PINCTRL_DOUT_MASK: u32 = 0x7f;
const VF2_PINCTRL_GPI_MASK: u32 = 0x7f;
const VF2_PADCFG_SMT: u32 = 1 << 6;
const VF2_PADCFG_SLEW: u32 = 1 << 5;
const VF2_PADCFG_PD: u32 = 1 << 4;
const VF2_PADCFG_PU: u32 = 1 << 3;
const VF2_PADCFG_DS_MASK: u32 = 0b11 << 1;
const VF2_PADCFG_IE: u32 = 1;
const VF2_PADCFG_CONFIG_MASK: u32 = VF2_PADCFG_SMT
    | VF2_PADCFG_SLEW
    | VF2_PADCFG_PD
    | VF2_PADCFG_PU
    | VF2_PADCFG_DS_MASK
    | VF2_PADCFG_IE;
const VF2_PADCFG_CLOCK: u32 = VF2_PADCFG_PU | (0b11 << 1);
const VF2_PADCFG_DATA: u32 = VF2_PADCFG_CLOCK | VF2_PADCFG_SMT | VF2_PADCFG_IE;

#[derive(Clone, Copy)]
struct Vf2PinConfig {
    pin: usize,
    dout: u32,
    doen: u32,
    din: Option<usize>,
    padcfg: u32,
}

// Values mirror mmc1_pins in the JH7110 Linux device tree. The packed GPIO
// selectors are deliberately kept explicit: GPIO7/8/9 have no function-select
// field, while GPIO10/11/12 use the 0x29c selector register.
const VF2_SDIO1_PINS: [Vf2PinConfig; 6] = [
    Vf2PinConfig {
        pin: 10,
        dout: 55,
        doen: 0,
        din: None,
        padcfg: VF2_PADCFG_CLOCK,
    },
    Vf2PinConfig {
        pin: 9,
        dout: 57,
        doen: 19,
        din: Some(44),
        padcfg: VF2_PADCFG_DATA,
    },
    Vf2PinConfig {
        pin: 11,
        dout: 58,
        doen: 20,
        din: Some(45),
        padcfg: VF2_PADCFG_DATA,
    },
    Vf2PinConfig {
        pin: 12,
        dout: 59,
        doen: 21,
        din: Some(46),
        padcfg: VF2_PADCFG_DATA,
    },
    Vf2PinConfig {
        pin: 7,
        dout: 60,
        doen: 22,
        din: Some(47),
        padcfg: VF2_PADCFG_DATA,
    },
    Vf2PinConfig {
        pin: 8,
        dout: 61,
        doen: 23,
        din: Some(48),
        padcfg: VF2_PADCFG_DATA,
    },
];

const fn rmw_value(old: u32, mask: u32, value: u32) -> u32 {
    (old & !mask) | (value & mask)
}

const fn vf2_pin_function_select(pin: usize) -> Option<(usize, u32)> {
    match pin {
        10 => Some((VF2_PINCTRL_FUNCTION_OFFSET, 2)),
        11 => Some((VF2_PINCTRL_FUNCTION_OFFSET, 5)),
        12 => Some((VF2_PINCTRL_FUNCTION_OFFSET, 8)),
        _ => None,
    }
}

unsafe fn mmio_rmw(base: *mut u8, offset: usize, mask: u32, value: u32) -> u32 {
    let register = base.add(offset).cast::<u32>();
    let old = register.read_volatile();
    let new = rmw_value(old, mask, value);
    register.write_volatile(new);
    new
}

unsafe fn configure_vf2_sdmmc_pins(base: *mut u8) {
    for config in VF2_SDIO1_PINS {
        let field_shift = (config.pin % 4) * 8;
        let field_mask = VF2_PINCTRL_DOUT_MASK << field_shift;
        mmio_rmw(
            base,
            VF2_PINCTRL_DOUT_OFFSET + 4 * (config.pin / 4),
            field_mask,
            config.dout << field_shift,
        );

        let field_mask = VF2_PINCTRL_DOEN_MASK << field_shift;
        mmio_rmw(
            base,
            VF2_PINCTRL_DOEN_OFFSET + 4 * (config.pin / 4),
            field_mask,
            config.doen << field_shift,
        );

        if let Some(din) = config.din {
            let input_shift = (din % 4) * 8;
            let input_mask = VF2_PINCTRL_GPI_MASK << input_shift;
            // JH7110's GPI selector stores the GPIO number plus two.
            mmio_rmw(
                base,
                VF2_PINCTRL_GPI_OFFSET + 4 * (din / 4),
                input_mask,
                ((config.pin + 2) as u32) << input_shift,
            );
        }

        if let Some((offset, shift)) = vf2_pin_function_select(config.pin) {
            mmio_rmw(base, offset, 0x3 << shift, 0);
        }

        mmio_rmw(
            base,
            VF2_PINCTRL_PADCFG_BASE + 4 * config.pin,
            VF2_PADCFG_CONFIG_MASK,
            config.padcfg,
        );
    }
}

unsafe fn wait_vf2_reset_deasserted(base: *const u8, status_offset: usize, mask: u32) -> u32 {
    let status = base.add(status_offset).cast::<u32>();
    let mut value = status.read_volatile();
    for _ in 0..VF2_RESET_POLL_LIMIT {
        if value & mask == mask {
            break;
        }
        core::hint::spin_loop();
        value = status.read_volatile();
    }
    value
}

/// Take ownership of the fixed VF2 SDIO1 board resources.
///
/// The function is intentionally idempotent. It is safe to run after U-Boot
/// has already configured the same resources and, importantly, also repairs a
/// warm-reboot state in which U-Boot left the CIU clock gated.
fn configure_vf2_sdmmc_resources(paddr: usize) -> bool {
    if paddr != VF2_SDIO1_PADDR {
        return true;
    }

    let crg = phys_to_virt(VF2_SYS_CRG_PADDR.into()).as_mut_ptr();
    let pinctrl = phys_to_virt(VF2_SYS_PINCTRL_PADDR.into()).as_mut_ptr();
    let (
        ahb_before,
        iomux_clock_before,
        ciu_before,
        sdio_reset_before,
        iomux_reset_before,
        sdio_status_before,
        iomux_status_before,
    ) = unsafe {
        let ahb = crg.add(VF2_SYSCLK_SDIO1_AHB_OFFSET).cast::<u32>();
        let iomux_clock = crg.add(VF2_SYSCLK_IOMUX_APB_OFFSET).cast::<u32>();
        let ciu = crg.add(VF2_SYSCLK_SDIO1_SDCARD_OFFSET).cast::<u32>();
        let reset = crg.add(VF2_SYSRST_SDIO1_OFFSET).cast::<u32>();
        let iomux_reset = crg.add(VF2_SYSRST_IOMUX_APB_OFFSET).cast::<u32>();
        let ahb_before = ahb.read_volatile();
        let iomux_clock_before = iomux_clock.read_volatile();
        let ciu_before = ciu.read_volatile();
        let sdio_reset_before = reset.read_volatile();
        let iomux_reset_before = iomux_reset.read_volatile();
        let sdio_status_before = crg
            .add(VF2_SYSRST_SDIO1_STATUS_OFFSET)
            .cast::<u32>()
            .read_volatile();
        let iomux_status_before = crg
            .add(VF2_SYSRST_IOMUX_APB_STATUS_OFFSET)
            .cast::<u32>()
            .read_volatile();
        // Hold only the SDIO1 controller in SoC reset while the external clock
        // and pads are made coherent. IOMUX reset is a global GPIO reset, so
        // do not pulse it: that would also erase UART/GMAC pinmux state.
        reset.write_volatile(sdio_reset_before | VF2_SDIO1_RESET_MASK);
        (
            ahb_before,
            iomux_clock_before,
            ciu_before,
            sdio_reset_before,
            iomux_reset_before,
            sdio_status_before,
            iomux_status_before,
        )
    };
    fence(Ordering::SeqCst);

    let (ahb_after, iomux_clock_after, ciu_after) = unsafe {
        let ahb = crg.add(VF2_SYSCLK_SDIO1_AHB_OFFSET).cast::<u32>();
        let iomux_clock = crg.add(VF2_SYSCLK_IOMUX_APB_OFFSET).cast::<u32>();
        let ciu = crg.add(VF2_SYSCLK_SDIO1_SDCARD_OFFSET).cast::<u32>();
        let ahb_after = rmw_value(ahb_before, VF2_CRG_CLOCK_ENABLE, VF2_CRG_CLOCK_ENABLE);
        let iomux_clock_after = rmw_value(
            iomux_clock_before,
            VF2_CRG_CLOCK_ENABLE,
            VF2_CRG_CLOCK_ENABLE,
        );
        let ciu_after = rmw_value(
            ciu_before,
            VF2_CRG_CLOCK_ENABLE | VF2_CRG_CLOCK_DIV_MASK,
            VF2_CRG_CLOCK_ENABLE | VF2_SDIO1_CLOCK_DIVIDER,
        );
        ahb.write_volatile(ahb_after);
        iomux_clock.write_volatile(iomux_clock_after);
        ciu.write_volatile(ciu_after);
        (ahb_after, iomux_clock_after, ciu_after)
    };
    fence(Ordering::SeqCst);

    // The pinctrl block must be out of reset before its mux/pad registers are
    // touched. Clear a stale IOMUX reset without pulsing the global block.
    let iomux_reset_after = unsafe {
        let reset = crg.add(VF2_SYSRST_IOMUX_APB_OFFSET).cast::<u32>();
        let value = reset.read_volatile() & !VF2_SYSRST_IOMUX_APB_MASK;
        reset.write_volatile(value);
        value
    };
    axhal::time::busy_wait(VF2_RESET_SETTLE);
    let iomux_status_after = unsafe {
        wait_vf2_reset_deasserted(
            crg,
            VF2_SYSRST_IOMUX_APB_STATUS_OFFSET,
            VF2_SYSRST_IOMUX_APB_MASK,
        )
    };
    if iomux_status_after & VF2_SYSRST_IOMUX_APB_MASK != VF2_SYSRST_IOMUX_APB_MASK {
        error!(
            "JH7110 SD/MMC: VF2 IOMUX APB reset release timed out (status \
             {iomux_status_after:#010x})"
        );
        return false;
    }

    unsafe { configure_vf2_sdmmc_pins(pinctrl) };
    fence(Ordering::SeqCst);

    let sdio_reset_after = unsafe {
        let reset = crg.add(VF2_SYSRST_SDIO1_OFFSET).cast::<u32>();
        let value = reset.read_volatile() & !VF2_SDIO1_RESET_MASK;
        reset.write_volatile(value);
        value
    };
    fence(Ordering::SeqCst);
    axhal::time::busy_wait(VF2_RESET_SETTLE);
    let sdio_status_after = unsafe {
        wait_vf2_reset_deasserted(crg, VF2_SYSRST_SDIO1_STATUS_OFFSET, VF2_SDIO1_RESET_MASK)
    };

    info!(
        "JH7110 SD/MMC VF2 resources: AHB {ahb_before:#010x}->{ahb_after:#010x}, IOMUX clock \
         {iomux_clock_before:#010x}->{iomux_clock_after:#010x}, CIU \
         {ciu_before:#010x}->{ciu_after:#010x}, reset \
         {sdio_reset_before:#010x}->{sdio_reset_after:#010x}, IOMUX reset \
         {iomux_reset_before:#010x}->{iomux_reset_after:#010x}, status \
         {sdio_status_before:#010x}->{sdio_status_after:#010x}/{iomux_status_before:#\
         010x}->{iomux_status_after:#010x}"
    );
    if sdio_status_after & VF2_SDIO1_RESET_MASK != VF2_SDIO1_RESET_MASK {
        error!(
            "JH7110 SD/MMC: VF2 SDIO1 reset release timed out (status {sdio_status_after:#010x})"
        );
        return false;
    }
    true
}

/// Board wrapper around the serialized polling PIO controller.
pub(crate) struct Jh7110SdMmcDevice {
    device: Jh7110SdMmc,
}

pub(crate) fn probe() -> Option<Jh7110SdMmcDevice> {
    let paddr = axconfig::devices::SDMMC_PADDR;
    if !configure_vf2_sdmmc_resources(paddr) {
        error!("JH7110 SD/MMC: refusing to probe SDIO1 after resource initialization failure");
        return None;
    }
    let base = phys_to_virt(paddr.into()).as_usize();
    debug!("probing StarFive JH7110 SD/MMC at PA {paddr:#x}, polling PIO");
    let device = unsafe { Jh7110SdMmc::try_new(base) }
        .inspect_err(|error| error!("JH7110 SD/MMC initialization failed: {error:?}"))
        .ok()?;
    info!("JH7110 SD/MMC: using serialized polling PIO");
    Some(Jh7110SdMmcDevice { device })
}

impl BaseDriverOps for Jh7110SdMmcDevice {
    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }

    fn device_name(&self) -> &str {
        self.device.device_name()
    }
}

impl BlockDriverOps for Jh7110SdMmcDevice {
    fn num_blocks(&self) -> u64 {
        self.device.num_blocks()
    }

    fn block_size(&self) -> usize {
        self.device.block_size()
    }

    fn read_block(&mut self, block_id: u64, buf: &mut [u8]) -> DevResult {
        self.device.read_block(block_id, buf)
    }

    fn write_block(&mut self, block_id: u64, buf: &[u8]) -> DevResult {
        self.device.write_block(block_id, buf)
    }

    fn flush(&mut self) -> DevResult {
        self.device.flush()
    }
}

impl AsyncBlockDriverOps for Jh7110SdMmcDevice {
    type ReadFuture<'a>
        = <Jh7110SdMmc as AsyncBlockDriverOps>::ReadFuture<'a>
    where
        Self: 'a;
    type WriteFuture<'a>
        = <Jh7110SdMmc as AsyncBlockDriverOps>::WriteFuture<'a>
    where
        Self: 'a;
    type FlushFuture<'a>
        = <Jh7110SdMmc as AsyncBlockDriverOps>::FlushFuture<'a>
    where
        Self: 'a;

    fn read_block_async<'a>(&'a self, block_id: u64, buf: &'a mut [u8]) -> Self::ReadFuture<'a> {
        self.device.read_block_async(block_id, buf)
    }

    fn write_block_async<'a>(&'a self, block_id: u64, buf: &'a [u8]) -> Self::WriteFuture<'a> {
        self.device.write_block_async(block_id, buf)
    }

    fn flush_async(&self) -> Self::FlushFuture<'_> {
        self.device.flush_async()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vf2_resource_registers_match_jh7110_provider_ids() {
        assert_eq!(VF2_SYSCLK_IOMUX_APB_OFFSET, 0x1c0);
        assert_eq!(VF2_SYSCLK_SDIO1_AHB_OFFSET, 0x170);
        assert_eq!(VF2_SYSCLK_SDIO1_SDCARD_OFFSET, 0x178);
        assert_eq!(VF2_SYSRST_IOMUX_APB_OFFSET, 0x2f8);
        assert_eq!(VF2_SYSRST_IOMUX_APB_STATUS_OFFSET, 0x308);
        assert_eq!(VF2_SYSRST_SDIO1_OFFSET, 0x300);
        assert_eq!(VF2_SYSRST_SDIO1_STATUS_OFFSET, 0x310);
        assert_eq!(VF2_SYSRST_IOMUX_APB_MASK, 1 << 2);
        assert_eq!(VF2_SDIO1_CLOCK_DIVIDER, 8);
        assert_eq!(VF2_SDIO1_RESET_MASK, 1 << 1);
    }

    #[test]
    fn vf2_pinmux_matches_linux_mmc1_pins() {
        assert_eq!(vf2_pin_function_select(7), None);
        assert_eq!(vf2_pin_function_select(8), None);
        assert_eq!(vf2_pin_function_select(9), None);
        assert_eq!(vf2_pin_function_select(10), Some((0x29c, 2)));
        assert_eq!(vf2_pin_function_select(11), Some((0x29c, 5)));
        assert_eq!(vf2_pin_function_select(12), Some((0x29c, 8)));
        assert_eq!(VF2_SDIO1_PINS[0].dout, 55);
        assert_eq!(VF2_SDIO1_PINS[1].din, Some(44));
        assert_eq!(VF2_SDIO1_PINS[5].din, Some(48));
        assert_eq!(VF2_PADCFG_CLOCK, 0x0e);
        assert_eq!(VF2_PADCFG_DATA, 0x4f);
    }

    #[test]
    fn resource_rmw_preserves_unrelated_clock_bits() {
        assert_eq!(
            rmw_value(
                0xa500_0011,
                VF2_CRG_CLOCK_ENABLE | VF2_CRG_CLOCK_DIV_MASK,
                0x8000_0008
            ),
            0xa500_0008
        );
        assert_eq!(rmw_value(0xffff_ffff, 0x3 << 5, 0), 0xffff_ff9f);
    }
}
