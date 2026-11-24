//! Defines types and probe methods of all supported devices.

#[cfg(bus = "pci")]
use axdriver_pci::{DeviceFunction, DeviceFunctionInfo, PciRoot};

#[cfg(any(net_dev = "dummy", block_dev = "dummy", display_dev = "dummy",))]
pub use super::dummy::*;
use crate::AxDeviceEnum;

pub trait DriverProbe {
    fn probe_global() -> Option<AxDeviceEnum> {
        None
    }

    #[cfg(bus = "mmio")]
    fn probe_mmio(_mmio_base: usize, _mmio_size: usize) -> Option<AxDeviceEnum> {
        None
    }

    #[cfg(bus = "pci")]
    fn probe_pci(
        _root: &mut PciRoot,
        _bdf: DeviceFunction,
        _dev_info: &DeviceFunctionInfo,
    ) -> Option<AxDeviceEnum> {
        None
    }
}

#[cfg(net_dev = "virtio-net")]
register_net_driver!(<crate::virtio::VirtIoNet as crate::virtio::VirtIoDevMeta>::Device);

#[cfg(block_dev = "virtio-blk")]
register_block_driver!(<crate::virtio::VirtIoBlk as crate::virtio::VirtIoDevMeta>::Device);

#[cfg(display_dev = "virtio-gpu")]
register_display_driver!(<crate::virtio::VirtIoGpu as crate::virtio::VirtIoDevMeta>::Device);

cfg_if::cfg_if! {
    if #[cfg(block_dev = "ramdisk")] {
        pub struct RamDiskDriver;
        register_block_driver!(axdriver_block::ramdisk::RamDisk);

        impl DriverProbe for RamDiskDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                // TODO: format RAM disk
                Some(AxDeviceEnum::from_block(
                    axdriver_block::ramdisk::RamDisk::new(0x100_0000), // 16 MiB
                ))
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(block_dev = "bcm2835-sdhci")]{
        pub struct BcmSdhciDriver;
        register_block_driver!(axdriver_block::bcm2835sdhci::SDHCIDriver);

        impl DriverProbe for BcmSdhciDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                debug!("mmc probe");
                axdriver_block::bcm2835sdhci::SDHCIDriver::try_new().ok().map(AxDeviceEnum::from_block)
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(block_dev = "starfive-jh7110-sdmmc")] {
        pub struct StarfiveJh7110SdMmcDriver;
        register_block_driver!(
            crate::starfive_jh7110_sdmmc::Jh7110SdMmcDevice
        );

        impl DriverProbe for StarfiveJh7110SdMmcDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                crate::starfive_jh7110_sdmmc::probe()
                    .map(AxDeviceEnum::from_block)
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(block_dev = "ls2k1000-ahci")] {
        pub struct Ls2k1000AhciDriver;
        register_block_driver!(
            axdriver_block::ls2k1000_ahci::Ls2k1000Ahci
        );

        impl DriverProbe for Ls2k1000AhciDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                let base: usize = hal::mem::phys_to_virt(
                    config::devices::AHCI_PADDR.into(),
                )
                .into();
                debug!(
                    "probing LS2K1000 AHCI at PA {:#x}",
                    config::devices::AHCI_PADDR
                );
                unsafe { axdriver_block::ls2k1000_ahci::Ls2k1000Ahci::try_new(base) }
                    .ok()
                    .map(AxDeviceEnum::from_block)
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(net_dev = "starfive-jh7110-dwmac")] {
        pub struct StarfiveJh7110DwmacDriver;
        register_net_driver!(
            crate::starfive_jh7110::Jh7110DwmacDevice
        );

        impl DriverProbe for StarfiveJh7110DwmacDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                crate::starfive_jh7110::probe().map(AxDeviceEnum::from_net)
            }
        }
    }
}
