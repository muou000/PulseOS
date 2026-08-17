//! TODO: generate registered drivers in `for_each_drivers!` automatically.

#[cfg(any(
    net_dev = "virtio-net",
    net_dev = "ixgbe",
    net_dev = "starfive-jh7110-dwmac",
    net_dev = "fxmac",
    net_dev = "dummy",
))]
macro_rules! register_net_driver {
    ($device_type:ty) => {
        /// The unified type of the NIC devices.
        #[cfg(not(feature = "dyn"))]
        pub type AxNetDevice = $device_type;
    };
}

#[cfg(any(
    block_dev = "virtio-blk",
    block_dev = "ramdisk",
    block_dev = "bcm2835-sdhci",
    block_dev = "starfive-jh7110-sdmmc",
    block_dev = "ls2k1000-ahci",
    block_dev = "dummy",
))]
macro_rules! register_block_driver {
    ($device_type:ty) => {
        /// The unified type of the block devices.
        #[cfg(not(feature = "dyn"))]
        pub type AxBlockDevice = $device_type;
    };
}

#[cfg(any(display_dev = "virtio-gpu", display_dev = "dummy"))]
macro_rules! register_display_driver {
    ($device_type:ty) => {
        /// The unified type of the display devices.
        #[cfg(not(feature = "dyn"))]
        pub type AxDisplayDevice = $device_type;
    };
}

macro_rules! for_each_drivers {
    (type $drv_type:ident, $code:block) => {{
        #[allow(unused_imports)]
        use crate::drivers::DriverProbe;
        #[cfg(feature = "virtio")]
        #[allow(unused_imports)]
        use crate::virtio::{self, VirtIoDevMeta};

        #[cfg(net_dev = "virtio-net")]
        {
            type $drv_type = <virtio::VirtIoNet as VirtIoDevMeta>::Driver;
            $code
        }
        #[cfg(block_dev = "virtio-blk")]
        {
            type $drv_type = <virtio::VirtIoBlk as VirtIoDevMeta>::Driver;
            $code
        }
        #[cfg(display_dev = "virtio-gpu")]
        {
            type $drv_type = <virtio::VirtIoGpu as VirtIoDevMeta>::Driver;
            $code
        }
        #[cfg(block_dev = "ramdisk")]
        {
            type $drv_type = crate::drivers::RamDiskDriver;
            $code
        }
        #[cfg(block_dev = "bcm2835-sdhci")]
        {
            type $drv_type = crate::drivers::BcmSdhciDriver;
            $code
        }
        #[cfg(block_dev = "starfive-jh7110-sdmmc")]
        {
            type $drv_type = crate::drivers::StarfiveJh7110SdMmcDriver;
            $code
        }
        #[cfg(block_dev = "ls2k1000-ahci")]
        {
            type $drv_type = crate::drivers::Ls2k1000AhciDriver;
            $code
        }
        #[cfg(net_dev = "ixgbe")]
        {
            type $drv_type = crate::drivers::IxgbeDriver;
            $code
        }
        #[cfg(net_dev = "starfive-jh7110-dwmac")]
        {
            type $drv_type = crate::drivers::StarfiveJh7110DwmacDriver;
            $code
        }
        #[cfg(net_dev = "fxmac")]
        {
            type $drv_type = crate::drivers::FXmacDriver;
            $code
        }
    }};
}
