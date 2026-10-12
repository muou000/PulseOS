# axplat-riscv64-visionfive2

PulseOS platform implementation for the StarFive VisionFive 2 (JH7110).

The crate shares PulseOS's FDT-driven RISC-V SBI/PLIC implementation with the
QEMU virt platform, but makes the board contract explicit: U-Boot/OpenSBI must
pass a live VisionFive 2 DTB in `a1`. The DTB supplies the enabled U74 harts,
actual RAM regions, reserved ranges, and PLIC supervisor contexts.

The initial path reuses U-Boot's UART0 setup and accesses the DW APB UART by
MMIO, while timer, IPI, CPU boot, and reset use SBI services. It provides PLIC
initialization and SMP across U74 hart IDs 1 through 4. The topology parser
rejects the S7 management hart at ID 0 even when U-Boot's control DTB marks it
as available. The PulseOS driver layer separately provides a serialized
polling driver for the JH7110 SDIO1 microSD slot. Ethernet, PCIe, USB, and RTC
drivers remain outside this crate's initial scope.
