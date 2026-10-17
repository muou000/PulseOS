//! [ArceOS](https://github.com/arceos-org/arceos) graphics module.
//!
//! Currently only supports direct writing to the framebuffer.

#![no_std]

#[macro_use]
extern crate log;

#[doc(no_inline)]
pub use axdriver_display::DisplayInfo;

use axdriver::{prelude::*, AxDeviceContainer};
use axsync::Mutex;
use lazyinit::LazyInit;

static MAIN_DISPLAY: LazyInit<Mutex<AxDisplayDevice>> = LazyInit::new();

/// Initializes the graphics subsystem by underlayer devices.
pub fn init_display(mut display_devs: AxDeviceContainer<AxDisplayDevice>) {
    info!("Initialize graphics subsystem...");

    let dev = display_devs.take_one().expect("No graphics device found!");
    info!("  use graphics device 0: {:?}", dev.device_name());
    let info = dev.info();
    info!(
        "  framebuffer: {}x{}, size: {:#x}, base: {:#x}",
        info.width, info.height, info.fb_size, info.fb_base_vaddr
    );
    MAIN_DISPLAY.init_once(Mutex::new(dev));

    #[cfg(feature = "smoke-test")]
    run_display_smoke_check();
}

/// Gets the framebuffer information.
pub fn framebuffer_info() -> DisplayInfo {
    MAIN_DISPLAY.lock().info()
}

/// Flushes the framebuffer, i.e. show on the screen.
pub fn framebuffer_flush() {
    MAIN_DISPLAY.lock().flush().unwrap();
}

/// Runs a framebuffer smoke check: verifies dimensions, writes a recognizable test pattern
/// via the [`FrameBuffer`] abstraction, and flushes to the screen.
#[cfg(feature = "smoke-test")]
pub fn run_display_smoke_check() {
    let mut display = MAIN_DISPLAY.lock();
    let info = display.info();
    assert!(info.width > 0, "display width must be nonzero");
    assert!(info.height > 0, "display height must be nonzero");
    assert!(info.fb_size > 0, "framebuffer size must be nonzero");
    assert!(
        info.fb_base_vaddr != 0,
        "framebuffer base virtual address must be valid"
    );

    let mut fb = display.fb();
    let half_w = info.width / 2;
    let half_h = info.height / 2;
    let pixel_count = (info.fb_size / 4).min((info.width * info.height) as usize);

    for y in 0..info.height {
        for x in 0..info.width {
            let idx = (y * info.width + x) as usize;
            if idx >= pixel_count {
                break;
            }
            let byte_offset = idx * 4;
            if byte_offset + 4 > fb.len() {
                break;
            }
            // VirtIO-GPU format is B8G8R8A8UNORM (opaque alpha = 0xFF)
            let color: u32 = if x < 4 || x + 4 >= info.width || y < 4 || y + 4 >= info.height {
                0xFF_FF_FF_FF // White (A=0xFF, R=0xFF, G=0xFF, B=0xFF)
            } else if x < half_w && y < half_h {
                0xFF_FF_00_00 // Red (A=0xFF, R=0xFF, G=0x00, B=0x00)
            } else if x >= half_w && y < half_h {
                0xFF_00_FF_00 // Green (A=0xFF, R=0x00, G=0xFF, B=0x00)
            } else if x < half_w && y >= half_h {
                0xFF_00_00_FF // Blue (A=0xFF, R=0x00, G=0x00, B=0xFF)
            } else {
                0xFF_FF_FF_00 // Yellow (A=0xFF, R=0xFF, G=0xFF, B=0x00)
            };
            fb[byte_offset..byte_offset + 4].copy_from_slice(&color.to_le_bytes());
        }
    }

    display.flush().expect("failed to flush framebuffer");
    info!("Display smoke check: test pattern written via FrameBuffer and flushed successfully.");
}
