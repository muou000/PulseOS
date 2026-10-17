//! Common traits and types for graphics display device drivers.

#![no_std]

#[cfg(test)]
extern crate std;

use core::ops::{Deref, DerefMut};

#[doc(no_inline)]
pub use axdriver_base::{BaseDriverOps, DevError, DevResult, DeviceType};

/// The information of the graphics device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayInfo {
    /// The visible width in pixels.
    pub width: u32,
    /// The visible height in pixels.
    pub height: u32,
    /// The base virtual address of the framebuffer.
    pub fb_base_vaddr: usize,
    /// The size of the framebuffer in bytes.
    pub fb_size: usize,
}

/// The framebuffer.
///
/// It's a special memory buffer that mapped from the device memory.
pub struct FrameBuffer<'a> {
    raw: &'a mut [u8],
}

impl<'a> FrameBuffer<'a> {
    /// Use the given raw pointer and size as the framebuffer.
    ///
    /// # Safety
    ///
    /// Caller must ensure that the given memory region is valid and accessible.
    pub unsafe fn from_raw_parts_mut(ptr: *mut u8, len: usize) -> Self {
        Self {
            raw: unsafe { core::slice::from_raw_parts_mut(ptr, len) },
        }
    }

    /// Use the given slice as the framebuffer.
    pub fn from_slice(slice: &'a mut [u8]) -> Self {
        Self { raw: slice }
    }

    /// Returns the framebuffer slice as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.raw
    }

    /// Returns the framebuffer slice as a mutable byte slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.raw
    }
}

impl<'a> Deref for FrameBuffer<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.raw
    }
}

impl<'a> DerefMut for FrameBuffer<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.raw
    }
}

/// Operations that require a graphics device driver to implement.
pub trait DisplayDriverOps: BaseDriverOps {
    /// Get the display information.
    fn info(&self) -> DisplayInfo;

    /// Get the framebuffer.
    fn fb(&self) -> FrameBuffer<'_>;

    /// Whether need to flush the framebuffer to the screen.
    fn need_flush(&self) -> bool;

    /// Flush framebuffer to the screen.
    fn flush(&mut self) -> DevResult;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockGpuDriver {
        info: DisplayInfo,
        buffer: [u8; 16],
        flush_count: usize,
    }

    impl MockGpuDriver {
        fn new() -> Self {
            Self {
                info: DisplayInfo {
                    width: 2,
                    height: 2,
                    fb_base_vaddr: 0x1000,
                    fb_size: 16,
                },
                buffer: [0u8; 16],
                flush_count: 0,
            }
        }
    }

    impl BaseDriverOps for MockGpuDriver {
        fn device_name(&self) -> &str {
            "mock-gpu"
        }

        fn device_type(&self) -> DeviceType {
            DeviceType::Display
        }
    }

    impl DisplayDriverOps for MockGpuDriver {
        fn info(&self) -> DisplayInfo {
            self.info
        }

        fn fb(&self) -> FrameBuffer<'_> {
            FrameBuffer::from_slice(unsafe {
                let ptr = self.buffer.as_ptr() as *mut u8;
                core::slice::from_raw_parts_mut(ptr, self.buffer.len())
            })
        }

        fn need_flush(&self) -> bool {
            true
        }

        fn flush(&mut self) -> DevResult {
            self.flush_count += 1;
            Ok(())
        }
    }

    #[test]
    fn test_display_info() {
        let info = DisplayInfo {
            width: 1024,
            height: 768,
            fb_base_vaddr: 0x8000_0000,
            fb_size: 1024 * 768 * 4,
        };
        assert_eq!(info.width, 1024);
        assert_eq!(info.height, 768);
        assert_eq!(info.fb_size, 3_145_728);
    }

    #[test]
    fn test_framebuffer_deref() {
        let mut buf = [0u8; 8];
        let mut fb = FrameBuffer::from_slice(&mut buf);
        assert_eq!(fb.len(), 8);
        fb[0] = 0xAA;
        fb[7] = 0x55;
        assert_eq!(fb[0], 0xAA);
        assert_eq!(fb[7], 0x55);
        assert_eq!(fb.as_slice(), &[0xAA, 0, 0, 0, 0, 0, 0, 0x55]);
    }

    #[test]
    fn test_mock_gpu_driver_ops() {
        let mut dev = MockGpuDriver::new();
        assert_eq!(dev.device_name(), "mock-gpu");
        assert_eq!(dev.device_type(), DeviceType::Display);
        assert!(dev.need_flush());
        assert_eq!(dev.info().width, 2);
        assert_eq!(dev.info().height, 2);

        let mut fb = dev.fb();
        fb[0] = 42;
        assert_eq!(dev.buffer[0], 42);

        assert_eq!(dev.flush_count, 0);
        assert!(dev.flush().is_ok());
        assert_eq!(dev.flush_count, 1);
    }
}

