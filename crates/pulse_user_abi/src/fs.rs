//! File metadata and ioctl output representations.

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
use linux_raw_sys::ctypes::{c_long, c_ulong};
use linux_raw_sys::{
    ctypes::{c_int, c_uint},
    general::{
        __kernel_fsid_t, __kernel_long_t, __kernel_ulong_t, __s32, __s64, __u16, __u32, __u64,
        stat, statfs, statx, statx_timestamp,
    },
};

/// Linux HDIO_GETGEO output, including its zeroed alignment gap.
#[repr(C)]
pub struct HdGeometry {
    pub heads: u8,
    pub sectors: u8,
    pub cylinders: u16,
    pub start: u64,
}

/// Linux RTC_RD_TIME output.
#[repr(C)]
pub struct RtcTime {
    pub tm_sec: i32,
    pub tm_min: i32,
    pub tm_hour: i32,
    pub tm_mday: i32,
    pub tm_mon: i32,
    pub tm_year: i32,
    pub tm_wday: i32,
    pub tm_yday: i32,
    pub tm_isdst: i32,
}

/// Fixed 19-byte prefix of a Linux `getdents64` record. The name and alignment
/// bytes follow this prefix and are encoded by the directory iterator.
pub struct Dirent64Header {
    pub ino: u64,
    pub offset: i64,
    pub record_len: u16,
    pub file_type: u8,
}

impl crate::UserAbiType for Dirent64Header {
    type Buffer = [u8; 19];
}

impl crate::IntoUserAbi for Dirent64Header {
    fn encode_abi(&self, writer: &mut crate::AbiWriter<'_>) {
        writer.write(&self.ino);
        writer.write(&self.offset);
        writer.write(&self.record_len);
        writer.write(&self.file_type);
    }
}

crate::impl_user_abi_fixed_array!(i64, 3);
crate::impl_user_abi_fixed_array!(i64, 4);
crate::impl_user_abi_fixed_array!(u16, 1);
crate::impl_user_abi_fixed_array!(u32, 1);
crate::impl_user_abi_fixed_array!(u64, 8);

crate::impl_user_abi_struct! {
    for __kernel_fsid_t, size = 8 => {
        val: [c_int; 2usize],
    }
}

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
crate::impl_user_abi_struct! {
    for stat, size = 128 => {
        st_dev: c_ulong,
        st_ino: c_ulong,
        st_mode: c_uint,
        st_nlink: c_uint,
        st_uid: c_uint,
        st_gid: c_uint,
        st_rdev: c_ulong,
        __pad1: c_ulong,
        st_size: c_long,
        st_blksize: c_int,
        __pad2: c_int,
        st_blocks: c_long,
        st_atime: c_long,
        st_atime_nsec: c_ulong,
        st_mtime: c_long,
        st_mtime_nsec: c_ulong,
        st_ctime: c_long,
        st_ctime_nsec: c_ulong,
        __unused4: c_uint,
        __unused5: c_uint,
    }
}

#[cfg(target_arch = "x86_64")]
crate::impl_user_abi_struct! {
    for stat, size = 144 => {
        st_dev: __kernel_ulong_t,
        st_ino: __kernel_ulong_t,
        st_nlink: __kernel_ulong_t,
        st_mode: c_uint,
        st_uid: c_uint,
        st_gid: c_uint,
        __pad0: c_uint,
        st_rdev: __kernel_ulong_t,
        st_size: __kernel_long_t,
        st_blksize: __kernel_long_t,
        st_blocks: __kernel_long_t,
        st_atime: __kernel_ulong_t,
        st_atime_nsec: __kernel_ulong_t,
        st_mtime: __kernel_ulong_t,
        st_mtime_nsec: __kernel_ulong_t,
        st_ctime: __kernel_ulong_t,
        st_ctime_nsec: __kernel_ulong_t,
        __unused: [__kernel_long_t; 3usize],
    }
}

crate::impl_user_abi_struct! {
    for statfs, size = 120 => {
        f_type: __kernel_long_t,
        f_bsize: __kernel_long_t,
        f_blocks: __kernel_long_t,
        f_bfree: __kernel_long_t,
        f_bavail: __kernel_long_t,
        f_files: __kernel_long_t,
        f_ffree: __kernel_long_t,
        f_fsid: __kernel_fsid_t,
        f_namelen: __kernel_long_t,
        f_frsize: __kernel_long_t,
        f_flags: __kernel_long_t,
        f_spare: [__kernel_long_t; 4usize],
    }
}

crate::impl_user_abi_struct! {
    for statx_timestamp, size = 16 => {
        tv_sec: __s64,
        tv_nsec: __u32,
        __reserved: __s32,
    }
}

crate::impl_user_abi_struct! {
    for statx, size = 256 => {
        stx_mask: __u32,
        stx_blksize: __u32,
        stx_attributes: __u64,
        stx_nlink: __u32,
        stx_uid: __u32,
        stx_gid: __u32,
        stx_mode: __u16,
        __spare0: [__u16; 1usize],
        stx_ino: __u64,
        stx_size: __u64,
        stx_blocks: __u64,
        stx_attributes_mask: __u64,
        stx_atime: statx_timestamp,
        stx_btime: statx_timestamp,
        stx_ctime: statx_timestamp,
        stx_mtime: statx_timestamp,
        stx_rdev_major: __u32,
        stx_rdev_minor: __u32,
        stx_dev_major: __u32,
        stx_dev_minor: __u32,
        stx_mnt_id: __u64,
        stx_dio_mem_align: __u32,
        stx_dio_offset_align: __u32,
        stx_subvol: __u64,
        stx_atomic_write_unit_min: __u32,
        stx_atomic_write_unit_max: __u32,
        stx_atomic_write_segments_max: __u32,
        stx_dio_read_offset_align: __u32,
        stx_atomic_write_unit_max_opt: __u32,
        __spare2: [__u32; 1usize],
        __spare3: [__u64; 8usize],
    }
}

crate::impl_user_abi_struct! {
    for HdGeometry, size = 16 => {
        heads: u8,
        sectors: u8,
        cylinders: u16,
        start: u64,
    }
}

crate::impl_user_abi_struct! {
    for RtcTime, size = 36 => {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        tm_mday: i32,
        tm_mon: i32,
        tm_year: i32,
        tm_wday: i32,
        tm_yday: i32,
        tm_isdst: i32,
    }
}

crate::impl_user_abi_struct! {
    for linux_raw_sys::general::termios, size = 36 => {
        c_iflag: u32,
        c_oflag: u32,
        c_cflag: u32,
        c_lflag: u32,
        c_line: u8,
        c_cc: [u8; 19],
    }
}

crate::impl_user_abi_struct! {
    for linux_raw_sys::general::termios2, size = 44 => {
        c_iflag: u32,
        c_oflag: u32,
        c_cflag: u32,
        c_lflag: u32,
        c_line: u8,
        c_cc: [u8; 19],
        c_ispeed: u32,
        c_ospeed: u32,
    }
}

#[cfg(test)]
mod tests {
    use axerrno::AxError;

    #[test]
    fn terminal_output_encodes_control_bytes_and_speeds_at_linux_offsets() {
        let term = linux_raw_sys::general::termios2 {
            c_iflag: 1,
            c_oflag: 2,
            c_cflag: 3,
            c_lflag: 4,
            c_line: 5,
            c_cc: [6; 19],
            c_ispeed: 9600,
            c_ospeed: 115200,
        };
        let bytes = encode_to_buffer(&term);
        assert_eq!(bytes.len(), 44);
        assert_eq!(&bytes[..4], &1u32.to_ne_bytes());
        assert_eq!(&bytes[4..8], &2u32.to_ne_bytes());
        assert_eq!(&bytes[8..12], &3u32.to_ne_bytes());
        assert_eq!(&bytes[12..16], &4u32.to_ne_bytes());
        assert_eq!(bytes[16], 5);
        assert_eq!(&bytes[17..36], &[6; 19]);
        assert_eq!(&bytes[36..40], &9600u32.to_ne_bytes());
        assert_eq!(&bytes[40..44], &115200u32.to_ne_bytes());
    }

    use super::*;
    use crate::{encode_to_buffer, write_user_value_with};

    #[test]
    fn directory_header_is_exactly_nineteen_native_order_bytes() {
        let header = Dirent64Header {
            ino: 0x1122_3344_5566_7788,
            offset: -2,
            record_len: 32,
            file_type: 8,
        };
        let bytes = encode_to_buffer(&header);
        assert_eq!(bytes.len(), 19);
        assert_eq!(&bytes[..8], &0x1122_3344_5566_7788u64.to_ne_bytes());
        assert_eq!(&bytes[8..16], &(-2i64).to_ne_bytes());
        assert_eq!(&bytes[16..18], &32u16.to_ne_bytes());
        assert_eq!(bytes[18], 8);
    }

    #[test]
    fn disk_geometry_output_zeroes_padding_and_preserves_every_short_prefix() {
        let geometry = HdGeometry {
            heads: 255,
            sectors: 63,
            cylinders: 0x1234,
            start: 0x1122_3344_5566_7788,
        };
        let mut expected = [0u8; 16];
        expected[..2].copy_from_slice(&[255, 63]);
        expected[2..4].copy_from_slice(&0x1234u16.to_ne_bytes());
        expected[8..16].copy_from_slice(&0x1122_3344_5566_7788u64.to_ne_bytes());
        assert_eq!(encode_to_buffer(&geometry), expected);
        for copied in 0..=16 {
            let mut dst = [0xa5; 16];
            let result = write_user_value_with(0x4000, &geometry, |addr, bytes| {
                assert_eq!(addr, 0x4000);
                dst[..copied].copy_from_slice(&bytes[..copied]);
                Ok(copied)
            });
            assert_eq!(
                result,
                if copied == 16 {
                    Ok(())
                } else {
                    Err(AxError::BadAddress)
                }
            );
            assert_eq!(&dst[..copied], &expected[..copied]);
            assert!(dst[copied..].iter().all(|byte| *byte == 0xa5));
        }
    }
}
