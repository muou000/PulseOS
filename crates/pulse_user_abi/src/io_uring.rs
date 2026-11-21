//! Validity-safe user ABI codecs for Linux `io_uring` structures.

use core::mem::{offset_of, size_of};

use linux_raw_sys::ctypes::c_longlong;
use linux_raw_sys::io_uring::{
    __IncompleteArrayField, __kernel_time64_t, __kernel_timespec, __s32, __u8, __u16, __u32,
    __u64, io_cqring_offsets, io_sqring_offsets, io_uring_cqe, io_uring_files_update,
    io_uring_getevents_arg, io_uring_params, io_uring_probe, io_uring_probe_op,
    io_uring_rsrc_update, io_uring_sqe, io_uring_sqe__bindgen_ty_1, io_uring_sqe__bindgen_ty_2,
    io_uring_sqe__bindgen_ty_3, io_uring_sqe__bindgen_ty_4, io_uring_sqe__bindgen_ty_5,
    io_uring_sqe__bindgen_ty_6, io_uring_sqe_flags_bit,
};

pub const IOSQE_FIXED_FILE: u8 = 1 << (io_uring_sqe_flags_bit::IOSQE_FIXED_FILE_BIT as u8);
pub const IOSQE_IO_DRAIN: u8 = 1 << (io_uring_sqe_flags_bit::IOSQE_IO_DRAIN_BIT as u8);
pub const IOSQE_IO_LINK: u8 = 1 << (io_uring_sqe_flags_bit::IOSQE_IO_LINK_BIT as u8);
pub const IOSQE_IO_HARDLINK: u8 = 1 << (io_uring_sqe_flags_bit::IOSQE_IO_HARDLINK_BIT as u8);
pub const IOSQE_ASYNC: u8 = 1 << (io_uring_sqe_flags_bit::IOSQE_ASYNC_BIT as u8);
pub const IOSQE_BUFFER_SELECT: u8 = 1 << (io_uring_sqe_flags_bit::IOSQE_BUFFER_SELECT_BIT as u8);
pub const IOSQE_CQE_SKIP_SUCCESS: u8 =
    1 << (io_uring_sqe_flags_bit::IOSQE_CQE_SKIP_SUCCESS_BIT as u8);

pub use linux_raw_sys::general::{RWF_APPEND, RWF_DSYNC, RWF_HIPRI, RWF_NOWAIT, RWF_SYNC};
pub use linux_raw_sys::io_uring::{
    IORING_ASYNC_CANCEL_ALL, IORING_ASYNC_CANCEL_ANY, IORING_ASYNC_CANCEL_FD,
    IORING_ASYNC_CANCEL_FD_FIXED, IORING_FSYNC_DATASYNC, IORING_LINK_TIMEOUT_UPDATE as IORING_TIMEOUT_LINK,
    IORING_TIMEOUT_ABS, IORING_TIMEOUT_BOOTTIME, IORING_TIMEOUT_CLOCK_MASK,
    IORING_TIMEOUT_ETIME_SUCCESS, IORING_TIMEOUT_MULTISHOT, IORING_TIMEOUT_REALTIME,
    IORING_TIMEOUT_UPDATE, IORING_TIMEOUT_UPDATE_MASK, SYNC_FILE_RANGE_WAIT_AFTER,
    SYNC_FILE_RANGE_WAIT_BEFORE, SYNC_FILE_RANGE_WRITE,
};

use crate::{
    AbiDecodeError, AbiReader, AbiWriter, FromUserAbi, IntoUserAbi, UserAbiType, decode_field_at,
    encode_field_at,
};

/// Flat, union-free representation of a Linux `io_uring_sqe` (64 bytes).
///
/// Linux `io_uring_sqe` uses raw C unions; Rust cannot read union fields in
/// `#![forbid(unsafe_code)]`, so this flat representation exposes all 64 bytes
/// as naturally aligned integer fields for safe encoding/decoding and copying.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoUringSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub op_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: u32,
    pub addr3: u64,
    pub pad2: u64,
}

/// Flat representation of a standard 16-byte Linux `io_uring_cqe`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoUringCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

crate::impl_user_abi_struct! {
    for io_sqring_offsets, size = 40 => {
        head: __u32,
        tail: __u32,
        ring_mask: __u32,
        ring_entries: __u32,
        flags: __u32,
        dropped: __u32,
        array: __u32,
        resv1: __u32,
        user_addr: __u64,
    }
}

crate::impl_user_abi_struct! {
    for io_cqring_offsets, size = 40 => {
        head: __u32,
        tail: __u32,
        ring_mask: __u32,
        ring_entries: __u32,
        overflow: __u32,
        cqes: __u32,
        flags: __u32,
        resv1: __u32,
        user_addr: __u64,
    }
}

crate::impl_user_abi_struct! {
    for io_uring_params, size = 120 => {
        sq_entries: __u32,
        cq_entries: __u32,
        flags: __u32,
        sq_thread_cpu: __u32,
        sq_thread_idle: __u32,
        features: __u32,
        wq_fd: __u32,
        resv: [__u32; 3],
        sq_off: io_sqring_offsets,
        cq_off: io_cqring_offsets,
    }
}

crate::impl_user_abi_struct! {
    for io_uring_getevents_arg, size = 24 => {
        sigmask: __u64,
        sigmask_sz: __u32,
        min_wait_usec: __u32,
        ts: __u64,
    }
}

crate::impl_user_abi_struct! {
    for __kernel_timespec, size = 16 => {
        tv_sec: __kernel_time64_t,
        tv_nsec: c_longlong,
    }
}

crate::impl_user_abi_struct! {
    for io_uring_rsrc_update, size = 16 => {
        offset: __u32,
        resv: __u32,
        data: __u64,
    }
}

crate::impl_user_abi_struct! {
    for io_uring_files_update, size = 16 => {
        offset: __u32,
        resv: __u32,
        fds: __u64,
    }
}

crate::impl_user_abi_struct! {
    for io_uring_probe_op, size = 8 => {
        op: __u8,
        resv: __u8,
        flags: __u16,
        resv2: __u32,
    }
}

crate::impl_user_abi_struct! {
    for IoUringCqe, size = 16 => {
        user_data: u64,
        res: i32,
        flags: u32,
    }
}

crate::impl_user_abi_struct! {
    for IoUringSqe, size = 64 => {
        opcode: u8,
        flags: u8,
        ioprio: u16,
        fd: i32,
        off: u64,
        addr: u64,
        len: u32,
        op_flags: u32,
        user_data: u64,
        buf_index: u16,
        personality: u16,
        splice_fd_in: u32,
        addr3: u64,
        pad2: u64,
    }
}

const _: () = {
    assert!(size_of::<io_uring_params>() == 120);
    assert!(offset_of!(io_uring_params, sq_off) == 40);
    assert!(offset_of!(io_uring_params, cq_off) == 80);

    assert!(size_of::<io_uring_probe>() == 16);
    assert!(offset_of!(io_uring_probe, last_op) == 0);
    assert!(offset_of!(io_uring_probe, ops_len) == 1);
    assert!(offset_of!(io_uring_probe, resv) == 2);
    assert!(offset_of!(io_uring_probe, resv2) == 4);
    assert!(offset_of!(io_uring_probe, ops) == 16);

    assert!(size_of::<io_uring_cqe>() == 16);
    assert!(offset_of!(io_uring_cqe, user_data) == 0);
    assert!(offset_of!(io_uring_cqe, res) == 8);
    assert!(offset_of!(io_uring_cqe, flags) == 12);
    assert!(offset_of!(io_uring_cqe, big_cqe) == 16);

    assert!(size_of::<io_uring_sqe>() == 64);
    assert!(offset_of!(io_uring_sqe, opcode) == offset_of!(IoUringSqe, opcode));
    assert!(offset_of!(io_uring_sqe, flags) == offset_of!(IoUringSqe, flags));
    assert!(offset_of!(io_uring_sqe, ioprio) == offset_of!(IoUringSqe, ioprio));
    assert!(offset_of!(io_uring_sqe, fd) == offset_of!(IoUringSqe, fd));
    assert!(offset_of!(io_uring_sqe, __bindgen_anon_1) == offset_of!(IoUringSqe, off));
    assert!(offset_of!(io_uring_sqe, __bindgen_anon_2) == offset_of!(IoUringSqe, addr));
    assert!(offset_of!(io_uring_sqe, len) == offset_of!(IoUringSqe, len));
    assert!(offset_of!(io_uring_sqe, __bindgen_anon_3) == offset_of!(IoUringSqe, op_flags));
    assert!(offset_of!(io_uring_sqe, user_data) == offset_of!(IoUringSqe, user_data));
    assert!(offset_of!(io_uring_sqe, __bindgen_anon_4) == offset_of!(IoUringSqe, buf_index));
    assert!(offset_of!(io_uring_sqe, personality) == offset_of!(IoUringSqe, personality));
    assert!(offset_of!(io_uring_sqe, __bindgen_anon_5) == offset_of!(IoUringSqe, splice_fd_in));
    assert!(offset_of!(io_uring_sqe, __bindgen_anon_6) == offset_of!(IoUringSqe, addr3));
};

impl UserAbiType for io_uring_probe {
    type Buffer = [u8; 16];
}

impl FromUserAbi for io_uring_probe {
    fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
        let raw = reader.take_exact(16)?;
        Ok(Self {
            last_op: decode_field_at::<__u8>(raw, offset_of!(Self, last_op))?,
            ops_len: decode_field_at::<__u8>(raw, offset_of!(Self, ops_len))?,
            resv: decode_field_at::<__u16>(raw, offset_of!(Self, resv))?,
            resv2: decode_field_at::<[__u32; 3]>(raw, offset_of!(Self, resv2))?,
            ops: __IncompleteArrayField::new(),
        })
    }
}

impl IntoUserAbi for io_uring_probe {
    fn encode_abi(&self, writer: &mut AbiWriter<'_>) {
        let dst = writer.take_exact_mut(16);
        dst.fill(0);
        encode_field_at::<__u8>(dst, offset_of!(Self, last_op), &self.last_op);
        encode_field_at::<__u8>(dst, offset_of!(Self, ops_len), &self.ops_len);
        encode_field_at::<__u16>(dst, offset_of!(Self, resv), &self.resv);
        encode_field_at::<[__u32; 3]>(dst, offset_of!(Self, resv2), &self.resv2);
    }
}

impl UserAbiType for io_uring_cqe {
    type Buffer = [u8; 16];
}

impl FromUserAbi for io_uring_cqe {
    fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
        let raw = reader.take_exact(16)?;
        Ok(Self {
            user_data: decode_field_at::<__u64>(raw, offset_of!(Self, user_data))?,
            res: decode_field_at::<__s32>(raw, offset_of!(Self, res))?,
            flags: decode_field_at::<__u32>(raw, offset_of!(Self, flags))?,
            big_cqe: __IncompleteArrayField::new(),
        })
    }
}

impl IntoUserAbi for io_uring_cqe {
    fn encode_abi(&self, writer: &mut AbiWriter<'_>) {
        let dst = writer.take_exact_mut(16);
        dst.fill(0);
        encode_field_at::<__u64>(dst, offset_of!(Self, user_data), &self.user_data);
        encode_field_at::<__s32>(dst, offset_of!(Self, res), &self.res);
        encode_field_at::<__u32>(dst, offset_of!(Self, flags), &self.flags);
    }
}

impl UserAbiType for io_uring_sqe {
    type Buffer = [u8; 64];
}

impl FromUserAbi for io_uring_sqe {
    fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
        let flat = IoUringSqe::decode_abi(reader)?;
        Ok(Self::from(&flat))
    }
}

impl From<&IoUringSqe> for io_uring_sqe {
    fn from(flat: &IoUringSqe) -> Self {
        Self {
            opcode: flat.opcode,
            flags: flat.flags,
            ioprio: flat.ioprio,
            fd: flat.fd,
            __bindgen_anon_1: io_uring_sqe__bindgen_ty_1 { off: flat.off },
            __bindgen_anon_2: io_uring_sqe__bindgen_ty_2 { addr: flat.addr },
            len: flat.len,
            __bindgen_anon_3: io_uring_sqe__bindgen_ty_3 {
                rw_flags: flat.op_flags,
            },
            user_data: flat.user_data,
            __bindgen_anon_4: io_uring_sqe__bindgen_ty_4 {
                buf_index: flat.buf_index,
            },
            personality: flat.personality,
            __bindgen_anon_5: io_uring_sqe__bindgen_ty_5 {
                file_index: flat.splice_fd_in,
            },
            __bindgen_anon_6: io_uring_sqe__bindgen_ty_6 {
                __bindgen_anon_1: linux_raw_sys::io_uring::__BindgenUnionField::new(),
                __bindgen_anon_2: linux_raw_sys::io_uring::__BindgenUnionField::new(),
                optval: linux_raw_sys::io_uring::__BindgenUnionField::new(),
                cmd: linux_raw_sys::io_uring::__BindgenUnionField::new(),
                bindgen_union_field: [flat.addr3, flat.pad2],
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{offset_of, size_of};

    use axerrno::AxError;
    use linux_raw_sys::io_uring::{
        __IncompleteArrayField, __kernel_timespec, io_cqring_offsets, io_sqring_offsets,
        io_uring_cqe, io_uring_files_update, io_uring_getevents_arg, io_uring_params,
        io_uring_probe, io_uring_probe_op, io_uring_rsrc_update, io_uring_sqe,
    };

    use super::{IoUringCqe, IoUringSqe};
    use crate::{
        abi_size_of, decode_from_bytes, encode_into_slice, encode_to_buffer, read_user_value_with,
    };

    #[test]
    fn io_uring_abi_sizes_and_offsets_match_linux_uapi() {
        assert_eq!(size_of::<io_sqring_offsets>(), 40);
        assert_eq!(abi_size_of::<io_sqring_offsets>(), 40);
        assert_eq!(size_of::<io_cqring_offsets>(), 40);
        assert_eq!(abi_size_of::<io_cqring_offsets>(), 40);
        assert_eq!(size_of::<io_uring_params>(), 120);
        assert_eq!(abi_size_of::<io_uring_params>(), 120);
        assert_eq!(offset_of!(io_uring_params, sq_off), 40);
        assert_eq!(offset_of!(io_uring_params, cq_off), 80);
        assert_eq!(size_of::<io_uring_getevents_arg>(), 24);
        assert_eq!(abi_size_of::<io_uring_getevents_arg>(), 24);
        assert_eq!(size_of::<__kernel_timespec>(), 16);
        assert_eq!(abi_size_of::<__kernel_timespec>(), 16);
        assert_eq!(size_of::<io_uring_rsrc_update>(), 16);
        assert_eq!(abi_size_of::<io_uring_rsrc_update>(), 16);
        assert_eq!(size_of::<io_uring_files_update>(), 16);
        assert_eq!(abi_size_of::<io_uring_files_update>(), 16);
        assert_eq!(size_of::<io_uring_probe_op>(), 8);
        assert_eq!(abi_size_of::<io_uring_probe_op>(), 8);
        assert_eq!(size_of::<io_uring_probe>(), 16);
        assert_eq!(abi_size_of::<io_uring_probe>(), 16);
        assert_eq!(size_of::<io_uring_cqe>(), 16);
        assert_eq!(abi_size_of::<io_uring_cqe>(), 16);
        assert_eq!(size_of::<IoUringCqe>(), 16);
        assert_eq!(abi_size_of::<IoUringCqe>(), 16);
        assert_eq!(size_of::<io_uring_sqe>(), 64);
        assert_eq!(abi_size_of::<io_uring_sqe>(), 64);
        assert_eq!(size_of::<IoUringSqe>(), 64);
        assert_eq!(abi_size_of::<IoUringSqe>(), 64);
    }

    #[test]
    fn io_uring_params_roundtrip_zeroes_output_buffer() {
        let params = io_uring_params {
            sq_entries: 16,
            cq_entries: 32,
            flags: 0x20,
            sq_thread_cpu: 1,
            sq_thread_idle: 50,
            features: 0x1bf,
            wq_fd: 0,
            resv: [0; 3],
            sq_off: io_sqring_offsets {
                head: 0,
                tail: 64,
                ring_mask: 128,
                ring_entries: 132,
                flags: 136,
                dropped: 140,
                array: 256,
                resv1: 0,
                user_addr: 0xdead_beef,
            },
            cq_off: io_cqring_offsets {
                head: 4,
                tail: 68,
                ring_mask: 144,
                ring_entries: 148,
                overflow: 152,
                cqes: 320,
                flags: 156,
                resv1: 0,
                user_addr: 0xcafe_babe,
            },
        };
        let mut raw = [0xa5u8; 120];
        encode_into_slice(&params, &mut raw);
        let decoded = decode_from_bytes::<io_uring_params>(&raw).unwrap();
        assert_eq!(decoded.sq_entries, 16);
        assert_eq!(decoded.cq_entries, 32);
        assert_eq!(decoded.features, 0x1bf);
        assert_eq!(decoded.sq_off.array, 256);
        assert_eq!(decoded.sq_off.user_addr, 0xdead_beef);
        assert_eq!(decoded.cq_off.cqes, 320);
        assert_eq!(decoded.cq_off.user_addr, 0xcafe_babe);
    }

    #[test]
    fn io_uring_sqe_and_cqe_roundtrip_all_fields() {
        let sqe = IoUringSqe {
            opcode: 22,
            flags: 0x12,
            ioprio: 0x3456,
            fd: -1,
            off: 0x0102_0304_0506_0708,
            addr: 0x1112_1314_1516_1718,
            len: 4096,
            op_flags: 0x89ab_cdef,
            user_data: 0xfeed_face_cafe_beef,
            buf_index: 7,
            personality: 9,
            splice_fd_in: 0x42,
            addr3: 0x2122_2324_2526_2728,
            pad2: 0x3132_3334_3536_3738,
        };
        let bytes = encode_to_buffer(&sqe);
        let decoded_flat = decode_from_bytes::<IoUringSqe>(&bytes).unwrap();
        assert_eq!(decoded_flat, sqe);
        let raw_sqe = decode_from_bytes::<io_uring_sqe>(&bytes).unwrap();
        assert_eq!(raw_sqe.opcode, sqe.opcode);
        assert_eq!(raw_sqe.flags, sqe.flags);
        assert_eq!(raw_sqe.ioprio, sqe.ioprio);
        assert_eq!(raw_sqe.fd, sqe.fd);
        assert_eq!(raw_sqe.len, sqe.len);
        assert_eq!(raw_sqe.user_data, sqe.user_data);
        assert_eq!(raw_sqe.personality, sqe.personality);

        let cqe = IoUringCqe {
            user_data: 0x1234_5678_9abc_def0,
            res: -22,
            flags: 3,
        };
        let cqe_bytes = encode_to_buffer(&cqe);
        assert_eq!(decode_from_bytes::<IoUringCqe>(&cqe_bytes).unwrap(), cqe);
        let raw_cqe = decode_from_bytes::<io_uring_cqe>(&cqe_bytes).unwrap();
        assert_eq!(raw_cqe.user_data, cqe.user_data);
        assert_eq!(raw_cqe.res, cqe.res);
        assert_eq!(raw_cqe.flags, cqe.flags);
        assert_eq!(encode_to_buffer(&raw_cqe), cqe_bytes);
    }

    #[test]
    fn io_uring_auxiliary_structs_decode_encode_and_reject_short_copy() {
        let arg = io_uring_getevents_arg {
            sigmask: 0x1000,
            sigmask_sz: 8,
            min_wait_usec: 500,
            ts: 0x2000,
        };
        let raw_arg = encode_to_buffer(&arg);
        let dec_arg = decode_from_bytes::<io_uring_getevents_arg>(&raw_arg).unwrap();
        assert_eq!(dec_arg.sigmask, 0x1000);
        assert_eq!(dec_arg.sigmask_sz, 8);
        assert_eq!(dec_arg.min_wait_usec, 500);
        assert_eq!(dec_arg.ts, 0x2000);

        let ts = __kernel_timespec {
            tv_sec: 5,
            tv_nsec: 123_456_789,
        };
        let dec_ts = decode_from_bytes::<__kernel_timespec>(&encode_to_buffer(&ts)).unwrap();
        assert_eq!(dec_ts.tv_sec, 5);
        assert_eq!(dec_ts.tv_nsec, 123_456_789);

        let rsrc = io_uring_rsrc_update {
            offset: 2,
            resv: 0,
            data: 0x3000,
        };
        let dec_rsrc =
            decode_from_bytes::<io_uring_rsrc_update>(&encode_to_buffer(&rsrc)).unwrap();
        assert_eq!(dec_rsrc.offset, 2);
        assert_eq!(dec_rsrc.data, 0x3000);

        let files = io_uring_files_update {
            offset: 4,
            resv: 0,
            fds: 0x4000,
        };
        let dec_files =
            decode_from_bytes::<io_uring_files_update>(&encode_to_buffer(&files)).unwrap();
        assert_eq!(dec_files.offset, 4);
        assert_eq!(dec_files.fds, 0x4000);

        let probe_op = io_uring_probe_op {
            op: 1,
            resv: 0,
            flags: 1,
            resv2: 0,
        };
        let dec_probe_op =
            decode_from_bytes::<io_uring_probe_op>(&encode_to_buffer(&probe_op)).unwrap();
        assert_eq!(dec_probe_op.op, 1);
        assert_eq!(dec_probe_op.flags, 1);

        let probe = io_uring_probe {
            last_op: 57,
            ops_len: 58,
            resv: 0,
            resv2: [0; 3],
            ops: __IncompleteArrayField::new(),
        };
        let mut raw_probe = [0xffu8; 16];
        encode_into_slice(&probe, &mut raw_probe);
        let dec_probe = decode_from_bytes::<io_uring_probe>(&raw_probe).unwrap();
        assert_eq!(dec_probe.last_op, 57);
        assert_eq!(dec_probe.ops_len, 58);

        let err = read_user_value_with::<io_uring_getevents_arg>(0x5000, |_, dst| {
            dst[..23].fill(0);
            Ok(23)
        });
        assert!(matches!(err, Err(AxError::BadAddress)));
    }
}
