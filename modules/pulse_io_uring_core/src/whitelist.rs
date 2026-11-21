//! v1 opcode, SQE/enter flag, and register operation whitelist + validation.

use axerrno::LinuxError;
use linux_raw_sys::io_uring::{io_uring_op, io_uring_probe, io_uring_probe_op};
use pulse_user_abi::io_uring::{
    IORING_ASYNC_CANCEL_ALL, IORING_ASYNC_CANCEL_ANY, IORING_ASYNC_CANCEL_FD,
    IORING_ASYNC_CANCEL_FD_FIXED, IORING_FSYNC_DATASYNC, IORING_TIMEOUT_ABS,
    IORING_TIMEOUT_BOOTTIME, IORING_TIMEOUT_CLOCK_MASK, IORING_TIMEOUT_ETIME_SUCCESS,
    IORING_TIMEOUT_LINK, IORING_TIMEOUT_REALTIME, IORING_TIMEOUT_UPDATE, IOSQE_FIXED_FILE,
    IoUringSqe, RWF_APPEND, RWF_DSYNC, RWF_HIPRI, RWF_NOWAIT, RWF_SYNC,
    SYNC_FILE_RANGE_WAIT_AFTER, SYNC_FILE_RANGE_WAIT_BEFORE, SYNC_FILE_RANGE_WRITE,
};

/// Linux v6.12 `IORING_OP_LAST` boundary (`0..=57`).
pub const IORING_OP_LAST_V1: u8 = 58;

#[inline]
pub const fn is_op_supported_v1(opcode: u8) -> bool {
    opcode == io_uring_op::IORING_OP_NOP as u8
        || opcode == io_uring_op::IORING_OP_READV as u8
        || opcode == io_uring_op::IORING_OP_WRITEV as u8
        || opcode == io_uring_op::IORING_OP_FSYNC as u8
        || opcode == io_uring_op::IORING_OP_READ_FIXED as u8
        || opcode == io_uring_op::IORING_OP_WRITE_FIXED as u8
        || opcode == io_uring_op::IORING_OP_POLL_ADD as u8
        || opcode == io_uring_op::IORING_OP_POLL_REMOVE as u8
        || opcode == io_uring_op::IORING_OP_SYNC_FILE_RANGE as u8
        || opcode == io_uring_op::IORING_OP_SENDMSG as u8
        || opcode == io_uring_op::IORING_OP_RECVMSG as u8
        || opcode == io_uring_op::IORING_OP_TIMEOUT as u8
        || opcode == io_uring_op::IORING_OP_TIMEOUT_REMOVE as u8
        || opcode == io_uring_op::IORING_OP_ACCEPT as u8
        || opcode == io_uring_op::IORING_OP_ASYNC_CANCEL as u8
        || opcode == io_uring_op::IORING_OP_LINK_TIMEOUT as u8
        || opcode == io_uring_op::IORING_OP_CONNECT as u8
        || opcode == io_uring_op::IORING_OP_FILES_UPDATE as u8
        || opcode == io_uring_op::IORING_OP_READ as u8
        || opcode == io_uring_op::IORING_OP_WRITE as u8
        || opcode == io_uring_op::IORING_OP_SEND as u8
        || opcode == io_uring_op::IORING_OP_RECV as u8
        || opcode == io_uring_op::IORING_OP_SHUTDOWN as u8
        || opcode == io_uring_op::IORING_OP_SOCKET as u8
}

#[inline]
pub const fn validate_enter_flags_v1(flags: u32) -> Result<(), LinuxError> {
    const ALLOWED: u32 = linux_raw_sys::io_uring::IORING_ENTER_GETEVENTS
        | linux_raw_sys::io_uring::IORING_ENTER_EXT_ARG;
    if flags & !ALLOWED != 0 {
        Err(LinuxError::EINVAL)
    } else {
        Ok(())
    }
}

#[inline]
pub const fn validate_register_op_v1(opcode: u32) -> Result<u32, LinuxError> {
    use linux_raw_sys::io_uring::io_uring_register_op;
    match opcode {
        x if x == io_uring_register_op::IORING_REGISTER_BUFFERS as u32
            || x == io_uring_register_op::IORING_UNREGISTER_BUFFERS as u32
            || x == io_uring_register_op::IORING_REGISTER_FILES as u32
            || x == io_uring_register_op::IORING_UNREGISTER_FILES as u32
            || x == io_uring_register_op::IORING_REGISTER_EVENTFD as u32
            || x == io_uring_register_op::IORING_UNREGISTER_EVENTFD as u32
            || x == io_uring_register_op::IORING_REGISTER_FILES_UPDATE as u32
            || x == io_uring_register_op::IORING_REGISTER_EVENTFD_ASYNC as u32
            || x == io_uring_register_op::IORING_REGISTER_PROBE as u32 =>
        {
            Ok(opcode)
        }
        _ => Err(LinuxError::EINVAL),
    }
}

pub fn validate_sqe_v1(sqe: &IoUringSqe) -> Result<(), LinuxError> {
    use linux_raw_sys::io_uring::io_uring_sqe_flags_bit;

    const IOSQE_UNKNOWN_RESERVED_BIT7: u8 = 1 << 7;
    const EINVAL_FLAGS: u8 =
        (1 << io_uring_sqe_flags_bit::IOSQE_CQE_SKIP_SUCCESS_BIT as u8)
            | IOSQE_UNKNOWN_RESERVED_BIT7;
    const BUFFER_SELECT_FLAG: u8 = 1 << io_uring_sqe_flags_bit::IOSQE_BUFFER_SELECT_BIT as u8;

    if sqe.flags & EINVAL_FLAGS != 0 {
        return Err(LinuxError::EINVAL);
    }
    if sqe.opcode >= IORING_OP_LAST_V1 {
        return Err(LinuxError::EINVAL);
    }
    if !is_op_supported_v1(sqe.opcode) {
        return Err(LinuxError::EOPNOTSUPP);
    }
    if sqe.flags & BUFFER_SELECT_FLAG != 0 {
        return Err(LinuxError::EOPNOTSUPP);
    }
    Ok(())
}

pub fn validate_nop_sqe(sqe: &IoUringSqe) -> Result<(), LinuxError> {
    validate_sqe_v1(sqe)?;
    if sqe.opcode != linux_raw_sys::io_uring::io_uring_op::IORING_OP_NOP as u8 {
        return Err(LinuxError::EINVAL);
    }
    if sqe.flags & IOSQE_FIXED_FILE != 0 {
        return Err(LinuxError::EBADF);
    }
    if sqe.op_flags != 0
        || sqe.ioprio != 0
        || sqe.buf_index != 0
        || sqe.splice_fd_in != 0
        || sqe.personality != 0
    {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

/// Validates an `IORING_OP_TIMEOUT` (opcode 11) SQE.
pub fn validate_timeout_sqe(sqe: &IoUringSqe) -> Result<(), LinuxError> {
    validate_sqe_v1(sqe)?;
    if sqe.opcode != io_uring_op::IORING_OP_TIMEOUT as u8 {
        return Err(LinuxError::EINVAL);
    }
    if sqe.flags & IOSQE_FIXED_FILE != 0 {
        return Err(LinuxError::EBADF);
    }
    if sqe.ioprio != 0
        || sqe.buf_index != 0
        || sqe.personality != 0
        || sqe.splice_fd_in != 0
        || sqe.len != 1
    {
        return Err(LinuxError::EINVAL);
    }
    const ALLOWED_TIMEOUT_FLAGS: u32 = IORING_TIMEOUT_ABS
        | IORING_TIMEOUT_BOOTTIME
        | IORING_TIMEOUT_REALTIME
        | IORING_TIMEOUT_ETIME_SUCCESS;
    if sqe.op_flags & !ALLOWED_TIMEOUT_FLAGS != 0 {
        return Err(LinuxError::EINVAL);
    }
    if (sqe.op_flags & IORING_TIMEOUT_CLOCK_MASK) == IORING_TIMEOUT_CLOCK_MASK {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

/// Validates an `IORING_OP_TIMEOUT_REMOVE` (opcode 12) SQE (both remove and `IORING_TIMEOUT_UPDATE`).
pub fn validate_timeout_remove_sqe(sqe: &IoUringSqe) -> Result<(), LinuxError> {
    validate_sqe_v1(sqe)?;
    if sqe.opcode != io_uring_op::IORING_OP_TIMEOUT_REMOVE as u8 {
        return Err(LinuxError::EINVAL);
    }
    if sqe.flags & IOSQE_FIXED_FILE != 0 {
        return Err(LinuxError::EBADF);
    }
    if sqe.ioprio != 0
        || sqe.buf_index != 0
        || sqe.len != 0
        || sqe.personality != 0
        || sqe.splice_fd_in != 0
    {
        return Err(LinuxError::EINVAL);
    }
    if (sqe.op_flags & IORING_TIMEOUT_UPDATE) != 0 {
        const ALLOWED_UPDATE_FLAGS: u32 = IORING_TIMEOUT_UPDATE
            | IORING_TIMEOUT_ABS
            | IORING_TIMEOUT_LINK
            | IORING_TIMEOUT_BOOTTIME
            | IORING_TIMEOUT_REALTIME;
        if sqe.op_flags & !ALLOWED_UPDATE_FLAGS != 0 {
            return Err(LinuxError::EINVAL);
        }
        if (sqe.op_flags & IORING_TIMEOUT_CLOCK_MASK) == IORING_TIMEOUT_CLOCK_MASK {
            return Err(LinuxError::EINVAL);
        }
    } else if sqe.op_flags != 0 || sqe.off != 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

/// Validates an `IORING_OP_ASYNC_CANCEL` (opcode 14) SQE.
pub fn validate_async_cancel_sqe(sqe: &IoUringSqe) -> Result<(), LinuxError> {
    validate_sqe_v1(sqe)?;
    if sqe.opcode != io_uring_op::IORING_OP_ASYNC_CANCEL as u8 {
        return Err(LinuxError::EINVAL);
    }
    if sqe.ioprio != 0
        || sqe.off != 0
        || sqe.len != 0
        || sqe.buf_index != 0
        || sqe.personality != 0
        || sqe.splice_fd_in != 0
    {
        return Err(LinuxError::EINVAL);
    }
    const ALLOWED_CANCEL_FLAGS: u32 = IORING_ASYNC_CANCEL_ALL
        | IORING_ASYNC_CANCEL_FD
        | IORING_ASYNC_CANCEL_ANY
        | IORING_ASYNC_CANCEL_FD_FIXED;
    if sqe.op_flags & !ALLOWED_CANCEL_FLAGS != 0 {
        return Err(LinuxError::EINVAL);
    }
    if (sqe.op_flags & IORING_ASYNC_CANCEL_FD_FIXED) != 0
        && (sqe.op_flags & IORING_ASYNC_CANCEL_FD) == 0
    {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

/// Validates an `IORING_OP_LINK_TIMEOUT` (opcode 15) SQE.
pub fn validate_link_timeout_sqe(sqe: &IoUringSqe) -> Result<(), LinuxError> {
    validate_sqe_v1(sqe)?;
    if sqe.opcode != io_uring_op::IORING_OP_LINK_TIMEOUT as u8 {
        return Err(LinuxError::EINVAL);
    }
    if sqe.flags & IOSQE_FIXED_FILE != 0 {
        return Err(LinuxError::EBADF);
    }
    if sqe.ioprio != 0
        || sqe.off != 0
        || sqe.len != 1
        || sqe.buf_index != 0
        || sqe.personality != 0
        || sqe.splice_fd_in != 0
    {
        return Err(LinuxError::EINVAL);
    }
    const ALLOWED_LINK_TIMEOUT_FLAGS: u32 =
        IORING_TIMEOUT_ABS | IORING_TIMEOUT_BOOTTIME | IORING_TIMEOUT_REALTIME;
    if sqe.op_flags & !ALLOWED_LINK_TIMEOUT_FLAGS != 0 {
        return Err(LinuxError::EINVAL);
    }
    if (sqe.op_flags & IORING_TIMEOUT_CLOCK_MASK) == IORING_TIMEOUT_CLOCK_MASK {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

const ALLOWED_RW_FLAGS_V1: u32 = RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND;

/// Resolved file offset semantics for `READ` / `WRITE` / `READV` / `WRITEV` / `*_FIXED`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RwOffset {
    CurrentPosition,
    Positional(u64),
}

#[inline]
pub fn validate_rw_flags(op_flags: u32) -> Result<(), LinuxError> {
    if (op_flags & RWF_HIPRI) != 0 {
        return Err(LinuxError::EOPNOTSUPP);
    }
    if (op_flags & !(ALLOWED_RW_FLAGS_V1 | RWF_HIPRI)) != 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

/// Resolves Linux tri-state `sqe.off` semantics against seekability and transfer length.
pub fn resolve_rw_offset(
    raw_off: u64,
    requested_len: usize,
    is_seekable: bool,
) -> Result<RwOffset, LinuxError> {
    if raw_off == u64::MAX {
        return Ok(RwOffset::CurrentPosition);
    }
    if raw_off > i64::MAX as u64 {
        return Err(LinuxError::EINVAL);
    }
    if !is_seekable {
        return if raw_off == 0 {
            Ok(RwOffset::CurrentPosition)
        } else {
            Err(LinuxError::ESPIPE)
        };
    }
    raw_off
        .checked_add(requested_len as u64)
        .filter(|&end| end <= i64::MAX as u64)
        .ok_or(LinuxError::EINVAL)?;
    Ok(RwOffset::Positional(raw_off))
}

#[inline]
fn validate_common_zero_fields(sqe: &IoUringSqe) -> Result<(), LinuxError> {
    if sqe.ioprio != 0 || sqe.personality != 0 || sqe.splice_fd_in != 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

/// Validates prep invariants for `IORING_OP_READ` / `WRITE` / `READV` / `WRITEV`.
pub fn validate_rw_sqe(sqe: &IoUringSqe) -> Result<(), LinuxError> {
    validate_sqe_v1(sqe)?;
    let op = sqe.opcode;
    if op != io_uring_op::IORING_OP_READ as u8
        && op != io_uring_op::IORING_OP_WRITE as u8
        && op != io_uring_op::IORING_OP_READV as u8
        && op != io_uring_op::IORING_OP_WRITEV as u8
    {
        return Err(LinuxError::EINVAL);
    }
    validate_common_zero_fields(sqe)?;
    if sqe.buf_index != 0 {
        return Err(LinuxError::EINVAL);
    }
    validate_rw_flags(sqe.op_flags)
}

/// Validates common prep invariants for poll/accept helper ops.
pub fn validate_rw_or_poll_sqe(sqe: &IoUringSqe) -> Result<(), LinuxError> {
    validate_sqe_v1(sqe)?;
    validate_common_zero_fields(sqe)?;
    if sqe.buf_index != 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

/// Validates prep invariants for `IORING_OP_READ_FIXED` / `IORING_OP_WRITE_FIXED`.
pub fn validate_rw_fixed_sqe(sqe: &IoUringSqe) -> Result<(), LinuxError> {
    validate_sqe_v1(sqe)?;
    if sqe.opcode != io_uring_op::IORING_OP_READ_FIXED as u8
        && sqe.opcode != io_uring_op::IORING_OP_WRITE_FIXED as u8
    {
        return Err(LinuxError::EINVAL);
    }
    validate_common_zero_fields(sqe)?;
    validate_rw_flags(sqe.op_flags)
}

/// Validates prep invariants for `IORING_OP_FSYNC` (opcode 3).
pub fn validate_fsync_sqe(sqe: &IoUringSqe) -> Result<(), LinuxError> {
    validate_sqe_v1(sqe)?;
    if sqe.opcode != io_uring_op::IORING_OP_FSYNC as u8 {
        return Err(LinuxError::EINVAL);
    }
    validate_common_zero_fields(sqe)?;
    if sqe.addr != 0 || sqe.buf_index != 0 {
        return Err(LinuxError::EINVAL);
    }
    if (sqe.op_flags & !IORING_FSYNC_DATASYNC) != 0 {
        return Err(LinuxError::EINVAL);
    }
    if sqe.off > i64::MAX as u64 {
        return Err(LinuxError::EINVAL);
    }
    sqe.off
        .checked_add(sqe.len as u64)
        .filter(|&end| end <= i64::MAX as u64)
        .ok_or(LinuxError::EINVAL)?;
    Ok(())
}

/// Validates prep invariants for `IORING_OP_SYNC_FILE_RANGE` (opcode 8).
pub fn validate_sync_file_range_sqe(sqe: &IoUringSqe) -> Result<(), LinuxError> {
    validate_sqe_v1(sqe)?;
    if sqe.opcode != io_uring_op::IORING_OP_SYNC_FILE_RANGE as u8 {
        return Err(LinuxError::EINVAL);
    }
    validate_common_zero_fields(sqe)?;
    if sqe.addr != 0 || sqe.buf_index != 0 {
        return Err(LinuxError::EINVAL);
    }
    const ALLOWED_SYNC_RANGE_FLAGS: u32 =
        SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    if (sqe.op_flags & !ALLOWED_SYNC_RANGE_FLAGS) != 0 {
        return Err(LinuxError::EINVAL);
    }
    if sqe.off > i64::MAX as u64 {
        return Err(LinuxError::EINVAL);
    }
    sqe.off
        .checked_add(sqe.len as u64)
        .filter(|&end| end <= i64::MAX as u64)
        .ok_or(LinuxError::EINVAL)?;
    Ok(())
}

/// Validates prep invariants for `IORING_OP_FILES_UPDATE`.
pub fn validate_files_update_sqe(sqe: &IoUringSqe) -> Result<(), LinuxError> {
    validate_sqe_v1(sqe)?;
    if sqe.opcode != io_uring_op::IORING_OP_FILES_UPDATE as u8 {
        return Err(LinuxError::EINVAL);
    }
    if sqe.flags & IOSQE_FIXED_FILE != 0 {
        return Err(LinuxError::EBADF);
    }
    validate_common_zero_fields(sqe)?;
    if sqe.buf_index != 0 || sqe.op_flags != 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

pub fn populate_probe(
    header: &mut io_uring_probe,
    nr_args: u32,
) -> Result<[io_uring_probe_op; IORING_OP_LAST_V1 as usize], LinuxError> {
    if header.last_op != 0 || header.ops_len != 0 || header.resv != 0 || header.resv2 != [0; 3] {
        return Err(LinuxError::EINVAL);
    }

    let ops_len = (nr_args as usize).min(IORING_OP_LAST_V1 as usize);
    header.last_op = IORING_OP_LAST_V1 - 1;
    header.ops_len = ops_len as u8;

    let ops = core::array::from_fn(|idx| {
        let op = idx as u8;
        let flags = if is_op_supported_v1(op) {
            linux_raw_sys::io_uring::IO_URING_OP_SUPPORTED as u16
        } else {
            0
        };
        io_uring_probe_op {
            op,
            resv: 0,
            flags,
            resv2: 0,
        }
    });

    Ok(ops)
}

#[cfg(test)]
mod tests {
    use super::*;
    use linux_raw_sys::io_uring::{
        __IncompleteArrayField, IO_URING_OP_SUPPORTED, IORING_ENTER_EXT_ARG,
        IORING_ENTER_GETEVENTS, IORING_ENTER_REGISTERED_RING, IORING_ENTER_SQ_WAIT,
        IORING_ENTER_SQ_WAKEUP, io_uring_register_op, io_uring_sqe_flags_bit,
    };

    const SUPPORTED_OPS: [u8; 24] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 22, 23, 26, 27, 34, 45,
    ];

    fn empty_sqe(opcode: u8) -> IoUringSqe {
        IoUringSqe {
            opcode,
            fd: -1,
            ..Default::default()
        }
    }

    #[test]
    fn opcode_whitelist_and_validation_errors_match_v1_tier() {
        let mut supported_count = 0usize;
        for op in 0..IORING_OP_LAST_V1 {
            let expected = SUPPORTED_OPS.contains(&op);
            assert_eq!(is_op_supported_v1(op), expected, "opcode {op}");
            let sqe = empty_sqe(op);
            if expected {
                assert_eq!(validate_sqe_v1(&sqe), Ok(()));
                supported_count += 1;
            } else {
                assert_eq!(validate_sqe_v1(&sqe), Err(LinuxError::EOPNOTSUPP));
            }
        }
        assert_eq!(supported_count, 24);

        for op in IORING_OP_LAST_V1..=u8::MAX {
            assert!(!is_op_supported_v1(op));
            assert_eq!(validate_sqe_v1(&empty_sqe(op)), Err(LinuxError::EINVAL));
        }
    }

    #[test]
    fn sqe_flags_and_nop_validation_follow_error_precedence() {
        let mut sqe = empty_sqe(0);
        sqe.flags = (1 << io_uring_sqe_flags_bit::IOSQE_IO_DRAIN_BIT as u8)
            | (1 << io_uring_sqe_flags_bit::IOSQE_ASYNC_BIT as u8);
        assert_eq!(validate_nop_sqe(&sqe), Ok(()));

        sqe.flags = 1 << io_uring_sqe_flags_bit::IOSQE_BUFFER_SELECT_BIT as u8;
        assert_eq!(validate_sqe_v1(&sqe), Err(LinuxError::EOPNOTSUPP));

        sqe.flags = 1 << io_uring_sqe_flags_bit::IOSQE_CQE_SKIP_SUCCESS_BIT as u8;
        assert_eq!(validate_sqe_v1(&sqe), Err(LinuxError::EINVAL));

        sqe.flags = 1 << 7;
        assert_eq!(validate_sqe_v1(&sqe), Err(LinuxError::EINVAL));

        let mut bad_fixed = empty_sqe(0);
        bad_fixed.flags = 1 << io_uring_sqe_flags_bit::IOSQE_FIXED_FILE_BIT as u8;
        assert_eq!(validate_nop_sqe(&bad_fixed), Err(LinuxError::EBADF));

        let mut bad_op_flags = empty_sqe(0);
        bad_op_flags.op_flags = 1;
        assert_eq!(validate_nop_sqe(&bad_op_flags), Err(LinuxError::EINVAL));

        let mut bad_prio = empty_sqe(0);
        bad_prio.ioprio = 1;
        assert_eq!(validate_nop_sqe(&bad_prio), Err(LinuxError::EINVAL));

        let mut bad_personality = empty_sqe(0);
        bad_personality.personality = 1;
        assert_eq!(validate_nop_sqe(&bad_personality), Err(LinuxError::EINVAL));

        let mut bad_file_idx = empty_sqe(0);
        bad_file_idx.splice_fd_in = 1;
        assert_eq!(validate_nop_sqe(&bad_file_idx), Err(LinuxError::EINVAL));
    }

    #[test]
    fn enter_register_and_probe_match_v1_contract() {
        assert_eq!(validate_enter_flags_v1(0), Ok(()));
        assert_eq!(
            validate_enter_flags_v1(IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG),
            Ok(())
        );
        for flag in [
            IORING_ENTER_SQ_WAKEUP,
            IORING_ENTER_SQ_WAIT,
            IORING_ENTER_REGISTERED_RING,
            1 << 31,
        ] {
            assert_eq!(validate_enter_flags_v1(flag), Err(LinuxError::EINVAL));
        }

        for op in [
            io_uring_register_op::IORING_REGISTER_BUFFERS,
            io_uring_register_op::IORING_UNREGISTER_BUFFERS,
            io_uring_register_op::IORING_REGISTER_FILES,
            io_uring_register_op::IORING_UNREGISTER_FILES,
            io_uring_register_op::IORING_REGISTER_EVENTFD,
            io_uring_register_op::IORING_UNREGISTER_EVENTFD,
            io_uring_register_op::IORING_REGISTER_FILES_UPDATE,
            io_uring_register_op::IORING_REGISTER_EVENTFD_ASYNC,
            io_uring_register_op::IORING_REGISTER_PROBE,
        ] {
            assert!(validate_register_op_v1(op as u32).is_ok());
        }
        for op in [
            io_uring_register_op::IORING_REGISTER_PERSONALITY,
            io_uring_register_op::IORING_REGISTER_LAST,
        ] {
            assert_eq!(
                validate_register_op_v1(op as u32),
                Err(LinuxError::EINVAL)
            );
        }

        let mut header = io_uring_probe {
            last_op: 0,
            ops_len: 0,
            resv: 0,
            resv2: [0; 3],
            ops: __IncompleteArrayField::new(),
        };
        let ops = populate_probe(&mut header, 0).unwrap();
        assert_eq!(header.last_op, 57);
        assert_eq!(header.ops_len, 0);
        assert_eq!(ops.len(), 58);

        let mut header256 = io_uring_probe {
            last_op: 0,
            ops_len: 0,
            resv: 0,
            resv2: [0; 3],
            ops: __IncompleteArrayField::new(),
        };
        let ops256 = populate_probe(&mut header256, 256).unwrap();
        assert_eq!(header256.last_op, 57);
        assert_eq!(header256.ops_len, 58);
        for (idx, entry) in ops256.iter().enumerate() {
            assert_eq!(entry.op, idx as u8);
            let expected_flags = if SUPPORTED_OPS.contains(&(idx as u8)) {
                IO_URING_OP_SUPPORTED as u16
            } else {
                0
            };
            assert_eq!(entry.flags, expected_flags);
        }

        let mut dirty_header = io_uring_probe {
            last_op: 1,
            ops_len: 0,
            resv: 0,
            resv2: [0; 3],
            ops: __IncompleteArrayField::new(),
        };
        assert!(matches!(
            populate_probe(&mut dirty_header, 10),
            Err(LinuxError::EINVAL)
        ));
    }

    #[test]
    fn timeout_cancel_and_link_timeout_validators_match_linux_contract() {
        let mut to = empty_sqe(io_uring_op::IORING_OP_TIMEOUT as u8);
        to.len = 1;
        to.op_flags = IORING_TIMEOUT_ABS | IORING_TIMEOUT_ETIME_SUCCESS;
        assert_eq!(validate_timeout_sqe(&to), Ok(()));

        // Conflicting clocks or unsupported multishot -> -EINVAL.
        to.op_flags = IORING_TIMEOUT_BOOTTIME | IORING_TIMEOUT_REALTIME;
        assert_eq!(validate_timeout_sqe(&to), Err(LinuxError::EINVAL));
        to.op_flags = pulse_user_abi::io_uring::IORING_TIMEOUT_MULTISHOT;
        assert_eq!(validate_timeout_sqe(&to), Err(LinuxError::EINVAL));

        // Remove vs Update flags.
        let mut rem = empty_sqe(io_uring_op::IORING_OP_TIMEOUT_REMOVE as u8);
        assert_eq!(validate_timeout_remove_sqe(&rem), Ok(()));
        rem.op_flags = IORING_TIMEOUT_ABS; // ABS without UPDATE
        assert_eq!(validate_timeout_remove_sqe(&rem), Err(LinuxError::EINVAL));
        rem.op_flags = IORING_TIMEOUT_UPDATE | IORING_TIMEOUT_LINK | IORING_TIMEOUT_ABS;
        assert_eq!(validate_timeout_remove_sqe(&rem), Ok(()));

        // Link timeout.
        let mut lt = empty_sqe(io_uring_op::IORING_OP_LINK_TIMEOUT as u8);
        lt.len = 1;
        assert_eq!(validate_link_timeout_sqe(&lt), Ok(()));
        lt.ioprio = 89;
        assert_eq!(validate_link_timeout_sqe(&lt), Err(LinuxError::EINVAL));

        // Async cancel.
        let mut cancel = empty_sqe(io_uring_op::IORING_OP_ASYNC_CANCEL as u8);
        cancel.op_flags = IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_ALL;
        assert_eq!(validate_async_cancel_sqe(&cancel), Ok(()));
        cancel.op_flags = IORING_ASYNC_CANCEL_FD_FIXED; // missing FD flag
        assert_eq!(validate_async_cancel_sqe(&cancel), Err(LinuxError::EINVAL));

        // RW/Poll with IOSQE_FIXED_FILE, READ_FIXED/WRITE_FIXED, and FILES_UPDATE.
        let mut rw = empty_sqe(io_uring_op::IORING_OP_READ as u8);
        rw.flags = IOSQE_FIXED_FILE;
        assert_eq!(validate_rw_or_poll_sqe(&rw), Ok(()));

        let mut rw_fixed = empty_sqe(io_uring_op::IORING_OP_READ_FIXED as u8);
        rw_fixed.flags = IOSQE_FIXED_FILE;
        rw_fixed.buf_index = 3;
        assert_eq!(validate_rw_fixed_sqe(&rw_fixed), Ok(()));
        rw_fixed.ioprio = 1;
        assert_eq!(validate_rw_fixed_sqe(&rw_fixed), Err(LinuxError::EINVAL));

        let mut files_upd = empty_sqe(io_uring_op::IORING_OP_FILES_UPDATE as u8);
        assert_eq!(validate_files_update_sqe(&files_upd), Ok(()));
        files_upd.flags = IOSQE_FIXED_FILE;
        assert_eq!(validate_files_update_sqe(&files_upd), Err(LinuxError::EBADF));
        files_upd.flags = 0;
        files_upd.op_flags = 1;
        assert_eq!(validate_files_update_sqe(&files_upd), Err(LinuxError::EINVAL));
    }

    #[test]
    fn rw_offset_resolution_covers_tristate_overflow_and_stream_espipe() {
        // u64::MAX selects current file position for both seekable and stream FDs.
        assert_eq!(
            resolve_rw_offset(u64::MAX, 4096, true),
            Ok(RwOffset::CurrentPosition)
        );
        assert_eq!(
            resolve_rw_offset(u64::MAX, 4096, false),
            Ok(RwOffset::CurrentPosition)
        );

        // Seekable positive offsets validate overflow past i64::MAX.
        assert_eq!(resolve_rw_offset(0, 4096, true), Ok(RwOffset::Positional(0)));
        assert_eq!(
            resolve_rw_offset(i64::MAX as u64, 0, true),
            Ok(RwOffset::Positional(i64::MAX as u64))
        );
        assert_eq!(
            resolve_rw_offset(i64::MAX as u64, 1, true),
            Err(LinuxError::EINVAL)
        );

        // Negative offsets other than u64::MAX fail with -EINVAL regardless of seekability.
        assert_eq!(
            resolve_rw_offset((i64::MAX as u64) + 1, 1, true),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            resolve_rw_offset(u64::MAX - 1, 1, false),
            Err(LinuxError::EINVAL)
        );

        // Stream FDs permit 0 and u64::MAX, returning -ESPIPE for positive explicit offsets.
        assert_eq!(
            resolve_rw_offset(0, 64, false),
            Ok(RwOffset::CurrentPosition)
        );
        assert_eq!(
            resolve_rw_offset(1, 64, false),
            Err(LinuxError::ESPIPE)
        );
        assert_eq!(
            resolve_rw_offset(4096, 0, false),
            Err(LinuxError::ESPIPE)
        );
    }

    #[test]
    fn rw_fsync_and_sync_file_range_validators_enforce_flags_and_ranges() {
        // RW & RW_FIXED flags.
        for op in [
            io_uring_op::IORING_OP_READ as u8,
            io_uring_op::IORING_OP_WRITE as u8,
            io_uring_op::IORING_OP_READV as u8,
            io_uring_op::IORING_OP_WRITEV as u8,
        ] {
            let mut sqe = empty_sqe(op);
            sqe.op_flags = RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND;
            assert_eq!(validate_rw_sqe(&sqe), Ok(()));

            sqe.op_flags = RWF_HIPRI;
            assert_eq!(validate_rw_sqe(&sqe), Err(LinuxError::EOPNOTSUPP));

            sqe.op_flags = 1 << 30;
            assert_eq!(validate_rw_sqe(&sqe), Err(LinuxError::EINVAL));
        }

        let mut rw_fixed = empty_sqe(io_uring_op::IORING_OP_WRITE_FIXED as u8);
        rw_fixed.op_flags = RWF_APPEND | RWF_DSYNC;
        assert_eq!(validate_rw_fixed_sqe(&rw_fixed), Ok(()));
        rw_fixed.op_flags = RWF_HIPRI;
        assert_eq!(validate_rw_fixed_sqe(&rw_fixed), Err(LinuxError::EOPNOTSUPP));
        rw_fixed.op_flags = 1 << 29;
        assert_eq!(validate_rw_fixed_sqe(&rw_fixed), Err(LinuxError::EINVAL));

        // FSYNC validation.
        let mut fsync = empty_sqe(io_uring_op::IORING_OP_FSYNC as u8);
        assert_eq!(validate_fsync_sqe(&fsync), Ok(()));
        fsync.op_flags = IORING_FSYNC_DATASYNC;
        fsync.off = 4096;
        fsync.len = 4096;
        assert_eq!(validate_fsync_sqe(&fsync), Ok(()));

        let mut bad_fsync = empty_sqe(io_uring_op::IORING_OP_FSYNC as u8);
        bad_fsync.op_flags = 2;
        assert_eq!(validate_fsync_sqe(&bad_fsync), Err(LinuxError::EINVAL));
        bad_fsync.op_flags = 0;
        bad_fsync.addr = 0x1000;
        assert_eq!(validate_fsync_sqe(&bad_fsync), Err(LinuxError::EINVAL));
        bad_fsync.addr = 0;
        bad_fsync.off = i64::MAX as u64;
        bad_fsync.len = 1;
        assert_eq!(validate_fsync_sqe(&bad_fsync), Err(LinuxError::EINVAL));

        // SYNC_FILE_RANGE validation.
        let mut sfr = empty_sqe(io_uring_op::IORING_OP_SYNC_FILE_RANGE as u8);
        assert_eq!(validate_sync_file_range_sqe(&sfr), Ok(()));
        sfr.op_flags = SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
        sfr.off = 512;
        sfr.len = 4096;
        assert_eq!(validate_sync_file_range_sqe(&sfr), Ok(()));

        sfr.op_flags = 1 << 3;
        assert_eq!(validate_sync_file_range_sqe(&sfr), Err(LinuxError::EINVAL));
        sfr.op_flags = 0;
        sfr.off = (i64::MAX as u64) + 1;
        assert_eq!(validate_sync_file_range_sqe(&sfr), Err(LinuxError::EINVAL));
    }
}
