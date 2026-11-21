//! `io_uring` setup validation, feature advertisement, and ring geometry layout.

use axerrno::LinuxError;
use linux_raw_sys::io_uring::{io_cqring_offsets, io_sqring_offsets, io_uring_params};

pub const IORING_MAX_ENTRIES: u32 = 32_768;
pub const IORING_MAX_CQ_ENTRIES: u32 = IORING_MAX_ENTRIES * 2;
pub const PAGE_SIZE_4K: usize = 4096;

/// Strictly advertised `IORING_FEAT_*` mask for v1.
pub const V1_FEATURES: u32 = linux_raw_sys::io_uring::IORING_FEAT_SINGLE_MMAP
    | linux_raw_sys::io_uring::IORING_FEAT_NODROP
    | linux_raw_sys::io_uring::IORING_FEAT_SUBMIT_STABLE
    | linux_raw_sys::io_uring::IORING_FEAT_RW_CUR_POS
    | linux_raw_sys::io_uring::IORING_FEAT_CUR_PERSONALITY
    | linux_raw_sys::io_uring::IORING_FEAT_FAST_POLL
    | linux_raw_sys::io_uring::IORING_FEAT_POLL_32BITS
    | linux_raw_sys::io_uring::IORING_FEAT_EXT_ARG;

/// Supported `io_uring_setup` flags for v1.
pub const V1_SUPPORTED_SETUP_FLAGS: u32 = linux_raw_sys::io_uring::IORING_SETUP_CQSIZE
    | linux_raw_sys::io_uring::IORING_SETUP_CLAMP
    | linux_raw_sys::io_uring::IORING_SETUP_SUBMIT_ALL;

/// Byte offsets of fields inside the shared rings memory region (`IORING_OFF_SQ_RING` / `IORING_OFF_CQ_RING`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingRegionLayout {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_head_off: usize,
    pub sq_tail_off: usize,
    pub cq_head_off: usize,
    pub cq_tail_off: usize,
    pub sq_mask_off: usize,
    pub sq_entries_off: usize,
    pub sq_flags_off: usize,
    pub sq_dropped_off: usize,
    pub cq_mask_off: usize,
    pub cq_entries_off: usize,
    pub cq_overflow_off: usize,
    pub cq_flags_off: usize,
    pub cqes_off: usize,
    pub sq_array_off: usize,
    pub rings_raw_bytes: usize,
    pub rings_alloc_bytes: usize,
    pub sqes_alloc_bytes: usize,
}

impl RingRegionLayout {
    #[inline]
    pub fn to_sq_offsets(&self) -> io_sqring_offsets {
        io_sqring_offsets {
            head: self.sq_head_off as u32,
            tail: self.sq_tail_off as u32,
            ring_mask: self.sq_mask_off as u32,
            ring_entries: self.sq_entries_off as u32,
            flags: self.sq_flags_off as u32,
            dropped: self.sq_dropped_off as u32,
            array: self.sq_array_off as u32,
            resv1: 0,
            user_addr: 0,
        }
    }

    #[inline]
    pub fn to_cq_offsets(&self) -> io_cqring_offsets {
        io_cqring_offsets {
            head: self.cq_head_off as u32,
            tail: self.cq_tail_off as u32,
            ring_mask: self.cq_mask_off as u32,
            ring_entries: self.cq_entries_off as u32,
            overflow: self.cq_overflow_off as u32,
            cqes: self.cqes_off as u32,
            flags: self.cq_flags_off as u32,
            resv1: 0,
            user_addr: 0,
        }
    }
}

pub fn validate_and_compute_ring_geometry(
    entries: u32,
    params: &mut io_uring_params,
) -> Result<RingRegionLayout, LinuxError> {
    if entries == 0 {
        return Err(LinuxError::EINVAL);
    }
    if params.flags & !V1_SUPPORTED_SETUP_FLAGS != 0 {
        return Err(LinuxError::EINVAL);
    }
    if params.sq_thread_cpu != 0
        || params.sq_thread_idle != 0
        || params.wq_fd != 0
        || params.resv != [0; 3]
    {
        return Err(LinuxError::EINVAL);
    }

    let clamp = params.flags & linux_raw_sys::io_uring::IORING_SETUP_CLAMP != 0;
    let sq_entries = if entries > IORING_MAX_ENTRIES {
        if !clamp {
            return Err(LinuxError::EINVAL);
        }
        IORING_MAX_ENTRIES
    } else {
        entries.next_power_of_two()
    };

    let cq_entries = if params.flags & linux_raw_sys::io_uring::IORING_SETUP_CQSIZE != 0 {
        if params.cq_entries == 0 {
            return Err(LinuxError::EINVAL);
        }
        let requested_cq = if params.cq_entries > IORING_MAX_CQ_ENTRIES {
            if !clamp {
                return Err(LinuxError::EINVAL);
            }
            IORING_MAX_CQ_ENTRIES
        } else {
            params.cq_entries.next_power_of_two()
        };
        if requested_cq < sq_entries {
            return Err(LinuxError::EINVAL);
        }
        requested_cq
    } else {
        sq_entries * 2
    };

    const SQ_HEAD_OFF: usize = 0;
    const SQ_TAIL_OFF: usize = 64;
    const CQ_HEAD_OFF: usize = 128;
    const CQ_TAIL_OFF: usize = 192;
    const SQ_MASK_OFF: usize = 256;
    const SQ_ENTRIES_OFF: usize = 260;
    const SQ_FLAGS_OFF: usize = 264;
    const SQ_DROPPED_OFF: usize = 268;
    const CQ_MASK_OFF: usize = 272;
    const CQ_ENTRIES_OFF: usize = 276;
    const CQ_OVERFLOW_OFF: usize = 280;
    const CQ_FLAGS_OFF: usize = 284;
    const CQES_OFF: usize = 320;

    let cqe_bytes = (cq_entries as usize) * core::mem::size_of::<pulse_user_abi::io_uring::IoUringCqe>();
    let sq_array_off = CQES_OFF + cqe_bytes;
    let rings_raw_bytes = sq_array_off + (sq_entries as usize) * core::mem::size_of::<u32>();
    let rings_alloc_bytes = rings_raw_bytes.next_multiple_of(PAGE_SIZE_4K);
    let sqes_alloc_bytes =
        ((sq_entries as usize) * core::mem::size_of::<pulse_user_abi::io_uring::IoUringSqe>())
            .next_multiple_of(PAGE_SIZE_4K);

    let layout = RingRegionLayout {
        sq_entries,
        cq_entries,
        flags: params.flags,
        sq_head_off: SQ_HEAD_OFF,
        sq_tail_off: SQ_TAIL_OFF,
        cq_head_off: CQ_HEAD_OFF,
        cq_tail_off: CQ_TAIL_OFF,
        sq_mask_off: SQ_MASK_OFF,
        sq_entries_off: SQ_ENTRIES_OFF,
        sq_flags_off: SQ_FLAGS_OFF,
        sq_dropped_off: SQ_DROPPED_OFF,
        cq_mask_off: CQ_MASK_OFF,
        cq_entries_off: CQ_ENTRIES_OFF,
        cq_overflow_off: CQ_OVERFLOW_OFF,
        cq_flags_off: CQ_FLAGS_OFF,
        cqes_off: CQES_OFF,
        sq_array_off,
        rings_raw_bytes,
        rings_alloc_bytes,
        sqes_alloc_bytes,
    };

    params.sq_entries = sq_entries;
    params.cq_entries = cq_entries;
    params.features = V1_FEATURES;
    params.sq_off = layout.to_sq_offsets();
    params.cq_off = layout.to_cq_offsets();

    Ok(layout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use linux_raw_sys::io_uring::{
        IORING_SETUP_ATTACH_WQ, IORING_SETUP_CLAMP, IORING_SETUP_COOP_TASKRUN, IORING_SETUP_CQE32,
        IORING_SETUP_CQSIZE, IORING_SETUP_DEFER_TASKRUN, IORING_SETUP_IOPOLL, IORING_SETUP_NO_MMAP,
        IORING_SETUP_NO_SQARRAY, IORING_SETUP_R_DISABLED, IORING_SETUP_REGISTERED_FD_ONLY,
        IORING_SETUP_SINGLE_ISSUER, IORING_SETUP_SQE128, IORING_SETUP_SQPOLL,
        IORING_SETUP_SUBMIT_ALL,
    };

    fn zero_params() -> io_uring_params {
        io_uring_params {
            sq_entries: 0,
            cq_entries: 0,
            flags: 0,
            sq_thread_cpu: 0,
            sq_thread_idle: 0,
            features: 0,
            wq_fd: 0,
            resv: [0; 3],
            sq_off: io_sqring_offsets {
                head: 0,
                tail: 0,
                ring_mask: 0,
                ring_entries: 0,
                flags: 0,
                dropped: 0,
                array: 0,
                resv1: 0,
                user_addr: 0,
            },
            cq_off: io_cqring_offsets {
                head: 0,
                tail: 0,
                ring_mask: 0,
                ring_entries: 0,
                overflow: 0,
                cqes: 0,
                flags: 0,
                resv1: 0,
                user_addr: 0,
            },
        }
    }

    #[test]
    fn rejects_invalid_entries_resv_and_unsupported_flags() {
        let mut p = zero_params();
        assert_eq!(
            validate_and_compute_ring_geometry(0, &mut p),
            Err(LinuxError::EINVAL)
        );

        let mut p = zero_params();
        assert_eq!(
            validate_and_compute_ring_geometry(IORING_MAX_ENTRIES + 1, &mut p),
            Err(LinuxError::EINVAL)
        );

        for resv_val in [[1, 0, 0], [0, 1, 0], [0, 0, 1]] {
            let mut p = zero_params();
            p.resv = resv_val;
            assert_eq!(
                validate_and_compute_ring_geometry(4, &mut p),
                Err(LinuxError::EINVAL)
            );
        }

        let mut p = zero_params();
        p.sq_thread_cpu = 1;
        assert_eq!(
            validate_and_compute_ring_geometry(4, &mut p),
            Err(LinuxError::EINVAL)
        );
        let mut p = zero_params();
        p.sq_thread_idle = 10;
        assert_eq!(
            validate_and_compute_ring_geometry(4, &mut p),
            Err(LinuxError::EINVAL)
        );
        let mut p = zero_params();
        p.wq_fd = 3;
        assert_eq!(
            validate_and_compute_ring_geometry(4, &mut p),
            Err(LinuxError::EINVAL)
        );

        let unsupported = [
            IORING_SETUP_IOPOLL,
            IORING_SETUP_SQPOLL,
            IORING_SETUP_NO_SQARRAY,
            IORING_SETUP_SINGLE_ISSUER,
            IORING_SETUP_DEFER_TASKRUN,
            IORING_SETUP_COOP_TASKRUN,
            IORING_SETUP_R_DISABLED,
            IORING_SETUP_SQE128,
            IORING_SETUP_CQE32,
            IORING_SETUP_ATTACH_WQ,
            IORING_SETUP_NO_MMAP,
            IORING_SETUP_REGISTERED_FD_ONLY,
            1u32 << 31,
        ];
        for flag in unsupported {
            let mut p = zero_params();
            p.flags = flag;
            assert_eq!(
                validate_and_compute_ring_geometry(4, &mut p),
                Err(LinuxError::EINVAL),
                "flag {flag:#x} must be rejected"
            );
        }
    }

    #[test]
    fn powers_of_two_clamp_and_cqsize_geometry_match_contract() {
        let mut p = zero_params();
        p.flags = IORING_SETUP_SUBMIT_ALL;
        let layout = validate_and_compute_ring_geometry(3, &mut p).unwrap();
        assert_eq!(layout.sq_entries, 4);
        assert_eq!(layout.cq_entries, 8);
        assert_eq!(p.sq_entries, 4);
        assert_eq!(p.cq_entries, 8);
        assert_eq!(p.features, V1_FEATURES);
        assert_eq!(layout.rings_alloc_bytes % PAGE_SIZE_4K, 0);
        assert_eq!(layout.sqes_alloc_bytes % PAGE_SIZE_4K, 0);
        assert_eq!(layout.sqes_alloc_bytes, PAGE_SIZE_4K);
        assert!(layout.cqes_off + (layout.cq_entries as usize) * 16 <= layout.sq_array_off);
        assert!(layout.sq_array_off + (layout.sq_entries as usize) * 4 <= layout.rings_raw_bytes);
        assert!(layout.rings_raw_bytes <= layout.rings_alloc_bytes);

        let mut p = zero_params();
        p.flags = IORING_SETUP_CLAMP;
        let layout = validate_and_compute_ring_geometry(100_000, &mut p).unwrap();
        assert_eq!(layout.sq_entries, IORING_MAX_ENTRIES);
        assert_eq!(layout.cq_entries, IORING_MAX_CQ_ENTRIES);

        let mut p = zero_params();
        p.flags = IORING_SETUP_CQSIZE;
        p.cq_entries = 0;
        assert_eq!(
            validate_and_compute_ring_geometry(4, &mut p),
            Err(LinuxError::EINVAL)
        );

        let mut p = zero_params();
        p.flags = IORING_SETUP_CQSIZE;
        p.cq_entries = IORING_MAX_CQ_ENTRIES + 1;
        assert_eq!(
            validate_and_compute_ring_geometry(4, &mut p),
            Err(LinuxError::EINVAL)
        );

        let mut p = zero_params();
        p.flags = IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP;
        p.cq_entries = IORING_MAX_CQ_ENTRIES + 123;
        let layout = validate_and_compute_ring_geometry(4, &mut p).unwrap();
        assert_eq!(layout.sq_entries, 4);
        assert_eq!(layout.cq_entries, IORING_MAX_CQ_ENTRIES);

        let mut p = zero_params();
        p.flags = IORING_SETUP_CQSIZE;
        p.cq_entries = 12;
        let layout = validate_and_compute_ring_geometry(4, &mut p).unwrap();
        assert_eq!(layout.sq_entries, 4);
        assert_eq!(layout.cq_entries, 16);

        let mut p = zero_params();
        p.flags = IORING_SETUP_CQSIZE;
        p.cq_entries = 4;
        assert_eq!(
            validate_and_compute_ring_geometry(8, &mut p),
            Err(LinuxError::EINVAL)
        );
    }
}
