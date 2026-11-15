//! Task ABI wire values whose userspace addresses are data, never Rust functions.

use linux_raw_sys::general::{siginfo, siginfo__bindgen_ty_1};

use crate::{AbiDecodeError, AbiReader, FromUserAbi, UserAbiType};

/// Initialized Linux siginfo bytes. Incoming union payloads remain opaque;
/// kernel-generated records initialize all padding and unused fields to zero.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalInfo {
    bytes: [u8; 128],
}

crate::impl_user_abi_struct! {
    for SignalInfo, size = 128 => {
        bytes: [u8; 128],
    }
}

impl SignalInfo {
    pub fn new(signo: i32, code: i32) -> Self {
        let mut info = Self { bytes: [0; 128] };
        info.set_signo(signo);
        info.bytes[8..12].copy_from_slice(&code.to_ne_bytes());
        info
    }

    pub fn for_kill(signo: i32, code: i32, pid: i32, uid: u32) -> Self {
        let mut info = Self::new(signo, code);
        info.bytes[16..20].copy_from_slice(&pid.to_ne_bytes());
        info.bytes[20..24].copy_from_slice(&uid.to_ne_bytes());
        info
    }

    pub fn for_child(signo: i32, code: i32, pid: i32, uid: u32, status: i32) -> Self {
        let mut info = Self::for_kill(signo, code, pid, uid);
        info.bytes[24..28].copy_from_slice(&status.to_ne_bytes());
        info
    }

    pub fn for_fault(signo: i32, code: i32, address: u64) -> Self {
        let mut info = Self::new(signo, code);
        info.bytes[16..24].copy_from_slice(&address.to_ne_bytes());
        info
    }

    pub fn signo(&self) -> i32 {
        i32::from_ne_bytes(self.bytes[..4].try_into().unwrap())
    }

    pub fn code(&self) -> i32 {
        i32::from_ne_bytes(self.bytes[8..12].try_into().unwrap())
    }

    pub fn set_signo(&mut self, signo: i32) {
        self.bytes[..4].copy_from_slice(&signo.to_ne_bytes());
    }
}

// These offsets describe both supported guest ABIs. Check the generated
// Linux layouts without accessing any union value or its Rust padding.
const _: () = {
    use linux_raw_sys::general::{
        __sifields__bindgen_ty_1 as Kill, __sifields__bindgen_ty_4 as Child,
        __sifields__bindgen_ty_5 as Fault, siginfo__bindgen_ty_1__bindgen_ty_1 as Header,
    };
    assert!(core::mem::offset_of!(Header, si_signo) == 0);
    assert!(core::mem::offset_of!(Header, si_errno) == 4);
    assert!(core::mem::offset_of!(Header, si_code) == 8);
    assert!(core::mem::offset_of!(Header, _sifields) == 16);
    assert!(core::mem::offset_of!(Kill, _pid) == 0);
    assert!(core::mem::offset_of!(Kill, _uid) == 4);
    assert!(core::mem::offset_of!(Child, _pid) == 0);
    assert!(core::mem::offset_of!(Child, _uid) == 4);
    assert!(core::mem::offset_of!(Child, _status) == 8);
    assert!(core::mem::offset_of!(Fault, _addr) == 0);
    assert!(core::mem::size_of::<usize>() == 8);
};

/// The fixed-size userspace record returned by signalfd reads.
///
/// This intentionally is not `siginfo_t`: Linux exposes a stable 128-byte
/// layout so a caller's ABI does not change with `siginfo_t` internals.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SignalFdSigInfo {
    pub ssi_signo: u32,
    pub ssi_errno: i32,
    pub ssi_code: i32,
    pub ssi_pid: u32,
    pub ssi_uid: u32,
    pub ssi_fd: i32,
    pub ssi_tid: u32,
    pub ssi_band: u32,
    pub ssi_overrun: u32,
    pub ssi_trapno: u32,
    pub ssi_status: i32,
    pub ssi_int: i32,
    pub ssi_ptr: u64,
    pub ssi_utime: u64,
    pub ssi_stime: u64,
    pub ssi_addr: u64,
    pub ssi_addr_lsb: u16,
    pub __pad2: u16,
    pub ssi_syscall: i32,
    pub ssi_call_addr: u64,
    pub ssi_arch: u32,
    pub __pad: [u8; 28],
}

crate::impl_user_abi_struct! {
    for SignalFdSigInfo, size = 128 => {
        ssi_signo: u32,
        ssi_errno: i32,
        ssi_code: i32,
        ssi_pid: u32,
        ssi_uid: u32,
        ssi_fd: i32,
        ssi_tid: u32,
        ssi_band: u32,
        ssi_overrun: u32,
        ssi_trapno: u32,
        ssi_status: i32,
        ssi_int: i32,
        ssi_ptr: u64,
        ssi_utime: u64,
        ssi_stime: u64,
        ssi_addr: u64,
        ssi_addr_lsb: u16,
        __pad2: u16,
        ssi_syscall: i32,
        ssi_call_addr: u64,
        ssi_arch: u32,
        __pad: [u8; 28],
    }
}

/// The RISC-V 64 and LoongArch64 kernel signal-action ABI.
///
/// A handler can be SIG_DFL (0), SIG_IGN (1), or a userspace instruction address.
/// None of these addresses is materialized as a Rust function pointer.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalAction {
    pub handler: u64,
    pub flags: u64,
    pub mask: u64,
}

crate::impl_user_abi_struct! {
    for SignalAction, size = 24 => {
        handler: u64,
        flags: u64,
        mask: u64,
    }
}

impl UserAbiType for siginfo {
    type Buffer = [u8; 128];
}

impl FromUserAbi for siginfo {
    fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
        // Construct the union's integer storage member explicitly. No union
        // field, Rust padding, pointer, or function value is read from bytes.
        let mut words = [0; 32];
        for word in &mut words {
            *word = reader.read()?;
        }
        Ok(Self {
            __bindgen_anon_1: siginfo__bindgen_ty_1 { _si_pad: words },
        })
    }
}

const _: () = assert!(core::mem::size_of::<siginfo>() == 128);

#[cfg(test)]
mod tests {
    use axerrno::AxError;

    use super::*;
    use crate::{decode_from_bytes, read_user_value_with};

    #[test]
    fn signalfd_record_encodes_fields_without_exposing_padding() {
        let info = SignalFdSigInfo {
            ssi_signo: 17,
            ssi_code: 1,
            ssi_pid: 42,
            ssi_uid: 1000,
            ssi_status: 7,
            ssi_ptr: 0x1234_5678_9abc_def0,
            ssi_addr_lsb: 12,
            ssi_syscall: -1,
            ssi_arch: 0xc00000f3,
            ..SignalFdSigInfo::default()
        };
        let mut expected = [0; 128];
        expected[0..4].copy_from_slice(&17u32.to_ne_bytes());
        expected[8..12].copy_from_slice(&1i32.to_ne_bytes());
        expected[12..16].copy_from_slice(&42u32.to_ne_bytes());
        expected[16..20].copy_from_slice(&1000u32.to_ne_bytes());
        expected[40..44].copy_from_slice(&7i32.to_ne_bytes());
        expected[48..56].copy_from_slice(&0x1234_5678_9abc_def0u64.to_ne_bytes());
        expected[80..82].copy_from_slice(&12u16.to_ne_bytes());
        expected[84..88].copy_from_slice(&(-1i32).to_ne_bytes());
        expected[96..100].copy_from_slice(&0xc00000f3u32.to_ne_bytes());
        assert_eq!(crate::encode_to_buffer(&info), expected);
    }

    #[test]
    fn signal_info_output_initializes_padding_and_unused_union_bytes() {
        use crate::encode_to_buffer;

        let info = SignalInfo::for_child(17, 1, 123, 456, 7);
        let bytes = encode_to_buffer(&info);
        assert_eq!(&bytes[0..4], &17i32.to_ne_bytes());
        assert_eq!(&bytes[4..8], &[0; 4]);
        assert_eq!(&bytes[8..12], &1i32.to_ne_bytes());
        assert_eq!(&bytes[12..16], &[0; 4]);
        assert_eq!(&bytes[16..20], &123i32.to_ne_bytes());
        assert_eq!(&bytes[20..24], &456u32.to_ne_bytes());
        assert_eq!(&bytes[24..28], &7i32.to_ne_bytes());
        assert_eq!(&bytes[28..], &[0; 100]);
    }

    #[test]
    fn signal_info_fault_output_preserves_address_and_zeroes_unused_fields() {
        let info = SignalInfo::for_fault(11, 2, 0x1234_5678_9abc_def0);
        let bytes = crate::encode_to_buffer(&info);
        assert_eq!(&bytes[0..4], &11i32.to_ne_bytes());
        assert_eq!(&bytes[4..8], &[0; 4]);
        assert_eq!(&bytes[8..12], &2i32.to_ne_bytes());
        assert_eq!(&bytes[12..16], &[0; 4]);
        assert_eq!(&bytes[16..24], &0x1234_5678_9abc_def0u64.to_ne_bytes());
        assert_eq!(&bytes[24..], &[0; 104]);
    }

    #[test]
    fn signal_info_opaque_payload_survives_header_update_and_short_write() {
        use crate::{encode_to_buffer, write_user_value_with};

        let mut info = decode_from_bytes::<SignalInfo>(&[0xab; 128]).unwrap();
        info.set_signo(42);
        assert_eq!(info.signo(), 42);
        assert_eq!(info.code(), i32::from_ne_bytes([0xab; 4]));
        let bytes = encode_to_buffer(&info);
        assert_eq!(&bytes[4..], &[0xab; 124]);
        let mut prefix = [0; 13];
        assert_eq!(
            write_user_value_with(0x4ff3, &info, |_, bytes| {
                prefix.copy_from_slice(&bytes[..13]);
                Ok(13)
            }),
            Err(AxError::BadAddress),
        );
        assert_eq!(&prefix[..4], &42i32.to_ne_bytes());
        assert_eq!(&prefix[4..], &[0xab; 9]);
    }

    #[test]
    fn signal_action_preserves_sentinel_and_arbitrary_handler_addresses() {
        for handler in [0u64, 1, 0x1234_5678, u64::MAX] {
            let mut bytes = [0xff; 24];
            bytes[..8].copy_from_slice(&handler.to_ne_bytes());
            let action = decode_from_bytes::<SignalAction>(&bytes).unwrap();
            assert_eq!(action.handler, handler);
            assert_eq!(action.flags, u64::MAX);
            assert_eq!(action.mask, u64::MAX);
        }
    }

    #[test]
    fn signal_action_short_copy_faults_before_interpreting_fields() {
        assert_eq!(
            read_user_value_with::<SignalAction>(0x4000, |_, bytes| {
                bytes[..16].fill(0xff);
                Ok(16)
            }),
            Err(AxError::BadAddress),
        );
        assert!(decode_from_bytes::<SignalAction>(&[0; 23]).is_err());
    }

    #[test]
    fn siginfo_preserves_opaque_integer_storage_and_rejects_short_copies() {
        assert!(decode_from_bytes::<siginfo>(&[0xff; 128]).is_ok());
        assert!(decode_from_bytes::<siginfo>(&[0; 127]).is_err());
        assert_eq!(
            read_user_value_with::<siginfo>(0x4000, |_, bytes| {
                bytes[..127].fill(0xff);
                Ok(127)
            })
            .err(),
            Some(AxError::BadAddress),
        );
    }
}
