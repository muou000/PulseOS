//! Task ABI wire values whose userspace addresses are data, never Rust functions.

use linux_raw_sys::general::{siginfo, siginfo__bindgen_ty_1};

use crate::{AbiDecodeError, AbiReader, FromUserAbi, UserAbiType};

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
