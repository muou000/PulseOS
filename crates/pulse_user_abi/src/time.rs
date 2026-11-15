//! Timer notification input. User callback addresses remain opaque data.

use linux_raw_sys::general::{sigevent, sigevent__bindgen_ty_1, sigval};

use crate::{AbiDecodeError, AbiReader, FromUserAbi, UserAbiType};

const _: () = {
    assert!(core::mem::size_of::<sigevent>() == 64);
    assert!(core::mem::offset_of!(sigevent, sigev_value) == 0);
    assert!(core::mem::offset_of!(sigevent, sigev_signo) == 8);
    assert!(core::mem::offset_of!(sigevent, sigev_notify) == 12);
    assert!(core::mem::offset_of!(sigevent, _sigev_un) == 16);
};

impl UserAbiType for sigevent {
    type Buffer = [u8; 64];
}

impl FromUserAbi for sigevent {
    fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
        let value = reader.read()?;
        let signo = reader.read()?;
        let notify = reader.read()?;
        let mut words = [0; 12];
        for word in &mut words {
            *word = reader.read()?;
        }
        // Decode opaque notification data into integer storage, including
        // SIGEV_THREAD's userspace callback address. Never construct its Rust
        // function-pointer union member. Timer consumers only read signo/notify.
        Ok(Self {
            sigev_value: sigval { sival_ptr: value },
            sigev_signo: signo,
            sigev_notify: notify,
            _sigev_un: sigevent__bindgen_ty_1 { _pad: words },
        })
    }
}

#[cfg(test)]
mod tests {
    use axerrno::AxError;
    use linux_raw_sys::general::sigevent;

    use crate::{decode_from_bytes, read_user_value_with};

    #[test]
    fn sigevent_keeps_opaque_thread_callback_bytes_as_data() {
        let mut raw = [0xff; 64];
        raw[8..12].copy_from_slice(&14i32.to_ne_bytes());
        raw[12..16].copy_from_slice(&2i32.to_ne_bytes()); // SIGEV_THREAD
        let event = decode_from_bytes::<sigevent>(&raw).unwrap();
        assert_eq!(event.sigev_signo, 14);
        assert_eq!(event.sigev_notify, 2);
    }

    #[test]
    fn sigevent_preserves_invalid_notification_values_for_syscall_validation() {
        let event = decode_from_bytes::<sigevent>(&[0xff; 64]).unwrap();
        assert_eq!(event.sigev_signo, -1);
        assert_eq!(event.sigev_notify, -1);
    }

    #[test]
    fn sigevent_requires_a_full_copy_before_decoding() {
        let result = read_user_value_with::<sigevent>(0x4000, |_, dst| {
            dst[..63].fill(0xff);
            Ok(63)
        });
        assert!(matches!(result, Err(AxError::BadAddress)));
    }
}
