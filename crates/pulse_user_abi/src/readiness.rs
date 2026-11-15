use linux_raw_sys::general::epoll_event;

use crate::{AbiDecodeError, AbiReader, FromUserAbi, UserAbiType, decode_field_at};

// epoll_event is packed on the host and naturally aligned on RV64/LA64.
// Decode fields by ABI offsets without borrowing packed fields or padding.
impl UserAbiType for epoll_event {
    type Buffer = [u8; core::mem::size_of::<Self>()];
}

impl FromUserAbi for epoll_event {
    fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
        let bytes = reader.take_exact(core::mem::size_of::<Self>())?;
        Ok(Self {
            events: decode_field_at(bytes, core::mem::offset_of!(Self, events))?,
            data: decode_field_at(bytes, core::mem::offset_of!(Self, data))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axerrno::AxError;
    use linux_raw_sys::general::epoll_event;

    use crate::{abi_size_of, decode_from_bytes, read_user_value_with};

    #[test]
    fn epoll_event_decodes_native_fields_and_ignores_padding() {
        let mut bytes = [0xa5; core::mem::size_of::<epoll_event>()];
        bytes[..4].copy_from_slice(&0x8000_0001u32.to_ne_bytes());
        let offset = core::mem::offset_of!(epoll_event, data);
        bytes[offset..offset + 8].copy_from_slice(&0xfedc_ba98_7654_3210u64.to_ne_bytes());
        let event = decode_from_bytes::<epoll_event>(&bytes).unwrap();
        let events = event.events;
        let data = event.data;
        assert_eq!(events, 0x8000_0001);
        assert_eq!(data, 0xfedc_ba98_7654_3210);
    }

    #[test]
    fn epoll_event_read_rejects_faults_and_every_short_copy() {
        for copied in 0..abi_size_of::<epoll_event>() {
            let result = read_user_value_with::<epoll_event>(0x4000, |_, bytes| {
                bytes[..copied].fill(0xff);
                Ok(copied)
            });
            assert_eq!(result.err(), Some(AxError::BadAddress));
        }
        assert_eq!(
            read_user_value_with::<epoll_event>(0, |_, _| Err(AxError::BadAddress)).err(),
            Some(AxError::BadAddress)
        );
    }
}
