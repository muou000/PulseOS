//! System information output. Linux's reserved and implicit padding bytes are
//! encoded from an initialized buffer, never from the Rust object layout.

use linux_raw_sys::system::sysinfo;

use crate::{AbiWriter, IntoUserAbi, UserAbiType, encode_field_at};

const _: () = assert!(core::mem::size_of::<sysinfo>() == 112);

impl UserAbiType for sysinfo {
    type Buffer = [u8; 112];
}

impl IntoUserAbi for sysinfo {
    fn encode_abi(&self, writer: &mut AbiWriter<'_>) {
        let Self {
            uptime,
            loads,
            totalram,
            freeram,
            sharedram,
            bufferram,
            totalswap,
            freeswap,
            procs,
            pad,
            totalhigh,
            freehigh,
            mem_unit,
            _f: _,
        } = self;
        let bytes = writer.take_exact_mut(112);
        macro_rules! field {
            ($($name:ident),+ $(,)?) => {$(
                encode_field_at(bytes, core::mem::offset_of!(sysinfo, $name), $name);
            )+};
        }
        field!(
            uptime, totalram, freeram, sharedram, bufferram, totalswap, freeswap, procs, pad,
            totalhigh, freehigh, mem_unit
        );
        for (index, load) in loads.iter().enumerate() {
            encode_field_at(
                bytes,
                core::mem::offset_of!(sysinfo, loads) + index * 8,
                load,
            );
        }
        // `_f` has zero length on both 64-bit guest ABIs. AbiWriter initialized
        // the implicit padding at 84..88 and 108..112 before writing fields.
    }
}

#[cfg(test)]
mod tests {
    use linux_raw_sys::system::{__IncompleteArrayField, sysinfo};

    use crate::encode_to_buffer;

    #[test]
    fn sysinfo_initializes_interior_and_tail_padding() {
        let info = sysinfo {
            uptime: 42,
            loads: [1, 2, 3],
            totalram: 4096,
            freeram: 2048,
            sharedram: 0,
            bufferram: 0,
            totalswap: 0,
            freeswap: 0,
            procs: 7,
            pad: 0,
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 1,
            _f: __IncompleteArrayField::new(),
        };
        let bytes = encode_to_buffer(&info);
        assert_eq!(bytes.len(), 112);
        assert_eq!(&bytes[..8], &42i64.to_ne_bytes());
        assert_eq!(&bytes[8..16], &1u64.to_ne_bytes());
        assert_eq!(&bytes[16..24], &2u64.to_ne_bytes());
        assert_eq!(&bytes[24..32], &3u64.to_ne_bytes());
        assert_eq!(&bytes[80..82], &7u16.to_ne_bytes());
        assert_eq!(&bytes[82..88], &[0; 6]);
        assert_eq!(&bytes[104..108], &1u32.to_ne_bytes());
        assert_eq!(&bytes[108..112], &[0; 4]);
    }
}
