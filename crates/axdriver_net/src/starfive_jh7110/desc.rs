use core::ptr::{read_volatile, write_volatile};

pub(crate) const DESC_SIZE: usize = core::mem::size_of::<DmaDesc>();

const OWN: u32 = 1 << 31;
const TX_IOC: u32 = 1 << 31;
const TX_FIRST: u32 = 1 << 29;
const TX_LAST: u32 = 1 << 28;
const RX_IOC: u32 = 1 << 30;
const RX_BUFFER1_VALID: u32 = 1 << 24;
const RX_FIRST: u32 = 1 << 29;
const RX_LAST: u32 = 1 << 28;
const RX_ERROR: u32 = 1 << 15;
const RX_PACKET_LEN: u32 = 0x7fff;

#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub(crate) struct DmaDesc {
    words: [u32; 4],
}

impl DmaDesc {
    pub(crate) unsafe fn read(ptr: *const Self) -> Self {
        Self {
            words: [
                unsafe { read_volatile(core::ptr::addr_of!((*ptr).words[0])) },
                unsafe { read_volatile(core::ptr::addr_of!((*ptr).words[1])) },
                unsafe { read_volatile(core::ptr::addr_of!((*ptr).words[2])) },
                unsafe { read_volatile(core::ptr::addr_of!((*ptr).words[3])) },
            ],
        }
    }

    pub(crate) unsafe fn write(self, ptr: *mut Self) {
        for (index, word) in self.words.into_iter().enumerate() {
            unsafe { write_volatile(core::ptr::addr_of_mut!((*ptr).words[index]), word) };
        }
    }

    pub(crate) fn rx(buffer_addr: u64) -> Self {
        Self {
            words: [
                buffer_addr as u32,
                (buffer_addr >> 32) as u32,
                0,
                OWN | RX_IOC | RX_BUFFER1_VALID,
            ],
        }
    }

    pub(crate) fn tx(buffer_addr: u64, packet_len: usize) -> Self {
        Self {
            words: [
                buffer_addr as u32,
                (buffer_addr >> 32) as u32,
                (packet_len as u32) | TX_IOC,
                (packet_len as u32) | TX_FIRST | TX_LAST | OWN,
            ],
        }
    }

    pub(crate) const fn empty() -> Self {
        Self { words: [0; 4] }
    }

    pub(crate) const fn owned_by_dma(&self) -> bool {
        self.words[3] & OWN != 0
    }

    pub(crate) const fn status_word(&self) -> u32 {
        self.words[3]
    }

    pub(crate) const fn control_word(&self) -> u32 {
        self.words[2]
    }

    pub(crate) const fn received_len(&self) -> Option<usize> {
        let status = self.words[3];
        if status & OWN != 0
            || status & RX_ERROR != 0
            || status & RX_FIRST == 0
            || status & RX_LAST == 0
        {
            None
        } else {
            Some((status & RX_PACKET_LEN) as usize)
        }
    }

    #[cfg(test)]
    pub(crate) const fn rx_writeback(packet_len: usize) -> Self {
        Self {
            words: [
                0,
                0,
                0,
                RX_FIRST | RX_LAST | (packet_len as u32 & RX_PACKET_LEN),
            ],
        }
    }

    #[cfg(test)]
    pub(crate) const fn words(&self) -> [u32; 4] {
        self.words
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_layout_matches_dwmac5_enhanced_format() {
        assert_eq!(DESC_SIZE, 16);
        assert_eq!(core::mem::align_of::<DmaDesc>(), 16);
    }

    #[test]
    fn rx_descriptor_preserves_40_bit_buffer_address() {
        let desc = DmaDesc::rx(0x12_3456_7890);
        assert_eq!(desc.words()[0], 0x3456_7890);
        assert_eq!(desc.words()[1], 0x12);
        assert!(desc.owned_by_dma());
        assert_eq!(
            desc.words()[3] & (RX_IOC | RX_BUFFER1_VALID),
            RX_IOC | RX_BUFFER1_VALID
        );
    }

    #[test]
    fn tx_descriptor_is_one_complete_frame() {
        let desc = DmaDesc::tx(0x01_2345_6780, 1514);
        assert_eq!(desc.words()[0], 0x2345_6780);
        assert_eq!(desc.words()[1], 1);
        assert_eq!(desc.words()[2] & 0x3fff, 1514);
        assert_eq!(desc.words()[3] & 0x7fff, 1514);
        assert_eq!(
            desc.words()[3] & (TX_FIRST | TX_LAST | OWN),
            TX_FIRST | TX_LAST | OWN
        );
    }

    #[test]
    fn rx_writeback_rejects_partial_and_error_frames() {
        let mut desc = DmaDesc::empty();
        desc.words[3] = RX_FIRST | RX_LAST | 128;
        assert_eq!(desc.received_len(), Some(128));
        desc.words[3] |= RX_ERROR;
        assert_eq!(desc.received_len(), None);
        desc.words[3] = RX_FIRST | 128;
        assert_eq!(desc.received_len(), None);
    }
}
