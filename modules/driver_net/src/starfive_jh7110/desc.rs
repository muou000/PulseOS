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
    /// Reads a 16-byte DMA descriptor from the given raw pointer via volatile 32-bit word reads.
    ///
    /// # Safety
    ///
    /// The caller must ensure all of the following preconditions:
    /// - **Alignment**: `ptr` must be properly aligned to at least a 16-byte boundary
    ///   (`core::mem::align_of::<DmaDesc>() == 16`).
    /// - **Range**: `ptr` must be non-null and valid for reads of [`DESC_SIZE`] (16 contiguous bytes,
    ///   spanning four 32-bit words) within a single live allocation (e.g., the fixed DMA descriptor ring).
    ///   The memory range `[ptr, ptr + DESC_SIZE)` must not wrap around the address space.
    /// - **Initialization**: All four 32-bit words (16 bytes) at `ptr` must be fully initialized memory.
    /// - **DMA ownership**: The caller must satisfy one of:
    ///   1. The descriptor is owned by the CPU (`OWN` bit is 0), guaranteeing hardware will not mutate
    ///      the descriptor during or after the read until ownership is surrendered; or
    ///   2. The caller is performing an ownership-polling read to inspect the descriptor's status word (`words[3]`)
    ///      to determine whether DMA has completed and cleared `OWN`. In this mode, non-status words must not be
    ///      treated as stable until CPU ownership is established.
    /// - **Cache synchronization**: If the memory region backing `ptr` is subject to CPU caching, the caller
    ///   must have synchronized DMA cache state (e.g., via `DmaOps::dma_sync`) and established acquire
    ///   ordering (e.g., `core::sync::atomic::fence(Ordering::Acquire)`) prior to reading, ensuring that writes
    ///   completed by the DMA controller are visible to the CPU.
    /// - **No-alias conditions**: No concurrent CPU writes and no active mutable Rust references (`&mut`)
    ///   may alias `*ptr` for the duration of the read operation.
    pub(crate) unsafe fn read(ptr: *const Self) -> Self {
        debug_assert!(!ptr.is_null(), "DmaDesc::read: null pointer");
        debug_assert_eq!(
            ptr as usize % core::mem::align_of::<Self>(),
            0,
            "DmaDesc::read: misaligned pointer"
        );
        let mut words = [0u32; 4];
        for (index, word) in words.iter_mut().enumerate() {
            // SAFETY:
            // Operation: `read_volatile` on word `index` (`ptr` offset `index * 4`).
            // Contract: pointer must be valid for reads of `u32`, aligned to 4 bytes, initialized,
            // and free from concurrent conflicting writes.
            // 1. Alignment: `ptr` is 16-byte aligned by caller precondition. Offset `index * 4` (0, 4, 8, 12)
            //    preserves 4-byte alignment required for `u32`.
            // 2. Range: `ptr` is non-null and valid for 16 contiguous bytes in a single allocation by
            //    caller precondition. Bytes `index * 4..(index + 1) * 4` are strictly within bounds without wraparound.
            // 3. Initialization: Caller guarantees all 4 words are initialized memory.
            // 4. Aliasing: Caller guarantees no concurrent CPU writes or `&mut` aliases exist.
            *word = unsafe { read_volatile(core::ptr::addr_of!((*ptr).words[index])) };
        }
        Self { words }
    }

    /// Writes a 16-byte DMA descriptor to the given raw pointer via volatile 32-bit word writes.
    ///
    /// # Safety
    ///
    /// The caller must ensure all of the following preconditions:
    /// - **Alignment**: `ptr` must be properly aligned to at least a 16-byte boundary
    ///   (`core::mem::align_of::<DmaDesc>() == 16`).
    /// - **Range**: `ptr` must be non-null and valid for writes of [`DESC_SIZE`] (16 contiguous bytes,
    ///   spanning four 32-bit words) within a single live allocation (e.g., the fixed DMA descriptor ring).
    ///   The memory range `[ptr, ptr + DESC_SIZE)` must not wrap around the address space.
    /// - **Initialization**: The memory at `ptr` must be allocated and writable for at least 16 bytes.
    ///   Pre-initialization is not required because all four words are completely overwritten.
    /// - **DMA ownership**: The descriptor slot must be owned exclusively by the CPU (i.e. `OWN` bit is 0
    ///   prior to this write, ensuring the DMA controller is not reading from or writing to this slot).
    ///   If this write sets the `OWN` bit to hand ownership to hardware, the CPU surrenders ownership
    ///   only after this function returns and following necessary release fences and cache synchronization.
    /// - **Cache synchronization**: After writing the descriptor, the caller must issue release ordering
    ///   (e.g., `core::sync::atomic::fence(Ordering::Release)`) and synchronize DMA caches (e.g., via
    ///   `DmaOps::dma_sync`) before notifying the hardware controller (e.g., by updating ring tail registers).
    /// - **No-alias conditions**: The caller must hold exclusive access to `*ptr`. No concurrent CPU reads
    ///   or writes and no active Rust references (`&` or `&mut`) may alias the destination memory during
    ///   the write operation.
    pub(crate) unsafe fn write(self, ptr: *mut Self) {
        debug_assert!(!ptr.is_null(), "DmaDesc::write: null pointer");
        debug_assert_eq!(
            ptr as usize % core::mem::align_of::<Self>(),
            0,
            "DmaDesc::write: misaligned pointer"
        );
        for (index, word) in self.words.into_iter().enumerate() {
            // SAFETY:
            // Operation: `write_volatile` on word `index` (`ptr` offset `index * 4`).
            // Contract: pointer must be valid for writes of `u32`, aligned to 4 bytes, and
            // exclusively accessed (no concurrent aliasing reads or writes).
            // 1. Alignment: `ptr` is 16-byte aligned by caller precondition. Each word offset
            //    `index * 4` (0, 4, 8, 12) preserves 4-byte alignment required for `u32`.
            // 2. Range: `ptr` is non-null and valid for 16 contiguous writable bytes in a single allocation
            //    by caller precondition. Bytes `index * 4..(index + 1) * 4` are strictly within bounds.
            // 3. DMA ownership & aliasing: Caller guarantees exclusive CPU ownership; the DMA controller is
            //    not accessing this slot, and no concurrent CPU threads or aliasing references exist.
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

    #[test]
    fn descriptor_read_write_roundtrip_preserves_words_and_ownership() {
        let mut slot = DmaDesc::empty();
        let slot_ptr = core::ptr::addr_of_mut!(slot);

        let tx = DmaDesc::tx(0xdead_beef_0000, 1024);
        // SAFETY: `slot_ptr` points to a 16-byte aligned, live stack allocation of `DmaDesc`,
        // exclusively owned by this test thread without concurrency or aliasing references.
        unsafe { tx.write(slot_ptr) };

        // SAFETY: `slot_ptr` points to the same 16-byte aligned, initialized `DmaDesc` allocation,
        // exclusively owned by this test thread.
        let read_back = unsafe { DmaDesc::read(slot_ptr) };
        assert_eq!(read_back.words(), tx.words());
        assert!(read_back.owned_by_dma());

        let rx = DmaDesc::rx(0x1234_5678);
        // SAFETY: Same contract as above for write.
        unsafe { rx.write(slot_ptr) };

        // SAFETY: Same contract as above for read.
        let read_back_rx = unsafe { DmaDesc::read(slot_ptr) };
        assert_eq!(read_back_rx.words(), rx.words());
        assert!(read_back_rx.owned_by_dma());
    }
}
