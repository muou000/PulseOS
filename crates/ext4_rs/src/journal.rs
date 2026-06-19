use crate::prelude::*;
use crate::ext4_defs::BlockDevice;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::Mutex;
use core::any::Any;
use core::mem::size_of;

// JBD2 Constants
pub const JBD2_MAGIC_NUMBER: u32 = 0xC03B3998;
pub const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
pub const JBD2_COMMIT_BLOCK: u32 = 2;
pub const JBD2_SUPERBLOCK_V2: u32 = 4;

pub const JBD2_FLAG_ESCAPE: u32 = 1;
pub const JBD2_FLAG_LAST_TAG: u32 = 8;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Jbd2Header {
    pub h_magic: u32,
    pub h_blocktype: u32,
    pub h_sequence: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Jbd2Superblock {
    pub s_header: Jbd2Header,
    pub s_blocksize: u32,
    pub s_maxlen: u32,
    pub s_first: u32,
    pub s_sequence: u32,
    pub s_start: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Jbd2BlockTag {
    pub t_blocknr: u32,
    pub t_flags: u32,
}

pub struct JournalState {
    pub is_in_transaction: bool,
    pub metadata_writing: bool,
    pub current_sequence: u32,
    pub nesting_count: usize,
    pub cached_blocks: BTreeMap<u64, Vec<u8>>, // fs block index -> data
    pub journal_blocks: Vec<u64>,               // physical block indices of the journal inode
    pub journal_head: u32,                      // current write block offset in journal_blocks (starts at 1)
}

pub struct JournalBlockDevice {
    pub underlying: Arc<dyn BlockDevice>,
    pub state: Mutex<JournalState>,
}

impl JournalBlockDevice {
    pub fn new(underlying: Arc<dyn BlockDevice>) -> Self {
        Self {
            underlying,
            state: Mutex::new(JournalState {
                is_in_transaction: false,
                metadata_writing: false,
                current_sequence: 100, // Start with a generic sequence number
                nesting_count: 0,
                cached_blocks: BTreeMap::new(),
                journal_blocks: Vec::new(),
                journal_head: 1,
            }),
        }
    }

    pub fn init_journal(&self, journal_blocks: Vec<u64>) {
        let mut state = self.state.lock();
        log::info!("JournalBlockDevice::init_journal: resolved {} blocks", journal_blocks.len());
        state.journal_blocks = journal_blocks;
        state.journal_head = 1;
    }

    // Helper to read a block from the journal space
    fn read_journal_block(&self, state: &JournalState, journal_block_idx: u32, buf: &mut [u8]) {
        let block_size = self.block_size();
        if (journal_block_idx as usize) < state.journal_blocks.len() {
            let pblk = state.journal_blocks[journal_block_idx as usize];
            self.underlying.read_offset(pblk as usize * block_size, buf);
        } else {
            log::error!("read_journal_block: Index out of bounds ({} >= {})", journal_block_idx, state.journal_blocks.len());
        }
    }

    // Helper to write a block to the journal space
    fn write_journal_block(&self, state: &JournalState, journal_block_idx: u32, buf: &[u8]) {
        let block_size = self.block_size();
        if (journal_block_idx as usize) < state.journal_blocks.len() {
            let pblk = state.journal_blocks[journal_block_idx as usize];
            self.underlying.write_offset(pblk as usize * block_size, buf);
        } else {
            log::error!("write_journal_block: Index out of bounds ({} >= {})", journal_block_idx, state.journal_blocks.len());
        }
    }

    fn next_journal_block(&self, state: &JournalState, curr: u32) -> u32 {
        let mut next = curr + 1;
        let max_len = state.journal_blocks.len() as u32;
        if next >= max_len {
            next = 1; // Wrap around to block 1 (JBD2 Superblock is block 0)
        }
        next
    }

    // Write a new state superblock to journal
    fn write_journal_superblock(&self, state: &JournalState, start_block: u32, sequence: u32) -> Result<()> {
        let block_size = self.block_size();
        let mut sb_buf = vec![0u8; block_size];
        
        // Read existing superblock to preserve details if any
        self.read_journal_block(state, 0, &mut sb_buf);
        
        let mut j_sb: Jbd2Superblock = unsafe { core::ptr::read_unaligned(sb_buf.as_ptr() as *const Jbd2Superblock) };
        j_sb.s_header.h_magic = JBD2_MAGIC_NUMBER.to_be();
        j_sb.s_header.h_blocktype = JBD2_SUPERBLOCK_V2.to_be();
        j_sb.s_blocksize = (block_size as u32).to_be();
        j_sb.s_maxlen = (state.journal_blocks.len() as u32).to_be();
        j_sb.s_first = 1u32.to_be();
        j_sb.s_sequence = sequence.to_be();
        j_sb.s_start = start_block.to_be();

        unsafe {
            core::ptr::write_unaligned(sb_buf.as_mut_ptr() as *mut Jbd2Superblock, j_sb);
        }
        self.write_journal_block(state, 0, &sb_buf);
        Ok(())
    }

    pub fn start_transaction(&self) {
        let mut state = self.state.lock();
        if state.nesting_count == 0 {
            state.is_in_transaction = true;
            state.metadata_writing = true;
            state.current_sequence += 1;
            state.cached_blocks.clear();
            log::trace!("Transaction started. Sequence = {}", state.current_sequence);
        }
        state.nesting_count += 1;
    }

    pub fn stop_transaction(&self) -> Result<()> {
        let mut commit_needed = false;
        {
            let mut state = self.state.lock();
            if state.nesting_count > 0 {
                state.nesting_count -= 1;
                if state.nesting_count == 0 {
                    commit_needed = true;
                }
            }
        }
        if commit_needed {
            self.commit_transaction()?;
        }
        Ok(())
    }

    pub fn commit_transaction(&self) -> Result<()> {
        let mut state = self.state.lock();
        if !state.is_in_transaction {
            return Ok(());
        }
        if state.cached_blocks.is_empty() {
            state.is_in_transaction = false;
            return Ok(());
        }

        log::trace!("Committing transaction sequence {} with {} cached blocks", state.current_sequence, state.cached_blocks.len());

        let block_size = self.block_size();
        let num_cached = state.cached_blocks.len();
        
        // Format Descriptor block
        let mut desc_buf = vec![0u8; block_size];
        let header = Jbd2Header {
            h_magic: JBD2_MAGIC_NUMBER.to_be(),
            h_blocktype: JBD2_DESCRIPTOR_BLOCK.to_be(),
            h_sequence: state.current_sequence.to_be(),
        };
        unsafe {
            core::ptr::write_unaligned(desc_buf.as_mut_ptr() as *mut Jbd2Header, header);
        }

        let mut offset = size_of::<Jbd2Header>();
        let mut tags_data = Vec::new();
        
        for (i, (&dest_block, data)) in state.cached_blocks.iter().enumerate() {
            let is_last = i == num_cached - 1;
            let mut flags = 0u32;
            if is_last {
                flags |= JBD2_FLAG_LAST_TAG;
            }
            
            let mut block_data = data.clone();
            if block_data.len() >= 4 && block_data[0..4] == JBD2_MAGIC_NUMBER.to_be_bytes() {
                flags |= JBD2_FLAG_ESCAPE;
                block_data[0..4].fill(0);
            }
            
            let tag = Jbd2BlockTag {
                t_blocknr: (dest_block as u32).to_be(),
                t_flags: flags.to_be(),
            };
            
            if offset + size_of::<Jbd2BlockTag>() <= block_size {
                unsafe {
                    core::ptr::write_unaligned(desc_buf.as_mut_ptr().add(offset) as *mut Jbd2BlockTag, tag);
                }
                offset += size_of::<Jbd2BlockTag>();
            } else {
                log::error!("Transaction exceeds single descriptor block capacity limit!");
                return Err(Ext4Error::new(Errno::ENOSPC));
            }
            tags_data.push(block_data);
        }

        // Write Descriptor block to journal
        let desc_pos = state.journal_head;
        self.write_journal_block(&state, desc_pos, &desc_buf);
        state.journal_head = self.next_journal_block(&state, state.journal_head);

        // Write all metadata blocks to journal
        for block_data in tags_data {
            let pos = state.journal_head;
            self.write_journal_block(&state, pos, &block_data);
            state.journal_head = self.next_journal_block(&state, state.journal_head);
        }

        // Format Commit block
        let mut commit_buf = vec![0u8; block_size];
        let commit_header = Jbd2Header {
            h_magic: JBD2_MAGIC_NUMBER.to_be(),
            h_blocktype: JBD2_COMMIT_BLOCK.to_be(),
            h_sequence: state.current_sequence.to_be(),
        };
        unsafe {
            core::ptr::write_unaligned(commit_buf.as_mut_ptr() as *mut Jbd2Header, commit_header);
        }
        
        // Write Commit block to journal
        let commit_pos = state.journal_head;
        self.write_journal_block(&state, commit_pos, &commit_buf);
        state.journal_head = self.next_journal_block(&state, state.journal_head);

        // Flush the journal blocks to disk
        self.underlying.write_offset(0, &[]); // Flush the underlying device

        // Update JBD2 superblock to indicate the active transactions
        self.write_journal_superblock(&state, desc_pos, state.current_sequence)?;
        self.underlying.write_offset(0, &[]);

        // Checkpoint: Copy the cached blocks to their final destination blocks
        for (&dest_block, data) in &state.cached_blocks {
            self.underlying.write_offset(dest_block as usize * block_size, data);
        }

        // Flush the disk to complete checkpointing
        self.underlying.write_offset(0, &[]);

        // Mark the journal as clean again
        self.write_journal_superblock(&state, 0, state.current_sequence + 1)?;
        self.underlying.write_offset(0, &[]);

        // Clear transaction cache
        state.cached_blocks.clear();
        state.is_in_transaction = false;
        Ok(())
    }

    pub fn recover(&self) -> Result<()> {
        let block_size = self.block_size();
        let state = self.state.lock();
        if state.journal_blocks.is_empty() {
            log::info!("Journal is empty. Skipping recovery.");
            return Ok(());
        }

        let mut sb_buf = vec![0u8; block_size];
        self.read_journal_block(&state, 0, &mut sb_buf);

        let j_sb: Jbd2Superblock = unsafe { core::ptr::read_unaligned(sb_buf.as_ptr() as *const Jbd2Superblock) };
        if u32::from_be(j_sb.s_header.h_magic) != JBD2_MAGIC_NUMBER {
            log::info!("Journal magic invalid. Skipping recovery.");
            return Ok(());
        }

        let start_block = u32::from_be(j_sb.s_start);
        let sequence = u32::from_be(j_sb.s_sequence);
        if start_block == 0 {
            log::info!("Journal is clean. No recovery needed.");
            return Ok(());
        }

        log::info!("Journal is dirty. Replaying starting at block {}, sequence {}...", start_block, sequence);

        let mut curr_block = start_block;
        let mut expected_seq = sequence;

        loop {
            let mut desc_buf = vec![0u8; block_size];
            self.read_journal_block(&state, curr_block, &mut desc_buf);
            let header: Jbd2Header = unsafe { core::ptr::read_unaligned(desc_buf.as_ptr() as *const Jbd2Header) };

            if u32::from_be(header.h_magic) != JBD2_MAGIC_NUMBER {
                break; // End of valid journal space or corruption
            }
            if u32::from_be(header.h_sequence) != expected_seq {
                break; // Sequence mismatch
            }

            let blocktype = u32::from_be(header.h_blocktype);
            if blocktype == JBD2_DESCRIPTOR_BLOCK {
                // Descriptor block - Parse tags
                let mut tags = Vec::new();
                let tag_start = size_of::<Jbd2Header>();
                let mut offset = tag_start;
                
                loop {
                    if offset + size_of::<Jbd2BlockTag>() > block_size {
                        break;
                    }
                    let tag: Jbd2BlockTag = unsafe { core::ptr::read_unaligned(desc_buf.as_ptr().add(offset) as *const Jbd2BlockTag) };
                    tags.push(tag);
                    offset += size_of::<Jbd2BlockTag>();
                    if (u32::from_be(tag.t_flags) & JBD2_FLAG_LAST_TAG) != 0 {
                        break;
                    }
                }

                // Read corresponding metadata blocks following the descriptor
                let mut meta_blocks = Vec::new();
                for _ in 0..tags.len() {
                    curr_block = self.next_journal_block(&state, curr_block);
                    let mut data = vec![0u8; block_size];
                    self.read_journal_block(&state, curr_block, &mut data);
                    meta_blocks.push(data);
                }

                // Expect a commit block next
                curr_block = self.next_journal_block(&state, curr_block);
                let mut commit_buf = vec![0u8; block_size];
                self.read_journal_block(&state, curr_block, &mut commit_buf);
                let commit_header: Jbd2Header = unsafe { core::ptr::read_unaligned(commit_buf.as_ptr() as *const Jbd2Header) };

                if u32::from_be(commit_header.h_magic) != JBD2_MAGIC_NUMBER 
                    || u32::from_be(commit_header.h_blocktype) != JBD2_COMMIT_BLOCK 
                    || u32::from_be(commit_header.h_sequence) != expected_seq 
                {
                    log::info!("Transaction {} not fully committed in journal. Stopping replay.", expected_seq);
                    break;
                }

                // Replay the metadata blocks to their final destination blocks
                for (tag, mut data) in tags.iter().zip(meta_blocks.into_iter()) {
                    let dest_block = u32::from_be(tag.t_blocknr) as u64;
                    let flags = u32::from_be(tag.t_flags);
                    if (flags & JBD2_FLAG_ESCAPE) != 0 {
                        // Restore escaped magic
                        if data.len() >= 4 {
                            data[0..4].copy_from_slice(&JBD2_MAGIC_NUMBER.to_be_bytes());
                        }
                    }
                    log::info!("Replaying block {} to filesystem offset {}...", dest_block, dest_block * block_size as u64);
                    self.underlying.write_offset(dest_block as usize * block_size, &data);
                }

                expected_seq += 1;
                curr_block = self.next_journal_block(&state, curr_block);
            } else {
                break;
            }
        }

        // Mark the journal as clean
        self.write_journal_superblock(&state, 0, expected_seq)?;
        self.underlying.write_offset(0, &[]); // Flush disk
        log::info!("Journal recovery completed. Journal is clean.");
        Ok(())
    }

    pub fn set_metadata_writing(&self, enabled: bool) {
        let mut state = self.state.lock();
        state.metadata_writing = enabled;
    }
}

impl BlockDevice for JournalBlockDevice {
    fn read_offset(&self, offset: usize, buf: &mut [u8]) {
        let block_size = self.block_size();
        let block_idx = (offset / block_size) as u64;
        let inner_offset = offset % block_size;

        let state = self.state.lock();
        if state.is_in_transaction && state.metadata_writing {
            if let Some(cached_data) = state.cached_blocks.get(&block_idx) {
                let len = buf.len();
                buf.copy_from_slice(&cached_data[inner_offset..inner_offset + len]);
                return;
            }
        }
        self.underlying.read_offset(offset, buf);
    }

    fn write_offset(&self, offset: usize, data: &[u8]) {
        let block_size = self.block_size();
        let block_idx = (offset / block_size) as u64;
        let inner_offset = offset % block_size;

        let mut state = self.state.lock();
        if state.is_in_transaction && state.metadata_writing {
            let entry = state.cached_blocks.entry(block_idx).or_insert_with(|| {
                let mut buf = vec![0u8; block_size];
                self.underlying.read_offset((block_idx as usize) * block_size, &mut buf);
                buf
            });
            let len = data.len();
            entry[inner_offset..inner_offset + len].copy_from_slice(data);
        } else {
            self.underlying.write_offset(offset, data);
        }
    }

    fn block_size(&self) -> usize {
        self.underlying.block_size()
    }

    fn set_block_size(&self, size: usize) {
        self.underlying.set_block_size(size);
    }
}

unsafe impl Send for JournalBlockDevice {}
unsafe impl Sync for JournalBlockDevice {}
impl core::fmt::Debug for JournalBlockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JournalBlockDevice").finish()
    }
}
