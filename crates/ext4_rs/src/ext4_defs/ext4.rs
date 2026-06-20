use crate::prelude::*;

use super::*;

#[derive(Debug, Clone)]
pub struct SystemZone {
    pub group: u32,
    pub start_blk: u64,
    pub end_blk: u64,
}

pub struct Ext4 {
    pub block_device: Arc<dyn BlockDevice>,
    pub super_block: Ext4Superblock,
    pub system_zone_cache: Option<Vec<SystemZone>>,
    pub inode_table_cache: Vec<u32>,
    pub inode_cache: spin::Mutex<[Option<InodeCacheEntry>; 16]>,
    #[cfg(feature = "journal")]
    pub journal: Option<Arc<crate::journal::JournalBlockDevice>>,
}

impl Ext4 {
    pub fn start_transaction(&self) {
        #[cfg(feature = "journal")]
        if let Some(ref journal) = self.journal {
            journal.start_transaction();
        }
    }

    pub fn stop_transaction(&self) -> Result<()> {
        #[cfg(feature = "journal")]
        if let Some(ref journal) = self.journal {
            journal.stop_transaction()?;
        }
        Ok(())
    }
}
