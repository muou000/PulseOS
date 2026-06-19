use crate::prelude::*;
use crate::return_errno_with_message;
use crate::utils::*;

use crate::ext4_defs::*;

impl Ext4 {
    /// 获取system zone缓存
    pub fn get_system_zone(&self) -> Vec<SystemZone> {
        let mut zones = Vec::new();
        let group_count = self.super_block.block_group_count();
        let inodes_per_group = self.super_block.inodes_per_group();
        let inode_size = self.super_block.inode_size() as u64;
        let block_size = self.super_block.block_size() as u64;
        log::debug!("get_system_zone: group_count={}", group_count);
        for bgid in 0..group_count {
            if bgid % 1024 == 0 && bgid > 0 {
                log::debug!("get_system_zone: processed {}/{} groups", bgid, group_count);
            }
            // meta blocks
            let meta_blks = self.num_base_meta_blocks(bgid);
            if meta_blks != 0 {
                let start = self.get_block_of_bgid(bgid);
                zones.push(SystemZone {
                    group: bgid,
                    start_blk: start,
                    end_blk: start + meta_blks as u64 - 1,
                });
            }
            // block group描述符
            let block_group = Ext4BlockGroup::load_new(&self.block_device, &self.super_block, bgid as usize);
            // block bitmap
            let blk_bmp = block_group.get_block_bitmap_block(&self.super_block);
            zones.push(SystemZone {
                group: bgid,
                start_blk: blk_bmp,
                end_blk: blk_bmp,
            });
            // inode bitmap
            let ino_bmp = block_group.get_inode_bitmap_block(&self.super_block);
            zones.push(SystemZone {
                group: bgid,
                start_blk: ino_bmp,
                end_blk: ino_bmp,
            });
            // inode table
            let ino_tbl = block_group.get_inode_table_blk_num() as u64;
            let itb_per_group = ((inodes_per_group as u64 * inode_size + block_size - 1) / block_size) as u64;
            zones.push(SystemZone {
                group: bgid,
                start_blk: ino_tbl,
                end_blk: ino_tbl + itb_per_group - 1,
            });
        }
        log::debug!("get_system_zone: finished, total zones={}", zones.len());
        zones
    }

    /// Opens and loads an Ext4 from the `block_device`.
    pub fn open(block_device: Arc<dyn BlockDevice>) -> Self {
        // Load the superblock (aligned to block 0)
        block_device.set_block_size(4096);
        let block = Block::load(&block_device, 0);
        let super_block: Ext4Superblock = block.read_offset_as(SUPERBLOCK_OFFSET);

        let block_size = super_block.block_size() as usize;
        block_device.set_block_size(block_size);

        let journal_device = Arc::new(crate::journal::JournalBlockDevice::new(block_device));
        let journal_device_dyn: Arc<dyn BlockDevice> = journal_device.clone();

        let group_count = super_block.block_group_count() as usize;
        log::debug!("Ext4::open: group_count={}", group_count);
        let mut inode_table_cache = Vec::with_capacity(group_count);
        for bgid in 0..group_count {
            if bgid % 1024 == 0 && bgid > 0 {
                log::debug!("Ext4::open: caching inode tables {}/{}", bgid, group_count);
            }
            let block_group = Ext4BlockGroup::load_new(&journal_device_dyn, &super_block, bgid);
            inode_table_cache.push(block_group.get_inode_table_blk_num());
        }
        
        let mut ext4 = Ext4 {
            block_device: journal_device_dyn.clone(),
            super_block,
            system_zone_cache: None,
            inode_table_cache,
            inode_cache: spin::Mutex::new([None; 16]),
            journal: None,
        };

        if super_block.journal_inode_number > 0 {
            log::info!("Ext4::open: journal inode number = {}", super_block.journal_inode_number);
            
            // Read journal inode info directly (avoiding cache lookup issues before journal is ready)
            let offset = ext4.inode_disk_pos(super_block.journal_inode_number);
            let block_offset = (offset / block_size) * block_size;
            let inner_offset = offset % block_size;

            let mut ext4block = Block::load(&journal_device_dyn, block_offset);
            let inode_val: Ext4Inode = ext4block.read_offset_as(inner_offset);
            let journal_inode_ref = Ext4InodeRef {
                inode_num: super_block.journal_inode_number,
                inode: inode_val,
            };

            let j_size = journal_inode_ref.inode.size();
            let num_blocks = (j_size / block_size as u64) as u32;
            let mut journal_blocks = Vec::new();
            for lblk in 0..num_blocks {
                if let Ok(pblk) = ext4.get_pblock_idx(&journal_inode_ref, lblk) {
                    journal_blocks.push(pblk);
                }
            }

            if !journal_blocks.is_empty() {
                log::info!("Ext4::open: found {} blocks for journal", journal_blocks.len());
                journal_device.init_journal(journal_blocks);
                if let Err(e) = journal_device.recover() {
                    log::error!("Journal recovery failed: {:?}", e);
                }
                ext4.journal = Some(journal_device);
            }
        }

        log::debug!("Ext4::open: initializing system zone cache");
        let zones = ext4.get_system_zone();

        log::debug!("Ext4::open: complete");
        Ext4 {
            system_zone_cache: Some(zones),
            ..ext4
        }
    }

    // with dir result search path offset
    pub fn generic_open(
        &self,
        path: &str,
        parent_inode_num: &mut u32,
        create: bool,
        ftype: u16,
        name_off: &mut u32,
    ) -> Result<u32> {
        let mut is_goal = false;

        let mut parent = parent_inode_num;

        let mut search_path = path;

        let mut dir_search_result = Ext4DirSearchResult::new(Ext4DirEntry::default());

        loop {
            while search_path.starts_with('/') {
                *name_off += 1; // Skip the slash
                search_path = &search_path[1..];
            }

            let len = path_check(search_path, &mut is_goal);

            let current_path = &search_path[..len];

            if len == 0 || search_path.is_empty() {
                break;
            }

            search_path = &search_path[len..];

            let r = self.dir_find_entry(*parent, current_path, &mut dir_search_result);

            // log::trace!("find in parent {:x?} r {:?} name {:?}", parent, r, current_path);
            if let Err(e) = r {
                if e.error() != Errno::ENOENT || !create {
                    return_errno_with_message!(Errno::ENOENT, "No such file or directory");
                }

                let mut inode_mode = 0;
                if is_goal {
                    inode_mode = ftype;
                } else {
                    inode_mode = InodeFileType::S_IFDIR.bits();
                }

                let new_inode_ref = self.create(*parent, current_path, inode_mode)?;

                // Update parent to the new inode
                *parent = new_inode_ref.inode_num;

                // Now, update dir_search_result to reflect the new inode
                dir_search_result.dentry.inode = new_inode_ref.inode_num;

                continue;
            }

            if is_goal {
                break;
            } else {
                // update parent
                *parent = dir_search_result.dentry.inode;
            }
            *name_off += len as u32;
        }

        if is_goal {
            return Ok(dir_search_result.dentry.inode);
        }

        Ok(dir_search_result.dentry.inode)
    }

    #[allow(unused)]
    pub fn dir_mk(&self, path: &str) -> Result<usize> {
        self.start_transaction();
        let res = (|| {
            let mut nameoff = 0;
            let filetype = InodeFileType::S_IFDIR;
            let mut parent = ROOT_INODE;
            let _ = self.generic_open(path, &mut parent, true, filetype.bits(), &mut nameoff)?;
            Ok(EOK)
        })();
        self.stop_transaction()?;
        res
    }

    pub fn unlink(
        &self,
        parent: &mut Ext4InodeRef,
        child: &mut Ext4InodeRef,
        name: &str,
    ) -> Result<usize> {
        self.start_transaction();
        let res = (|| {
            self.dir_remove_entry(parent, name)?;
            let is_dir = child.inode.is_dir();
            self.ialloc_free_inode(child.inode_num, is_dir);
            Ok(EOK)
        })();
        self.stop_transaction()?;
        res
    }
}
