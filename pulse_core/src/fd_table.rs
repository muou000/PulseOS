use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::any::Any;
use spin::Mutex;

pub const FD_RESERVED: usize = 3;
pub const FD_LIMIT: usize = 1024;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct FdFlags: u32 {
        const CLOEXEC = 1 << 0;
        const NONBLOCK = 1 << 1;
    }
}

pub trait FdObject: Send + Sync {
    fn as_any(&self) -> &dyn Any;
}

pub struct RawFdObject {
    pub raw_fd: i32,
}

impl FdObject for RawFdObject {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Clone)]
pub struct FdEntry {
    pub object: Arc<dyn FdObject>,
    pub flags: FdFlags,
}

#[derive(Default)]
pub struct FdTable {
    entries: BTreeMap<usize, FdEntry>,
}

impl FdTable {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn clone_for_fork(&self) -> Self {
        Self {
            entries: self.entries.clone(),
        }
    }

    pub fn close_cloexec_on_exec(&mut self) {
        self.entries
            .retain(|_, entry| !entry.flags.contains(FdFlags::CLOEXEC));
    }

    pub fn get(&self, fd: usize) -> Option<&FdEntry> {
        self.entries.get(&fd)
    }

    pub fn get_mut(&mut self, fd: usize) -> Option<&mut FdEntry> {
        self.entries.get_mut(&fd)
    }

    pub fn insert_at(&mut self, fd: usize, entry: FdEntry) -> Result<(), ()> {
        if fd >= FD_LIMIT {
            return Err(());
        }
        self.entries.insert(fd, entry);
        Ok(())
    }

    pub fn insert_next(&mut self, entry: FdEntry) -> Result<usize, ()> {
        for fd in FD_RESERVED..FD_LIMIT {
            if !self.entries.contains_key(&fd) {
                self.entries.insert(fd, entry);
                return Ok(fd);
            }
        }
        Err(())
    }

    pub fn remove(&mut self, fd: usize) -> Option<FdEntry> {
        self.entries.remove(&fd)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn ensure_raw_fd(&mut self, fd: usize, raw_fd: i32) {
        self.entries.entry(fd).or_insert_with(|| FdEntry {
            object: Arc::new(RawFdObject { raw_fd }),
            flags: FdFlags::empty(),
        });
    }
}

pub type SharedFdTable = Arc<Mutex<FdTable>>;
